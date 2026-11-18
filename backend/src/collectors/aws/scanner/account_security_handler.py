"""
account_security_handler.py — Personal Privacy & Security (issue #291). Lambda `account-security-handler` behind
GET/POST /account-security.

Boundaries (as the issue asks to keep them apart)
  identity verification  email ownership: Cognito's own verification code (done in the browser via Amplify)
  authentication         password + TOTP + passkeys: Cognito; passkeys are WebAuthn credentials Cognito validates
                         (challenge, origin, relying-party id). Niagaros never sees biometric data.
  step-up                sensitive changes here need a sign-in from the last STEP_UP_MINUTES (the token's auth_time,
                         verified by Cognito) and, when the user set one, their security PIN
  recovery               one-time recovery codes; a valid code + the account's email resets two-step verification
                         and signs the account out everywhere. The password is still needed to sign in afterwards.

GET  /account-security                         overview: methods, status, sessions, recent events, org policy
POST /account-security {action, ...}
       set_pin {pin, current_pin}             remove_pin {pin}            verify_pin {pin}
       generate_recovery_codes {pin}          disable_totp {pin}          delete_passkey {credential_id, pin}
       sign_out_everywhere {pin}
       recover {email, code}                  public (no token); generic answer, rate-limited

Secrets: the PIN and recovery codes are stored only as salted PBKDF2 / SHA-256 hashes and are never logged; the TOTP
secret never reaches this Lambda (Cognito returns it to the browser only).

Known limit: Cognito's own self-service API accepts the user's access token for MFA and passkey changes. The step-up
here protects every change made through Niagaros, but someone holding a stolen, unexpired access token (at most one
hour) could call Cognito directly. Such changes are not hidden: the overview compares Cognito's state with the last
visit and records any difference as an "observed" event.
"""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import psycopg2
from psycopg2.extras import Json

from collectors.aws.scanner.tenant_auth import _issued_by_our_pool

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
CORS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization"}
STEP_UP_MINUTES = 15
PIN_ITERATIONS = 310_000
PIN_MAX_FAILURES = 5
PIN_LOCK_MINUTES = 15
RECOVERY_CODES = 10
# Failures per email from one address, per email overall, and per address overall. The per-email total is set high
# enough that a stranger cannot cheaply lock someone out of recovery, and low enough that guessing a 40-bit code
# stays hopeless.
RECOVERY_LIMIT_PER_EMAIL_IP_HOUR = 5
RECOVERY_LIMIT_PER_EMAIL_HOUR = 30
RECOVERY_LIMIT_PER_IP_HOUR = 20
CODE_RE = re.compile(r"^[A-Z2-7]{4}-[A-Z2-7]{4}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")
GENERIC_RECOVERY = ("If the email address and recovery code are valid, two-step verification has been reset and every "
                    "session was signed out. Sign in with your password and set up two-step verification again.")
_J = lambda o: Json(o, dumps=lambda x: json.dumps(x, default=str))  # noqa: E731


class BadRequest(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status, self.message = status, message


class _Commit(BadRequest):
    """A refusal whose bookkeeping (failed-attempt counter, event) must still be committed."""


def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _get_connection():
    s = json.loads(boto3.client("secretsmanager", region_name=REGION).get_secret_value(
        SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _cognito():
    return boto3.client("cognito-idp", region_name=REGION)


def _now():
    return datetime.now(timezone.utc)


# ── caller ──────────────────────────────────────────────────────────────────

def _claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def _caller(event):
    """Cognito validates the token (GetUser); only then are its claims read. Returns None when invalid."""
    headers = (event or {}).get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token or not _issued_by_our_pool(token):
        return None
    try:
        user = _cognito().get_user(AccessToken=token)
        claims = _claims(token)
    except Exception:
        return None
    attrs = {a["Name"]: a["Value"] for a in user.get("UserAttributes") or []}
    return {"token": token, "sub": attrs.get("sub") or user["Username"], "username": user["Username"],
            "email": attrs.get("email"), "attrs": attrs, "mfa": user.get("UserMFASettingList") or [],
            "preferred_mfa": user.get("PreferredMfaSetting"), "claims": claims}


def _ctx(event):
    rc = (event or {}).get("requestContext") or {}
    ip = (rc.get("identity") or {}).get("sourceIp") or (rc.get("http") or {}).get("sourceIp")
    headers = (event or {}).get("headers") or {}
    ua = (headers.get("User-Agent") or headers.get("user-agent") or "")[:300]
    return ip, ua, rc.get("requestId")


def _event(cur, who, event, outcome="success", detail=None, ctx=(None, None, None)):
    cur.execute("""INSERT INTO account_security_events (user_sub, email, event, outcome, detail, ip, user_agent, correlation_id)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (who.get("sub"), who.get("email"), event, outcome, _J(detail or {}), ctx[0], ctx[1], ctx[2]))


# ── PIN / codes ─────────────────────────────────────────────────────────────

def _pin_ok_format(pin):
    if not isinstance(pin, str) or not re.fullmatch(r"\d{6,8}", pin):
        return "The PIN must be 6 to 8 digits"
    if len(set(pin)) == 1 or pin in "0123456789012345" or pin in "9876543210987654":
        return "Choose a PIN that is not a repeated or sequential number"
    return None


def _hash_pin(pin, salt, iterations=PIN_ITERATIONS):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, iterations)


def _new_code():
    raw = base64.b32encode(secrets.token_bytes(5)).decode()  # 40 bits
    return f"{raw[:4]}-{raw[4:8]}"


def _hash_code(code, salt):
    return hashlib.sha256(salt + code.upper().encode()).digest()


def _row(cur, who, lock=False):
    cur.execute(f"""SELECT pin_hash, pin_salt, pin_iterations, pin_set_at, pin_failed, pin_locked_until, snapshot
                    FROM account_security WHERE user_sub = %s {"FOR UPDATE" if lock else ""}""", (who["sub"],))
    r = cur.fetchone()
    if not r:
        cur.execute("""INSERT INTO account_security (user_sub, email) VALUES (%s, %s) ON CONFLICT (user_sub) DO NOTHING""",
                    (who["sub"], who["email"] or ""))
        # Re-read (and lock): a concurrent request may have created the row, with a PIN, in the meantime.
        cur.execute(f"""SELECT pin_hash, pin_salt, pin_iterations, pin_set_at, pin_failed, pin_locked_until, snapshot
                        FROM account_security WHERE user_sub = %s {"FOR UPDATE" if lock else ""}""", (who["sub"],))
        r = cur.fetchone()
    return dict(zip(("pin_hash", "pin_salt", "pin_iterations", "pin_set_at", "pin_failed", "pin_locked_until", "snapshot"), r))


def _check_pin(cur, who, row, pin, ctx):
    """True when the PIN matches. Failures count towards a temporary lock; the lock is checked first."""
    if row["pin_locked_until"] and row["pin_locked_until"] > _now():
        raise BadRequest(429, "Too many wrong PIN attempts. Try again after " + row["pin_locked_until"].strftime("%H:%M UTC"))
    ok = isinstance(pin, str) and bool(row["pin_hash"]) and hmac.compare_digest(
        _hash_pin(pin, bytes(row["pin_salt"]), row["pin_iterations"]), bytes(row["pin_hash"]))
    if ok:
        cur.execute("UPDATE account_security SET pin_failed = 0, pin_locked_until = NULL WHERE user_sub = %s", (who["sub"],))
        return True
    failed = row["pin_failed"] + 1
    locked = _now() + timedelta(minutes=PIN_LOCK_MINUTES) if failed >= PIN_MAX_FAILURES else None
    cur.execute("UPDATE account_security SET pin_failed = %s, pin_locked_until = %s WHERE user_sub = %s",
                (0 if locked else failed, locked, who["sub"]))
    _event(cur, who, "pin_locked" if locked else "pin_failed", "failure", {"attempt": failed}, ctx)
    return False


def _step_up(cur, who, body, ctx, row=None):
    """Sensitive changes: a recent sign-in, and the PIN when the user has one. Failures are recorded."""
    auth_time = who["claims"].get("auth_time")
    if not auth_time or _now() - datetime.fromtimestamp(int(auth_time), timezone.utc) > timedelta(minutes=STEP_UP_MINUTES):
        _event(cur, who, "step_up_required", "failure", {"reason": "sign-in older than %d minutes" % STEP_UP_MINUTES}, ctx)
        raise _Commit(403, f"For your security, sign in again (sign-ins older than {STEP_UP_MINUTES} minutes cannot change security settings)")
    row = row or _row(cur, who, lock=True)
    if row["pin_hash"]:
        if not _check_pin(cur, who, row, body.get("pin"), ctx):
            raise _Commit(403, "The PIN is not correct")
    return row




# ── overview ────────────────────────────────────────────────────────────────

def _passkeys(token):
    try:
        out, nxt = [], None
        while True:
            r = _cognito().list_web_authn_credentials(AccessToken=token, **({"NextToken": nxt} if nxt else {}))
            out += [{"id": c.get("CredentialId"), "name": c.get("FriendlyCredentialName"), "created_at": c.get("CreatedAt"),
                     "authenticator": c.get("AuthenticatorAttachment"), "transports": c.get("AuthenticatorTransports") or []}
                    for c in r.get("Credentials") or []]
            nxt = r.get("NextToken")
            if not nxt:
                return out, None
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
        return None, ("Passkeys are not enabled for this sign-in service yet" if code in ("WebAuthnNotEnabledException", "WebAuthnConfigurationMissingException")
                      else "Passkeys could not be read")


def _org_policy(cur, email):
    cur.execute("SAVEPOINT org_policy")
    try:
        cur.execute("""SELECT o.name, o.mfa_required, u.role FROM users u JOIN organizations o ON o.id = u.organization_id
                       WHERE lower(u.email) = lower(%s) AND u.status = 'active' LIMIT 1""", (email,))
        r = cur.fetchone()
        cur.execute("RELEASE SAVEPOINT org_policy")
    except Exception:  # noqa: BLE001 - a missing table (older environment) means "no known policy"
        cur.execute("ROLLBACK TO SAVEPOINT org_policy")
        return None
    if not r:
        return None
    return {"organization": r[0], "mfa_required": bool(r[1]), "role": r[2],
            "managed_in": "/settings/team" if r[2] == "admin" else None}


def assess(email_verified, totp, passkeys, recovery_remaining, policy, passkeys_known=True):
    """Overall status from the effective policy, the enrolled methods and recovery. Never 'protected' on a verified
    email alone, and 'unknown' when what is enrolled cannot be determined."""
    missing, recs = [], []
    if not email_verified:
        missing.append("Verify your email address")
    if policy and policy.get("mfa_required") and not totp:
        missing.append(f"{policy['organization']} requires two-step verification: set up an authenticator app")
    if missing:
        return {"status": "action_required", "required": missing, "recommendations": recs}
    # Password sign-in stays available, so only a second factor ON that path (the authenticator app) means a stolen
    # password is not enough. A passkey adds a phishing-resistant way in; it does not close the password path.
    if not totp and not passkeys and not passkeys_known:
        return {"status": "unknown", "required": [], "recommendations": ["Passkeys could not be checked; try again later"]}
    if not totp:
        recs.append("Add an authenticator app: without it your password alone is enough to sign in"
                    + (" (your passkey does not change that)" if passkeys else ""))
    elif recovery_remaining == 0:
        recs.append("Create recovery codes so you can get back in if you lose your device")
    if passkeys_known and not passkeys:
        recs.append("Add a passkey: it cannot be phished")
    return {"status": "protected" if totp and recovery_remaining > 0 else "review_recommended",
            "required": [], "recommendations": recs}


def _observe(cur, who, row, current, ctx):
    """Record changes Niagaros can see in Cognito since the last visit (made here, in Cognito or elsewhere)."""
    old = row.get("snapshot") or {}
    if old:
        for key, label in (("totp", "authenticator_app"), ("email_verified", "email_verification")):
            if key in current and key in old and current[key] != old[key]:
                _event(cur, who, f"{label}_changed", "observed", {"from": old[key], "to": current[key]}, ctx)
        if "passkeys" in current and "passkeys" in old and current["passkeys"] != old["passkeys"]:
            before = set(old["passkeys"]) if isinstance(old["passkeys"], list) else set()
            after = set(current["passkeys"])
            _event(cur, who, "passkeys_changed", "observed",
                   {"added": len(after - before), "removed": len(before - after) if before else None, "now": len(after)}, ctx)
    cur.execute("UPDATE account_security SET snapshot = %s, email = %s, updated_at = NOW() WHERE user_sub = %s",
                (_J(current), who["email"] or "", who["sub"]))


def _session_seen(cur, who, ctx):
    c = who["claims"]
    key = c.get("origin_jti") or c.get("jti")
    if not key:
        return
    signed_in = datetime.fromtimestamp(int(c["auth_time"]), timezone.utc) if c.get("auth_time") else None
    cur.execute("""INSERT INTO account_sessions (user_sub, session_key, signed_in_at, ip, user_agent)
                   VALUES (%s, %s, %s, %s, %s)
                   ON CONFLICT (user_sub, session_key) DO UPDATE SET last_seen = NOW(), ip = EXCLUDED.ip, user_agent = EXCLUDED.user_agent
                   RETURNING (xmax = 0)""", (who["sub"], hashlib.sha256(key.encode()).hexdigest(), signed_in, ctx[0], ctx[1]))
    if cur.fetchone()[0]:
        _event(cur, who, "new_sign_in_session_seen", "observed", {"signed_in_at": signed_in}, ctx)


def view_overview(cur, who, ctx):
    row = _row(cur, who, lock=True)
    _session_seen(cur, who, ctx)
    totp = "SOFTWARE_TOKEN_MFA" in who["mfa"]
    passkeys, pk_error = _passkeys(who["token"])
    cur.execute("""SELECT count(*), max(created_at) FROM account_recovery_codes WHERE user_sub = %s AND used_at IS NULL
                   AND superseded_at IS NULL""", (who["sub"],))
    remaining, generated = cur.fetchone()
    email_verified = who["attrs"].get("email_verified") == "true"
    policy = _org_policy(cur, who["email"])
    current = {"totp": totp, "email_verified": email_verified}
    if passkeys is not None:
        # Hashed credential ids, so a replaced passkey is noticed even when the number stays the same.
        current["passkeys"] = sorted(hashlib.sha256((p["id"] or "").encode()).hexdigest()[:16] for p in passkeys)
    _observe(cur, who, row, current, ctx)
    c = who["claims"]
    auth_time = datetime.fromtimestamp(int(c["auth_time"]), timezone.utc) if c.get("auth_time") else None
    cur.execute("""SELECT session_key, signed_in_at, first_seen, last_seen, ip, user_agent, signed_out_at FROM account_sessions
                   WHERE user_sub = %s AND last_seen > NOW() - interval '30 days' ORDER BY last_seen DESC LIMIT 20""", (who["sub"],))
    this_key = hashlib.sha256((c.get("origin_jti") or c.get("jti") or "").encode()).hexdigest()
    sessions = [{"current": k == this_key, "signed_in_at": a, "first_seen": b, "last_seen": d, "ip": e, "user_agent": f,
                 "signed_out_at": g} for k, a, b, d, e, f, g in cur.fetchall()]
    cur.execute("""SELECT at, event, outcome, detail, ip, user_agent FROM account_security_events WHERE user_sub = %s
                   ORDER BY at DESC LIMIT 50""", (who["sub"],))
    events = [{"at": a, "event": b, "outcome": o, "detail": d, "ip": i, "user_agent": u} for a, b, o, d, i, u in cur.fetchall()]
    return {
        "email": who["email"], "email_verified": email_verified,
        "phone": {"number": who["attrs"].get("phone_number"), "verified": who["attrs"].get("phone_number_verified") == "true",
                  "available": False, "reason": "SMS delivery is not available yet: Niagaros' SMS provider is still in its "
                                                "sandbox, so codes would not reliably reach you"},
        "totp": {"enabled": totp, "preferred": who["preferred_mfa"] == "SOFTWARE_TOKEN_MFA"},
        "passkeys": passkeys, "passkeys_error": pk_error,
        "pin": {"set": bool(row["pin_hash"]), "set_at": row["pin_set_at"], "locked_until": row["pin_locked_until"],
                "used_for": "Confirming sensitive changes on this page (together with a recent sign-in)"},
        "recovery_codes": {"remaining": remaining, "generated_at": generated},
        "session": {"signed_in_at": auth_time, "expires_at": datetime.fromtimestamp(int(c["exp"]), timezone.utc) if c.get("exp") else None,
                    "recent_enough_for_changes": bool(auth_time and _now() - auth_time <= timedelta(minutes=STEP_UP_MINUTES)),
                    "step_up_minutes": STEP_UP_MINUTES},
        "sessions": sessions, "events": events, "policy": policy,
        "assessment": assess(email_verified, totp, bool(passkeys), remaining, policy, passkeys is not None),
        "federation": {"available": False, "reason": "Single sign-on with your own identity provider (SAML / OIDC) is not offered yet"},
    }


# ── actions ─────────────────────────────────────────────────────────────────

def do_action(cur, who, body, ctx):
    a = body.get("action")
    if a == "verify_pin":
        row = _row(cur, who, lock=True)
        if not row["pin_hash"]:
            raise BadRequest(409, "No PIN is set")
        if not _check_pin(cur, who, row, body.get("pin"), ctx):
            raise _Commit(403, "The PIN is not correct")
        return {"ok": True}
    if a == "confirm_step_up":
        # Called right before adding a sign-in method in the browser: recent sign-in and the PIN, checked here.
        _step_up(cur, who, body, ctx)
        _event(cur, who, "step_up_confirmed", "success", {"for": str(body.get("purpose") or "")[:40]}, ctx)
        return {"ok": True}
    if a == "set_pin":
        row = _step_up(cur, who, {"pin": body.get("current_pin")}, ctx)
        err = _pin_ok_format(body.get("new_pin"))
        if err:
            raise BadRequest(400, err)
        salt = secrets.token_bytes(16)
        cur.execute("""UPDATE account_security SET pin_hash = %s, pin_salt = %s, pin_iterations = %s, pin_set_at = NOW(),
                       pin_failed = 0, pin_locked_until = NULL WHERE user_sub = %s""",
                    (_hash_pin(body["new_pin"], salt), salt, PIN_ITERATIONS, who["sub"]))
        _event(cur, who, "pin_changed" if row["pin_hash"] else "pin_set", "success", {}, ctx)
        return {"saved": True, "note": "Security PIN saved."}
    if a == "remove_pin":
        row = _step_up(cur, who, body, ctx)
        if not row["pin_hash"]:
            raise BadRequest(409, "No PIN is set")
        cur.execute("UPDATE account_security SET pin_hash = NULL, pin_salt = NULL, pin_iterations = NULL, pin_set_at = NULL WHERE user_sub = %s",
                    (who["sub"],))
        _event(cur, who, "pin_removed", "success", {}, ctx)
        return {"saved": True, "note": "Security PIN removed."}
    if a == "generate_recovery_codes":
        _step_up(cur, who, body, ctx)
        cur.execute("UPDATE account_recovery_codes SET superseded_at = NOW() WHERE user_sub = %s AND used_at IS NULL AND superseded_at IS NULL",
                    (who["sub"],))
        batch, codes = str(uuid.uuid4()), []
        for _ in range(RECOVERY_CODES):
            code, salt = _new_code(), secrets.token_bytes(16)
            codes.append(code)
            cur.execute("""INSERT INTO account_recovery_codes (user_sub, batch_id, code_salt, code_hash) VALUES (%s, %s, %s, %s)""",
                        (who["sub"], batch, salt, _hash_code(code, salt)))
        _event(cur, who, "recovery_codes_generated", "success", {"count": RECOVERY_CODES}, ctx)
        return {"codes": codes, "note": "Save these codes somewhere safe. They are shown only once; older codes stop working."}
    if a == "disable_totp":
        _step_up(cur, who, body, ctx)
        policy = _org_policy(cur, who["email"])
        if policy and policy["mfa_required"]:
            _event(cur, who, "authenticator_app_disable_refused", "failure", {"reason": "organization policy"}, ctx)
            raise _Commit(403, f"{policy['organization']} requires two-step verification, so the authenticator app cannot be turned off")
        _cognito().set_user_mfa_preference(AccessToken=who["token"], SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False})
        _event(cur, who, "authenticator_app_disabled", "success", {}, ctx)
        return {"saved": True, "note": "The authenticator app is turned off."}
    if a == "delete_passkey":
        cid = body.get("credential_id")
        if not isinstance(cid, str) or not cid or len(cid) > 1024:
            raise BadRequest(400, "Choose a passkey")
        _step_up(cur, who, body, ctx)
        passkeys, _err = _passkeys(who["token"])
        policy = _org_policy(cur, who["email"])
        totp = "SOFTWARE_TOKEN_MFA" in who["mfa"]
        if passkeys is not None and len(passkeys) == 1 and policy and policy["mfa_required"] and not totp:
            raise _Commit(403, "This is your only second factor and your organization requires one. Add an authenticator app first.")
        _cognito().delete_web_authn_credential(AccessToken=who["token"], CredentialId=cid)
        _event(cur, who, "passkey_removed", "success", {}, ctx)
        return {"saved": True, "note": "Passkey removed."}
    if a == "sign_out_everywhere":
        _step_up(cur, who, body, ctx)
        _cognito().global_sign_out(AccessToken=who["token"])
        cur.execute("UPDATE account_sessions SET signed_out_at = NOW() WHERE user_sub = %s AND signed_out_at IS NULL", (who["sub"],))
        _event(cur, who, "signed_out_everywhere", "success", {}, ctx)
        return {"saved": True, "note": "Signed out everywhere. Every session, including this one, has to sign in again."}
    raise BadRequest(400, "Unknown action")


def recover(cur, body, ctx):
    """Public. Always answers the same, whatever the outcome, so it cannot be used to find accounts."""
    email = body.get("email") if isinstance(body.get("email"), str) else ""
    code = body.get("code").strip().upper() if isinstance(body.get("code"), str) else ""
    email_hash = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    # Serialise attempts per address and per email (always in this order) so concurrent requests cannot all pass
    # the same allowance.
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('recover-ip:' || %s))", (str(ctx[0]),))
    cur.execute("SELECT pg_advisory_xact_lock(hashtext('recover:' || %s))", (email_hash,))
    cur.execute("""SELECT count(*) FILTER (WHERE email_hash = %s AND ip IS NOT DISTINCT FROM %s AND NOT success),
                          count(*) FILTER (WHERE email_hash = %s AND NOT success),
                          count(*) FILTER (WHERE ip IS NOT DISTINCT FROM %s)
                   FROM account_recovery_attempts WHERE at > NOW() - interval '1 hour' AND (email_hash = %s OR ip = %s)""",
                (email_hash, ctx[0], email_hash, ctx[0], email_hash, ctx[0]))
    by_email_ip, by_email, by_ip = cur.fetchone()
    if (by_email_ip >= RECOVERY_LIMIT_PER_EMAIL_IP_HOUR or by_email >= RECOVERY_LIMIT_PER_EMAIL_HOUR
            or by_ip >= RECOVERY_LIMIT_PER_IP_HOUR):
        raise _Commit(429, "Too many attempts. Try again in an hour.")
    ok, sub, username = False, None, None
    if EMAIL_RE.match(email or "") and CODE_RE.match(code):
        try:
            users = _cognito().list_users(UserPoolId=POOL_ID, Filter=f'email = "{email.strip().lower()}"', Limit=2).get("Users") or []
        except Exception:  # noqa: BLE001
            users = []
        if len(users) == 1:
            username = users[0]["Username"]
            sub = next((a["Value"] for a in users[0].get("Attributes") or [] if a["Name"] == "sub"), username)
            cur.execute("""SELECT id, code_salt, code_hash FROM account_recovery_codes WHERE user_sub = %s AND used_at IS NULL
                           AND superseded_at IS NULL FOR UPDATE""", (sub,))
            for cid, salt, h in cur.fetchall():
                if hmac.compare_digest(_hash_code(code, bytes(salt)), bytes(h)):
                    cur.execute("UPDATE account_recovery_codes SET used_at = NOW() WHERE id = %s AND used_at IS NULL", (cid,))
                    ok = cur.rowcount == 1
                    break
    cur.execute("INSERT INTO account_recovery_attempts (email_hash, ip, success) VALUES (%s, %s, %s)", (email_hash, ctx[0], ok))
    who = {"sub": sub, "email": email.strip().lower()}
    if not ok:
        if sub:
            _event(cur, who, "recovery_failed", "failure", {}, ctx)
        return {"message": GENERIC_RECOVERY}
    # The code is spent before anything changes in Cognito, so a partial failure can never leave it reusable.
    _event(cur, who, "recovery_code_used", "success", {"effect": "sign out everywhere, then reset two-step verification and PIN"}, ctx)
    cur.connection.commit()
    try:
        c = _cognito()
        c.admin_user_global_sign_out(UserPoolId=POOL_ID, Username=username)   # first: end every session
        c.admin_set_user_mfa_preference(UserPoolId=POOL_ID, Username=username,
                                        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False})
    except Exception:  # noqa: BLE001
        logger.exception("recovery could not complete in Cognito")
        _event(cur, who, "recovery_incomplete", "failure", {"note": "the code was used; use another code or contact support"}, ctx)
        return {"message": GENERIC_RECOVERY}
    cur.execute("UPDATE account_sessions SET signed_out_at = NOW() WHERE user_sub = %s AND signed_out_at IS NULL", (sub,))
    # A forgotten PIN must not keep blocking the account after a successful recovery.
    cur.execute("""UPDATE account_security SET pin_hash = NULL, pin_salt = NULL, pin_iterations = NULL, pin_set_at = NULL,
                   pin_failed = 0, pin_locked_until = NULL WHERE user_sub = %s""", (sub,))
    return {"message": GENERIC_RECOVERY}


def handler(event, context):
    method = (event or {}).get("httpMethod") or "GET"
    if method == "OPTIONS":
        return _resp(200, {})
    body = {}
    if method == "POST":
        try:
            body = json.loads((event or {}).get("body") or "{}")
        except (TypeError, ValueError):
            return _resp(400, {"error": "Invalid request"})
        if not isinstance(body, dict):
            return _resp(400, {"error": "Invalid request"})
    ctx = _ctx(event)
    conn = None
    try:
        conn = _get_connection()
        with conn.cursor() as cur:
            if method == "POST" and body.get("action") == "recover":
                out = recover(cur, body, ctx)
                conn.commit()
                return _resp(200, out)
            who = _caller(event)
            if not who or not who.get("email"):
                return _resp(401, {"error": "Unauthorized"})
            if method == "GET":
                out = view_overview(cur, who, ctx)
            elif method == "POST":
                out = do_action(cur, who, body, ctx)
            else:
                return _resp(405, {"error": "Method not allowed"})
            conn.commit()
            return _resp(200, out)
    except _Commit as e:
        conn.commit()
        return _resp(e.status, {"error": e.message})
    except BadRequest as e:
        if conn:
            conn.rollback()
        return _resp(e.status, {"error": e.message})
    except Exception:
        logger.exception("account security request failed")
        if conn:
            conn.rollback()
        return _resp(500, {"error": "Something went wrong. Nothing was changed. Please try again."})
    finally:
        if conn:
            conn.close()
