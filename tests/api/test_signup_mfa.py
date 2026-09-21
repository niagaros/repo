"""Sign up -> verify identity -> MFA (TOTP) -> session -> sign out, against the real Cognito user pool.

Verification codes are delivered by email, which a test cannot read, so the flow proves what can be proven without a
mailbox: an unverified user cannot sign in, a wrong code is refused, and only after the account is confirmed (by the
AWS administrator API - the stand-in for typing the emailed code) does the rest run for real: TOTP enrolment, an MFA
challenge on every sign-in, a wrong MFA code being refused, and a working session that is revoked on sign-out.
Needs AWS administrator credentials (local runs); it is reported as blocked, never as passed, without them."""
import base64
import hashlib
import hmac
import json
import secrets
import string
import struct
import time

import pytest
import requests

from conftest import API_BASE, COGNITO_CLIENT_ID

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-AUTH-003"), pytest.mark.severity("P0")]
POOL = "eu-west-1_mHQf9RNTc"


def cognito(target, body):
    r = requests.post("https://cognito-idp.eu-west-1.amazonaws.com/", timeout=30,
                      headers={"X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}", "Content-Type": "application/x-amz-json-1.1"},
                      data=json.dumps(body))
    return r.status_code, (r.json() if r.text else {})


def totp(secret_b32, at=None):
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    counter = int((at or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


@pytest.fixture
def admin():
    boto3 = pytest.importorskip("boto3")
    try:
        c = boto3.client("cognito-idp", region_name="eu-west-1")
        c.describe_user_pool(UserPoolId=POOL)
    except Exception as e:
        pytest.skip(f"blocked: needs AWS administrator credentials ({type(e).__name__})")
    return c


def test_signup_verification_mfa_session_and_signout(admin, step):
    email = f"e2e-signup-{secrets.token_hex(4)}@niagaros.test"
    password = "Aa1!" + "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    try:
        with step("sign up: the account is created but unverified"):
            s, d = cognito("SignUp", {"ClientId": COGNITO_CLIENT_ID, "Username": email, "Password": password,
                                      "UserAttributes": [{"Name": "email", "Value": email}]})
            assert s == 200 and d["UserConfirmed"] is False, (s, d)
            assert admin.admin_get_user(UserPoolId=POOL, Username=email)["UserStatus"] == "UNCONFIRMED"

        with step("weak passwords are refused at sign-up"):
            s, d = cognito("SignUp", {"ClientId": COGNITO_CLIENT_ID, "Username": f"weak-{email}", "Password": "short",
                                      "UserAttributes": [{"Name": "email", "Value": f"weak-{email}"}]})
            assert s == 400 and d["__type"] in ("InvalidPasswordException", "InvalidParameterException")

        with step("an unverified user cannot sign in"):
            s, d = cognito("InitiateAuth", {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"USERNAME": email, "PASSWORD": password}})
            assert s == 400 and "AuthenticationResult" not in d, d

        with step("verification: a wrong emailed code is refused"):
            s, d = cognito("ConfirmSignUp", {"ClientId": COGNITO_CLIENT_ID, "Username": email, "ConfirmationCode": "000000"})
            assert s == 400 and d["__type"] in ("CodeMismatchException", "ExpiredCodeException", "NotAuthorizedException"), d

        with step("identity verified (administrator confirms, standing in for the emailed code)"):
            admin.admin_confirm_sign_up(UserPoolId=POOL, Username=email)
            s, d = cognito("InitiateAuth", {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"USERNAME": email, "PASSWORD": password}})
            assert s == 200 and "AuthenticationResult" in d, d
            access = d["AuthenticationResult"]["AccessToken"]

        with step("MFA: enrol an authenticator app (TOTP) and enable it"):
            s, d = cognito("AssociateSoftwareToken", {"AccessToken": access})
            assert s == 200 and d["SecretCode"], d
            secret = d["SecretCode"]
            s, d = cognito("VerifySoftwareToken", {"AccessToken": access, "UserCode": totp(secret), "FriendlyDeviceName": "e2e"})
            assert s == 200 and d["Status"] == "SUCCESS", d
            s, _ = cognito("SetUserMFAPreference", {"AccessToken": access, "SoftwareTokenMfaSettings": {"Enabled": True, "PreferredMfa": True}})
            assert s == 200

        with step("signing in now requires MFA: password alone gives a challenge, not a session"):
            s, d = cognito("InitiateAuth", {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"USERNAME": email, "PASSWORD": password}})
            assert s == 200 and d.get("ChallengeName") == "SOFTWARE_TOKEN_MFA" and "AuthenticationResult" not in d, d
            challenge = d

        with step("a wrong MFA code is refused"):
            s, d = cognito("RespondToAuthChallenge", {"ClientId": COGNITO_CLIENT_ID, "ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": challenge["Session"],
                                                      "ChallengeResponses": {"USERNAME": email, "SOFTWARE_TOKEN_MFA_CODE": "000000"}})
            assert s == 400 and "AuthenticationResult" not in d

        with step("the correct MFA code opens a session that works against the API"):
            s, d = cognito("InitiateAuth", {"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID, "AuthParameters": {"USERNAME": email, "PASSWORD": password}})
            code = totp(secret, at=time.time() + 30)   # Cognito refuses to reuse the enrolment code's 30-second window
            s, d = cognito("RespondToAuthChallenge", {"ClientId": COGNITO_CLIENT_ID, "ChallengeName": "SOFTWARE_TOKEN_MFA", "Session": d["Session"],
                                                      "ChallengeResponses": {"USERNAME": email, "SOFTWARE_TOKEN_MFA_CODE": code}})
            assert s == 200 and "AuthenticationResult" in d, d
            access, refresh = d["AuthenticationResult"]["AccessToken"], d["AuthenticationResult"]["RefreshToken"]
            r = requests.get(f"{API_BASE}/get-dashboard-data", headers={"Authorization": f"Bearer {access}"}, timeout=30)
            assert r.status_code == 200 and r.json().get("needs_onboarding") is True     # a brand-new user has no account yet

        with step("signing out revokes the session"):
            s, _ = cognito("RevokeToken", {"Token": refresh, "ClientId": COGNITO_CLIENT_ID})
            assert s == 200
            r = requests.get(f"{API_BASE}/get-dashboard-data", headers={"Authorization": f"Bearer {access}"}, timeout=30)
            assert r.status_code == 401
    finally:
        for u in (email, f"weak-{email}"):
            try:
                admin.admin_delete_user(UserPoolId=POOL, Username=u)
            except Exception:
                pass
