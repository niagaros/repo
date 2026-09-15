import json
import logging

from config.database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Roles match the PVA's own Step 2 wording (#265) exactly: Admin, Security,
# Compliance, Viewer. Anything beyond these four (custom roles, permission
# inheritance, ...) is explicitly out of scope for this first pass.
VALID_ROLES = {"admin", "security", "compliance", "viewer"}


def _response(status: int, body: dict) -> dict:
    return {"statusCode": status, "body": json.dumps(body)}


def _get_authenticated_email(event: dict) -> str | None:
    """
    KNOWN GAP — do not treat this as solved: every route on this API
    (see docs/internal/architecture/aws/api_inventory.md) has
    AuthorizationType "NONE" at the API Gateway level, meaning whatever
    validates the "Authorization: Bearer <token>" header the frontend
    sends (see frontend/src/settings/*.tsx) happens *inside* each existing
    Lambda (profile-handler, github-oauth-handler, ...) — but none of that
    code lives in this repository, so the exact mechanism (Cognito JWT
    signature verification against the user pool's JWKS, presumably) is
    unverified here.

    This function is a placeholder that must be reconciled with whatever
    the real, already-deployed handlers do, before this handler is wired
    up to a real API Gateway route. Isolated behind this one function on
    purpose so that reconciliation is a one-line change, not a rewrite.
    """
    raise NotImplementedError(
        "Wire this up to the same Cognito token verification the existing "
        "profile-handler / github-oauth-handler Lambdas use — that code "
        "isn't in this repo, so it can't be copied here yet."
    )


def _get_caller(event: dict, db: Database) -> dict | None:
    email = _get_authenticated_email(event)
    if not email:
        return None
    return db.get_user_by_email(email)


def handle_list_team(event: dict, db: Database) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})

    members = db.get_organization_members(caller["organization_id"])
    invites = db.list_pending_invites(caller["organization_id"])
    return _response(200, {"members": members, "pending_invites": invites})


def handle_invite_member(event: dict, db: Database) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can invite team members"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    email = (body.get("email") or "").strip().lower()
    role  = (body.get("role")  or "viewer").strip().lower()

    if not email or "@" not in email:
        return _response(400, {"error": "a valid email is required"})
    if role not in VALID_ROLES:
        return _response(400, {"error": f"role must be one of {sorted(VALID_ROLES)}"})

    try:
        invite_id = db.create_team_invite(
            organization_id=caller["organization_id"],
            email=email, role=role, invited_by=caller["id"],
        )
    except Exception as e:
        # Covers the UNIQUE (organization_id, email) constraint — psycopg2's
        # exact exception class depends on the driver version, so this is
        # deliberately broad rather than importing psycopg2.errors here.
        if "duplicate key" in str(e).lower() or "unique" in str(e).lower():
            return _response(409, {"error": f"{email} is already invited or a member"})
        raise

    logger.info(f"Team invite created: {invite_id} for {email} by {caller['email']}")
    return _response(201, {"invite_id": invite_id, "email": email, "role": role})


def handle_accept_invite(event: dict, db: Database) -> dict:
    """
    Issue #265, acceptance criterion #1. Meant to be called once,
    automatically, right after login (see useRequireAuth.ts) — not
    something the user clicks. A no-op (200, accepted: False) when there
    was nothing to accept, so it's always safe to call.
    """
    email = _get_authenticated_email(event)
    if not email:
        return _response(401, {"error": "unauthorized"})

    caller = db.get_user_by_email(email)
    if not caller:
        return _response(404, {"error": "user not found"})

    result = db.accept_pending_invite(caller["id"], email)
    if result is None:
        return _response(200, {"accepted": False})
    return _response(200, {"accepted": True, **result})


def handle_revoke_invite(event: dict, db: Database, invite_id: str) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can revoke invites"})

    revoked = db.revoke_team_invite(invite_id, caller["organization_id"])
    if not revoked:
        return _response(404, {"error": "invite not found or already resolved"})
    return _response(200, {"revoked": invite_id})


def handle_update_role(event: dict, db: Database, user_id: str) -> dict:
    """Issue #265, acceptance criterion #2."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can change roles"})
    if user_id == caller["id"]:
        return _response(400, {"error": "you cannot change your own role"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    new_role = (body.get("role") or "").strip().lower()
    if new_role not in VALID_ROLES:
        return _response(400, {"error": f"role must be one of {sorted(VALID_ROLES)}"})

    updated = db.update_user_role(user_id, caller["organization_id"], new_role)
    if not updated:
        return _response(404, {"error": "user not found in your organization"})

    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="role_changed", target_user_id=user_id, details={"new_role": new_role},
    )
    logger.info(f"Role changed: {user_id} -> {new_role} by {caller['email']}")
    return _response(200, {"user_id": user_id, "role": new_role})


def handle_deactivate_member(event: dict, db: Database, user_id: str) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can remove team members"})
    if user_id == caller["id"]:
        return _response(400, {"error": "you cannot deactivate your own account"})

    deactivated = db.deactivate_user(user_id, caller["organization_id"])
    if not deactivated:
        return _response(404, {"error": "user not found in your organization"})
    return _response(200, {"deactivated": user_id})


def lambda_handler(event, context):
    """
    Proposed routes (payload format v2.0, matching the other Lambdas behind
    hzf92ft6j7 — see api_inventory.md). Not yet registered on API Gateway;
    that's a manual deploy step, same as everything else in this repo.

        GET    /team                 -> handle_list_team
        POST   /team/invite          -> handle_invite_member
        POST   /team/accept-invite   -> handle_accept_invite
        PATCH  /team/member/{id}     -> handle_update_role
        DELETE /team/invite/{id}     -> handle_revoke_invite
        DELETE /team/member/{id}     -> handle_deactivate_member
    """
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path   = event.get("rawPath", "")
    params = event.get("pathParameters") or {}

    db = None
    try:
        db = Database()

        if method == "GET" and path.rstrip("/") == "/team":
            return handle_list_team(event, db)
        if method == "POST" and path.rstrip("/") == "/team/invite":
            return handle_invite_member(event, db)
        if method == "POST" and path.rstrip("/") == "/team/accept-invite":
            return handle_accept_invite(event, db)
        if method == "DELETE" and path.startswith("/team/invite/"):
            return handle_revoke_invite(event, db, params.get("id", ""))
        if method == "PATCH" and path.startswith("/team/member/"):
            return handle_update_role(event, db, params.get("id", ""))
        if method == "DELETE" and path.startswith("/team/member/"):
            return handle_deactivate_member(event, db, params.get("id", ""))

        return _response(404, {"error": f"no route for {method} {path}"})

    except NotImplementedError as e:
        logger.error(f"team_handler: {e}")
        return _response(501, {"error": str(e)})
    except Exception as e:
        logger.error(f"team_handler: unhandled error — {e}", exc_info=True)
        return _response(500, {"error": str(e)})
    finally:
        if db:
            db.close()
