import json
import logging

from config.database import Database
from auth.cognito_admin import terminate_all_sessions

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
    """
    Issue #265, acceptance criterion #5's actual mechanism: rejecting a
    deactivated user here (not just on shared-resource endpoints, but on
    every single endpoint that resolves a caller through this function)
    is what makes "access is updated automatically based on current
    membership" true — the moment someone is offboarded, every one of
    their existing tokens stops working everywhere, not just for shared
    resources. Previously this only checked *whether* a user row existed,
    not whether it was still active — a deactivated admin could still act
    as one for as long as their Cognito session lasted.
    """
    email = _get_authenticated_email(event)
    if not email:
        return None
    user = db.get_user_by_email(email)
    if not user or user["status"] != "active":
        return None
    return user


def handle_list_team(event: dict, db: Database) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})

    members = db.get_organization_members(caller["organization_id"])
    invites = db.list_pending_invites(caller["organization_id"])
    org     = db.get_organization(caller["organization_id"])
    return _response(200, {
        "members": members,
        "pending_invites": invites,
        "mfa_required": org["mfa_required"] if org else False,
    })


def handle_update_mfa_policy(event: dict, db: Database) -> dict:
    """Issue #265, acceptance criterion #3 — the policy half."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can change the MFA policy"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    if "required" not in body or not isinstance(body["required"], bool):
        return _response(400, {"error": "body must include a boolean 'required' field"})

    db.set_organization_mfa_policy(caller["organization_id"], body["required"])
    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="mfa_policy_changed", details={"required": body["required"]},
    )
    return _response(200, {"mfa_required": body["required"]})


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

    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="invite_created", details={"email": email, "role": role},
    )
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

    # Self-service action — actor and target are the same person, there's
    # no admin "doing" this to log as a separate actor.
    db.log_audit_event(
        organization_id=result["organization_id"], actor_user_id=caller["id"],
        action="invite_accepted", target_user_id=caller["id"],
        details={"role": result["role"]},
    )
    return _response(200, {"accepted": True, **result})


def handle_revoke_invite(event: dict, db: Database, invite_id: str) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can revoke invites"})

    revoked_email = db.revoke_team_invite(invite_id, caller["organization_id"])
    if not revoked_email:
        return _response(404, {"error": "invite not found or already resolved"})

    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="invite_revoked", details={"email": revoked_email},
    )
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
    """
    Issue #265, acceptance criterion #4: "access is revoked, active
    sessions are terminated, and owned resources are reassigned." There's
    no "pick a successor" UI in this pass, so any cloud_accounts the
    departing member owned transfer to the admin doing the offboarding —
    the simplest safe default, not a real ownership-transfer workflow.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can remove team members"})
    if user_id == caller["id"]:
        return _response(400, {"error": "you cannot deactivate your own account"})

    target = db.get_user_by_id(user_id, caller["organization_id"])
    if not target:
        return _response(404, {"error": "user not found in your organization"})

    db.deactivate_user(user_id, caller["organization_id"])
    reassigned = db.reassign_owned_cloud_accounts(target["email"], caller["email"])
    sessions_terminated = terminate_all_sessions(target["cognito_sub"])

    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="member_offboarded", target_user_id=user_id,
        details={"reassigned_cloud_accounts": reassigned, "sessions_terminated": sessions_terminated},
    )
    return _response(200, {
        "deactivated": user_id,
        "reassigned_cloud_accounts": reassigned,
        "sessions_terminated": sessions_terminated,
    })


def handle_share_resource(event: dict, db: Database) -> dict:
    """Issue #265, acceptance criterion #5 — admin shares a dashboard."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can share resources"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    resource_name = (body.get("resource_name") or "").strip()
    if not resource_name:
        return _response(400, {"error": "resource_name is required"})

    resource_id = db.create_shared_resource(caller["organization_id"], resource_name, caller["id"])
    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="resource_shared", details={"resource_name": resource_name},
    )
    return _response(201, {"resource_id": resource_id, "resource_name": resource_name})


def handle_list_shared_resources(event: dict, db: Database) -> dict:
    """
    Any ACTIVE member sees this — not admin-only, unlike most of this
    file. Sharing something with "the team" should mean the team can
    actually see it. _get_caller already rejects deactivated callers, so
    reaching this line at all proves current, active membership.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})

    resources = db.list_shared_resources(caller["organization_id"])
    return _response(200, {"resources": resources})


def handle_unshare_resource(event: dict, db: Database, resource_id: str) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can unshare resources"})

    deleted = db.delete_shared_resource(resource_id, caller["organization_id"])
    if not deleted:
        return _response(404, {"error": "resource not found in your organization"})

    db.log_audit_event(
        organization_id=caller["organization_id"], actor_user_id=caller["id"],
        action="resource_unshared", details={"resource_id": resource_id},
    )
    return _response(200, {"unshared": resource_id})


def handle_view_audit_log(event: dict, db: Database) -> dict:
    """
    Issue #265, acceptance criterion #6: "Given an auditor reviews
    administrative activity, when viewing audit logs, then all user,
    role, and permission changes are available with timestamps and actor
    information." Admin-only — this is the same data an auditor would be
    shown, but issue #266 (Invite Auditors) is what will actually grant
    auditors their own restricted access; that role doesn't exist yet.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can view the audit log"})

    entries = db.get_audit_log(caller["organization_id"])
    return _response(200, {"entries": entries})


def lambda_handler(event, context):
    """
    Proposed routes (payload format v2.0, matching the other Lambdas behind
    hzf92ft6j7 — see api_inventory.md). Not yet registered on API Gateway;
    that's a manual deploy step, same as everything else in this repo.

        GET    /team                       -> handle_list_team (includes mfa_required)
        GET    /team/audit-log             -> handle_view_audit_log
        GET    /team/shared-resources      -> handle_list_shared_resources
        POST   /team/shared-resources      -> handle_share_resource
        DELETE /team/shared-resources/{id} -> handle_unshare_resource
        POST   /team/invite                -> handle_invite_member
        POST   /team/accept-invite         -> handle_accept_invite
        PATCH  /team/member/{id}           -> handle_update_role
        PATCH  /team/mfa-policy            -> handle_update_mfa_policy
        DELETE /team/invite/{id}           -> handle_revoke_invite
        DELETE /team/member/{id}           -> handle_deactivate_member
    """
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path   = event.get("rawPath", "")
    params = event.get("pathParameters") or {}

    db = None
    try:
        db = Database()

        if method == "GET" and path.rstrip("/") == "/team":
            return handle_list_team(event, db)
        if method == "GET" and path.rstrip("/") == "/team/audit-log":
            return handle_view_audit_log(event, db)
        if method == "GET" and path.rstrip("/") == "/team/shared-resources":
            return handle_list_shared_resources(event, db)
        if method == "POST" and path.rstrip("/") == "/team/shared-resources":
            return handle_share_resource(event, db)
        if method == "DELETE" and path.startswith("/team/shared-resources/"):
            return handle_unshare_resource(event, db, params.get("id", ""))
        if method == "POST" and path.rstrip("/") == "/team/invite":
            return handle_invite_member(event, db)
        if method == "POST" and path.rstrip("/") == "/team/accept-invite":
            return handle_accept_invite(event, db)
        if method == "DELETE" and path.startswith("/team/invite/"):
            return handle_revoke_invite(event, db, params.get("id", ""))
        if method == "PATCH" and path.rstrip("/") == "/team/mfa-policy":
            return handle_update_mfa_policy(event, db)
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
