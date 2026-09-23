"""
auditor_handler.py

Issue #266 ("Invite Auditors") — Settings -> Auditors module.

Scope for this MVP pass (matching the acceptance-criteria-first approach
already used for #269 and #265): the 5 literal Given/When/Then criteria
from the PVA are built and tested here. The much larger "Proposed
Solution" list (formal auditor profiles/types, watermarked downloads,
document version control, comment threads, SSO for auditors, Trust
Center / Questionnaire Automation / Ticketing System integrations, ...)
is explicitly out of scope — see the Eindverslag's afbakening.

Auditors are deliberately NOT rows in `users` — see the comment at the
top of migrations/007_audit_engagements.sql for why. They still log in
through the same Cognito pool as everyone else (hence reusing
_get_authenticated_email from team_handler), but are recognized purely
by email against engagement_auditors, never joining an organization.

Not yet registered on API Gateway — same deployment gap as
team_handler.py, and blocked on the same unresolved
_get_authenticated_email() implementation.
"""
import json
import logging

from config.database import Database
from api.team_handler import _get_authenticated_email, _get_caller

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _response(status: int, body: dict) -> dict:
    return {"statusCode": status, "body": json.dumps(body)}


def _get_auditor(event: dict, db: Database) -> dict | None:
    """
    Issue #266, acceptance criterion #3's actual mechanism: an auditor's
    access is resolved fresh on every call from
    Database.get_active_engagement_for_auditor (end_date >= CURRENT_DATE),
    not from a stored grant. The moment an engagement closes, the very
    next request from that auditor simply stops matching here — no
    separate revocation step needed, the same pattern as issue #265 AC5's
    deactivated-member check in team_handler._get_caller.
    """
    email = _get_authenticated_email(event)
    if not email:
        return None
    engagement = db.get_active_engagement_for_auditor(email)
    if not engagement:
        return None
    return {"email": email, "engagement": engagement}


def handle_create_engagement(event: dict, db: Database) -> dict:
    """
    Issue #266, acceptance criterion #1 — the write side: an admin
    defines an engagement's scope up front as a set of the organization's
    own, already-connected cloud accounts (the same real entity the
    shared-dashboard fix uses), and assigns the auditors who may see it.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can create audit engagements"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    name = (body.get("name") or "").strip()
    end_date = (body.get("end_date") or "").strip()
    cloud_account_ids = body.get("cloud_account_ids") or []
    auditor_emails = [e.strip().lower() for e in (body.get("auditor_emails") or []) if e.strip()]

    if not name:
        return _response(400, {"error": "name is required"})
    if not end_date:
        return _response(400, {"error": "end_date is required"})
    if not cloud_account_ids:
        return _response(400, {"error": "at least one cloud_account_id is required"})
    if not auditor_emails:
        return _response(400, {"error": "at least one auditor_email is required"})

    # Scoped to this organization's own accounts, same guard used when
    # sharing a dashboard — prevents scoping an engagement to another
    # organization's cloud account by guessing its id.
    org_account_ids = {a["id"] for a in db.list_organization_cloud_accounts(caller["organization_id"])}
    unknown = [cid for cid in cloud_account_ids if cid not in org_account_ids]
    if unknown:
        return _response(404, {"error": "one or more cloud accounts not found in your organization"})

    engagement_id = db.create_audit_engagement(
        organization_id=caller["organization_id"], name=name, end_date=end_date,
        created_by=caller["id"], cloud_account_ids=cloud_account_ids, auditor_emails=auditor_emails,
    )
    logger.info(f"Audit engagement created: {engagement_id} by {caller['email']}")
    return _response(201, {"engagement_id": engagement_id, "name": name, "end_date": end_date})


def handle_list_engagements(event: dict, db: Database) -> dict:
    """Admin-only view of this organization's own engagements."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can view audit engagements"})

    engagements = db.list_organization_engagements(caller["organization_id"])
    return _response(200, {"engagements": engagements})


def handle_auditor_view_scope(event: dict, db: Database) -> dict:
    """
    Issue #266, acceptance criterion #1 — the read side, from the
    auditor's own point of view: only the cloud accounts in their active
    engagement's scope are returned. A closed engagement (AC3) or an
    email with no engagement at all both simply produce 401 here — there
    is nothing further to reject once _get_auditor already returned None.

    Also where "login" activity is logged for acceptance criterion #5
    ("all logins, downloads, comments, and evidence requests are
    displayed"). This is the one call the auditor portal always makes on
    load, so it's the natural single place to count as "logged in" —
    logging it in every other auditor-facing handler too would count one
    visit to the portal as several separate logins.
    """
    auditor = _get_auditor(event, db)
    if not auditor:
        return _response(401, {"error": "unauthorized"})

    engagement_id = auditor["engagement"]["id"]
    scope = db.list_engagement_scope(engagement_id)
    db.log_engagement_activity(engagement_id, auditor["email"], "login")
    return _response(200, {"engagement": auditor["engagement"], "scope": scope})


def handle_request_evidence(event: dict, db: Database) -> dict:
    """Issue #266, acceptance criterion #2 — an auditor requests one more
    of the organization's cloud accounts be added to their scope."""
    auditor = _get_auditor(event, db)
    if not auditor:
        return _response(401, {"error": "unauthorized"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    cloud_account_id = (body.get("cloud_account_id") or "").strip()
    if not cloud_account_id:
        return _response(400, {"error": "cloud_account_id is required"})

    # Same guard as handle_create_engagement / handle_share_resource:
    # without this, an auditor could request (and an admin could then
    # unknowingly approve) access to an id that isn't a real account in
    # this organization at all — silently in this stand-in's SQLite
    # tables, or as a foreign-key violation in real Postgres, neither of
    # which is a useful failure mode for either side.
    org_account_ids = {a["id"] for a in db.list_organization_cloud_accounts(auditor["engagement"]["organization_id"])}
    if cloud_account_id not in org_account_ids:
        return _response(404, {"error": "cloud account not found in this engagement's organization"})

    engagement_id = auditor["engagement"]["id"]
    request_id = db.create_evidence_request(engagement_id, auditor["email"], cloud_account_id)
    db.log_engagement_activity(
        engagement_id, auditor["email"], "evidence_requested",
        details={"cloud_account_id": cloud_account_id},
    )
    return _response(201, {"request_id": request_id})


def handle_list_evidence_requests(event: dict, db: Database, engagement_id: str) -> dict:
    """Admin-only — reviewing an engagement's pending/resolved requests."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can view evidence requests"})

    # Without this, an admin from a different organization could pass
    # this organization's engagement_id and read its evidence requests —
    # list_evidence_requests itself has no organization scoping.
    if not db.get_engagement(engagement_id, caller["organization_id"]):
        return _response(404, {"error": "engagement not found in your organization"})

    requests = db.list_evidence_requests(engagement_id)
    return _response(200, {"requests": requests})


def handle_resolve_evidence_request(event: dict, db: Database, engagement_id: str, request_id: str) -> dict:
    """
    Issue #266, acceptance criterion #2 — the approval side. Approving
    grows the auditor's scope by exactly the one requested account (see
    Database.resolve_evidence_request); denying changes nothing.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can resolve evidence requests"})

    # Same guard as handle_list_evidence_requests — without it, an admin
    # from a different organization could approve or deny another
    # organization's evidence request outright.
    if not db.get_engagement(engagement_id, caller["organization_id"]):
        return _response(404, {"error": "engagement not found in your organization"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _response(400, {"error": "invalid JSON body"})

    approve = body.get("approve")
    if not isinstance(approve, bool):
        return _response(400, {"error": "body must include a boolean 'approve' field"})

    resolved = db.resolve_evidence_request(request_id, engagement_id, approve)
    if not resolved:
        return _response(404, {"error": "request not found or already resolved"})
    return _response(200, {"request_id": request_id, "approved": approve})


def handle_download_evidence(event: dict, db: Database, cloud_account_id: str) -> dict:
    """
    Issue #266, acceptance criterion #4 — every download is logged.
    "Evidence" for this MVP pass is the account's own compliance data,
    the same real data #269 already scans and stores — not a fabricated
    document — and only ever the account itself, never findings for
    accounts outside engagement_scope.
    """
    auditor = _get_auditor(event, db)
    if not auditor:
        return _response(401, {"error": "unauthorized"})

    engagement_id = auditor["engagement"]["id"]
    if not db.is_cloud_account_in_engagement_scope(engagement_id, cloud_account_id):
        return _response(403, {"error": "this cloud account is not in your engagement's approved scope"})

    db.log_engagement_activity(
        engagement_id, auditor["email"], "evidence_downloaded",
        details={"cloud_account_id": cloud_account_id},
    )
    account = db.get_cloud_account_compliance(cloud_account_id)
    return _response(200, {"cloud_account_id": cloud_account_id, "compliance_score": account})


def handle_view_engagement_activity(event: dict, db: Database, engagement_id: str) -> dict:
    """Issue #266, acceptance criterion #5 — admin-facing activity
    dashboard: every login, download, and evidence request for one
    engagement, in one place."""
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if caller["role"] != "admin":
        return _response(403, {"error": "only admins can view auditor activity"})

    # Same guard as the evidence-request handlers — get_engagement_activity
    # has no organization scoping of its own, so without this an admin
    # from a different organization could read another organization's
    # full login/download/request history by guessing its engagement_id.
    if not db.get_engagement(engagement_id, caller["organization_id"]):
        return _response(404, {"error": "engagement not found in your organization"})

    entries = db.get_engagement_activity(engagement_id)
    return _response(200, {"entries": entries})


def lambda_handler(event, context):
    """
    Proposed routes, same not-yet-deployed status as team_handler.py.

        POST   /auditors/engagements                          -> handle_create_engagement
        GET    /auditors/engagements                           -> handle_list_engagements
        GET    /auditors/engagements/{engagement_id}/requests  -> handle_list_evidence_requests
        PATCH  /auditors/engagements/{engagement_id}/requests/{request_id} -> handle_resolve_evidence_request
        GET    /auditors/engagements/{engagement_id}/activity  -> handle_view_engagement_activity
        GET    /auditor/scope                                  -> handle_auditor_view_scope
        POST   /auditor/evidence-requests                      -> handle_request_evidence
        GET    /auditor/evidence/{cloud_account_id}            -> handle_download_evidence
    """
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path   = event.get("rawPath", "")
    params = event.get("pathParameters") or {}

    db = None
    try:
        db = Database()

        if method == "POST" and path.rstrip("/") == "/auditors/engagements":
            return handle_create_engagement(event, db)
        if method == "GET" and path.rstrip("/") == "/auditors/engagements":
            return handle_list_engagements(event, db)
        if method == "GET" and path.rstrip("/") == "/auditor/scope":
            return handle_auditor_view_scope(event, db)
        if method == "POST" and path.rstrip("/") == "/auditor/evidence-requests":
            return handle_request_evidence(event, db)
        if method == "GET" and path.startswith("/auditor/evidence/"):
            return handle_download_evidence(event, db, params.get("cloud_account_id", ""))
        if method == "GET" and path.startswith("/auditors/engagements/") and path.endswith("/requests"):
            return handle_list_evidence_requests(event, db, params.get("engagement_id", ""))
        if method == "PATCH" and "/requests/" in path:
            return handle_resolve_evidence_request(
                event, db, params.get("engagement_id", ""), params.get("request_id", ""),
            )
        if method == "GET" and path.startswith("/auditors/engagements/") and path.endswith("/activity"):
            return handle_view_engagement_activity(event, db, params.get("engagement_id", ""))

        return _response(404, {"error": f"no route for {method} {path}"})

    except NotImplementedError as e:
        logger.error(f"auditor_handler: {e}")
        return _response(501, {"error": str(e)})
    except Exception as e:
        logger.error(f"auditor_handler: unhandled error — {e}", exc_info=True)
        return _response(500, {"error": str(e)})
    finally:
        if db:
            db.close()
