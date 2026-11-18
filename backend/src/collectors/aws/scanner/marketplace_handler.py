"""
marketplace_handler.py
Niagaros Marketplace (issue #90): discover integrations, see which ones this account has connected and whether they
work, request the ones that are not built yet, rate and review, report problems.

  GET  ?cloud_account_id=...                     catalog + this account's connections/health + counts + recommendations
  GET  ?cloud_account_id=...&slug=...            one integration: detail, reviews, this account's requests/reports
  POST {"action": "request", slug | name, note}  request an integration (one request per account and integration)
  POST {"action": "withdraw_request", slug}
  POST {"action": "review", slug, rating 1-5, message}   only for integrations this account has connected
  POST {"action": "report_issue", slug, message}

Connecting itself happens on the existing setup pages (AWS wizard, GitHub, Integrations, Notification Settings),
which already validate credentials, store secrets in Secrets Manager and handle disconnecting; the marketplace links to
them instead of building a second, weaker copy of each flow.

Security: every call goes through tenant_auth.guard (private endpoint; POST needs write access to the account).
Aggregates across tenants are numbers only; reviews from other accounts are shown without author or account.
"""
import json
import logging
import os
import re

import boto3
import psycopg2

from collectors.aws.scanner import marketplace_lib as M
from collectors.aws.scanner.tenant_auth import authenticate, guard

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
CORS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
MAX_TEXT = 2000
AUDIT_ACTIONS = ("marketplace_request", "marketplace_request_withdrawn", "marketplace_review", "marketplace_issue")


def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _get_connection():
    sm = boto3.client("secretsmanager", region_name=REGION)
    s = json.loads(sm.get_secret_value(SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"],
                            password=s["password"], sslmode="require", connect_timeout=10)


def _text(v, limit=MAX_TEXT):
    v = (v or "").strip() if isinstance(v, str) else ""
    return v[:limit]


def _audit(cur, account_id, actor, action, slug, **details):
    cur.execute("""INSERT INTO integration_audit_log (cloud_account_id, provider, actor_email, action, details)
                   VALUES (%s, %s, %s, %s, %s)""", (account_id, slug, actor, action, json.dumps(details)))


def _aggregates(cur):
    cur.execute("SELECT slug, count(*) FROM integration_requests GROUP BY slug")
    requests = dict(cur.fetchall())
    cur.execute("SELECT slug, avg(rating), count(*) FROM marketplace_feedback WHERE kind = 'review' GROUP BY slug")
    ratings = {s: {"average": round(float(a), 1), "count": n} for s, a, n in cur.fetchall() if n >= M.MIN_RATINGS}
    return requests, ratings


def overview(cur, account_id):
    state = M.connections(cur, account_id)
    installs = M.install_counts(cur)
    requests, ratings = _aggregates(cur)
    cur.execute("SELECT slug, name, created_at FROM integration_requests WHERE cloud_account_id = %s ORDER BY created_at DESC",
                (account_id,))
    mine = [{"slug": s, "name": n, "requested_at": t} for s, n, t in cur.fetchall()]
    mine_slugs = {m["slug"] for m in mine}
    items = []
    for e in M.catalog():
        items.append({**{k: e[k] for k in ("slug", "name", "vendor", "category", "delivers", "objects", "status",
                                           "maintained_by", "certification")},
                      "auth_methods": (e["detail"] or {}).get("auth_methods", []),
                      "deployment": (e["detail"] or {}).get("deployment"),
                      "frameworks": (e["detail"] or {}).get("frameworks", []),
                      "installs": installs.get(e["slug"]) if e["status"] == "Available" else None,
                      "requests": requests.get(e["slug"], 0),
                      "rating": ratings.get(e["slug"]),
                      "requested": e["slug"] in mine_slugs,
                      "connection": state.get(e["slug"])})
    cats = {}
    for e in items:
        cats[e["category"]] = cats.get(e["category"], 0) + 1
    cur.execute(f"""SELECT created_at, actor_email, action, provider, details FROM integration_audit_log
                    WHERE cloud_account_id = %s ORDER BY created_at DESC LIMIT 30""", (account_id,))
    audit = [{"at": t, "actor": a, "action": act, "integration": p, "details": d} for t, a, act, p, d in cur.fetchall()]
    return {"integrations": items,
            "categories": [{"name": k, "count": v} for k, v in sorted(cats.items())],
            "counts": {"total": len(items), **{s: sum(1 for e in items if e["status"] == s) for s in M.STATUSES},
                       "connected": len(state)},
            "connected": [{"slug": s, "name": M.by_slug()[s]["name"], **v} for s, v in state.items()],
            "recommendations": M.recommendations(cur, account_id, state),
            "my_requests": [m for m in mine if m["slug"].startswith("new:") or m["slug"] not in M.by_slug()],
            "audit": audit,
            "notes": {"ratings": f"An average rating is shown once {M.MIN_RATINGS} accounts have reviewed an integration.",
                      "installs": "Number of Niagaros accounts that have this integration set up.",
                      "health": "Health is worked out from real scans, synchronizations and deliveries on every page load; "
                                "rate limits and API availability of the provider are not measured.",
                      "partners": "Only integrations built by Niagaros are listed as available. There is no partner "
                                  "publishing program yet."}}


def detail(cur, account_id, slug):
    e = M.by_slug().get(slug)
    if not e:
        return None
    state = M.connections(cur, account_id).get(slug)
    requests, ratings = _aggregates(cur)
    cur.execute("""SELECT cloud_account_id = %s, rating, message, created_at, author FROM marketplace_feedback
                   WHERE slug = %s AND kind = 'review' ORDER BY created_at DESC LIMIT 50""", (account_id, slug))
    reviews = [{"own": own, "rating": r, "message": m, "at": t, "author": a if own else None} for own, r, m, t, a in cur.fetchall()]
    cur.execute("""SELECT message, created_at, author FROM marketplace_feedback
                   WHERE slug = %s AND kind = 'issue' AND cloud_account_id = %s ORDER BY created_at DESC LIMIT 20""",
                (slug, account_id))
    issues = [{"message": m, "at": t, "author": a} for m, t, a in cur.fetchall()]
    cur.execute("SELECT note, requested_by, created_at FROM integration_requests WHERE cloud_account_id = %s AND slug = %s",
                (account_id, slug))
    req = cur.fetchone()
    return {**e, "connection": state, "installs": M.install_counts(cur).get(slug) if e["status"] == "Available" else None,
            "requests": requests.get(slug, 0), "rating": ratings.get(slug), "reviews": reviews, "my_issues": issues,
            "my_request": {"note": req[0], "by": req[1], "at": req[2]} if req else None}


def handler(event, context):
    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}
    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})
    qs = event.get("queryStringParameters") or {}
    try:
        body = json.loads(event["body"]) if event.get("body") else {}
        if not isinstance(body, dict):
            raise ValueError
    except (ValueError, TypeError):
        return _resp(400, {"error": "Invalid JSON"})
    account_id = qs.get("cloud_account_id") if method == "GET" else body.get("cloud_account_id")
    if not account_id or not UUID_RE.match(str(account_id)):
        return _resp(400, {"error": "cloud_account_id is required"})

    conn = _get_connection()
    try:
        denied = guard(event, conn, qs, body, None, None)
        if denied:
            return _resp(denied[0], {"error": denied[1]})
        actor = authenticate(event) or "unknown"
        if method == "GET":
            with conn.cursor() as cur:
                if qs.get("slug"):
                    d = detail(cur, account_id, qs["slug"])
                    return _resp(200, d) if d else _resp(404, {"error": "That integration is not in the catalog."})
                return _resp(200, overview(cur, account_id))
        if method != "POST":
            return _resp(405, {"error": "method not allowed"})

        action = body.get("action")
        slug = _text(body.get("slug"), 200)  # longer than "new:" + a 120-character name, so every request can be withdrawn
        entry = M.by_slug().get(slug)

        if action == "request":
            if entry:
                if entry["status"] == "Available":
                    return _resp(400, {"error": f"{entry['name']} is already available; you can connect it now."})
                name = entry["name"]
            else:
                name = _text(body.get("name"), 120)
                if not name:
                    return _resp(400, {"error": "Choose an integration from the catalog or enter the name of the tool you need."})
                known = M.by_slug().get(M.slugify(name))
                if known:
                    slug, name = known["slug"], known["name"]
                    if known["status"] == "Available":
                        return _resp(400, {"error": f"{name} is already available; you can connect it now."})
                else:
                    slug = "new:" + M.slugify(name)
            note = _text(body.get("note"))
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO integration_requests (cloud_account_id, slug, name, note, requested_by)
                                   VALUES (%s, %s, %s, %s, %s)
                                   ON CONFLICT (cloud_account_id, slug) DO UPDATE SET note = EXCLUDED.note
                                   RETURNING (xmax = 0)""", (account_id, slug, name, note or None, actor))
                    new = cur.fetchone()[0]
                    _audit(cur, account_id, actor, "marketplace_request", slug, name=name, updated=not new)
            return _resp(200, {"requested": True, "slug": slug, "name": name, "updated": not new,
                               "note": "Your request is recorded. Requests decide which integrations are built next."})

        if action == "withdraw_request":
            with conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM integration_requests WHERE cloud_account_id = %s AND slug = %s", (account_id, slug))
                    gone = cur.rowcount
                    if gone:
                        _audit(cur, account_id, actor, "marketplace_request_withdrawn", slug)
            return _resp(200 if gone else 404, {"withdrawn": bool(gone)} if gone else {"error": "No request to withdraw."})

        if action in ("review", "report_issue"):
            if not entry:
                return _resp(404, {"error": "That integration is not in the catalog."})
            message = _text(body.get("message"))
            with conn.cursor() as cur:
                connected = slug in M.connections(cur, account_id)
            if action == "review":
                try:
                    rating = int(body.get("rating"))
                except (TypeError, ValueError):
                    rating = 0
                if not 1 <= rating <= 5:
                    return _resp(400, {"error": "Give a rating from 1 to 5."})
                if not connected:
                    return _resp(400, {"error": "Only accounts that have connected an integration can review it."})
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("""INSERT INTO marketplace_feedback (cloud_account_id, slug, kind, rating, message, author)
                                       VALUES (%s, %s, 'review', %s, %s, %s)
                                       ON CONFLICT (cloud_account_id, slug) WHERE kind = 'review'
                                       DO UPDATE SET rating = EXCLUDED.rating, message = EXCLUDED.message,
                                                     author = EXCLUDED.author, created_at = now()""",
                                    (account_id, slug, rating, message or None, actor))
                        _audit(cur, account_id, actor, "marketplace_review", slug, rating=rating)
                return _resp(200, {"saved": True})
            if not message:
                return _resp(400, {"error": "Describe the problem."})
            if not connected:
                return _resp(400, {"error": "Report problems for integrations you have connected. For others, request them."})
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO marketplace_feedback (cloud_account_id, slug, kind, message, author)
                                   VALUES (%s, %s, 'issue', %s, %s)""", (account_id, slug, message, actor))
                    _audit(cur, account_id, actor, "marketplace_issue", slug)
            return _resp(200, {"saved": True, "note": "Problem recorded."})

        return _resp(400, {"error": f"unknown action: {action}"})
    except Exception:
        logger.exception("marketplace_handler error")
        return _resp(500, {"error": "An unexpected error occurred. Please try again, or contact support if this keeps happening."})
    finally:
        conn.close()
