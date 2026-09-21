"""
integrations_handler.py
Workspace integrations: Jira Cloud and Monday.com (issue #279: "Workspace Integration").

  Connect -> authenticate -> select workspace/project -> map project -> create ticket from a finding ->
  synchronize status -> update the Niagaros finding -> verify synchronization.

  POST {"action": "connect", provider: "jira"|"monday", ...}   validates the credentials against the provider FIRST, stores the
                                                                token in Secrets Manager (never in the database), lists projects/boards
  POST {"action": "select_project", integration_id, project}   maps the integration to a Jira project key / Monday board id
  POST {"action": "create_ticket", integration_id, finding_id} creates the ticket and stores the mapping
  POST {"action": "sync", integration_id}                      pulls the status of every mapped ticket and updates the findings
  POST {"action": "disconnect", integration_id}
  GET  ?cloud_account_id=...                                   integrations and their tickets (tokens are never returned)

Security: owner/admin only through the tenant guard; Jira sites must be https://<name>.atlassian.net (no arbitrary hosts, so the
Lambda cannot be pointed at internal addresses); all provider errors are reported, never swallowed.
"""
import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
import uuid

import boto3
import psycopg2

from collectors.aws.scanner.tenant_auth import guard

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REGION = os.environ.get("SECRET_REGION", "eu-west-1")
JIRA_SITE_RE = re.compile(r"^https://[a-z0-9][a-z0-9-]{1,62}\.atlassian\.net$")
MONDAY_API = os.environ.get("MONDAY_API_URL", "https://api.monday.com/v2")
DONE_WORDS = ("done", "complete", "completed", "closed", "resolved")
CORS = {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"}

BOOTSTRAP_SQL = """
CREATE TABLE IF NOT EXISTS workspace_integrations (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    provider         TEXT NOT NULL CHECK (provider IN ('jira', 'monday')),
    site_url         TEXT,
    account_label    TEXT,
    account_email    TEXT,
    project          TEXT,
    secret_name      TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_sync_at     TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS integration_tickets (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id   UUID NOT NULL REFERENCES workspace_integrations(id) ON DELETE CASCADE,
    audit_finding_id UUID NOT NULL REFERENCES audit_findings(id) ON DELETE CASCADE,
    external_id      TEXT NOT NULL,
    external_key     TEXT,
    external_url     TEXT,
    external_status  TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at   TIMESTAMPTZ,
    UNIQUE (integration_id, audit_finding_id)
);
CREATE INDEX IF NOT EXISTS workspace_integrations_account_idx ON workspace_integrations (cloud_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON workspace_integrations, integration_tickets TO cspm_lambda;
"""

REFS = {
    "integration_id": "SELECT cloud_account_id FROM workspace_integrations WHERE id = %s",
    "finding_id": ("SELECT a.cloud_account_id FROM audit_findings f JOIN audits a ON a.id = f.audit_id WHERE f.id = %s"),
}


class ProviderError(Exception):
    pass


def _http_json(method, url, headers, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
            return json.loads(text) if text else {}
    except urllib.error.HTTPError as e:
        raise ProviderError(f"{method} {url.split('?')[0]} -> HTTP {e.code}: {e.read(300).decode('utf-8', 'replace')}")
    except Exception as e:
        raise ProviderError(f"{type(e).__name__}: {e}")


class Jira:
    PRIORITY = {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}

    def __init__(self, site_url, email, token):
        self.base = site_url.rstrip("/")
        self.h = {"Authorization": "Basic " + base64.b64encode(f"{email}:{token}".encode()).decode()}

    def whoami(self):
        me = _http_json("GET", f"{self.base}/rest/api/3/myself", self.h)
        return {"label": me.get("displayName") or me.get("accountId"), "email": me.get("emailAddress")}

    def projects(self):
        r = _http_json("GET", f"{self.base}/rest/api/3/project/search?maxResults=50", self.h)
        return [{"id": p["key"], "name": p["name"]} for p in r.get("values", [])]

    def create_ticket(self, project, title, description, severity):
        adf = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": description or title}]}]}
        r = _http_json("POST", f"{self.base}/rest/api/3/issue", self.h, {"fields": {
            "project": {"key": project}, "summary": title[:250], "issuetype": {"name": "Task"}, "description": adf,
            "priority": {"name": self.PRIORITY.get((severity or "MEDIUM").upper(), "Medium")}}})
        return {"id": str(r["id"]), "key": r["key"], "url": f"{self.base}/browse/{r['key']}"}

    def status(self, external):
        r = _http_json("GET", f"{self.base}/rest/api/3/issue/{external['key']}?fields=status", self.h)
        st = (r.get("fields") or {}).get("status") or {}
        return {"name": st.get("name"), "done": ((st.get("statusCategory") or {}).get("key") == "done")}


class Monday:
    def __init__(self, token, api_url=None):
        self.url = api_url or MONDAY_API
        self.h = {"Authorization": token, "API-Version": "2024-01"}

    def _q(self, query, variables=None):
        r = _http_json("POST", self.url, self.h, {"query": query, "variables": variables or {}})
        if r.get("errors"):
            raise ProviderError(f"Monday API error: {json.dumps(r['errors'])[:300]}")
        return r["data"]

    def whoami(self):
        me = self._q("query { me { id name email } }")["me"]
        return {"label": me["name"], "email": me.get("email")}

    def projects(self):
        return [{"id": str(b["id"]), "name": b["name"]} for b in self._q("query { boards(limit: 50) { id name } }")["boards"]]

    def create_ticket(self, project, title, description, severity):
        item = self._q("mutation ($b: ID!, $n: String!) { create_item(board_id: $b, item_name: $n) { id } }", {"b": project, "n": title[:250]})["create_item"]
        if description:
            self._q("mutation ($i: ID!, $t: String!) { create_update(item_id: $i, body: $t) { id } }", {"i": item["id"], "t": description[:2000]})
        return {"id": str(item["id"]), "key": str(item["id"]), "url": None}

    def status(self, external):
        items = self._q("query ($i: [ID!]) { items(ids: $i) { id state column_values { type text } } }", {"i": [external["id"]]})["items"]
        if not items:
            return {"name": "deleted", "done": False}
        cols = [c for c in items[0].get("column_values", []) if c.get("type") == "status"]
        name = (cols[0].get("text") if cols else None) or items[0].get("state")
        return {"name": name, "done": bool(name) and name.strip().lower() in DONE_WORDS}


def make_client(provider, site_url, email, token):
    if provider == "jira":
        if not JIRA_SITE_RE.match(site_url or ""):
            raise ProviderError("site_url must look like https://your-company.atlassian.net")
        return Jira(site_url, email or "", token)
    if provider == "monday":
        return Monday(token)
    raise ProviderError("provider must be jira or monday")


# ── persistence ─────────────────────────────────────────────────────────

def _resp(status, body):
    return {"statusCode": status, "headers": CORS, "body": json.dumps(body, default=str)}


def _sm():
    return boto3.client("secretsmanager", region_name=REGION)


def _get_connection():
    s = json.loads(_sm().get_secret_value(SecretId=os.environ.get("DB_SECRET_NAME", "cspm/database/credentials"))["SecretString"])
    return psycopg2.connect(host=s["host"], port=s.get("port", 5432), dbname=s["database"], user=s["username"], password=s["password"],
                            sslmode="require", connect_timeout=10)


def _load(cur, integration_id):
    cur.execute("SELECT id, cloud_account_id, provider, site_url, account_email, project, secret_name FROM workspace_integrations WHERE id = %s", (integration_id,))
    r = cur.fetchone()
    return None if not r else {"id": str(r[0]), "cloud_account_id": str(r[1]), "provider": r[2], "site_url": r[3], "email": r[4], "project": r[5], "secret_name": r[6]}


def _client_for(integration):
    token = _sm().get_secret_value(SecretId=integration["secret_name"])["SecretString"]
    return make_client(integration["provider"], integration["site_url"], integration["email"], token)


def _map_status(done, current_name):
    return "closed" if done else "in_remediation"


def sync_tickets(conn, integration, client):
    """Pull every mapped ticket's status; a finished ticket closes the Niagaros finding, an active one marks it in remediation."""
    updated = []
    with conn.cursor() as cur:
        cur.execute("SELECT id, audit_finding_id, external_id, external_key FROM integration_tickets WHERE integration_id = %s", (integration["id"],))
        tickets = cur.fetchall()
    for tid, fid, ext_id, ext_key in tickets:
        st = client.status({"id": ext_id, "key": ext_key})
        finding_status = _map_status(st["done"], st["name"])
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE integration_tickets SET external_status = %s, last_synced_at = now() WHERE id = %s", (st["name"], tid))
                cur.execute("""UPDATE audit_findings SET status = %s, resolved_at = CASE WHEN %s = 'closed' THEN COALESCE(resolved_at, now()) ELSE NULL END
                               WHERE id = %s AND status <> %s""", (finding_status, finding_status, fid, finding_status))
        updated.append({"finding_id": str(fid), "ticket": ext_key or ext_id, "external_status": st["name"], "finding_status": finding_status})
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE workspace_integrations SET last_sync_at = now() WHERE id = %s", (integration["id"],))
    return updated


def handler(event, context):
    if event and event.get("action") == "migrate":
        conn = _get_connection()
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(BOOTSTRAP_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()
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

    conn = _get_connection()
    try:
        denied = guard(event, conn, qs, body, REFS, None)
        if denied:
            return _resp(denied[0], {"error": denied[1]})
        if method == "GET":
            account_id = qs.get("cloud_account_id")
            if not account_id:
                return _resp(400, {"error": "cloud_account_id is required"})
            with conn.cursor() as cur:
                cur.execute("""SELECT id, provider, site_url, account_label, project, created_at, last_sync_at FROM workspace_integrations
                               WHERE cloud_account_id = %s ORDER BY created_at""", (account_id,))
                out = []
                for i, p, site, label, project, created, synced in cur.fetchall():
                    cur.execute("""SELECT audit_finding_id, external_key, external_url, external_status, last_synced_at FROM integration_tickets WHERE integration_id = %s""", (i,))
                    out.append({"id": str(i), "provider": p, "site_url": site, "account_label": label, "project": project, "created_at": created, "last_sync_at": synced,
                                "tickets": [{"finding_id": str(f), "key": k, "url": u, "status": s, "last_synced_at": ls} for f, k, u, s, ls in cur.fetchall()]})
            return _resp(200, {"integrations": out})
        if method != "POST":
            return _resp(405, {"error": "method not allowed"})

        action = body.get("action")
        if action == "connect":
            provider = body.get("provider")
            token = (body.get("api_token") or "").strip()
            if not token:
                return _resp(400, {"error": "api_token is required"})
            try:
                client = make_client(provider, body.get("site_url"), body.get("email"), token)
                who = client.whoami()                                     # authenticate BEFORE storing anything
                projects = client.projects()
            except ProviderError as e:
                return _resp(400, {"error": f"Could not connect to {provider}: {e}"})
            secret_name = f"cspm/integrations/{uuid.uuid4()}"
            _sm().create_secret(Name=secret_name, SecretString=token)
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO workspace_integrations (cloud_account_id, provider, site_url, account_label, account_email, secret_name)
                                   VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                                (body["cloud_account_id"], provider, body.get("site_url"), who["label"], body.get("email") or who.get("email"), secret_name))
                    iid = cur.fetchone()[0]
            return _resp(200, {"id": str(iid), "authenticated_as": who["label"], "projects": projects})

        with conn.cursor() as cur:
            integ = _load(cur, body.get("integration_id"))
        if not integ:
            return _resp(404, {"error": "integration not found"})

        if action == "select_project":
            client = _client_for(integ)
            valid = {p["id"] for p in client.projects()}
            if str(body.get("project")) not in valid:
                return _resp(400, {"error": "that project/board does not exist in the connected workspace"})
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE workspace_integrations SET project = %s WHERE id = %s", (str(body["project"]), integ["id"]))
            return _resp(200, {"project": str(body["project"])})

        if action == "create_ticket":
            if not integ["project"]:
                return _resp(400, {"error": "select a project first"})
            with conn.cursor() as cur:
                cur.execute("SELECT title, description, severity FROM audit_findings WHERE id = %s", (body.get("finding_id"),))
                f = cur.fetchone()
                cur.execute("SELECT 1 FROM integration_tickets WHERE integration_id = %s AND audit_finding_id = %s", (integ["id"], body.get("finding_id")))
                exists = cur.fetchone()
            if not f:
                return _resp(404, {"error": "finding not found"})
            if exists:
                return _resp(409, {"error": "a ticket already exists for this finding"})
            t = _client_for(integ).create_ticket(integ["project"], f[0], f[1], f[2])
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""INSERT INTO integration_tickets (integration_id, audit_finding_id, external_id, external_key, external_url, external_status)
                                   VALUES (%s, %s, %s, %s, %s, 'created')""", (integ["id"], body["finding_id"], t["id"], t["key"], t["url"]))
            return _resp(200, {"ticket": t})

        if action == "sync":
            return _resp(200, {"synced": sync_tickets(conn, integ, _client_for(integ))})

        if action == "disconnect":
            with conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM workspace_integrations WHERE id = %s", (integ["id"],))
            try:
                _sm().delete_secret(SecretId=integ["secret_name"], ForceDeleteWithoutRecovery=True)
            except Exception:
                logger.exception("could not delete the integration secret")
            return _resp(200, {"disconnected": True})
        return _resp(400, {"error": f"unknown action: {action}"})
    except ProviderError as e:
        return _resp(502, {"error": str(e)})
    except Exception as e:
        logger.error("integrations_handler error: %s", e, exc_info=True)
        return _resp(500, {"error": "internal error"})
    finally:
        conn.close()
