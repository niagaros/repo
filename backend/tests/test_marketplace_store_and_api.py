"""
Marketplace (#90): catalog, connection health from real tables, requests, reviews, problem reports, recommendations,
AI Agent evidence and tenant isolation -- against a real PostgreSQL with the real migration.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import json
import os
import sys
import uuid
from unittest.mock import patch

import pytest

from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/ai_inventory_schema.sql",
          "tests/fixtures/security_agents_schema.sql", "migrations/024_security_audit_log.sql",
          "migrations/026_enterprise.sql", "migrations/021_notifications.sql",
          "migrations/043_marketplace.sql", "migrations/043_marketplace.sql"]  # twice: must be re-runnable

from collectors.aws.scanner import marketplace_handler as h  # noqa: E402
from collectors.aws.scanner import marketplace_lib as M  # noqa: E402


@pytest.fixture(scope="module")
def conn():
    name = f"mkt_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA[:3]:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.cursor().execute("""ALTER TABLE cloud_accounts ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMP;
        ALTER TABLE workspace_integrations ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
        ALTER TABLE workspace_integrations ADD COLUMN IF NOT EXISTS credential_error TEXT;
        ALTER TABLE workspace_integrations ADD COLUMN IF NOT EXISTS last_sync_at TIMESTAMPTZ;""")
    for f in SCHEMA[3:]:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
    c.cursor().execute("ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS discord_webhook_url VARCHAR(500)")
    # notification_recipients is created by notification_handler's bootstrap, not by a migration.
    c.cursor().execute("""CREATE TABLE IF NOT EXISTS notification_recipients (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        cloud_account_id UUID NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
        label VARCHAR(120) NOT NULL, domains TEXT[], notify_email VARCHAR(255), sms_number VARCHAR(20),
        slack_webhook_url VARCHAR(500), teams_webhook_url VARCHAR(500), discord_webhook_url VARCHAR(500),
        webhook_url VARCHAR(500), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
        CREATE TABLE IF NOT EXISTS notification_delivery_attempts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        notification_id UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
        channel VARCHAR(20) NOT NULL, recipient_id UUID, sent BOOLEAN NOT NULL, reason TEXT,
        attempt_kind VARCHAR(20) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    c.autocommit = False
    yield c
    c.close()
    admin.cursor().execute(f"DROP DATABASE {name} WITH (FORCE)")
    admin.close()


class _NoClose:
    def __init__(self, c):
        self._c = c

    def __getattr__(self, k):
        return getattr(self._c, k)

    def __enter__(self):
        return self._c.__enter__()

    def __exit__(self, *a):
        return self._c.__exit__(*a)

    def close(self):
        pass


@pytest.fixture(scope="module")
def world(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name, last_scan_at) "
                    "VALUES ('owner@a.test', '111122223333', 'A', NOW()) RETURNING id")
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name) VALUES ('other@b.test', '444455556666', 'B') RETURNING id")
        b = str(cur.fetchone()[0])
        cur.execute("INSERT INTO organizations (name, owner_email) VALUES ('Org A', 'owner@a.test') RETURNING id")
        org = cur.fetchone()[0]
        cur.execute("INSERT INTO business_units (organization_id, name) VALUES (%s, 'Payments') RETURNING id", (org,))
        bu = cur.fetchone()[0]
        cur.execute("INSERT INTO bu_accounts (business_unit_id, cloud_account_id) VALUES (%s, %s)", (bu, a))
        cur.execute("INSERT INTO org_members (organization_id, email, role) VALUES (%s, 'viewer@a.test', 'viewer')", (org,))
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, resource_name, last_scanned_at)
                       VALUES (%s, 'iam-account', 'account', 'account', NOW()) RETURNING id""", (a,))
        res = cur.fetchone()[0]
        cur.execute("""INSERT INTO findings (resource_id, check_id, title, severity, status, framework)
                       VALUES (%s, 'IAM.6', 'Hardware MFA should be enabled for the root user', 'CRITICAL', 'open',
                               'AWS Foundational Security Best Practices'),
                              (%s, 'S3.1', 'S3 general purpose buckets should block public access', 'HIGH', 'open',
                               'AWS Foundational Security Best Practices'),
                              (%s, 'NIST-IA-2.1', 'MFA for Privileged Accounts', 'CRITICAL', 'open', 'NIST 800-53 Rev 5'),
                              (%s, 'EC2.1', 'Passed check', 'HIGH', 'pass', 'AWS Foundational Security Best Practices')""",
                    (res, res, res, res))
    conn.commit()
    return {"a": a, "b": b}


def attempt(cur, account, channel, sent, recipient, ago, reason=None):
    """One real delivery attempt as notification_lib records it (notification_delivery_attempts)."""
    cur.execute("INSERT INTO notifications (cloud_account_id, domain, event_type, severity, title) "
                "VALUES (%s, 'security', %s, 'P2', 't') RETURNING id", (account, "ev-" + uuid.uuid4().hex[:6]))
    nid = cur.fetchone()[0]
    cur.execute("INSERT INTO notification_delivery_attempts (notification_id, channel, recipient_id, sent, reason, attempt_kind, created_at) "
                "VALUES (%s, %s, %s, %s, %s, 'initial', NOW() - %s::interval)", (nid, channel, recipient, sent, reason, ago))
    return nid


def call(conn, email, method="GET", qs=None, body=None):
    event = {"httpMethod": method, "headers": {"Authorization": "Bearer t"}, "queryStringParameters": qs,
             "body": json.dumps(body) if body is not None else None}
    with patch.object(h, "_get_connection", return_value=_NoClose(conn)), \
            patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
            patch.object(h, "authenticate", return_value=email):
        r = h.handler(event, None)
    return r["statusCode"], json.loads(r["body"])


def overview(conn, acct, email="owner@a.test"):
    s, b = call(conn, email, qs={"cloud_account_id": acct})
    assert s == 200, b
    return b


def test_catalog_and_aws_health_from_the_last_scan(conn, world):
    b = overview(conn, world["a"])
    assert b["counts"]["total"] == len(M.catalog()) >= 340
    assert b["counts"]["Available"] == 8
    aws = next(c for c in b["connected"] if c["slug"] == "amazon-web-services")
    assert aws["health"] == "ok"
    with conn.cursor() as cur:
        # A GitHub scan bumps cloud_accounts.last_scan_at; that must not make stale AWS data look healthy.
        cur.execute("UPDATE cloud_accounts SET last_scan_at = NOW() WHERE id = %s", (world["a"],))
        cur.execute("UPDATE resources SET last_scanned_at = NOW() - interval '30 days' WHERE cloud_account_id = %s", (world["a"],))
    conn.commit()
    aws = next(c for c in overview(conn, world["a"])["connected"] if c["slug"] == "amazon-web-services")
    assert aws["health"] == "stale" and "30 days" in aws["health_reason"]
    with conn.cursor() as cur:
        cur.execute("UPDATE resources SET last_scanned_at = NOW() WHERE cloud_account_id = %s", (world["a"],))
    conn.commit()


def test_github_health_only_counts_data_scanned_since_this_connection(conn, world):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, last_scanned_at)
                       VALUES (%s, 'github_repository', 'old-org/repo', NOW() - interval '2 days')""", (world["b"],))
        cur.execute("INSERT INTO github_integrations (cloud_account_id, org_name, github_token_secret, created_at) "
                    "VALUES (%s, 'new-org', 's', NOW() - interval '1 hour')", (world["b"],))
    conn.commit()
    gh = next(c for c in overview(conn, world["b"], "other@b.test")["connected"] if c["slug"] == "github")
    assert gh["health"] == "waiting"
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO resources (cloud_account_id, resource_type, resource_id, last_scanned_at)
                       VALUES (%s, 'github_repository', 'new-org/repo', NOW())""", (world["b"],))
    conn.commit()
    gh = next(c for c in overview(conn, world["b"], "other@b.test")["connected"] if c["slug"] == "github")
    assert gh["health"] == "ok"
    with conn.cursor() as cur:
        cur.execute("DELETE FROM github_integrations WHERE cloud_account_id = %s", (world["b"],))
        cur.execute("DELETE FROM resources WHERE cloud_account_id = %s", (world["b"],))
    conn.commit()


def test_named_recipient_failures_count_for_channel_health(conn, world):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO notification_recipients (cloud_account_id, label, teams_webhook_url) VALUES (%s, 'SecOps', 'https://x.webhook.office.com/y') RETURNING id",
                    (world["a"],))
        rid = str(cur.fetchone()[0])
        cur.execute("INSERT INTO notification_recipients (cloud_account_id, label, teams_webhook_url) VALUES (%s, 'Old', 'https://x.webhook.office.com/z') RETURNING id",
                    (world["a"],))
        old = str(cur.fetchone()[0])
        attempt(cur, world["a"], "teams", True, rid, "3 hours")
        nid = attempt(cur, world["a"], "teams", False, rid, "2 hours", "HTTP 410 from Teams")
        attempt(cur, world["a"], "teams", False, old, "1 hour", "HTTP 500 from Teams")
    conn.commit()
    teams = next(c for c in overview(conn, world["a"])["connected"] if c["slug"] == "microsoft-teams")
    assert teams["health"] == "failing" and "2 destinations" in teams["health_reason"] and teams["attempts"] == 3
    # A removed recipient no longer counts, and a successful retry (newer attempt) clears the failure.
    with conn.cursor() as cur:
        cur.execute("DELETE FROM notification_recipients WHERE id = %s", (old,))
        cur.execute("INSERT INTO notification_delivery_attempts (notification_id, channel, recipient_id, sent, attempt_kind) "
                    "VALUES (%s, 'teams', %s, TRUE, 'retry')", (nid, rid))
    conn.commit()
    teams = next(c for c in overview(conn, world["a"])["connected"] if c["slug"] == "microsoft-teams")
    assert teams["health"] == "ok" and teams["attempts"] == 3 and teams["failures"] == 1, teams
    with conn.cursor() as cur:
        cur.execute("DELETE FROM notification_recipients WHERE id = %s", (rid,))
    conn.commit()


def test_credential_alerts_are_kept_apart_per_integration():
    from collectors.aws.scanner import integrations_handler as ih
    seen = []
    with patch("collectors.aws.scanner.notification_lib.create_notification", side_effect=lambda *a, **k: seen.append(k)):
        ih._notify_rejected(object(), {"id": "i1", "cloud_account_id": "a", "provider": "jira"})
        ih._notify_rejected(object(), {"id": "i2", "cloud_account_id": "a", "provider": "monday"})
    assert [k["resource_link"] for k in seen] == ["integrations.html?account_id=a&integration_id=i1",
                                                  "integrations.html?account_id=a&integration_id=i2"]
    assert "Jira" in seen[0]["title"] and "Monday" in seen[1]["title"]


def test_long_custom_request_can_be_withdrawn(conn, world):
    name = "x" * 120
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "name": name})
    assert s == 200
    s, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "withdraw_request", "slug": b["slug"]})
    assert s == 200


def test_recommendations_use_real_counts_and_skip_mapped_duplicates(conn, world):
    recs = {r["slug"]: r for r in overview(conn, world["a"])["recommendations"]}
    # IAM.6 and S3.1 are open critical/high; the NIST copy is a mapped duplicate and the passed one does not count.
    assert recs["jira"]["evidence"]["open_critical_high_checks"] == 2 and recs["jira"]["kind"] == "connect"
    assert recs["slack"]["kind"] == "connect" and recs["github"]["kind"] == "connect"
    # Identity providers are not built: offered as a request, not as connectable.
    assert recs["okta"]["kind"] == "request" and recs["okta"]["evidence"]["open_identity_checks"] == 1


def test_workspace_and_channel_health(conn, world):
    with conn.cursor() as cur:
        cur.execute("""INSERT INTO workspace_integrations (cloud_account_id, provider, secret_name, status, credential_error)
                       VALUES (%s, 'jira', 's', 'needs_reauth', 'Jira returned 401')""", (world["a"],))
        cur.execute("INSERT INTO notification_channels (cloud_account_id, slack_webhook_url) VALUES (%s, 'https://hooks.slack.com/x')",
                    (world["a"],))
        attempt(cur, world["a"], "slack", True, None, "2 hours")
        attempt(cur, world["a"], "slack", False, None, "1 hour", "HTTP 404 from Slack")
    conn.commit()
    b = overview(conn, world["a"])
    st = {c["slug"]: c for c in b["connected"]}
    assert st["jira"]["health"] == "needs_reauth" and "401" in st["jira"]["health_reason"]
    assert st["slack"]["health"] == "failing" and "404" in st["slack"]["health_reason"]
    recs = {r["slug"]: r for r in b["recommendations"]}
    assert recs["jira"]["kind"] == "fix" and "slack" in recs and recs["slack"]["kind"] == "fix"
    assert b["counts"]["connected"] == 3
    jira = next(i for i in b["integrations"] if i["slug"] == "jira")
    assert jira["installs"] == 1 and jira["connection"]["health"] == "needs_reauth"


def test_request_lifecycle_and_counts(conn, world):
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "slug": "okta", "note": "SOC 2"})
    assert s == 200 and b["slug"] == "okta" and not b["updated"]
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "slug": "okta", "note": "again"})
    assert s == 200 and b["updated"]
    s, _ = call(conn, "other@b.test", "POST", body={"cloud_account_id": world["b"], "action": "request", "slug": "okta"})
    assert s == 200
    okta = next(i for i in overview(conn, world["a"])["integrations"] if i["slug"] == "okta")
    assert okta["requests"] == 2 and okta["requested"] is True
    # Available integrations are connected, not requested.
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "slug": "github"})
    assert s == 400 and "already available" in b["error"]
    # A name typed by hand that matches the catalog is filed under the catalog entry.
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "name": "  CrowdStrike Falcon "})
    assert s == 200 and b["slug"] == "crowdstrike-falcon"
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "name": "Acme Internal Tool"})
    assert s == 200 and b["slug"] == "new:acme-internal-tool"
    assert any(r["slug"] == "new:acme-internal-tool" for r in overview(conn, world["a"])["my_requests"])
    s, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "withdraw_request", "slug": "new:acme-internal-tool"})
    assert s == 200
    d = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "slug": "okta"})[1]
    assert d["my_request"]["note"] == "again" and d["detail"] is None
    audit = [e["action"] for e in overview(conn, world["a"])["audit"]]
    assert "marketplace_request" in audit and "marketplace_request_withdrawn" in audit


def test_reviews_need_a_connection_and_ratings_need_three_accounts(conn, world):
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "review", "slug": "github", "rating": 5})
    assert s == 400 and "connected" in b["error"]
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "review", "slug": "slack", "rating": 9})
    assert s == 400
    s, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "review", "slug": "slack",
                                                    "rating": 4, "message": "<b>works</b>"})
    assert s == 200
    slack = next(i for i in overview(conn, world["a"])["integrations"] if i["slug"] == "slack")
    assert slack["rating"] is None  # one review is not shown as an average
    # Another account's review is visible without author.
    with conn.cursor() as cur:
        cur.execute("INSERT INTO marketplace_feedback (cloud_account_id, slug, kind, rating, message, author) "
                    "VALUES (%s, 'slack', 'review', 2, 'slow', 'other@b.test')", (world["b"],))
    conn.commit()
    d = call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "slug": "slack"})[1]
    other = next(r for r in d["reviews"] if not r["own"])
    assert other["author"] is None and other["message"] == "slow"
    s, b = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "report_issue", "slug": "slack", "message": ""})
    assert s == 400
    s, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": world["a"], "action": "report_issue", "slug": "slack", "message": "No messages arrive"})
    assert s == 200
    assert call(conn, "owner@a.test", qs={"cloud_account_id": world["a"], "slug": "slack"})[1]["my_issues"][0]["message"] == "No messages arrive"


def test_tenant_isolation(conn, world):
    assert call(conn, "other@b.test", qs={"cloud_account_id": world["a"]})[0] == 403
    assert call(conn, "other@b.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "slug": "okta"})[0] == 403
    # A viewer can browse but not write.
    assert call(conn, "viewer@a.test", qs={"cloud_account_id": world["a"]})[0] == 200
    assert call(conn, "viewer@a.test", "POST", body={"cloud_account_id": world["a"], "action": "request", "slug": "wiz"})[0] == 403
    assert call(conn, None, qs={"cloud_account_id": world["a"]})[0] == 401
    # B sees none of A's connections.
    b = overview(conn, world["b"], "other@b.test")
    assert {c["slug"] for c in b["connected"]} == {"amazon-web-services"}


def test_ai_agent_gets_the_same_recommendations(conn, world):
    from collectors.aws.scanner import ai_agent_handler as ai
    with conn.cursor() as cur:
        ev = ai._run_intent(cur, world["a"], "integration_recommendations", None)
    assert {c["name"] for c in ev["connected_integrations"]} >= {"Amazon Web Services", "Jira", "Slack"}
    assert any(r["integration"] == "Okta" and r["action"] == "request" for r in ev["recommendations"])
    assert "Jira" in ev["available_to_connect_now"] and ev["catalog_size"] == len(M.catalog())
