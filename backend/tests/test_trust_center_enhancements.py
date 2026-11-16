"""
Trust Center second pass (#258) against a real PostgreSQL with the real migrations: certificate validity recalculated
at every read, status notices, branding and disclosure validation, logo type checks, page-load analytics, and the
admin actor taken from the verified token instead of the request body. S3 is faked.
Needs NIAGAROS_PGTEST_DSN (see test_governance_handler.py).
"""
import base64
import json
import os
import sys
import uuid
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

psycopg2 = pytest.importorskip("psycopg2")
DSN = os.environ.get("NIAGAROS_PGTEST_DSN", "")
pytestmark = pytest.mark.skipif(not DSN, reason="blocked: set NIAGAROS_PGTEST_DSN to a throwaway PostgreSQL")

from collectors.aws.scanner import trust_center_handler as T  # noqa: E402

SCHEMA = ["tests/fixtures/ciem_schema.sql", "tests/fixtures/security_agents_schema.sql", "migrations/024_security_audit_log.sql",
          "migrations/026_enterprise.sql", "migrations/007_questionnaire_automation.sql", "migrations/011_trust_center.sql",
          "migrations/012_trust_center_nda_and_email.sql", "migrations/036_trust_center_custom_domain.sql",
          "migrations/040_trust_center_enhancements.sql", "migrations/040_trust_center_enhancements.sql"]
def _png():
    import struct, zlib

    def chunk(k, d):
        return struct.pack(">I", len(d)) + k + d + struct.pack(">I", zlib.crc32(k + d) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00")) + chunk(b"IEND", b""))


PNG = _png()


@pytest.fixture(scope="module")
def conn():
    name = f"trust_test_{uuid.uuid4().hex[:8]}"
    admin = psycopg2.connect(DSN)
    admin.autocommit = True
    admin.cursor().execute(f"CREATE DATABASE {name}")
    c = psycopg2.connect(DSN.rsplit("/", 1)[0] + "/" + name)
    c.autocommit = True
    for f in SCHEMA:
        c.cursor().execute((BACKEND / f).read_text(encoding="utf-8"))
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
def acct(conn):
    with conn.cursor() as cur:
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name) VALUES ('owner@a.test', '111122223333', 'A') RETURNING id")
        a = str(cur.fetchone()[0])
        cur.execute("INSERT INTO cloud_accounts (owner_email, account_id, account_name) VALUES ('other@b.test', '444455556666', 'B') RETURNING id")
        b = str(cur.fetchone()[0])
    conn.commit()
    return {"a": a, "b": b}


def call(conn, email, method="GET", qs=None, body=None):
    event = {"httpMethod": method, "headers": {"Authorization": "Bearer t"}, "queryStringParameters": qs,
             "body": json.dumps(body) if body is not None else None}
    s3 = MagicMock()
    s3.generate_presigned_url.return_value = "https://s3.example/signed"
    with patch.object(T, "_get_connection", return_value=_NoClose(conn)), patch.object(T, "_s3", return_value=s3), \
            patch("collectors.aws.scanner.tenant_auth.authenticate", return_value=email), \
            patch.object(T, "authenticate", return_value=email):
        r = T.handler(event, None)
    return r["statusCode"], json.loads(r["body"]), s3


def test_certificate_validity_is_calculated_at_every_read(conn, acct):
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "upload_document", "title": "ISO 27001 certificate",
                                                       "category": "iso_certificate", "visibility": "public", "filename": "iso.pdf",
                                                       "file_base64": base64.b64encode(b"%PDF").decode(), "actor_name": "Spoofed Name"})
    doc = b["id"]
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "set_document_validity", "document_id": doc,
                                                    "valid_from": "2027-01-01", "valid_until": "2026-01-01"})[0] == 400
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "set_document_validity", "document_id": doc,
                                                       "valid_from": "2024-01-01", "valid_until": str(date.today() - timedelta(days=1)),
                                                       "issuer": "BSI"})
    assert s == 200 and b["validity_status"] == "expired"
    call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "update_settings", "is_public": True})
    s, settings, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"]})
    slug = settings["settings"]["public_slug"]
    s, pub, _ = call(conn, None, qs={"slug": slug})
    d = pub["documents"][0]
    assert d["validity_status"] == "expired" and d["issuer"] == "BSI"
    with conn.cursor() as cur:
        cur.execute("UPDATE trust_documents SET valid_until = CURRENT_DATE + 10 WHERE id = %s", (doc,))
    conn.commit()
    assert call(conn, None, qs={"slug": slug})[1]["documents"][0]["validity_status"] == "expiring_soon"
    # The audit trail names the signed-in person, not the name the browser sent.
    s, log, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"], "audit_log": "1"})
    actors = {e["actor"] for e in log["entries"] if e["action"] in ("uploaded_version", "validity_updated")}
    assert actors == {"owner@a.test"}


def test_a_certificate_that_has_not_started_is_not_valid():
    assert T._doc_status(date.today() + timedelta(days=500), valid_from=date.today() + timedelta(days=100)) == "not_yet_valid"
    assert T._doc_status(None, valid_from=date.today() - timedelta(days=1)) == "no_expiry"


def test_admin_calls_fail_closed_when_the_token_cannot_be_verified(conn, acct):
    s, _, _ = call(conn, None, "POST", body={"cloud_account_id": acct["a"], "action": "update_settings", "company_name": "x",
                                              "actor_name": "Forged"})
    assert s == 401


def test_settings_are_validated_and_audited(conn, acct):
    for body, msg in (({"brand_color": "red"}, "#1D4ED8"), ({"status_page_url": "http://status.x.test"}, "https"),
                      ({"security_contact": "not-an-email"}, "email"), ({"disclosure_policy": "x" * 5001}, "5000")):
        s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "update_settings", **body})
        assert s == 400 and msg in b["error"], body
    s, _, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "update_settings", "brand_color": "#1D4ED8",
                                                       "status_page_url": "https://status.a.test", "security_contact": "security@a.test",
                                                       "disclosure_policy": "Mail us, we answer within 3 days."})
    assert s == 200
    s, ev, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"], "events": "1"})
    assert ev["events"][0]["actor"] == "owner@a.test" and "brand_color" in ev["events"][0]["detail"]["fields"]


def test_logo_must_be_png_or_jpeg(conn, acct):
    svg = base64.b64encode(b"<svg onload=alert(1)></svg>").decode()
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "upload_logo", "filename": "x.svg", "file_base64": svg})[0] == 400
    header_only = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).decode()
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "upload_logo", "filename": "x.png", "file_base64": header_only})[0] == 400
    s, b, s3 = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "upload_logo", "filename": "l.png",
                                                        "file_base64": base64.b64encode(PNG).decode()})
    assert s == 200 and s3.put_object.call_args.kwargs["ContentType"] == "image/png"


def test_notices_and_public_view(conn, acct):
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "create_update", "kind": "outage", "title": "x"})[0] == 400
    s, b, _ = call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "create_update", "kind": "incident",
                                                       "title": "API errors", "body": "Some requests failed."})
    uid = b["id"]
    s, settings, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"]})
    s, pub, _ = call(conn, None, qs={"slug": settings["settings"]["public_slug"]})
    assert pub["status"]["status_page_url"] == "https://status.a.test" and pub["status"]["updates"][0]["title"] == "API errors"
    assert "published_by" not in pub["status"]["updates"][0], "who published is not shown publicly"
    assert pub["branding"]["brand_color"] == "#1D4ED8" and pub["branding"]["logo_url"]
    assert pub["disclosure"]["security_contact"] == "security@a.test"
    assert call(conn, "owner@a.test", "POST", body={"cloud_account_id": acct["a"], "action": "resolve_update", "update_id": uid, "note": "Fixed"})[0] == 200
    s, ups, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"], "updates": "1"})
    assert ups["updates"][0]["resolved_at"] and "Resolved: Fixed" in ups["updates"][0]["body"]


def test_analytics_counts_page_loads_without_visitor_data(conn, acct):
    s, a, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"], "analytics": "1"})
    assert s == 200 and a["page_loads_total_30d"] == 3 and "no visitor identity" in a["method"]
    with conn.cursor() as cur:
        cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'trust_center_page_views'")
        assert {r[0] for r in cur.fetchall()} == {"cloud_account_id", "day", "views"}


def test_tenant_isolation_on_new_ids(conn, acct):
    s, ups, _ = call(conn, "owner@a.test", qs={"cloud_account_id": acct["a"], "updates": "1"})
    uid = ups["updates"][0]["id"]
    s, _, _ = call(conn, "other@b.test", "POST", body={"cloud_account_id": acct["b"], "action": "resolve_update", "update_id": uid})
    assert s == 403
    s, _, _ = call(conn, "other@b.test", qs={"cloud_account_id": acct["a"], "analytics": "1"})
    assert s == 403
