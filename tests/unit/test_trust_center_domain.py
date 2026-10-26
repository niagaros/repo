"""Trust Center custom domains (#272): a hostname only serves an account's Trust Center after that account proved DNS
control with a TXT record, Niagaros's own hosts can never be claimed, and a failed DNS lookup is never read as
"record absent". DNS and the database are simulated."""
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest

pytest.importorskip("psycopg2")
from collectors.aws.scanner import trust_center_handler as T  # noqa: E402

pytestmark = [pytest.mark.flow("E2E-TRUST-001"), pytest.mark.severity("P2")]

ACC = "11111111-1111-1111-1111-111111111111"


@pytest.mark.parametrize("raw,want", [
    ("trust.domits.com", "trust.domits.com"),
    ("  Trust.Domits.COM. ", "trust.domits.com"),
    ("trust.niagaros.com", "trust.niagaros.com"),
    ("https://trust.domits.com", None),
    ("trust.domits.com/page", None),
    ("app.niagaros.com", None),
    ("niagaros.com", None),
    ("main.d3joqokkaynfaq.amplifyapp.com", None),
    ("localhost", None),
    ("-bad-.com", None),
    ("", None),
    (None, None),
])
def test_normalise_domain(raw, want):
    assert T.normalise_domain(raw) == want


class Cur:
    """Cursor over one trust_center_settings row (plus optional rows of other accounts)."""

    def __init__(self, row=None, others=()):
        self.row = row
        self.others = list(others)
        self.sql = []
        self._result = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=()):
        self.sql.append((sql, params))
        s = " ".join(sql.split())
        if s.startswith("SELECT custom_domain, custom_domain_token"):
            self._result = (self.row["custom_domain"], self.row["custom_domain_token"]) if self.row else None
        elif s.startswith("SELECT custom_domain FROM"):
            self._result = (self.row["custom_domain"],)
        elif s.startswith("SELECT 1 FROM trust_center_settings WHERE custom_domain"):
            self._result = (1,) if any(o["custom_domain"] == params[0] and o["custom_domain_verified_at"] for o in self.others) else None
        elif s.startswith("SELECT public_slug FROM trust_center_settings WHERE custom_domain"):
            match = [r for r in [self.row, *self.others] if r and r["custom_domain"] == params[0] and r["custom_domain_verified_at"]]
            self._result = (match[0]["public_slug"],) if match else None
        elif s.startswith("SELECT cloud_account_id, is_public"):
            r = self.row
            self._result = (ACC, r["is_public"], r["public_slug"], None, None, None, r["custom_domain"],
                            r["custom_domain_token"], r["custom_domain_verified_at"])
        elif s.startswith("UPDATE trust_center_settings SET custom_domain = %s"):
            self.row.update(custom_domain=params[0], custom_domain_token=params[1], custom_domain_verified_at=None)
        elif s.startswith("UPDATE trust_center_settings SET custom_domain = NULL"):
            self.row.update(custom_domain=None, custom_domain_token=None, custom_domain_verified_at=None)
        elif s.startswith("UPDATE trust_center_settings SET custom_domain_verified_at = NULL"):
            self.row["custom_domain_verified_at"] = None
        elif s.startswith("UPDATE trust_center_settings SET custom_domain_verified_at = NOW()"):
            self.row["custom_domain_verified_at"] = datetime.now(timezone.utc)

    def fetchone(self):
        return self._result


def conn_for(cur):
    conn = MagicMock()
    conn.cursor.return_value = cur
    conn.__enter__.return_value = conn
    conn.__exit__.return_value = False
    return conn


def row(**kw):
    return {"is_public": True, "public_slug": "abc123", "custom_domain": None, "custom_domain_token": None,
            "custom_domain_verified_at": None, **kw}


def test_setting_a_domain_starts_unverified_with_a_txt_record():
    cur = Cur(row())
    info = T._set_custom_domain(conn_for(cur), ACC, "Trust.Domits.com")
    assert info["domain"] == "trust.domits.com" and info["verified"] is False
    assert info["txt_name"] == "_niagaros-trust.trust.domits.com"
    assert info["txt_value"] == f"niagaros-verify={cur.row['custom_domain_token']}" and len(cur.row["custom_domain_token"]) == 32


def test_saving_the_same_domain_keeps_the_token_and_verification():
    verified = datetime.now(timezone.utc)
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="t" * 32, custom_domain_verified_at=verified))
    info = T._set_custom_domain(conn_for(cur), ACC, "trust.domits.com")
    assert info["verified"] is True and cur.row["custom_domain_token"] == "t" * 32


def test_changing_the_domain_drops_the_old_verification():
    cur = Cur(row(custom_domain="trust.old.com", custom_domain_token="t" * 32, custom_domain_verified_at=datetime.now(timezone.utc)))
    info = T._set_custom_domain(conn_for(cur), ACC, "trust.new.com")
    assert info["verified"] is False and cur.row["custom_domain_token"] != "t" * 32


def test_an_invalid_or_reserved_domain_is_refused():
    with pytest.raises(ValueError):
        T._set_custom_domain(conn_for(Cur(row())), ACC, "app.niagaros.com")


def test_an_empty_value_removes_the_domain():
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="t" * 32))
    assert T._set_custom_domain(conn_for(cur), ACC, "  ") is None and cur.row["custom_domain"] is None


def test_verify_succeeds_only_with_the_exact_txt_value(monkeypatch):
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="a" * 32))
    monkeypatch.setattr(T, "_dns_lookup", lambda name, rtype: ["niagaros-verify=" + "b" * 32])
    status, body = T._verify_custom_domain(conn_for(cur), ACC)
    assert status == 200 and body["verified"] is False and cur.row["custom_domain_verified_at"] is None

    seen = {}
    monkeypatch.setattr(T, "_dns_lookup", lambda name, rtype: seen.setdefault("name", name) and ["niagaros-verify=" + "a" * 32])
    status, body = T._verify_custom_domain(conn_for(cur), ACC)
    assert seen["name"] == "_niagaros-trust.trust.domits.com"
    assert status == 200 and body["verified"] is True and cur.row["custom_domain_verified_at"] is not None


def test_a_failed_dns_lookup_is_not_record_absent(monkeypatch):
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="a" * 32))

    def boom(name, rtype):
        raise OSError("timed out")
    monkeypatch.setattr(T, "_dns_lookup", boom)
    status, body = T._verify_custom_domain(conn_for(cur), ACC)
    assert status == 503 and "verified" not in body and cur.row["custom_domain_verified_at"] is None


def test_a_domain_verified_by_another_account_cannot_be_taken(monkeypatch):
    other = row(custom_domain="trust.domits.com", custom_domain_verified_at=datetime.now(timezone.utc), public_slug="domits")
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="a" * 32), others=[other])
    monkeypatch.setattr(T, "_dns_lookup", lambda name, rtype: ["niagaros-verify=" + "a" * 32])
    status, _ = T._verify_custom_domain(conn_for(cur), ACC)
    assert status == 409 and cur.row["custom_domain_verified_at"] is None


def test_only_a_verified_domain_resolves_to_a_trust_center():
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="a" * 32))
    assert T._slug_for_domain(cur, "trust.domits.com") is None
    cur.row["custom_domain_verified_at"] = datetime.now(timezone.utc)
    assert T._slug_for_domain(cur, "TRUST.domits.com") == "abc123"
    assert T._slug_for_domain(cur, "app.niagaros.com") is None


def test_dns_lookup_distinguishes_absent_from_failure(monkeypatch):
    class R:
        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self.body
    monkeypatch.setattr(T.urllib.request, "urlopen", lambda req, timeout: R(b'{"Status": 3}'))
    assert T._dns_lookup("_niagaros-trust.x.com", "TXT") == []
    monkeypatch.setattr(T.urllib.request, "urlopen", lambda req, timeout: R(b'{"Status": 2}'))
    with pytest.raises(RuntimeError):
        T._dns_lookup("_niagaros-trust.x.com", "TXT")
    monkeypatch.setattr(T.urllib.request, "urlopen", lambda req, timeout: R(
        b'{"Status": 0, "Answer": [{"type": 16, "data": "\\"niagaros-verify=abc\\""}, {"type": 5, "data": "x."}]}'))
    assert T._dns_lookup("_niagaros-trust.x.com", "TXT") == ["niagaros-verify=abc"]


def test_the_domain_lookup_is_a_public_request():
    assert T._is_public({"httpMethod": "GET"}, {"domain": "trust.domits.com"}, {})
    assert not T._is_public({"httpMethod": "POST"}, {}, {"action": "set_custom_domain"})
    assert not T._is_public({"httpMethod": "POST"}, {}, {"action": "verify_custom_domain"})


@pytest.mark.parametrize("bad", ["11111111111111111111111111111111", "{11111111-1111-1111-1111-111111111111}", "x"])
def test_a_noncanonical_id_is_refused_before_the_guard(monkeypatch, bad):
    monkeypatch.setattr(T, "_get_connection", lambda: pytest.fail("no database access expected"))
    event = {"httpMethod": "POST", "body": '{"action": "set_custom_domain", "cloud_account_id": "%s"}' % bad}
    assert T.handler(event, None)["statusCode"] == 400
    event = {"httpMethod": "GET", "queryStringParameters": {"download_document": bad, "access_token": "t"}}
    assert T.handler(event, None)["statusCode"] == 400


def test_a_removed_txt_record_ends_the_verification(monkeypatch):
    cur = Cur(row(custom_domain="trust.domits.com", custom_domain_token="a" * 32, custom_domain_verified_at=datetime.now(timezone.utc)))
    monkeypatch.setattr(T, "_dns_lookup", lambda name, rtype: [])
    status, body = T._verify_custom_domain(conn_for(cur), ACC)
    assert status == 200 and body["verified"] is False and cur.row["custom_domain_verified_at"] is None
