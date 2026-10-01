"""Disaster-recovery evidence notifications: the latest restore test per resource is judged
against the published targets; failed, missed, incomplete or stale evidence is notified,
at most once per week per resource and problem (no database or network needed)."""
import pytest

from collectors.aws.scanner import notification_lib as nl

pytestmark = [pytest.mark.flow("E2E-NOT-002"), pytest.mark.severity("P2")]


@pytest.mark.parametrize("rpo,rto,integrity,age,expected", [
    (192, 1714, True, 10, None),                       # within every target, recent
    (300, 1800, True, 90, None),                       # exactly on the limits
    (192, 1714, False, 10, ("dr_test_failed", "P1")),  # integrity mismatch beats everything
    (400, 1714, True, 10, ("dr_target_missed", "P2")),
    (192, 2400, True, 10, ("dr_target_missed", "P2")),
    (None, 1714, True, 10, ("dr_test_incomplete", "P3")),
    (192, 1714, None, 10, ("dr_test_incomplete", "P3")),
    (192, 1714, True, 91, ("dr_test_overdue", "P3")),
    (400, 1714, True, 400, ("dr_target_missed", "P2")),  # worst problem wins over staleness
])
def test_dr_problem_classification(rpo, rto, integrity, age, expected):
    problem = nl._dr_problem(rpo, rto, integrity, age)
    assert (problem[:2] if problem else None) == expected


class _Cursor:
    def __init__(self, db):
        self.db, self._result = db, []

    def execute(self, sql, params=None):
        if "FROM dr_test_results" in sql:
            self._result = self.db["latest"]
        elif "FROM notifications" in sql:
            account, event_type, link, _days = params
            self._result = [(1,)] if (str(account), event_type, link) in self.db["recent"] else []
        else:
            raise AssertionError(f"unexpected SQL: {sql}")

    def fetchall(self):
        return self._result

    def fetchone(self):
        return self._result[0] if self._result else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    def __init__(self, db):
        self.db = db

    def cursor(self):
        return _Cursor(self.db)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(nl, "create_notification", lambda conn, account, **kw: calls.append((account, kw)) or {"id": "n1"})
    return calls


def test_only_problematic_resources_are_notified(sent):
    db = {"recent": set(), "latest": [
        ("acct-1", "rds-instance", "cspm-db", 192, 1714, True, 12.0),        # fine
        ("acct-1", "dynamodb-table", "orders", 192, 1714, False, 3.0),      # failed
        ("acct-2", "rds-instance", "billing-db", 192, 1714, True, 120.0),   # overdue
    ]}
    created = nl.run_dr_evidence_check(_Conn(db))
    assert [(c["resource"], c["event_type"]) for c in created] == [("orders", "dr_test_failed"), ("billing-db", "dr_test_overdue")]
    account, kw = sent[0]
    assert account == "acct-1" and kw["domain"] == "risk" and kw["severity"] == "P1"
    assert kw["resource_link"].startswith("niagaros-dashboard.html?account_id=acct-1&dr_resource=")


def _link(account, rtype, rname):
    import hashlib
    return (f"niagaros-dashboard.html?account_id={account}&dr_resource="
            + hashlib.sha256(f"{rtype}:{rname}".encode()).hexdigest()[:16] + "#issues")


def test_same_problem_is_not_renotified_within_a_week(sent):
    link = _link("acct-2", "rds-instance", "billing-db")
    db = {"recent": {("acct-2", "dr_test_overdue", link)}, "latest": [
        ("acct-2", "rds-instance", "billing-db", 192, 1714, True, 120.0),
    ]}
    assert nl.run_dr_evidence_check(_Conn(db)) == []
    assert sent == []


def test_one_failing_notification_does_not_stop_the_others(monkeypatch):
    calls = []

    def flaky(conn, account, **kw):
        calls.append(kw["title"])
        if len(calls) == 1:
            raise RuntimeError("queue down")
        return {"id": "n2"}

    monkeypatch.setattr(nl, "create_notification", flaky)
    db = {"recent": set(), "latest": [
        ("acct-1", "rds-instance", "a-db", None, 1714, True, 1.0),
        ("acct-1", "rds-instance", "b-db", None, 1714, True, 1.0),
    ]}
    created = nl.run_dr_evidence_check(_Conn(db))
    assert len(calls) == 2 and [c["resource"] for c in created] == ["b-db"]


def test_long_resource_names_fit_the_notification_columns(sent):
    uuid = "6f1c2a9e-1b2c-4d5e-8f90-123456789abc"
    db = {"recent": set(), "latest": [(uuid, "dynamodb-table", "t" * 255, None, 1714, True, 1.0)]}
    nl.run_dr_evidence_check(_Conn(db))
    _, kw = sent[0]
    assert len(kw["resource_link"]) <= 255 and len(kw["title"]) <= 255
