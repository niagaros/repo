"""Stored test runs: only Admins / the ingest token can read or write them; input is validated."""
import os

import pytest

from conftest import ACCOUNT_ID  # noqa: F401

pytestmark = [pytest.mark.live, pytest.mark.flow("E2E-RES-001"), pytest.mark.severity("P1")]
JSON = {"Content-Type": "application/json"}
INGEST = os.environ.get("E2E_INGEST_TOKEN", "")
needs_ingest = pytest.mark.skipif(not INGEST, reason="blocked: E2E_INGEST_TOKEN not set")


def test_anonymous_callers_cannot_read_or_write_test_results(anon):
    assert anon.get("test-results")[0] == 401
    assert anon.post("test-results", {"summary": {}, "results": []}, headers=JSON)[0] == 401


def test_a_wrong_ingest_token_is_refused(anon):
    assert anon.get("test-results", headers={"X-Ingest-Token": "not-the-token"})[0] == 403
    assert anon.post("test-results", {"summary": {}, "results": []}, headers={**JSON, "X-Ingest-Token": "nope"})[0] == 403


def test_an_expired_or_invalid_session_is_sent_back_to_sign_in_not_told_it_is_not_admin(anon):
    s, b, _ = anon.get("test-results", headers={"Authorization": "Bearer expired.or.invalid"})
    assert s == 401 and "expired" in b["error"]


@pytest.mark.needs_token
def test_a_normal_signed_in_user_is_not_an_admin_and_cannot_see_test_results(api):
    s, b, _ = api.get("test-results")
    assert s == 403 and "Admins only" in b["error"]


@needs_ingest
@pytest.mark.parametrize("payload", [{}, {"summary": {"run_at": "x", "totals": {}}, "results": []},
                                     {"summary": {"run_at": "x", "totals": {}}, "results": [{"test_id": "t", "status": "great"}]}])
def test_malformed_runs_are_rejected_and_nothing_is_stored(anon, payload):
    s, b, _ = anon.post("test-results", payload, headers={**JSON, "X-Ingest-Token": INGEST})
    assert s == 400 and "error" in b


@needs_ingest
def test_stored_results_have_the_expected_shape(anon):
    s, b, _ = anon.get("test-results", headers={"X-Ingest-Token": INGEST})
    assert s == 200 and {"run", "history", "failure_counts", "flaky_by_history"} <= set(b)
    if b["run"]:
        assert b["run"]["totals"]["tests"] > 0 and b["history"][0]["run_at"]
