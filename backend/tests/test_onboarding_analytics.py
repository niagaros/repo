"""
Tests for api/analytics_handler.py — the onboarding drop-off funnel (DV5).

Unlike the other handler tests in this folder, these need no database. Every
figure the dashboard shows is computed by three pure functions from two
inputs: when each organization signed up, and when it first completed each
step. Feeding those directly is what makes the arithmetic provable — the
design document warns that the real dataset is far too small to tell a correct
calculation from a wrong one.

    python -m pytest tests/test_onboarding_analytics.py      (from backend/)
"""
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND / "src"))

pytest.importorskip("psycopg2")
from api import analytics_handler as ah  # noqa: E402

NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
STEPS = ["infrastructure", "team", "auditor", "workspace"]


def at(days_ago: float) -> datetime:
    return NOW - timedelta(days=days_ago)


def org(oid: str, days_ago: float, name: str = "Example BV") -> dict:
    return {"id": oid, "name": name, "created_at": at(days_ago)}


# ── per organization (§3.1) ────────────────────────────────────────────────

def test_progress_is_counted_against_the_measured_steps_only():
    row = ah._org_row(org("a", 10), {"infrastructure": at(9), "team": at(8)}, STEPS, NOW)
    assert row["completed_steps"] == 2
    assert row["measured_steps"] == 4
    assert row["progress_pct"] == 50


def test_current_step_is_the_first_open_one_not_the_one_after_the_last_done():
    # Skipped ahead: team is done, infrastructure never was. The customer is
    # still stuck on step 1, and that is what has to be shown.
    row = ah._org_row(org("a", 10), {"team": at(2)}, STEPS, NOW)
    assert row["current_step"] == "infrastructure"


def test_idle_days_run_from_the_last_completion():
    row = ah._org_row(org("a", 30), {"infrastructure": at(20), "team": at(5)}, STEPS, NOW)
    assert row["idle_days"] == 5.0


def test_idle_days_run_from_signup_when_nothing_is_done_yet():
    assert ah._org_row(org("a", 2), {}, STEPS, NOW)["idle_days"] == 2.0


def test_elapsed_time_stops_at_the_last_step_once_everything_is_done():
    done = {s: at(20 - i) for i, s in enumerate(STEPS)}   # last one 17 days ago
    row = ah._org_row(org("a", 30), done, STEPS, NOW)
    assert row["status"] == "finished"
    assert row["current_step"] is None
    assert row["elapsed_days"] == 13.0     # 30 - 17, not 30


def test_elapsed_time_keeps_running_while_the_customer_is_not_done():
    assert ah._org_row(org("a", 9), {"infrastructure": at(8)}, STEPS, NOW)["elapsed_days"] == 9.0


@pytest.mark.parametrize("current,idle,expected", [
    ("team", 6, "in_progress"),     # R8 allows 7
    ("team", 8, "stuck"),
    ("auditor", 13, "in_progress"),  # R9 allows 14
    ("auditor", 15, "stuck"),
])
def test_stuck_uses_the_threshold_of_the_step_the_customer_is_on(current, idle, expected):
    # Complete everything before `current`, with the last one `idle` days ago.
    done = {s: at(idle) for s in STEPS[:STEPS.index(current)]}
    assert ah._org_row(org("a", 60), done, STEPS, NOW)["status"] == expected


def test_a_customer_who_signed_up_and_never_returned_does_not_stay_not_started():
    assert ah._org_row(org("a", 2), {}, STEPS, NOW)["status"] == "not_started"
    assert ah._org_row(org("a", 4), {}, STEPS, NOW)["status"] == "stuck"   # R3 allows 3


# ── the funnel (§3.2) ──────────────────────────────────────────────────────

def test_each_step_is_measured_against_the_previous_one_not_the_total():
    orgs = [org("a", 10), org("b", 10), org("c", 10), org("d", 10)]
    completions = {
        "a": {"infrastructure": at(9), "team": at(8)},
        "b": {"infrastructure": at(9), "team": at(8)},
        "c": {"infrastructure": at(9)},
        "d": {},
    }
    funnel = {f["step"]: f for f in ah._funnel(orgs, completions, STEPS)}

    assert (funnel["infrastructure"]["reached"], funnel["infrastructure"]["completed"]) == (4, 3)
    assert funnel["infrastructure"]["dropoff_pct"] == 25

    # Three reached step 2, two finished it. Against the total of four this
    # would read as 50% — the number the design calls blame moved forward.
    assert (funnel["team"]["reached"], funnel["team"]["completed"]) == (3, 2)
    assert funnel["team"]["dropoff_pct"] == 33


def test_median_duration_ignores_the_one_customer_who_came_back_months_later():
    orgs = [org(c, 200) for c in "abcd"]
    completions = {
        "a": {"infrastructure": at(199), "team": at(198)},   # 1 day
        "b": {"infrastructure": at(199), "team": at(197)},   # 2 days
        "c": {"infrastructure": at(199), "team": at(196)},   # 3 days
        "d": {"infrastructure": at(199), "team": at(99)},    # 100 days
    }
    team = next(f for f in ah._funnel(orgs, completions, STEPS) if f["step"] == "team")
    assert team["median_days"] == 2.5          # the mean would be 26.5


def test_the_first_step_is_measured_from_signup():
    orgs = [org("a", 10)]
    first = ah._funnel(orgs, {"a": {"infrastructure": at(7)}}, STEPS)[0]
    assert first["reached"] == 1
    assert first["median_days"] == 3.0


def test_a_step_nobody_can_finish_shows_its_drop_off_with_the_reason_beside_it():
    # Step 4 reads 100% drop-off on production because no Jira or Monday
    # account exists. The design asks for the reason to travel with the
    # number rather than for the number to be hidden.
    orgs = [org("a", 10)]
    completions = {"a": {"infrastructure": at(9), "team": at(8), "auditor": at(7)}}
    workspace = next(f for f in ah._funnel(orgs, completions, STEPS) if f["step"] == "workspace")
    assert (workspace["reached"], workspace["completed"]) == (1, 0)
    assert workspace["dropoff_pct"] == 100
    assert "Jira" in workspace["blocked_reason"]
    # No other step claims an excuse it does not have.
    assert all(f["blocked_reason"] is None for f in ah._funnel(orgs, completions, STEPS)
               if f["step"] != "workspace")


def test_an_empty_platform_reports_no_percentage_rather_than_zero():
    funnel = ah._funnel([], {}, STEPS)
    assert all(f["dropoff_pct"] is None and f["median_days"] is None for f in funnel)


# ── the aggregate (§3.3) ───────────────────────────────────────────────────

def test_summary_counts_every_status_and_reports_its_own_coverage():
    orgs = [org("a", 10), org("b", 1), org("c", 60)]
    completions = {
        "a": {s: at(5) for s in STEPS},    # finished
        "b": {},                            # too recent to be stuck
        "c": {"infrastructure": at(50)},    # long idle
    }
    rows = [ah._org_row(o, completions[o["id"]], STEPS, NOW) for o in orgs]
    summary = ah._summary(rows, orgs, completions, STEPS)

    assert summary["by_status"] == {"not_started": 1, "in_progress": 0, "stuck": 1, "finished": 1}
    assert summary["organizations"] == 3
    assert summary["measured_steps"] == 4
    assert summary["total_steps"] == 7


def test_median_total_time_counts_only_customers_who_finished_everything():
    orgs = [org("a", 10), org("b", 10)]
    completions = {
        "a": {s: at(4) for s in STEPS},     # 6 days from signup
        "b": {"infrastructure": at(9)},     # unfinished, must not count
    }
    rows = [ah._org_row(o, completions[o["id"]], STEPS, NOW) for o in orgs]
    assert ah._summary(rows, orgs, completions, STEPS)["median_total_days"] == 6.0


def test_median_total_time_is_absent_when_nobody_finished():
    orgs = [org("a", 10)]
    completions = {"a": {"infrastructure": at(9)}}
    rows = [ah._org_row(orgs[0], completions["a"], STEPS, NOW)]
    assert ah._summary(rows, orgs, completions, STEPS)["median_total_days"] is None


# ── who may look (§5) ──────────────────────────────────────────────────────

NIAGAROS = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


@pytest.mark.parametrize("role,org_id,allowed", [
    ("admin", NIAGAROS, True),
    ("admin", OTHER, False),        # an admin, but of a customer
    ("security", NIAGAROS, False),  # inside Niagaros, but not an admin
    ("viewer", OTHER, False),
])
def test_both_conditions_must_hold(role, org_id, allowed):
    with patch.dict(os.environ, {"NIAGAROS_ORGANIZATION_ID": NIAGAROS}):
        assert ah._may_view({"role": role, "organization_id": org_id}) is allowed


def test_it_refuses_everyone_when_the_environment_does_not_say_who_niagaros_is():
    with patch.dict(os.environ, {"NIAGAROS_ORGANIZATION_ID": ""}):
        assert ah._may_view({"role": "admin", "organization_id": NIAGAROS}) is False


@pytest.mark.parametrize("role,org_id", [("admin", NIAGAROS), ("admin", OTHER), ("viewer", NIAGAROS)])
def test_the_access_route_and_the_data_route_answer_from_the_same_rule(role, org_id):
    # A menu drawn from one rule and data guarded by another is a menu that
    # can offer a door that does not open. Both call _may_view; this pins that
    # down so a later change to one cannot quietly skip the other.
    caller = {"role": role, "organization_id": org_id, "id": "u1", "email": "x@example.com"}
    with patch.dict(os.environ, {"NIAGAROS_ORGANIZATION_ID": NIAGAROS}), \
         patch.object(ah, "_get_caller", return_value=caller):
        access = ah.handle_get_access({}, db=None)
        allowed = json.loads(access["body"])["may_view"]
        assert allowed is ah._may_view(caller)

        if not allowed:
            # Refused before a single query runs: db is None, so anything
            # that touched the database here would raise rather than pass.
            assert ah.handle_get_onboarding_analytics({}, db=None)["statusCode"] == 403


def test_an_unknown_caller_is_unauthorized_at_the_access_route_too():
    with patch.object(ah, "_get_caller", return_value=None):
        assert ah.handle_get_access({}, db=None)["statusCode"] == 401
