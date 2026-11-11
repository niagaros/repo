"""
Onboarding analytics (DV5) — the drop-off funnel, the aggregate and the
per-organization table described in `Ontwerp_Analyticsdashboard`.

Three things about this module are deliberate.

**It computes, it does not store.** Every number here is derived at request
time from `organizations.created_at` and `onboarding_step_completions`. There
is no roll-up table, no scheduled job and no cached figure, because a stale
number in a dashboard about drop-off is worse than a slow one. The dataset is
small by design (see §4 of the design document), so the cost is a few hundred
rows.

**The denominator is counted, never written down.** The design was drafted
when only the first four steps recorded a completion, and it fixed the
denominator at four while saying that it should widen by itself once the other
three began recording. They now do, so `MEASURED_STEPS` is derived from the
table's own CHECK constraint rather than from a number in this file.

**It is for Niagaros, not for the customer.** Unlike every other endpoint in
this package, this one reads across organizations. Access therefore needs two
things at once — an admin role *and* membership of Niagaros itself — and it
fails closed when the environment does not say which organization that is.
"""
import logging
import os
from statistics import median

from config.database import Database
# ONBOARDING_STEPS is imported rather than repeated: it is the order a customer
# walks the wizard in, and a funnel built from a second copy would drift.
from api.team_handler import ONBOARDING_STEPS, _get_caller, _response, _route_path

logger = logging.getLogger()

# Days without progress after which an organization counts as stuck, per step.
#
# These are not this dashboard's own thresholds. They are the ones the
# intelligence layer (DV4) acts on: R3 for a missing cloud account, R8 for a
# team that is still only the admin, R9 for a missing auditor, and R10 as the
# general rule for every other step. Two products with two definitions would
# let this page call a customer healthy on the same day the other one writes
# to them.
STUCK_AFTER_DAYS = {
    "infrastructure": 3,    # R3
    "team": 7,              # R8
    "auditor": 14,          # R9
}
STUCK_AFTER_DAYS_DEFAULT = 14   # R10

# Steps that cannot yet be completed on production, and why. The funnel shows
# these at a 100% drop-off; the design asks for the reason to travel with the
# number instead of the number being hidden.
#
# An entry here is a claim about the outside world, and the data can disprove
# it. The first reading of production did: two of the two organizations that
# reached the workspace step finished it, in October, while this table said
# nobody could. So _funnel drops the reason as soon as one organization gets
# through, rather than printing an excuse beside a step people are completing.
# That makes each entry self-retiring — it survives only as long as it is true.
BLOCKED_STEPS = {
    "workspace": "No Jira or Monday account is available on production, so no customer can finish this step.",
}


def _niagaros_organization_id() -> str | None:
    """
    Which organization is Niagaros itself. Unset means nobody passes the check
    below: an analytics page that reads every customer's progress should go
    dark when it cannot tell who is allowed to look, rather than fall back to
    something permissive.
    """
    return (os.environ.get("NIAGAROS_ORGANIZATION_ID") or "").strip() or None


def _may_view(caller: dict) -> bool:
    """
    The one place both conditions live.

    Two separate things have to be true: the caller is an admin, *and* their
    organization is Niagaros. Either alone is not enough — an admin of a
    customer would otherwise read every other customer's progress, and a
    viewer inside Niagaros would read data their role does not carry
    elsewhere in this platform.

    Everything that needs the answer asks this function: the dashboard
    endpoint before it computes anything, and the access endpoint the page
    uses to decide whether to offer the entrance at all. A second copy of
    this rule in the browser would be a rule that can drift out of step with
    the one that actually guards the data.
    """
    org = _niagaros_organization_id()
    if not org:
        logger.warning("Analytics: NIAGAROS_ORGANIZATION_ID is not set; refusing every caller.")
        return False
    return caller["role"] == "admin" and str(caller["organization_id"]) == org


def _measured_steps(db: Database) -> list:
    """
    The steps for which a completion moment can exist, in wizard order.

    Read from the CHECK constraint on `onboarding_step_completions` rather than
    from a constant here. The design's open question — is it right that this
    measures four of seven? — is answered by whatever that table accepts, and
    reading it means the answer cannot go stale in this file.
    """
    with db.conn.cursor() as cur:
        cur.execute("""
            SELECT pg_get_constraintdef(c.oid)
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            WHERE t.relname = 'onboarding_step_completions' AND c.contype = 'c'
        """)
        definitions = " ".join(r[0] for r in cur.fetchall())
    # Keep the wizard's order; a funnel in alphabetical order is not a funnel.
    return [s for s in ONBOARDING_STEPS if f"'{s}'" in definitions]


def _organizations(db: Database) -> list:
    with db.conn.cursor() as cur:
        cur.execute("SELECT id, name, created_at FROM organizations ORDER BY created_at")
        return [{"id": str(r[0]), "name": r[1], "created_at": r[2]} for r in cur.fetchall()]


def _completions(db: Database) -> dict:
    """organization_id -> {step: completed_at}."""
    with db.conn.cursor() as cur:
        cur.execute("SELECT organization_id, step, completed_at FROM onboarding_step_completions")
        rows = cur.fetchall()
    out: dict = {}
    for org_id, step, at in rows:
        out.setdefault(str(org_id), {})[step] = at
    return out


def _days_between(earlier, later) -> float:
    return (later - earlier).total_seconds() / 86400.0


def _org_row(org: dict, done: dict, steps: list, now) -> dict:
    """The per-organization indicators from §3.1 of the design."""
    completed = [s for s in steps if s in done]
    moments = [done[s] for s in completed]

    # Indicator 2: the first step in the customer's own order that is still
    # open. Not "the one after the last completion" — a customer who skipped
    # ahead should still be shown the step they left behind.
    current = next((s for s in steps if s not in done), None)

    last_moment = max(moments) if moments else None
    # Indicator 3: progress is measured from the last thing that happened, and
    # from signing up when nothing has happened yet.
    idle_days = _days_between(last_moment or org["created_at"], now)
    # Indicator 4: a finished customer's elapsed time stops at their last step;
    # an unfinished one's keeps running.
    finished = current is None
    elapsed_days = _days_between(org["created_at"], last_moment if finished and last_moment else now)

    if finished:
        status = "finished"
    elif not completed:
        # Nothing at all yet. Still "stuck" once step 1's own threshold passes,
        # so a customer who signs up and never returns does not sit in
        # "not started" forever.
        threshold = STUCK_AFTER_DAYS.get(steps[0], STUCK_AFTER_DAYS_DEFAULT) if steps else STUCK_AFTER_DAYS_DEFAULT
        status = "stuck" if idle_days > threshold else "not_started"
    else:
        threshold = STUCK_AFTER_DAYS.get(current, STUCK_AFTER_DAYS_DEFAULT)
        status = "stuck" if idle_days > threshold else "in_progress"

    return {
        "organization_id": org["id"],
        "name": org["name"],
        "created_at": org["created_at"].isoformat(),
        "completed_steps": len(completed),
        # Indicator 1 travels with its own denominator, so a percentage can
        # never be read as progress over a longer journey than was measured.
        "measured_steps": len(steps),
        "progress_pct": round(len(completed) / len(steps) * 100) if steps else 0,
        "current_step": current,
        "idle_days": round(idle_days, 1),
        "elapsed_days": round(elapsed_days, 1),
        "status": status,
    }


def _funnel(orgs: list, completions: dict, steps: list) -> list:
    """
    §3.2. Each step is measured against the step before it, not against the
    total: a funnel that compares everything to the total moves the blame
    forward, making a late step look bad for customers who left at the first.
    """
    out = []
    previous = None
    for step in steps:
        if previous is None:
            reached = [o["id"] for o in orgs]
        else:
            reached = [o["id"] for o in orgs if previous in completions.get(o["id"], {})]
        completed = [oid for oid in reached if step in completions.get(oid, {})]

        # Indicator 9: the median, because one customer who returns after three
        # months would drag a mean past the point of saying anything.
        durations = []
        for oid in completed:
            done = completions[oid]
            start = done[previous] if previous else next(o["created_at"] for o in orgs if o["id"] == oid)
            durations.append(_days_between(start, done[step]))

        out.append({
            "step": step,
            "reached": len(reached),
            "completed": len(completed),
            # The absolute numbers above stay next to this percentage on
            # purpose: a drop-off over a handful of organizations is an
            # anecdote, and the reader should be able to see that.
            "dropoff_pct": round((1 - len(completed) / len(reached)) * 100) if reached else None,
            "median_days": round(median(durations), 1) if durations else None,
            # Only while the claim still holds: one organization through the
            # step is enough to disprove "nobody can finish this".
            "blocked_reason": BLOCKED_STEPS.get(step) if not completed else None,
        })
        previous = step
    return out


def _summary(rows: list, orgs: list, completions: dict, steps: list) -> dict:
    """§3.3."""
    by_status = {k: 0 for k in ("not_started", "in_progress", "stuck", "finished")}
    for r in rows:
        by_status[r["status"]] += 1

    totals = [
        _days_between(o["created_at"], max(completions[o["id"]][s] for s in steps))
        for o in orgs
        if steps and all(s in completions.get(o["id"], {}) for s in steps)
    ]

    return {
        "organizations": len(orgs),
        "by_status": by_status,
        "median_total_days": round(median(totals), 1) if totals else None,
        # Indicator 12. Without it, 100% progress reads as a customer who
        # walked the whole journey rather than the part that is measured.
        "measured_steps": len(steps),
        "total_steps": len(ONBOARDING_STEPS),
    }


def handle_get_access(event: dict, db: Database) -> dict:
    """
    Whether this caller may open the analytics dashboard — and nothing else.

    The page needs the answer before it has any data: a menu entry that every
    customer can see but only Niagaros can open is a door with a sign on it.
    So it asks here first, and the answer comes from the same _may_view that
    guards the data, rather than from the browser working it out again.

    It deliberately returns a bare true or false. Saying *why* someone is
    refused would tell a customer's admin that an organization called
    Niagaros exists and that they are not in it, which is more than this
    endpoint needs to give away to decide whether to draw a menu item.
    """
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    return _response(200, {"may_view": _may_view(caller)})


def handle_get_onboarding_analytics(event: dict, db: Database) -> dict:
    caller = _get_caller(event, db)
    if not caller:
        return _response(401, {"error": "unauthorized"})
    if not _may_view(caller):
        return _response(403, {"error": "This dashboard is for Niagaros administrators."})

    with db.conn.cursor() as cur:
        cur.execute("SELECT NOW()")
        now = cur.fetchone()[0]

    steps = _measured_steps(db)
    orgs = _organizations(db)
    completions = _completions(db)

    rows = [_org_row(o, completions.get(o["id"], {}), steps, now) for o in orgs]
    # Stuck customers first: the table exists to be acted on, and the design
    # asks for it to be sorted by days without progress.
    rows.sort(key=lambda r: r["idle_days"], reverse=True)

    return _response(200, {
        "generated_at": now.isoformat(),
        "steps": steps,
        "funnel": _funnel(orgs, completions, steps),
        "summary": _summary(rows, orgs, completions, steps),
        "organizations": rows,
        "stuck_after_days": {s: STUCK_AFTER_DAYS.get(s, STUCK_AFTER_DAYS_DEFAULT) for s in steps},
    })


def lambda_handler(event, context):
    """
    Proposed route (payload format v2.0, same package and same manual deploy
    as team and auditor — see onboarding_lambda_deploy.md).

        GET /analytics/access     -> handle_get_access
        GET /analytics/onboarding -> handle_get_onboarding_analytics

    Two routes, one rule. The first says whether the door opens, the second
    is what is behind it; both ask _may_view, so the menu and the data can
    never disagree.

    Needs one environment variable the other two Lambdas do not:
    `NIAGAROS_ORGANIZATION_ID`. Without it every caller is refused.
    """
    method = event.get("requestContext", {}).get("http", {}).get("method", "")
    path = _route_path(event)

    db = None
    try:
        db = Database()
        if method == "GET" and path.rstrip("/") == "/analytics/access":
            return handle_get_access(event, db)
        if method == "GET" and path.rstrip("/") == "/analytics/onboarding":
            return handle_get_onboarding_analytics(event, db)
        return _response(404, {"error": f"no route for {method} {path}"})
    except Exception as e:
        # Same reasoning as team_handler: the detail goes to the log, never to
        # the caller, because a database error can carry column names.
        logger.error(f"analytics_handler: unhandled error — {e}", exc_info=True)
        return _response(500, {"error": "internal server error"})
    finally:
        if db:
            db.close()
