"""
local_analytics_server.py

⚠️ LOCAL DEV TOOL ONLY — NEVER DEPLOY THIS. It answers every request as if
the caller were a Niagaros administrator, and it serves made-up customers.

What this is for. The design document for the analytics dashboard (DV5) says
the real dataset is far too small to show whether the arithmetic is right:
"a drop-off over a handful of organizations is not a statistic but an anecdote
with a decimal point in it". So the page is checked against sample data that
is large and varied enough to be wrong in a visible way, and the numbers below
are chosen so that each one can be worked out by hand.

It runs the *real* calculation. _funnel, _org_row and _summary are imported
unchanged from api/analytics_handler.py — only the two database reads are
replaced by the table at the top of this file. What you see in the browser is
what the deployed handler would compute from the same rows.

Setup:
  1. .venv-test/Scripts/python.exe backend/scripts/local_analytics_server.py
     Leave it running in its own terminal.
  2. Point the frontend at it — in frontend/public/config.json set
     REACT_APP_API_BASE_URL to "http://localhost:8788".
  3. npm run dev, log in, open /analytics/onboarding.
  4. Afterwards: Ctrl+C, then
       git checkout -- frontend/public/config.json

What the sample data should produce, to check against the screen:

  Funnel          reached  completed  drop-off  median
  infrastructure    12          9        25%     2.0 days
  team               9          7        22%     1.0 day
  auditor            7          5        29%     2.0 days
  workspace          5          3        40%     1.0 day
  compliance         3          3         0%     1.0 day
  governance         3          2        33%     1.0 day
  training           2          1        50%     1.0 day

  Summary: 1 not started, 4 in progress, 6 stuck, 1 finished;
           median total time 9.0 days; 7 of 7 steps measured.

Two rows are worth reading closely.

Compliance shows nought per cent drop-off — out of three. Everyone who
connected a workspace also picked a framework. That is exactly the reading
the design warns about: a clean percentage resting on three customers is not
evidence that a step is easy, which is why the page keeps the absolute
numbers beside it at the same weight.

Team shows a median of one day while the mean would be fifteen. One customer
signed up, connected AWS, and came back three months later to invite a
colleague. The mean makes every other customer look slow; the median does not
notice.

Two differences from production. Steps 5 to 7 only hold numbers here because
governance_handler now records their completions — before that they had no
moment to put on a funnel, and the design measured four steps for that
reason. And step 4 is finished by three sample customers, which on production
nobody can do: there is no Jira or Monday account to connect to, so that row
reads a 100% drop-off there with the reason printed beside it.
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))

from api.analytics_handler import (  # noqa: E402
    ONBOARDING_STEPS, STUCK_AFTER_DAYS, STUCK_AFTER_DAYS_DEFAULT,
    _funnel, _org_row, _summary,
)

PORT = 8788
NOW = datetime.now(timezone.utc)

# All seven. Until the change to governance_handler only the first four
# recorded a completion, and the design fixed the denominator at four for
# exactly that reason — while saying it should widen by itself once the other
# three began recording. They do now, so there is no reason to measure a
# shorter journey than the customer actually walks.
STEPS = list(ONBOARDING_STEPS)


def ago(days: float) -> datetime:
    return NOW - timedelta(days=days)


# (name, days since signup, {step: days since that step was completed})
#
# Each row is a case the page has to get right:
SAMPLE = [
    # ── never got off the ground ──
    # Signed up today, nothing done. Too recent to be stuck.
    ("Vandaag BV", 0.5, {}),
    # A week in, still nothing. Past R3's three days.
    ("Stille Start NV", 7, {}),
    # Months in, still nothing.
    ("Nooit Begonnen BV", 90, {}),

    # ── stopped at the team step ──
    # Connected AWS, invited nobody, went quiet. Past R8's seven days.
    ("Eenpitter BV", 40, {"infrastructure": 30}),
    # The same shape but only five days idle, so inside R8.
    ("Net Op Tijd BV", 9, {"infrastructure": 5}),

    # ── stopped at the auditor step ──
    # The outlier: came back after three months to invite a colleague. This is
    # the row that would drag a mean and leaves a median alone.
    ("Lange Adem NV", 120, {"infrastructure": 118, "team": 20}),
    ("Halverwege BV", 30, {"infrastructure": 28, "team": 26}),

    # ── stopped at the workspace step ──
    ("Vlot Vooruit BV", 6, {"infrastructure": 4, "team": 3, "auditor": 1}),
    ("Bijna Klaar BV", 20, {"infrastructure": 18, "team": 17, "auditor": 12}),

    # ── into steps 5 to 7 ──
    # Nothing below this line could exist before governance_handler began
    # recording completions: compliance, governance and training had no moment
    # to put on a funnel, which is why the design measured four steps.
    ("Beleid Rond NV", 18, {"infrastructure": 17, "team": 16, "auditor": 15,
                            "workspace": 14, "compliance": 13}),
    ("Doorgepakt BV", 25, {"infrastructure": 24, "team": 23, "auditor": 22,
                           "workspace": 21, "compliance": 20, "governance": 19}),
    ("Helemaal Rond BV", 30, {"infrastructure": 28, "team": 27, "auditor": 25,
                              "workspace": 24, "compliance": 23, "governance": 22,
                              "training": 21}),
]

ORGS = [
    {"id": f"org-{i}", "name": name, "created_at": ago(signed_up)}
    for i, (name, signed_up, _) in enumerate(SAMPLE)
]
COMPLETIONS = {
    f"org-{i}": {step: ago(d) for step, d in done.items()}
    for i, (_, _, done) in enumerate(SAMPLE)
}


def payload() -> dict:
    rows = [_org_row(o, COMPLETIONS[o["id"]], STEPS, NOW) for o in ORGS]
    rows.sort(key=lambda r: r["idle_days"], reverse=True)
    return {
        "generated_at": NOW.isoformat(),
        "steps": STEPS,
        "funnel": _funnel(ORGS, COMPLETIONS, STEPS),
        "summary": _summary(rows, ORGS, COMPLETIONS, STEPS),
        "organizations": rows,
        "stuck_after_days": {s: STUCK_AFTER_DAYS.get(s, STUCK_AFTER_DAYS_DEFAULT) for s in STEPS},
    }


class Handler(BaseHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0].rstrip("/")
        if path == "/analytics/access":
            # Always yes here. The real rule is admin plus membership of
            # Niagaros, and this server has neither a user table nor an
            # organization to check it against.
            self.send_response(200)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"may_view": true}')
            return
        if path != "/analytics/onboarding":
            self.send_response(404)
            self._cors()
            self.end_headers()
            self.wfile.write(b'{"error":"no route"}')
            return
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload()).encode())

    def log_message(self, fmt, *args):
        print("  " + fmt % args)


if __name__ == "__main__":
    # Not print(__doc__): the Windows console is cp1252 and the warning sign
    # at the top of this file cannot be encoded in it.
    print("LOCAL DEV TOOL — sample data, no database, every caller is an admin.")
    print(f"Serving sample analytics on http://localhost:{PORT}/analytics/onboarding")
    print(f"Total steps in the wizard: {len(ONBOARDING_STEPS)}; measured in this sample: {len(STEPS)}\n")
    for f in payload()["funnel"]:
        print(f"  {f['step']:<16} reached {f['reached']}  completed {f['completed']}  "
              f"drop-off {f['dropoff_pct']}%  median {f['median_days']}")
    print("  summary:", payload()["summary"]["by_status"], "\n")
    ThreadingHTTPServer(("localhost", PORT), Handler).serve_forever()
