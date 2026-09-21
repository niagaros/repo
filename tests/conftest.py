"""
Shared pytest plumbing for the Niagaros critical-flow test framework (issue #279).

Every test is tagged with a critical-flow id (`flow`) and a severity (`severity`,
P0..P4) via pytestmark. This file turns each run into a machine-readable
`tests/reports/latest.json` containing, per test: flow, severity, outcome, duration,
the failed step, the last HTTP request/response, and the failure message — so a
failing test explains itself. `tests/tools/build_report.py` joins that with the
flow registry to compute real coverage.
"""
import json
import os
import subprocess
import sys
import time
import types
from contextlib import contextmanager
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = Path(os.environ.get("E2E_REPORT_PATH") or ROOT / "tests" / "reports" / "latest.json")

API_BASE = os.environ.get("E2E_API_BASE", "https://hzf92ft6j7.execute-api.eu-west-1.amazonaws.com/default")
SITE_BASE = os.environ.get("E2E_SITE_BASE", "https://sofyan-dev.d3joqokkaynfaq.amplifyapp.com")
# Two dedicated test tenants, each owned by its own dedicated Cognito test user (created through the real
# onboarding endpoint). Every write is refused for any account a client does not own, so a test can never
# modify a real customer's data. Domits (a real customer account) is only ever probed read-only / expect-denied.
ACCOUNT_ID = os.environ.get("E2E_ACCOUNT_ID", "1449717e-0e03-4cf7-b832-9c95ba69d821")      # tenant A
ACCOUNT_B_ID = os.environ.get("E2E_ACCOUNT_B_ID", "3e36a28a-e6c5-4a83-b00e-14f145d5ffbe")   # tenant B
REAL_CUSTOMER_ACCOUNT_ID = "cbb94e43-4e42-4fac-997e-8f931131bde7"                             # Domits: never written to
COGNITO_CLIENT_ID = os.environ.get("E2E_CLIENT_ID", "6vp0qrku3dkvia5qsf4cj199lj")           # dedicated test app client
USER_A = os.environ.get("E2E_USERNAME", "e2e-tests@niagaros.test")
USER_B = os.environ.get("E2E_USERNAME_B", "e2e-tests-b@niagaros.test")


def _login(username, password):
    """Real Cognito sign-in (USER_PASSWORD_AUTH on the dedicated test client); '' when no credentials are configured."""
    if not password:
        return ""
    r = requests.post("https://cognito-idp.eu-west-1.amazonaws.com/", timeout=30,
                      headers={"X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth", "Content-Type": "application/x-amz-json-1.1"},
                      data=json.dumps({"AuthFlow": "USER_PASSWORD_AUTH", "ClientId": COGNITO_CLIENT_ID,
                                       "AuthParameters": {"USERNAME": username, "PASSWORD": password}}))
    if r.status_code != 200:
        raise RuntimeError(f"test-user login failed for {username}: {r.status_code} {r.text[:120]}")
    return r.json()["AuthenticationResult"]["AccessToken"]


TOKEN = os.environ.get("E2E_TOKEN", "").strip() or _login(USER_A, os.environ.get("E2E_PASSWORD", ""))
TOKEN_B = _login(USER_B, os.environ.get("E2E_PASSWORD_B", ""))
ALLOWED_WRITE_ACCOUNTS = {ACCOUNT_ID}
TEST_PREFIX = "[E2E]"

sys.path.insert(0, str(ROOT / "backend" / "src"))


def pytest_configure(config):
    config.addinivalue_line("markers", "flow(id): critical-flow id from tests/registry/critical_flows.json")
    config.addinivalue_line("markers", "severity(level): P0 (deploy-blocking) .. P4")
    config.addinivalue_line("markers", "live: talks to the deployed environment")
    config.addinivalue_line("markers", "needs_two_tenants: requires both dedicated test users A and B")
    config.addinivalue_line("markers", "needs_token: requires E2E_TOKEN (skipped and reported as blocked otherwise)")
    config.addinivalue_line("markers", "known_failure(issue, reason): a real, tracked defect; strict-xfail so a fix is noticed")
    config._e2e_results = []
    config._e2e_started = time.time()


def pytest_collection_modifyitems(config, items):
    for item in items:
        kf = item.get_closest_marker("known_failure")
        if kf:
            item.add_marker(pytest.mark.xfail(strict=True, reason=f"{kf.kwargs.get('issue', '')}: {kf.kwargs.get('reason', '')}"))
        if item.get_closest_marker("needs_token") and not TOKEN:
            item.add_marker(pytest.mark.skip(reason="blocked: no test-user credentials (set E2E_PASSWORD, or E2E_TOKEN)"))
        if item.get_closest_marker("needs_two_tenants") and not (TOKEN and TOKEN_B):
            item.add_marker(pytest.mark.skip(reason="blocked: needs both test users (set E2E_PASSWORD and E2E_PASSWORD_B)"))


# ── Diagnostics captured per test ───────────────────────────────────────
class _Trace:
    def __init__(self):
        self.exchanges = []
        self.steps = []
        self.failed_step = None

    def reset(self):
        self.__init__()


TRACE = _Trace()


@pytest.fixture(autouse=True)
def _trace_reset():
    TRACE.reset()
    yield


@pytest.fixture
def step():
    """with step("name"): ... — records which step of a multi-step flow failed."""
    @contextmanager
    def _step(name):
        TRACE.steps.append(name)
        try:
            yield
        except BaseException:
            TRACE.failed_step = name
            raise
    return _step


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "setup" and not rep.skipped and not rep.failed:
        return
    if rep.when == "teardown" and not rep.failed:
        return
    flow = item.get_closest_marker("flow")
    sev = item.get_closest_marker("severity")
    if rep.skipped and hasattr(rep, "wasxfail"):
        status = "known_failure"
    elif rep.skipped:
        reason = str(rep.longrepr[2]) if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
        status = "blocked" if "blocked:" in reason else "skipped"
    elif hasattr(rep, "wasxfail"):
        status = "known_failure" if rep.outcome == "skipped" else "passed"
    else:
        status = "passed" if rep.passed else "failed"
    message = ""
    if rep.failed:
        message = str(rep.longrepr)[-1800:]
    elif rep.skipped:
        message = str(rep.longrepr[2]) if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
    last = TRACE.exchanges[-1] if TRACE.exchanges else None
    item.config._e2e_results.append({
        "test_id": item.nodeid,
        "name": item.name,
        "flow": flow.args[0] if flow else None,
        "severity": sev.args[0] if sev else "P3",
        "layer": item.nodeid.split("/")[1] if "/" in item.nodeid else "unit",
        "status": status,
        "duration_s": round(rep.duration, 3),
        "failed_step": TRACE.failed_step,
        "message": message,
        "last_exchange": last,
    })


def _git(*args):
    try:
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None


def pytest_sessionfinish(session, exitstatus):
    cfg = session.config
    if not getattr(cfg, "_e2e_results", None):
        return
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps({
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(time.time() - cfg._e2e_started, 1),
        "commit": os.environ.get("GITHUB_SHA") or _git("rev-parse", "--short=7", "HEAD"),
        "branch": os.environ.get("GITHUB_REF_NAME") or _git("rev-parse", "--abbrev-ref", "HEAD"),
        "trigger": "ci" if os.environ.get("CI") else "local",
        "environment": {"api": API_BASE, "site": SITE_BASE, "account": ACCOUNT_ID, "token_provided": bool(TOKEN), "two_tenants": bool(TOKEN and TOKEN_B)},
        "results": cfg._e2e_results,
    }, indent=2), encoding="utf-8")


# ── HTTP client: records every exchange, refuses cross-tenant writes ────
class Api:
    def __init__(self, token="", allowed=None):
        self.s = requests.Session()
        self.token = token
        self.allowed = set(allowed if allowed is not None else ALLOWED_WRITE_ACCOUNTS)

    def _do(self, method, path, params=None, body=None, headers=None, raw_body=None, timeout=45, allow_foreign=False):
        h = dict(headers or {})
        if self.token and "Authorization" not in h:
            h["Authorization"] = f"Bearer {self.token}"
        if allow_foreign and REAL_CUSTOMER_ACCOUNT_ID in json.dumps(body or {}) and body and body.get("action") not in ("create_vendor", "create_audit"):
            raise AssertionError("safety guard: probes against the real customer account may only use validation-failing create actions")
        if body is not None:
            acct = body.get("cloud_account_id") if isinstance(body, dict) else None
            if acct and acct not in self.allowed and not allow_foreign:
                raise AssertionError(f"safety guard: refusing to write to non-test account {acct}")
        data = raw_body if raw_body is not None else (json.dumps(body) if body is not None else None)
        url = f"{API_BASE}/{path.lstrip('/')}"
        r = self.s.request(method, url, params=params, data=data, headers=h, timeout=timeout)
        try:
            payload = r.json()
        except ValueError:
            payload = None
        redacted = {k: ("Bearer ***" if k.lower() == "authorization" else v) for k, v in h.items()}
        TRACE.exchanges.append({
            "request": {"method": method, "url": r.request.url, "headers": redacted,
                        "body": (data[:600] if isinstance(data, str) else None)},
            "response": {"status": r.status_code, "body": r.text[:600]},
        })
        return r.status_code, payload, r

    def get(self, path, **kw):
        return self._do("GET", path, **kw)

    def post(self, path, body=None, **kw):
        return self._do("POST", path, body=body, **kw)

    def delete(self, path, **kw):
        return self._do("DELETE", path, **kw)

    def options(self, path, **kw):
        return self._do("OPTIONS", path, **kw)


@pytest.fixture(scope="session")
def api():
    """Signed in as test user A (owner of tenant A)."""
    return Api(TOKEN)


@pytest.fixture(scope="session")
def api_b():
    """Signed in as test user B (owner of tenant B) — the 'other tenant' for isolation tests."""
    return Api(TOKEN_B, allowed={ACCOUNT_B_ID})


@pytest.fixture(scope="session")
def anon():
    """A client that never sends credentials — for authentication/authorization tests."""
    return Api("")


@pytest.fixture
def account_id():
    return ACCOUNT_ID


@pytest.fixture
def cleanup():
    """Register cleanup callables; they always run, even if the test fails midway."""
    fns = []
    yield fns.append
    for fn in reversed(fns):
        try:
            fn()
        except Exception as e:  # cleanup must never mask the real failure
            print(f"[cleanup] {e}")


# ── Handler-import support for unit tests (no DB, no AWS) ───────────────
def _install_psycopg2_stub():
    """Unit tests never touch a database. The repo root ships a vendored psycopg2 for the
    Lambda zip that can shadow the real one, so a stub keeps handler imports deterministic."""
    stub = types.ModuleType("psycopg2")
    stub._e2e_stub = True
    stub.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no database in unit tests"))
    extras = types.ModuleType("psycopg2.extras")
    extras.Json = lambda x: x
    extras.RealDictCursor = object
    stub.extras = extras
    sys.modules["psycopg2"] = stub
    sys.modules["psycopg2.extras"] = extras


_install_psycopg2_stub()


# ── UI layer: real frontend files + real Chromium ───────────────────────
import functools
import http.server
import threading

PUBLIC_DIR = ROOT / "frontend" / "public"


@pytest.fixture(scope="session")
def site():
    """Serves the real frontend files (frontend/public) on a random local port."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(PUBLIC_DIR))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture(scope="session")
def browser():
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def page(browser):
    ctx = browser.new_context()
    ctx.route("**/fonts.googleapis.com/**", lambda r: r.abort())
    ctx.route("**/fonts.gstatic.com/**", lambda r: r.abort())
    pg = ctx.new_page()
    pg.errors = []
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.dialogs = []

    def on_dialog(d):
        pg.dialogs.append((d.type, d.message))
        d.dismiss()

    pg.on("dialog", on_dialog)
    yield pg
    ctx.close()
