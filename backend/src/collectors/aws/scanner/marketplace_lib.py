"""
marketplace_lib.py
Niagaros Marketplace (issue #90): the integration catalog, the connection state and health of the integrations
Niagaros really has, and recommendations built from an account's own data.

Shared by marketplace_handler (the page's API) and ai_agent_handler (so the AI Agent can recommend integrations from
the same facts the page shows).

Honesty rules, the same as the rest of the product:
  * The catalog (marketplace_catalog.csv, 340 entries researched in issue #90) says per entry whether Niagaros can
    connect it today ("Available"), whether it is being built ("Planned") or whether it can only be requested
    ("On request"). Nothing that is not built is offered as connectable.
  * Detail fields such as permissions, authentication and supported frameworks are only filled in for integrations
    that exist, from the real code; for the rest they are left empty instead of guessed.
  * Health, install counts, request counts and ratings come from the database. Ratings are only shown once there are
    at least MIN_RATINGS of them, so a single score is not presented as a verdict.
"""
import csv
import os
import re
from datetime import datetime, timezone

# Kept identical to MAPPED_FRAMEWORK_NAMES in config/database.py (checked by tests/unit/test_marketplace_catalog.py),
# as critical_issues_handler and ai_agent_handler do: a copy keeps this module free of the database package, so the
# catalog loads anywhere. These per-framework copies of findings are excluded from counts.
MAPPED_FRAMEWORK_NAMES = (
    'ISO 27001:2022', 'NIST CSF v2.0', 'GDPR', 'SOC2', 'PCI DSS v4.0', 'NIS2', 'HIPAA',
    'NIST 800-53 Rev 5', 'BSI-C5', 'CSA CCM 4.0', 'FedRAMP Moderate Rev 4', 'ISO 42001',
    'ISO 27017', 'AWS FTR', 'MVSP', 'TISAX', 'HITRUST CSF', 'DORA', 'CRI Profile',
    'EU AI Act', 'NIST AI RMF', 'ISO 27701', 'ISO 27018', 'Microsoft SSPA',
    'CIS Controls v8.1', '23 NYCRR 500 (NYDFS)', 'NIST Privacy Framework',
)

CATALOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "marketplace_catalog.csv")
STATUSES = ("Available", "Planned", "On request")
MIN_RATINGS = 3
STALE_DAYS = 10            # same rule as the dashboard: weekly scan + slack
HEALTH_WINDOW_DAYS = 7     # delivery health of the alert channels


def slugify(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


# Real metadata of the integrations that exist. Every statement here can be checked in the code it names.
FIRST_PARTY = {
    "amazon-web-services": {
        "connection": "aws",
        "auth_method": "IAM role (cross-account, with an external ID)",
        "auth_methods": ["IAM roles"],
        "deployment": "Agentless (read-only API calls from Niagaros)",
        "permissions": ["IAM role CSPMScannerRole in your account, assumed by Niagaros with an external ID",
                        "AWS managed policies SecurityAudit and ReadOnlyAccess (read-only, no write access)"],
        "data_types": ["Resource configuration", "IAM and identity data", "Security findings", "Cost data (opt-in)"],
        "frameworks": ["AWS Foundational Security Best Practices", "CIS AWS Foundations"] + list(MAPPED_FRAMEWORK_NAMES),
        "environments": ["AWS commercial regions"],
        "setup": {"page": "/settings/infrastructure", "label": "Open the AWS connection wizard", "validates": True,
                  "steps": ["Download the CloudFormation template (it creates the read-only role)",
                            "Deploy it in your AWS account", "Paste the role ARN back into Niagaros",
                            "Niagaros validates the role and starts the first scan"]},
        "security": ["Read-only: the role has no permission to change your resources",
                     "The external ID stops other Niagaros customers from using your role",
                     "Revoke access at any time by deleting the CloudFormation stack"],
        "revoke": "Delete the CloudFormation stack (or the role) in your AWS account, then remove the account in Settings.",
        "sync": "Weekly scheduled scan plus scans you start yourself",
        "code": "backend/src/collectors/aws, frontend/src/settings/shared/AwsConnectWizard.tsx",
        "last_updated": "2026-10-27",
    },
    "github": {
        "connection": "github",
        "auth_method": "OAuth (GitHub OAuth app)",
        "auth_methods": ["OAuth"],
        "deployment": "Agentless (GitHub API calls from Niagaros)",
        "permissions": ["OAuth scopes read:org and repo (GitHub has no read-only variant of repo for OAuth apps; "
                        "Niagaros only reads)"],
        "data_types": ["Repositories", "Branch protection", "Organization members and MFA", "Secret scanning and Dependabot alerts"],
        "frameworks": ["CIS GitHub Benchmark v1.0.0"],
        "environments": ["github.com organizations"],
        "setup": {"page": "/settings/github", "label": "Connect GitHub", "validates": True,
                  "steps": ["Sign in with GitHub and approve the requested scopes",
                            "Grant access to your organization on the GitHub screen",
                            "Niagaros stores the token in AWS Secrets Manager and scans on the next scan run"]},
        "security": ["The token is stored in AWS Secrets Manager, never in the database",
                     "Revoke the OAuth app in GitHub at any time"],
        "revoke": "Disconnect in Settings > GitHub and revoke the Niagaros OAuth app in your GitHub settings.",
        "sync": "With every scan run",
        "code": "backend/src/collectors/github, frontend/src/settings/GitHub.tsx",
        "last_updated": "2026-10-22",
    },
    "jira": {
        "connection": "workspace", "provider": "jira",
        "auth_method": "API key (Atlassian API token with the account e-mail)",
        "auth_methods": ["API keys"],
        "deployment": "Agentless (Jira Cloud REST API)",
        "permissions": ["An Atlassian API token of a user who may create issues in the chosen project",
                        "Only https://<name>.atlassian.net sites are accepted"],
        "data_types": ["Issues created from findings", "Issue status"],
        "frameworks": [],
        "environments": ["Jira Cloud"],
        "setup": {"page": "integrations.html", "label": "Connect Jira", "validates": True,
                  "steps": ["Enter the site, e-mail and API token", "Niagaros checks the token with Jira before saving it",
                            "Choose the project tickets go to", "Create a ticket from a finding, then synchronize status"]},
        "security": ["The token is checked first and then stored in AWS Secrets Manager, never in the database",
                     "A token Jira stops accepting is marked 'needs re-authorization' and the admins are notified",
                     "Disconnecting deletes the stored token"],
        "revoke": "Disconnect on the Integrations page (deletes the stored token) and revoke the token at Atlassian.",
        "sync": "When you press Synchronize; finished tickets close the finding",
        "code": "backend/src/collectors/aws/scanner/integrations_handler.py",
        "last_updated": "2026-10-27",
    },
    "monday-com": {
        "connection": "workspace", "provider": "monday",
        "auth_method": "API key (monday.com personal API token)",
        "auth_methods": ["API keys"],
        "deployment": "Agentless (monday.com GraphQL API)",
        "permissions": ["A monday.com API token of a user who may create items on the chosen board"],
        "data_types": ["Items created from findings", "Item status"],
        "frameworks": [],
        "environments": ["monday.com"],
        "setup": {"page": "integrations.html", "label": "Connect Monday.com", "validates": True,
                  "steps": ["Enter the API token", "Niagaros checks the token with monday.com before saving it",
                            "Choose the board items go to", "Create an item from a finding, then synchronize status"]},
        "security": ["The token is checked first and then stored in AWS Secrets Manager, never in the database",
                     "A token monday.com stops accepting is marked 'needs re-authorization' and the admins are notified",
                     "Disconnecting deletes the stored token"],
        "revoke": "Disconnect on the Integrations page (deletes the stored token) and regenerate the token in monday.com.",
        "sync": "When you press Synchronize; finished items close the finding",
        "code": "backend/src/collectors/aws/scanner/integrations_handler.py",
        "last_updated": "2026-10-27",
    },
}
for _slug, _label, _col in (("slack", "Slack", "slack"), ("microsoft-teams", "Microsoft Teams", "teams"),
                            ("discord", "Discord", "discord"), ("custom-webhook", "your endpoint", "webhook")):
    FIRST_PARTY[_slug] = {
        "connection": "channel", "channel": _col,
        "auth_method": "Webhook (a URL you create in " + _label + ")" if _col != "webhook" else "Webhook (a URL you choose)",
        "auth_methods": ["Webhooks"],
        "deployment": "Outbound only (Niagaros sends, never reads)",
        "permissions": ["None in your workspace: Niagaros only posts messages to the webhook URL you give it"],
        "data_types": ["Notifications (alerts) sent by Niagaros"],
        "frameworks": [],
        "environments": [_label if _col != "webhook" else "Any endpoint reachable over the internet"],
        "setup": {"page": "notification_settings.html", "label": "Set up in Notification Settings", "validates": False,
                  "steps": ["Create an incoming webhook in " + _label if _col != "webhook" else "Prepare an endpoint that accepts JSON POSTs",
                            "Paste the URL in Notification Settings", "Send a test message",
                            "Choose which alert domains go to this channel"]},
        "security": ["Private and internal network addresses are refused (no requests into internal networks)",
                     "Remove the URL in Notification Settings to stop all delivery"],
        "revoke": "Remove the URL in Notification Settings and delete the webhook in " + _label + ".",
        "sync": "Each alert is delivered when it happens; failures are retried and recorded",
        "code": "backend/src/collectors/aws/scanner/notification_lib.py",
        "last_updated": "2026-10-01",
    }


def load_catalog(path=CATALOG_FILE):
    """All catalog entries, each with a stable slug. First-party entries carry their real metadata."""
    out, seen = [], set()
    with open(path, encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            slug = slugify(row["name"])
            if slug in seen:
                raise ValueError(f"duplicate catalog entry {row['name']}")
            seen.add(slug)
            status = row["status"].strip()
            if status not in STATUSES:
                raise ValueError(f"{row['name']}: unknown status {status}")
            entry = {"slug": slug, "name": row["name"].strip(), "vendor": row["vendor"].strip(),
                     "category": row["category"].strip(), "delivers": row["delivers"].strip(),
                     "objects": [o.strip() for o in row["niagaros_objects"].split("|") if o.strip()],
                     "status": status, "maintained_by": None, "certification": None, "detail": None}
            meta = FIRST_PARTY.get(slug)
            if status == "Available":
                if not meta:
                    raise ValueError(f"{row['name']} is marked Available but Niagaros has no connector for it")
                entry.update(maintained_by="Niagaros",
                             certification="Built and reviewed by Niagaros (first-party)",
                             detail={k: v for k, v in meta.items() if k not in ("connection", "provider", "channel")})
            out.append(entry)
    missing = set(FIRST_PARTY) - {e["slug"] for e in out if e["status"] == "Available"}
    if missing:
        raise ValueError(f"connectors without an Available catalog entry: {sorted(missing)}")
    return out


_CATALOG = None


def catalog():
    global _CATALOG
    if _CATALOG is None:
        _CATALOG = load_catalog()
    return _CATALOG


def by_slug():
    return {e["slug"]: e for e in catalog()}


# ── connection state and health ─────────────────────────────────────────

def _age_days(ts, now):
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (now - ts).total_seconds() / 86400


def _has_column(cur, table, column):
    cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name = %s AND column_name = %s", (table, column))
    return cur.fetchone() is not None


def _has_table(cur, table):
    cur.execute("SELECT to_regclass(%s)", (table,))
    return cur.fetchone()[0] is not None


def connections(cur, account_id, now=None):
    """{slug: state} for every first-party integration of this account. state["connected"] is False when it is
    not set up. Health levels: ok, stale, failing, needs_reauth, waiting (connected but no data yet)."""
    now = now or datetime.now(timezone.utc)
    out = {}

    # cloud_accounts.last_scan_at is also bumped by the GitHub collector, so AWS freshness is read from the AWS
    # resources themselves: a recent GitHub scan must not make a stopped AWS scan look healthy.
    cur.execute("""SELECT c.status,
                          (SELECT max(r.last_scanned_at) FROM resources r
                           WHERE r.cloud_account_id = c.id AND COALESCE(r.resource_type, '') NOT ILIKE 'github%%')
                   FROM cloud_accounts c WHERE c.id = %s""", (account_id,))
    row = cur.fetchone()
    if row:
        status, last = row
        age = _age_days(last, now)
        if status and status != "active":
            health, why = "failing", f"Account status is '{status}'"
        elif last is None:
            health, why = "waiting", "Connected; the first scan has not finished yet"
        elif age > STALE_DAYS:
            health, why = "stale", f"Last scan {int(age)} days ago (expected at least every {STALE_DAYS} days)"
        else:
            health, why = "ok", "Scanned within the expected interval"
        out["amazon-web-services"] = {"connected": True, "health": health, "health_reason": why,
                                      "last_sync": last, "items": 1}

    if _has_table(cur, "github_integrations"):
        cur.execute("SELECT org_name, created_at FROM github_integrations WHERE cloud_account_id = %s", (account_id,))
        gh = cur.fetchone()
        if gh:
            # Only data scanned since this connection was made: results of an earlier, disconnected organization
            # are kept by design and must not make a new connection look current before its first scan.
            cur.execute("""SELECT max(last_scanned_at) FROM resources
                           WHERE cloud_account_id = %s AND resource_type ILIKE 'github%%' AND last_scanned_at >= %s""",
                        (account_id, gh[1]))
            last = cur.fetchone()[0]
            age = _age_days(last, now)
            if last is None:
                health, why = "waiting", "Connected; no GitHub data has been scanned yet"
            elif age > STALE_DAYS:
                health, why = "stale", f"Last GitHub data {int(age)} days old"
            else:
                health, why = "ok", "GitHub data is current"
            out["github"] = {"connected": True, "health": health, "health_reason": why, "last_sync": last,
                             "label": gh[0], "items": 1}

    if _has_table(cur, "workspace_integrations"):
        cols = "status, credential_error, last_sync_at" if _has_column(cur, "workspace_integrations", "credential_error") \
            else "'active', NULL, NULL"
        cur.execute(f"SELECT provider, {cols} FROM workspace_integrations WHERE cloud_account_id = %s", (account_id,))
        per = {}
        for provider, status, err, last in cur.fetchall():
            per.setdefault(provider, []).append((status, err, last))
        for provider, slug in (("jira", "jira"), ("monday", "monday-com")):
            items = per.get(provider)
            if not items:
                continue
            bad = [i for i in items if i[0] == "needs_reauth"]
            last = max((i[2] for i in items if i[2]), default=None)
            if bad:
                health, why = "needs_reauth", f"The provider no longer accepts the token: {bad[0][1] or 'rejected'}"
            elif last is None:
                health, why = "waiting", "Connected; not synchronized yet"
            else:
                health, why = "ok", "Token accepted on the last call"
            out[slug] = {"connected": True, "health": health, "health_reason": why, "last_sync": last, "items": len(items)}

    out.update(_channel_states(cur, account_id, now))
    return out


CHANNELS = (("slack", "slack", "slack_webhook_url"), ("microsoft-teams", "teams", "teams_webhook_url"),
            ("discord", "discord", "discord_webhook_url"), ("custom-webhook", "webhook", "webhook_url"))


def _channel_states(cur, account_id, now):
    """Health of the alert channels, from notification_delivery_attempts (one row per real delivery attempt,
    retries included, with its own time), limited to the destinations that are configured now: the account's
    default channel and every named recipient that still has this channel set."""
    out = {}
    has_attempts = _has_table(cur, "notification_delivery_attempts")
    for slug, delivery_key, col in CHANNELS:
        default_on, recipients = False, []
        if _has_table(cur, "notification_channels") and _has_column(cur, "notification_channels", col):
            cur.execute(f"SELECT 1 FROM notification_channels WHERE cloud_account_id = %s AND COALESCE({col}, '') <> ''", (account_id,))
            default_on = cur.fetchone() is not None
        if _has_table(cur, "notification_recipients") and _has_column(cur, "notification_recipients", col):
            cur.execute(f"SELECT id::text FROM notification_recipients WHERE cloud_account_id = %s AND COALESCE({col}, '') <> ''", (account_id,))
            recipients = [r[0] for r in cur.fetchall()]
        n = int(default_on) + len(recipients)
        if not n:
            continue
        attempts = failures = failing_targets = 0
        last_ok = reason = None
        if has_attempts:
            cur.execute("""WITH d AS (
                             SELECT a.created_at, COALESCE(a.recipient_id::text, 'default') AS target, a.sent, a.reason
                             FROM notification_delivery_attempts a JOIN notifications n ON n.id = a.notification_id
                             WHERE n.cloud_account_id = %(a)s AND a.channel = %(k)s
                               AND ((a.recipient_id IS NULL AND %(def)s) OR a.recipient_id::text = ANY(%(rec)s))),
                           latest AS (SELECT DISTINCT ON (target) target, sent, reason FROM d ORDER BY target, created_at DESC)
                           SELECT (SELECT count(*) FROM d WHERE created_at > now() - make_interval(days => %(w)s)),
                                  (SELECT count(*) FROM d WHERE created_at > now() - make_interval(days => %(w)s) AND NOT sent),
                                  (SELECT max(created_at) FROM d WHERE sent),
                                  (SELECT count(*) FROM latest WHERE NOT sent),
                                  (SELECT reason FROM latest WHERE NOT sent LIMIT 1)""",
                        {"k": delivery_key, "a": account_id, "w": HEALTH_WINDOW_DAYS, "def": default_on, "rec": recipients})
            attempts, failures, last_ok, failing_targets, reason = cur.fetchone()
        if failing_targets:
            who = "" if failing_targets == 1 else f" for {failing_targets} destinations"
            health, why = "failing", f"The last delivery failed{who}: {reason or 'no reason given'}"
        elif not attempts:
            health, why = "waiting", f"Configured; nothing was sent in the last {HEALTH_WINDOW_DAYS} days"
        else:
            health, why = "ok", f"{attempts - failures} of {attempts} deliveries succeeded in the last {HEALTH_WINDOW_DAYS} days"
        out[slug] = {"connected": True, "health": health, "health_reason": why, "last_sync": last_ok, "items": n,
                     "attempts": attempts, "failures": failures}
    return out


def install_counts(cur):
    """How many accounts use each first-party integration (aggregate across all tenants, numbers only)."""
    counts = {slug: 0 for slug in FIRST_PARTY}
    cur.execute("SELECT count(*) FROM cloud_accounts WHERE COALESCE(status, 'active') = 'active'")
    counts["amazon-web-services"] = cur.fetchone()[0]
    if _has_table(cur, "github_integrations"):
        cur.execute("SELECT count(DISTINCT cloud_account_id) FROM github_integrations")
        counts["github"] = cur.fetchone()[0]
    if _has_table(cur, "workspace_integrations"):
        cur.execute("SELECT provider, count(DISTINCT cloud_account_id) FROM workspace_integrations GROUP BY provider")
        for provider, n in cur.fetchall():
            counts[{"jira": "jira", "monday": "monday-com"}.get(provider, provider)] = n
    for slug, _, col in CHANNELS:
        ids = []
        for table in ("notification_channels", "notification_recipients"):
            if _has_table(cur, table) and _has_column(cur, table, col):
                ids.append(f"SELECT cloud_account_id FROM {table} WHERE COALESCE({col}, '') <> ''")
        if ids:
            cur.execute(f"SELECT count(DISTINCT cloud_account_id) FROM ({' UNION '.join(ids)}) x")
            counts[slug] = cur.fetchone()[0]
    return counts


# ── recommendations ─────────────────────────────────────────────────────

def _checks(n):
    return f"{n} open critical/high check" + (" is" if n == 1 else "s are")


IDENTITY_WORDS = r"(mfa|multi-factor|password|access key|root user|credential|iam user|privileged|access review)"


def recommendations(cur, account_id, conn_state=None):
    """Integrations worth connecting for this account, each with the real numbers behind the advice."""
    state = conn_state if conn_state is not None else connections(cur, account_id)
    cat = by_slug()
    recs = []

    cur.execute("""SELECT count(DISTINCT f.check_id),
                          count(DISTINCT f.check_id) FILTER (WHERE f.title ~* %s)
                   FROM findings f JOIN resources r ON r.id = f.resource_id
                   WHERE r.cloud_account_id = %s AND f.status = 'open' AND upper(f.severity) IN ('CRITICAL', 'HIGH')
                     AND (f.framework IS NULL OR f.framework <> ALL(%s))""",
                (IDENTITY_WORDS, account_id, list(MAPPED_FRAMEWORK_NAMES)))
    open_checks, identity_checks = cur.fetchone()

    if open_checks and "jira" not in state and "monday-com" not in state:
        recs.append({"slug": "jira", "alternatives": ["monday-com"], "priority": 1,
                     "reason": f"{_checks(open_checks)} not tracked in a ticketing tool, so remediation does not "
                               "show up where your engineers work.",
                     "evidence": {"open_critical_high_checks": open_checks}})
    if not any(s in state for s in ("slack", "microsoft-teams", "discord", "custom-webhook")):
        recs.append({"slug": "slack", "alternatives": ["microsoft-teams", "discord", "custom-webhook"], "priority": 2,
                     "reason": "No chat or webhook channel is set up, so alerts only reach the Niagaros app and e-mail.",
                     "evidence": {"alert_channels_configured": 0}})
    if "github" not in state:
        recs.append({"slug": "github", "alternatives": [], "priority": 3,
                     "reason": "Source code controls (branch protection, secret scanning, organization MFA) are not "
                               "covered without a GitHub connection.",
                     "evidence": {"github_connected": False}})
    for slug, s in state.items():
        if s.get("health") in ("failing", "needs_reauth"):
            recs.append({"slug": slug, "alternatives": [], "priority": 0, "kind": "fix",
                         "reason": f"{cat[slug]['name']} is connected but not working: {s['health_reason']}",
                         "evidence": {"health": s["health"]}})
    if identity_checks:
        # The identity providers are not built yet; say so instead of implying they can be connected.
        recs.append({"slug": "okta", "alternatives": ["microsoft-entra-id", "google-workspace"], "priority": 4,
                     "kind": "request",
                     "reason": f"{_checks(identity_checks)} about identities and MFA. An identity "
                               "provider integration would add user-level evidence; it is not available yet, so you "
                               "can request it.",
                     "evidence": {"open_identity_checks": identity_checks}})
    for r in recs:
        e = cat.get(r["slug"])
        r["name"] = e["name"] if e else r["slug"]
        r["status"] = e["status"] if e else None
        r.setdefault("kind", "connect" if e and e["status"] == "Available" else "request")
    return sorted(recs, key=lambda r: r["priority"])
