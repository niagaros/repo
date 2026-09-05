"""
monthly_report_handler.py

Builds the recurring monthly compliance review (GitHub issue #234): a
presentation-ready HTML summary of scan results, trend data (new/resolved
findings, score delta) versus the previous monthly snapshot, and the top
unresolved findings — stored in S3 and recorded in compliance_snapshots so
the *next* run has a real prior data point to diff against.

Trend data only exists because this snapshots the full list of currently-
failing (check_id, resource_id) pairs each run, not just the aggregate
pass/fail counts — that's what makes a genuine new-vs-resolved diff possible
instead of only a change in totals.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

REPORTS_BUCKET = os.environ.get("REPORTS_BUCKET", "niagaros-compliance-reports")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# SES is in sandbox mode: both sender and recipient must be verified
# identities, so this uses one verified address as both until a real
# "reports@..." sending domain is verified and production access is granted.
REPORT_SENDER_EMAIL = os.environ.get("REPORT_SENDER_EMAIL")
REPORT_RECIPIENT_EMAILS = [
    e.strip() for e in os.environ.get("REPORT_RECIPIENT_EMAILS", "").split(",") if e.strip()
]

# Mapped-compliance-framework names — see the identical constant and
# rationale in backend/src/config/database.py's record_compliance_snapshot.
# Without this exclusion, every emailed report would count each real
# misconfiguration once per compliance framework that also cites it.
MAPPED_FRAMEWORK_NAMES = (
    'ISO 27001:2022', 'NIST CSF v2.0', 'GDPR', 'SOC2', 'PCI DSS v4.0', 'NIS2', 'HIPAA',
    'NIST 800-53 Rev 5', 'BSI-C5', 'CSA CCM 4.0', 'FedRAMP Moderate Rev 4', 'ISO 42001',
    'ISO 27017', 'AWS FTR', 'MVSP', 'TISAX', 'HITRUST CSF', 'DORA', 'CRI Profile',
    'EU AI Act', 'NIST AI RMF', 'ISO 27701', 'ISO 27018', 'Microsoft SSPA',
    'CIS Controls v8.1', '23 NYCRR 500 (NYDFS)', 'NIST Privacy Framework',
)

# Identical to the CASE mapping in trust_center_handler.py / get-dashboard-
# data — copied verbatim, not reimplemented, so a "SOC 2: 92%" line in this
# report can never silently disagree with the same framework's card on the
# dashboard or Trust Center. Unlike MAPPED_FRAMEWORK_NAMES above (used to
# EXCLUDE these for the raw/deduplicated headline numbers), this is used to
# INCLUDE them for the per-framework breakdown, which is supposed to show
# each framework's own citation.
FRAMEWORK_CASE_SQL = """
    CASE
        WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
        WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
        WHEN f.framework = 'GDPR'            THEN 'GDPR'
        WHEN f.framework = 'SOC2'            THEN 'SOC2'
        WHEN f.framework = 'PCI DSS v4.0'   THEN 'PCIDSS'
        WHEN f.framework = 'NIS2'            THEN 'NIS2'
        WHEN f.framework = 'HIPAA'           THEN 'HIPAA'
        WHEN f.framework = 'NIST 800-53 Rev 5' THEN 'NIST80053'
        WHEN f.framework = 'BSI-C5'          THEN 'BSIC5'
        WHEN f.framework = 'CSA CCM 4.0'     THEN 'CSACCM'
        WHEN f.framework = 'FedRAMP Moderate Rev 4' THEN 'FEDRAMP'
        WHEN f.framework = 'ISO 42001'       THEN 'ISO42001'
        WHEN f.framework = 'ISO 27017'       THEN 'ISO27017'
        WHEN f.framework = 'AWS FTR'         THEN 'AWSFTR'
        WHEN f.framework = 'MVSP'            THEN 'MVSP'
        WHEN f.framework = 'TISAX'           THEN 'TISAX'
        WHEN f.framework = 'HITRUST CSF'     THEN 'HITRUST'
        WHEN f.framework = 'DORA'            THEN 'DORA'
        WHEN f.framework = 'CRI Profile'     THEN 'CRIPROFILE'
        WHEN f.framework = 'EU AI Act'       THEN 'EUAIACT'
        WHEN f.framework = 'NIST AI RMF'     THEN 'NISTAIRMF'
        WHEN f.framework = 'ISO 27701'       THEN 'ISO27701'
        WHEN f.framework = 'ISO 27018'       THEN 'ISO27018'
        WHEN f.framework = 'Microsoft SSPA'  THEN 'SSPA'
        WHEN f.framework = 'CIS Controls v8.1' THEN 'CISCTRL'
        WHEN f.framework = '23 NYCRR 500 (NYDFS)' THEN 'NYDFS'
        WHEN f.framework = 'NIST Privacy Framework' THEN 'NISTPRIV'
        WHEN f.framework = 'CIS AWS Foundations Benchmark v5.0.0' THEN 'CISAWS'
        WHEN f.framework = 'AWS Foundational Security Best Practices' THEN 'FSBP'
        ELSE NULL
    END
"""

FRAMEWORK_LABELS = {
    "ISO27001": "ISO/IEC 27001:2022", "NIST": "NIST CSF v2.0", "GDPR": "GDPR", "SOC2": "SOC 2",
    "PCIDSS": "PCI DSS v4.0", "NIS2": "NIS2", "HIPAA": "HIPAA", "NIST80053": "NIST SP 800-53 Rev 5",
    "BSIC5": "BSI C5", "CSACCM": "CSA CCM 4.0", "FEDRAMP": "FedRAMP Moderate", "ISO42001": "ISO 42001:2023",
    "ISO27017": "ISO 27017:2015", "AWSFTR": "AWS FTR", "MVSP": "MVSP", "TISAX": "TISAX",
    "HITRUST": "HITRUST CSF", "DORA": "DORA", "CRIPROFILE": "CRI Profile", "EUAIACT": "EU AI Act",
    "NISTAIRMF": "NIST AI RMF", "ISO27701": "ISO 27701", "ISO27018": "ISO 27018", "SSPA": "Microsoft SSPA",
    "CISCTRL": "CIS Controls v8.1", "NYDFS": "23 NYCRR 500 (NYDFS)", "NISTPRIV": "NIST Privacy Framework",
    "CISAWS": "CIS AWS Foundations Benchmark", "FSBP": "AWS Foundational Security Best Practices",
}


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"],
        sslmode="require", connect_timeout=10,
    )


def _current_state(cur, cloud_account_id):
    cur.execute("""
        SELECT f.check_id, f.result, f.severity, f.title, r.id AS resource_id, r.resource_name
        FROM findings f
        JOIN resources r ON r.id = f.resource_id
        WHERE r.cloud_account_id = %s
          AND (f.framework IS NULL OR f.framework NOT IN %s)
    """, (cloud_account_id, MAPPED_FRAMEWORK_NAMES))
    rows = cur.fetchall()

    total = len(rows)
    passed = sum(1 for r in rows if r["result"] == "PASS")
    failed = total - passed

    by_severity = {}
    failing = []
    for r in rows:
        sev = r["severity"] or "MEDIUM"
        by_severity.setdefault(sev, {"passed": 0, "failed": 0})
        by_severity[sev]["passed" if r["result"] == "PASS" else "failed"] += 1
        if r["result"] == "FAIL":
            failing.append({
                "check_id": r["check_id"],
                "resource_id": str(r["resource_id"]),
                "resource_name": r["resource_name"],
                "severity": sev,
                "title": r["title"],
            })

    return {
        "total": total, "passed": passed, "failed": failed,
        "by_severity": by_severity, "failing": failing,
        "by_framework": _framework_breakdown(cur, cloud_account_id),
    }


def _framework_breakdown(cur, cloud_account_id):
    """Per-framework passed/failed/score — deliberately the opposite scope
    from _current_state's raw-only query above: this INCLUDES every mapped
    framework's own citation, because "SOC 2: 92%" is supposed to be that
    framework's own number, the same one shown on its dashboard card."""
    cur.execute(f"""
        SELECT service, COUNT(*) AS total, COUNT(*) FILTER (WHERE result = 'PASS') AS passed
        FROM (
            SELECT {FRAMEWORK_CASE_SQL} AS service, f.result
            FROM findings f
            JOIN resources r ON f.resource_id = r.id
            WHERE r.cloud_account_id = %s
        ) sub
        WHERE service IS NOT NULL
        GROUP BY service
    """, (cloud_account_id,))
    out = {}
    for row in cur.fetchall():
        # This cursor is a RealDictCursor (see generate_report) — rows are
        # dict-like, so `for a, b, c in row` would iterate its *keys*, not
        # values. Index by column name explicitly.
        service, total, passed = row["service"], row["total"], row["passed"]
        label = FRAMEWORK_LABELS.get(service, service)
        out[label] = {
            "total": total, "passed": passed, "failed": total - passed,
            "score": round(passed * 100.0 / total, 1) if total else 0,
        }
    return out


def _period_data(cur, cloud_account_id):
    """
    Builds the reporting window from the last 'monthly_report' snapshot (or
    30 days back, for the very first report) up to now, and returns every
    'scan' snapshot the orchestrator recorded in that window — one per
    completed scan cycle, not just the single point a month ago. That's what
    makes it possible to show the actual lowest/highest score reached during
    the month, e.g. a mid-month regression that was already fixed again by
    the time this report runs, instead of only comparing two isolated points.
    """
    cur.execute("""
        SELECT generated_at, by_framework FROM compliance_snapshots
        WHERE cloud_account_id = %s AND snapshot_type = 'monthly_report'
        ORDER BY generated_at DESC LIMIT 1
    """, (cloud_account_id,))
    last_report = cur.fetchone()
    period_start = last_report["generated_at"] if last_report else datetime.now(timezone.utc) - timedelta(days=30)
    # Framework before/after always compares against the *previous report*,
    # not an arbitrary mid-period scan snapshot (those don't carry a
    # per-framework breakdown) — "SOC 2 was 88%, now 92%" means since last
    # month's report, not since some scan a week ago.
    previous_by_framework = (last_report["by_framework"] or {}) if last_report else {}

    cur.execute("""
        SELECT total_checks, passed, failed, by_severity, failing_keys, generated_at
        FROM compliance_snapshots
        WHERE cloud_account_id = %s AND snapshot_type = 'scan' AND generated_at > %s
        ORDER BY generated_at ASC
    """, (cloud_account_id, period_start))
    scans = cur.fetchall()

    baseline = scans[0] if scans else last_report
    if baseline is not None and "failing_keys" not in baseline:
        # last_report row only carries generated_at from the query above;
        # re-fetch its full content if it's being used as the baseline
        cur.execute("""
            SELECT total_checks, passed, failed, by_severity, failing_keys, generated_at
            FROM compliance_snapshots
            WHERE cloud_account_id = %s AND snapshot_type = 'monthly_report' AND generated_at = %s
        """, (cloud_account_id, period_start))
        baseline = cur.fetchone()

    scores = [round(100 * s["passed"] / s["total_checks"]) for s in scans if s["total_checks"]]
    return {
        "period_start": period_start,
        "scans_in_period": len(scans),
        "baseline": baseline,
        "min_score": min(scores) if scores else None,
        "max_score": max(scores) if scores else None,
        "previous_by_framework": previous_by_framework,
    }


def _diff_findings(current_failing, previous_failing_keys):
    def key(f):
        return (f["check_id"], f["resource_id"])

    current_keys = {key(f) for f in current_failing}
    previous_keys = {(f["check_id"], f["resource_id"]) for f in (previous_failing_keys or [])}

    new_findings = [f for f in current_failing if key(f) not in previous_keys]
    resolved_keys = previous_keys - current_keys
    resolved_findings = [
        f for f in (previous_failing_keys or [])
        if (f["check_id"], f["resource_id"]) in resolved_keys
    ]
    return new_findings, resolved_findings


def _top_unresolved(failing, limit=5):
    ordered = sorted(failing, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return ordered[:limit]


def _esc(s):
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _render_html(account_name, period_label, current, period, new_findings, resolved_findings, top_findings, preview_only=False):
    score = round(100 * current["passed"] / current["total"]) if current["total"] else 0
    baseline = period["baseline"]
    baseline_score = None
    if baseline:
        baseline_total = baseline["total_checks"]
        baseline_score = round(100 * baseline["passed"] / baseline_total) if baseline_total else None
    delta = (score - baseline_score) if baseline_score is not None else None
    delta_html = (
        f'<span style="color:{"#10b981" if delta >= 0 else "#ef4444"}">{"+" if delta >= 0 else ""}{delta} pts since start of period</span>'
        if delta is not None else '<span style="color:#9ca3af">No prior snapshot — this is the first report</span>'
    )

    range_html = (
        f'<div class="tile"><div class="lbl">Lowest This Period</div><div class="val" style="color:#ef4444">{period["min_score"]}%</div></div>'
        f'<div class="tile"><div class="lbl">Highest This Period</div><div class="val" style="color:#10b981">{period["max_score"]}%</div></div>'
        if period["min_score"] is not None else
        '<div class="tile"><div class="lbl">Scans This Period</div><div class="val" style="color:#9ca3af">0</div></div>'
    )
    scans_note = (
        f'Based on {period["scans_in_period"]} scan(s) since {period["period_start"].strftime("%d %b %Y")}'
        if period["scans_in_period"] else
        f'No scans recorded since {period["period_start"].strftime("%d %b %Y")} — score reflects the current snapshot only'
    )

    baseline_by_severity = (baseline["by_severity"] or {}) if baseline else {}

    def _delta_cell(before, now):
        if before is None:
            return '<span style="color:#9ca3af">—</span>'
        d = now - before
        if d == 0:
            return '<span style="color:#9ca3af">no change</span>'
        color = "#ef4444" if d > 0 else "#10b981"  # more failures = red, fewer = green
        return f'<span style="color:{color};font-weight:600">{"+" if d > 0 else ""}{d}</span>'

    def _sev_row(sev, d):
        before = baseline_by_severity.get(sev, {}).get("failed") if baseline else None
        now = d["failed"]
        return (
            f'<tr><td>{_esc(sev)}</td>'
            f'<td>{before if before is not None else "—"}</td>'
            f'<td>{now}</td>'
            f'<td>{_delta_cell(before, now)}</td></tr>'
        )

    sev_rows = "".join(
        _sev_row(sev, d)
        for sev, d in sorted(current["by_severity"].items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9))
    )

    def _score_delta_cell(before, now):
        if before is None or now is None:
            return '<span style="color:#9ca3af">—</span>'
        d = now - before
        if d == 0:
            return '<span style="color:#9ca3af">no change</span>'
        color = "#10b981" if d > 0 else "#ef4444"  # higher score = better = green
        return f'<span style="color:{color};font-weight:600">{"+" if d > 0 else ""}{d} pts</span>'

    previous_by_framework = period.get("previous_by_framework") or {}
    all_frameworks = sorted(set(current["by_framework"]) | set(previous_by_framework))
    fw_row_parts = []
    for fw in all_frameworks:
        now_d = current["by_framework"].get(fw)
        prev_d = previous_by_framework.get(fw)
        now_score = now_d["score"] if now_d else None
        prev_score = prev_d["score"] if prev_d else None
        fw_row_parts.append(
            f'<tr><td>{_esc(fw)}</td>'
            f'<td>{f"{prev_score}%" if prev_score is not None else "—"}</td>'
            f'<td>{f"{now_score}%" if now_score is not None else "—"}</td>'
            f'<td>{_score_delta_cell(prev_score, now_score)}</td></tr>'
        )
    framework_rows = "".join(fw_row_parts) or '<tr><td colspan="4" style="color:#9ca3af;text-align:center;padding:16px">No framework data available.</td></tr>'

    def finding_rows(items, empty_msg):
        if not items:
            return f'<tr><td colspan="4" style="color:#9ca3af;text-align:center;padding:16px">{empty_msg}</td></tr>'
        return "".join(
            f'<tr><td>{_esc(f["severity"])}</td><td><code>{_esc(f["check_id"])}</code></td>'
            f'<td>{_esc(f.get("title") or "")}</td><td>{_esc(f["resource_name"])}</td></tr>'
            for f in items
        )

    next_steps = "".join(
        f'<li><strong>{_esc(f["check_id"])}</strong> ({_esc(f["resource_name"])}) — {_esc(f.get("title") or "review and remediate")}</li>'
        for f in top_findings
    ) or "<li>No open findings — nothing to act on this month.</li>"

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>{_esc(account_name)} — Monthly Security Review — {_esc(period_label)}</title>
<style>
body{{font-family:-apple-system,Segoe UI,Arial,sans-serif;margin:0;padding:40px;color:#111827;background:#f9fafb}}
.wrap{{max-width:820px;margin:0 auto;background:#fff;border-radius:12px;padding:36px;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:#6b7280;margin-bottom:24px}}
.score-row{{display:flex;gap:20px;margin:20px 0 28px;flex-wrap:wrap}}
.tile{{flex:1;min-width:140px;background:#f9fafb;border-radius:10px;padding:16px}}
.tile .lbl{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;color:#9ca3af}}
.tile .val{{font-size:26px;font-weight:800;margin-top:4px}}
h2{{font-size:15px;margin:28px 0 10px;border-bottom:2px solid #f3f4f6;padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;background:#f3f4f6;padding:8px 10px;font-size:11px;text-transform:uppercase;color:#6b7280}}
td{{padding:7px 10px;border-bottom:1px solid #f3f4f6}}
code{{font-family:monospace;font-size:12px}}
.footer{{margin-top:28px;font-size:11px;color:#9ca3af;border-top:1px solid #e5e7eb;padding-top:12px}}
</style></head><body>
<div class="wrap">
{'<div style="background:#eff6ff;border:1px solid #bfdbfe;color:#1d4ed8;border-radius:8px;padding:10px 14px;font-size:12.5px;font-weight:600;margin-bottom:18px">On-demand preview — a snapshot of the current state, not the official monthly close-out. Counted separately from the scheduled monthly report.</div>' if preview_only else ''}
<h1>🛡 Monthly Security Review — {_esc(account_name)}</h1>
<div class="sub">{_esc(period_label)} · Generated by Niagaros CSPM · {_esc(scans_note)}</div>

<div class="score-row">
  <div class="tile"><div class="lbl">Compliance Score</div><div class="val">{score}%</div><div style="font-size:12px;margin-top:4px">{delta_html}</div></div>
  {range_html}
  <div class="tile"><div class="lbl">Passing</div><div class="val" style="color:#10b981">{current["passed"]}</div></div>
  <div class="tile"><div class="lbl">Failing</div><div class="val" style="color:#ef4444">{current["failed"]}</div></div>
  <div class="tile"><div class="lbl">New Findings</div><div class="val" style="color:#f59e0b">{len(new_findings)}</div></div>
  <div class="tile"><div class="lbl">Resolved</div><div class="val" style="color:#3b82f6">{len(resolved_findings)}</div></div>
</div>

<h2>Failing Checks by Severity — Before vs. Now</h2>
<table><thead><tr><th>Severity</th><th>Before</th><th>Now</th><th>Change</th></tr></thead><tbody>{sev_rows}</tbody></table>

<h2>Compliance by Framework — Before vs. Now</h2>
<div class="sub" style="margin:-4px 0 10px">{'Before = last monthly report, ' + period["period_start"].strftime("%d %b %Y") + '. Shows exactly where compliance improved or regressed, not just the overall number.' if previous_by_framework else 'No prior report with framework data yet — this comparison starts from the next report.'}</div>
<table><thead><tr><th>Framework</th><th>Before</th><th>Now</th><th>Change</th></tr></thead><tbody>{framework_rows}</tbody></table>

<h2>New Findings This Period</h2>
<table><thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Resource</th></tr></thead>
<tbody>{finding_rows(new_findings, "No new findings since the start of this period.")}</tbody></table>

<h2>Resolved This Period</h2>
<table><thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Resource</th></tr></thead>
<tbody>{finding_rows(resolved_findings, "No findings were resolved this period.")}</tbody></table>

<h2>Top 5 Unresolved Findings</h2>
<table><thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Resource</th></tr></thead>
<tbody>{finding_rows(top_findings, "Nothing open — full compliance.")}</tbody></table>

<h2>Recommended Next Steps</h2>
<ul>{next_steps}</ul>

<div class="footer">Generated automatically by Niagaros CSPM · niagaros.io</div>
</div></body></html>"""


def _send_email(account_name, period_label, html, score, new_count, resolved_count, preview_only=False):
    if not REPORT_SENDER_EMAIL or not REPORT_RECIPIENT_EMAILS:
        logger.info("Email delivery skipped: REPORT_SENDER_EMAIL/REPORT_RECIPIENT_EMAILS not configured")
        return {"sent": False, "reason": "not_configured"}

    ses = boto3.client("sesv2", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
    prefix = "[Preview] " if preview_only else ""
    subject = f"{prefix}{account_name} — Monthly Security Review ({period_label}) — {score}% compliant"
    text_fallback = (
        f"{account_name} monthly security review for {period_label}.\n"
        f"Compliance score: {score}%. New findings: {new_count}. Resolved: {resolved_count}.\n"
        f"Open this email in an HTML-capable client to see the full report."
    )
    try:
        ses.send_email(
            FromEmailAddress=REPORT_SENDER_EMAIL,
            Destination={"ToAddresses": REPORT_RECIPIENT_EMAILS},
            Content={"Simple": {
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {
                    "Html": {"Data": html, "Charset": "UTF-8"},
                    "Text": {"Data": text_fallback, "Charset": "UTF-8"},
                },
            }},
        )
        return {"sent": True}
    except Exception as e:
        logger.error("Report email send failed: %s", str(e), exc_info=True)
        return {"sent": False, "reason": str(e)}


def generate_report(cloud_account_id: str, preview_only: bool = False) -> dict:
    """preview_only=True generates and emails the same report on demand
    without touching the official monthly cadence: no new 'monthly_report'
    snapshot is written (so the period boundary the next scheduled report
    diffs against is untouched), and the S3 object is stored under a
    separate preview key so it never overwrites that month's official
    report. Triggering a preview as often as you like can't quietly
    shorten or distort the real month-over-month trend data."""
    conn = _get_connection()
    try:
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT account_name FROM cloud_accounts WHERE id = %s", (cloud_account_id,))
                acct = cur.fetchone()
                account_name = acct["account_name"] if acct else cloud_account_id

                current = _current_state(cur, cloud_account_id)
                period = _period_data(cur, cloud_account_id)
                baseline_failing_keys = period["baseline"]["failing_keys"] if period["baseline"] else []

                new_findings, resolved_findings = _diff_findings(current["failing"], baseline_failing_keys)
                top_findings = _top_unresolved(current["failing"])

                now = datetime.now(timezone.utc)
                period_label = now.strftime("%B %Y")

                html = _render_html(account_name, period_label, current, period, new_findings, resolved_findings, top_findings, preview_only)

                if preview_only:
                    s3_key = f"{cloud_account_id}/preview-{now.strftime('%Y-%m-%dT%H%M%S')}.html"
                else:
                    s3_key = f"{cloud_account_id}/{now.strftime('%Y-%m')}.html"
                s3 = boto3.client("s3", region_name=os.environ.get("SECRET_REGION", "eu-west-1"))
                s3.put_object(
                    Bucket=REPORTS_BUCKET, Key=s3_key, Body=html.encode("utf-8"),
                    ContentType="text/html",
                )

                if not preview_only:
                    cur.execute("""
                        INSERT INTO compliance_snapshots
                            (cloud_account_id, total_checks, passed, failed, by_severity, by_framework, failing_keys, report_s3_key, snapshot_type)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'monthly_report')
                    """, (
                        cloud_account_id, current["total"], current["passed"], current["failed"],
                        json.dumps(current["by_severity"]), json.dumps(current["by_framework"]),
                        json.dumps(current["failing"]), s3_key,
                    ))

        score = round(100 * current["passed"] / current["total"]) if current["total"] else 0
        email_result = _send_email(account_name, period_label, html, score, len(new_findings), len(resolved_findings), preview_only)

        logger.info("Monthly report generated for %s: %s (preview_only=%s, email: %s)", account_name, s3_key, preview_only, email_result)
        return {
            "cloud_account_id": cloud_account_id,
            "account_name": account_name,
            "report_s3_key": s3_key,
            "score": score,
            "new_findings": len(new_findings),
            "resolved_findings": len(resolved_findings),
            "preview_only": preview_only,
            "email": email_result,
        }
    finally:
        conn.close()


CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def handler(event, context):
    # API Gateway proxy event (dashboard "Run report now" button) — kept
    # separate from the plain-invoke shape below, which is what the
    # EventBridge rule "monthly-domits-security-review" has always used and
    # must keep working unchanged.
    if event and "httpMethod" in event:
        if event["httpMethod"] == "OPTIONS":
            return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}
        body = json.loads(event["body"]) if event.get("body") else {}
        cloud_account_id = body.get("cloud_account_id")
        if not cloud_account_id:
            return {"statusCode": 400, "headers": CORS_HEADERS, "body": json.dumps({"error": "cloud_account_id is required"})}
        try:
            result = generate_report(cloud_account_id, preview_only=True)
            return {"statusCode": 200, "headers": CORS_HEADERS, "body": json.dumps(result)}
        except Exception as e:
            logger.error("Preview report failed for %s: %s", cloud_account_id, str(e), exc_info=True)
            return {"statusCode": 500, "headers": CORS_HEADERS, "body": json.dumps({"error": str(e)})}

    cloud_account_id = event.get("cloud_account_id")
    if not cloud_account_id:
        return {"statusCode": 400, "body": json.dumps({"error": "cloud_account_id is required"})}

    try:
        result = generate_report(cloud_account_id)
        return {"statusCode": 200, "body": json.dumps(result)}
    except Exception as e:
        logger.error("Monthly report failed for %s: %s", cloud_account_id, str(e), exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
