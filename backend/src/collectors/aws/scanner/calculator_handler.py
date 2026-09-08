"""
calculator_handler.py

Niagaros Calculators (GitHub issue #263), v1.

Scope decision: issue #263 proposes ~40 calculators (cyber risk exposure,
FAIR-based risk estimation, cost-of-a-data-breach, AI risk scores, cloud
cost/TCO, executive KPIs). Almost all of them require either a real
actuarial/industry benchmark dataset this platform has no access to
(breach-cost averages, FAIR probability distributions), or an AI model
asserting a risk judgement well beyond what this platform's existing AI
integration is used for (drafting answers strictly from real evidence).
Building those would mean presenting invented numbers as if they were
measured or verified.

The issue gives an explicit priority order, though:
  1st: Compliance Effort Calculator
  2nd: Compliance Cost Calculator
  3rd: [Framework] Cost Calculator

All three are built here, for real: the GAP INPUT (how many findings are
currently open for a chosen framework, broken down by severity) is real,
live data from the same findings/resources tables the dashboard, Trust
Center, monthly report, and Audit Management already read from.

v1 of this calculator used arbitrary, self-invented default assumptions
(8h/4h/2h/1h per severity, €75/hour) with no real source — the user
rejected that outright ("ik wil niks neps hebben"), correctly: a
specific-looking number nobody chose and nobody can trace to a source is
exactly what "fabricated" means, disclaimer or not. v2 replaces every
default with a REAL, named, dated, publicly-published external benchmark
— the same class of source every comparable product (Vanta, Drata, etc.)
cites for this exact purpose — via REAL_BENCHMARKS below:
  - Average days to remediate a vulnerability, by severity: Edgescan 2025
    Vulnerability Statistics Report (10th edition).
  - Average hourly rate for a cybersecurity/compliance consultant:
    Glassdoor, pulled 2026.
  - Average cost of a data breach (global and US): IBM Cost of a Data
    Breach Report 2025.
Where NO real, citable benchmark exists — hours of actual engineering
work needed to fix one finding, which nobody publishes reliably — the
field is left at 0 with an explicit note saying so, rather than guessed.
The Data Breach reference figures are shown as industry context next to
the account's own real critical/high finding count; they are never
multiplied together into a fake "your predicted breach cost" number,
since this platform has no real breach-probability or exposed-record data
to make that a true statement rather than an invented one.

Declined, explicitly, rather than silently invented: Cyber Risk Exposure /
FAIR-based Risk Estimator (no real probability-distribution dataset), AI
Risk Calculator / AI-generated forecasting (would require an AI judgement
of risk, not a drafted answer from real evidence), Kubernetes Security
Score (no Kubernetes collector exists), cloud-cost/TCO calculators (no
billing-data integration exists). See
docs/internal/architecture/aws/calculators.md for the full scope table.

FRAMEWORK_CASE_SQL / FRAMEWORK_LABELS / FRAMEWORK_DB_VALUES are copied
verbatim from trust_center_handler.py / audit_management_handler.py (same
reuse pattern already established across this codebase) so the calculator
framework picklist matches the exact real framework set the rest of the
product tracks.
"""

import json
import logging
import os
import re

import boto3
import psycopg2

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _is_uuid(value):
    return bool(value) and bool(_UUID_RE.match(value))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CORS_HEADERS = {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}

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

FRAMEWORK_DB_VALUES = {
    "ISO27001": ["ISO 27001:2022"], "NIST": ["NIST CSF v2.0"], "GDPR": ["GDPR"], "SOC2": ["SOC2"],
    "PCIDSS": ["PCI DSS v4.0"], "NIS2": ["NIS2"], "HIPAA": ["HIPAA"], "NIST80053": ["NIST 800-53 Rev 5"],
    "BSIC5": ["BSI-C5"], "CSACCM": ["CSA CCM 4.0"], "FEDRAMP": ["FedRAMP Moderate Rev 4"], "ISO42001": ["ISO 42001"],
    "ISO27017": ["ISO 27017"], "AWSFTR": ["AWS FTR"], "MVSP": ["MVSP"], "TISAX": ["TISAX"],
    "HITRUST": ["HITRUST CSF"], "DORA": ["DORA"], "CRIPROFILE": ["CRI Profile"], "EUAIACT": ["EU AI Act"],
    "NISTAIRMF": ["NIST AI RMF"], "ISO27701": ["ISO 27701"], "ISO27018": ["ISO 27018"], "SSPA": ["Microsoft SSPA"],
    "CISCTRL": ["CIS Controls v8.1"], "NYDFS": ["23 NYCRR 500 (NYDFS)"], "NISTPRIV": ["NIST Privacy Framework"],
    "CISAWS": ["CIS AWS Foundations Benchmark v5.0.0", "AWS Foundational Security Best Practices"],
}

CALCULATOR_TYPES = ("compliance_effort", "compliance_cost")

# Real, named, dated, publicly-published external benchmarks — every
# number here is traceable to a real report, never invented. Where no
# real benchmark exists (e.g. engineering hours per finding), there is no
# entry, and the frontend must say so rather than fill in a guess.
#
# Corrected 2026-09-07 after the user checked the sourcing closely and
# found two real problems with the first version:
#   1. The original table showed a clean number for all four severities
#      (Critical/High/Medium/Low) as if Edgescan published each
#      separately. It doesn't. Edgescan's own report groups High together
#      WITH Critical for its headline MTTR figures, and doesn't publish
#      Medium/Low remediation-time figures at all in the sources checked.
#      Presenting four clean, separate numbers was fabricating precision
#      the source doesn't have — exactly the kind of thing this feature
#      exists to avoid. Fixed by showing only the figures Edgescan
#      actually reports, labelled exactly as reported (combined where the
#      source combines them), instead of splitting them apart.
#   2. "Cost of a Data Breach" showing only an abstract global/US average
#      felt hollow ("is ook niet echt iets... kom met echte voorbeelden").
#      Replaced/supplemented with REAL_WORLD_INCIDENTS below — three
#      specific, named, dated, well-documented breaches with real
#      disclosed costs, so the context is concrete rather than abstract.
REAL_BENCHMARKS = {
    # Re-checked 2026-09-08 after the user asked "is this the most current
    # data" — it wasn't quite. Edgescan has an 11th (2026) edition and IBM
    # has a 2026 edition, both newer than what was first cited. Confirmed
    # via edgescan.com/stats-report directly: the High+Critical-combined
    # figure (54.81/39 days) is still the current figure in the 2026
    # edition. The standalone Critical-only breakdown (74.3/61/35) is only
    # confirmed attributed to the 2025 (10th) edition in every source
    # checked — cited to that specific edition rather than assumed to
    # carry over unchanged.
    "remediation_days": {
        "source": "Edgescan Vulnerability Statistics Report",
        "url": "https://www.edgescan.com/stats-report/",
        "critical_mean_days": 74.3,
        "critical_host_cloud_days": 61,
        "critical_internet_facing_days": 35,
        "critical_figures_edition": "2025 (10th edition)",
        "high_and_critical_combined_days": {"application_api": 54.81, "device_network": 39},
        "combined_figures_edition": "2026 (11th edition) — confirmed still current as of this check",
        "note": "Edgescan reports Critical on its own in the 2025 edition (74.3 days mean for application vulnerabilities; 61 days for host/cloud criticals; 35 days for internet-facing criticals). Its High+Critical combined figure (54.81 days app/API, 39 days device/network) is confirmed still current in the 2026 edition. It does not publish separate Medium or Low remediation-time figures in any edition checked.",
        # Corrected again 2026-09-08: the user rejected a *range* here
        # ("kom met een x aantal dagen" — give one specific number), and a
        # direct fetch of the two candidate sources showed the range had
        # been built from a blended, unreliable search-engine summary —
        # secure.com's own page actually lumps Medium+Low together at
        # 60-90 days and doesn't give Low separately at all. Cogent's page
        # was fetched directly and gives one clean, single number per
        # tier (not a range) from its own named "typical starting
        # framework" — used here as-is, verbatim, from that one source.
        "medium_low_sla_note": "No measured industry figure exists for Medium/Low remediation time. This is Cogent's own named \"typical starting framework\" (CVSS-tier based), quoted as a single number per tier, not a range — Cogent itself notes these numbers vary by organization and that regulated industries often use shorter windows.",
        "medium_low_sla_source": "Cogent, \"Vulnerability Remediation SLAs: How to Set Them\"",
        "medium_low_sla_url": "https://www.cogent.com/academy/vulnerability-remediation-slas-how-to-set-them",
        "medium_days": 90,
        "low_days": 180,
    },
    "hourly_rate_usd": {
        "source": "Glassdoor, Cyber Security Consultant hourly pay (US), pulled 2026",
        "url": "https://www.glassdoor.com/Salaries/cyber-security-consultant-salary-SRCH_KO0,25.htm",
        "value": 76,
        "note": "Median of a $58-$100/hr typical range for an employed consultant. See the rate-by-engagement-type comparison below for federal and freelance rates, each separately sourced.",
        # Real rate comparison by engagement type — each figure separately
        # sourced, so the calculator's default isn't presented as the only
        # real number when it's actually one of several genuinely different
        # markets (in-house employee vs. federal contractor vs. independent
        # freelancer pay very differently for the same job title).
        "by_engagement_type": [
            {"label": "Employed (in-house)", "value": 76, "range": [58, 100],
             "source": "Glassdoor", "url": "https://www.glassdoor.com/Salaries/cyber-security-consultant-salary-SRCH_KO0,25.htm"},
            {"label": "Federal contractor", "value": 63.41, "range": [47.84, 76.44],
             "source": "ZipRecruiter", "url": "https://www.ziprecruiter.com/Salaries/Federal-Cyber-Security-Consultant-Salary"},
            {"label": "Independent freelance", "value": 144, "range": [90, 178],
             "source": "contractrates.fyi", "url": "https://www.contractrates.fyi/CyberSecurity-Consultant/hourly-rates"},
        ],
    },
    "data_breach_cost_usd": {
        "source": "IBM Cost of a Data Breach Report 2026",
        "url": "https://www.ibm.com/reports/data-breach",
        "global_average": 4_990_000,
        "us_average": 11_500_000,
        "mean_days_to_identify_and_contain": 247,
        "report_period": "Breaches occurring Mar 2025-Feb 2026, 602 organizations, published Jul 2026 — the current edition, up from $4.44M/$10.22M/241 days in the 2025 edition",
        "note": "Industry-wide averages shown for context only — never multiplied against this account's own data, since this platform has no real breach-probability or exposed-record figures to make a personalized dollar prediction true rather than invented.",
    },
    "real_world_incidents": [
        {
            "name": "Capital One (2019)",
            "category": "Cloud storage / public exposure",
            "summary": "A misconfigured web application firewall let an attacker reach AWS's metadata service and pull temporary credentials, which were then used to read 700+ S3 buckets — 106 million customer records exposed.",
            "cost_usd": 190_000_000,
            "cost_label": "settlement + FDIC/OCC penalties",
            "source": "Krebs on Security",
            "url": "https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/",
        },
        {
            "name": "Change Healthcare (2024)",
            "category": "Missing MFA",
            "summary": "Attackers used a single compromised credential to log into a remote-access (Citrix) portal that had no MFA enabled, and went undetected for over a week — 190 million Americans affected, the largest healthcare data breach in US history.",
            "cost_usd": None,
            "cost_label": "190M people affected",
            "source": "Multiple outlets, incl. congressional testimony",
            "url": "https://www.breachsense.com/blog/change-healthcare-data-breach-case-study/",
        },
        {
            "name": "MGM Resorts (2023)",
            "category": "MFA bypassed via social engineering",
            "summary": "MGM DID have MFA — attackers researched an employee on LinkedIn, impersonated them in a 10-minute call to the IT help desk, and got the agent to approve an MFA reset, gaining admin access to MGM's Okta/Azure environment.",
            "cost_usd": 100_000_000,
            "cost_label": "SEC 8-K disclosed impact",
            "source": "MGM Resorts SEC Form 8-K / NBC News",
            "url": "https://www.nbcnews.com/business/business-news/cyberattack-cost-mgm-resorts-100-million-las-vegas-company-says-rcna119138",
        },
    ],
}


def _get_connection():
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    region = os.environ.get("SECRET_REGION", "eu-west-1")
    client = boto3.client("secretsmanager", region_name=region)
    secret = json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return psycopg2.connect(
        host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
        user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
    )


def _gap_data(cur, cloud_account_id, framework):
    """Real, live count of currently-FAILing findings for a framework,
    broken down by severity — the only real input this calculator uses."""
    db_values = FRAMEWORK_DB_VALUES.get(framework)
    if not db_values:
        return {"total": 0, "by_severity": {}}
    cur.execute("""
        SELECT UPPER(f.severity), COUNT(*)
        FROM findings f JOIN resources r ON f.resource_id = r.id
        WHERE r.cloud_account_id = %s AND f.result = 'FAIL' AND f.framework = ANY(%s)
        GROUP BY UPPER(f.severity)
    """, (cloud_account_id, db_values))
    by_severity = {sev: count for sev, count in cur.fetchall()}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        by_severity.setdefault(sev, 0)
    return {"total": sum(by_severity.values()), "by_severity": by_severity}


# Mapped-compliance-framework findings.framework values — excludes the two
# raw scanner baselines (CISAWS/FSBP) on purpose, same pattern/list as
# get-dashboard-data's MAPPED_FRAMEWORK_NAMES, so the raw dedup total below
# doesn't accidentally exclude the raw findings themselves.
_MAPPED_ONLY_DB_VALUES = tuple(
    v for code, vs in FRAMEWORK_DB_VALUES.items() if code not in ("CISAWS", "FSBP") for v in vs
)


def _raw_severity_totals(cur, cloud_account_id):
    """Real, deduplicated (one real problem counted once, not once per
    framework) open-finding count by severity for the whole account — same
    scope/exclusion the main dashboard's headline severity cards use.
    Shown as context next to the real data-breach benchmark, never
    multiplied against it."""
    cur.execute("""
        SELECT UPPER(f.severity), COUNT(*)
        FROM findings f JOIN resources r ON f.resource_id = r.id
        WHERE r.cloud_account_id = %s AND f.result = 'FAIL'
          AND (f.framework IS NULL OR f.framework NOT IN %s)
        GROUP BY UPPER(f.severity)
    """, (cloud_account_id, _MAPPED_ONLY_DB_VALUES))
    by_severity = {sev: count for sev, count in cur.fetchall()}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        by_severity.setdefault(sev, 0)
    return by_severity


def _save_scenario(conn, cloud_account_id, calculator_type, title, framework, gap_snapshot, assumptions, results, created_by):
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO calculator_scenarios
                    (cloud_account_id, calculator_type, title, framework, gap_snapshot, assumptions, results, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (cloud_account_id, calculator_type, title, framework,
                  json.dumps(gap_snapshot), json.dumps(assumptions), json.dumps(results), created_by))
            return str(cur.fetchone()[0])


def _list_scenarios(cur, cloud_account_id):
    cur.execute("""
        SELECT id, calculator_type, title, framework, gap_snapshot, assumptions, results, created_by, created_at
        FROM calculator_scenarios WHERE cloud_account_id = %s ORDER BY created_at DESC
    """, (cloud_account_id,))
    return [{
        "id": str(r[0]), "calculator_type": r[1], "title": r[2], "framework": r[3],
        "framework_label": FRAMEWORK_LABELS.get(r[3], r[3]),
        "gap_snapshot": r[4], "assumptions": r[5], "results": r[6],
        "created_by": r[7], "created_at": r[8].isoformat() if r[8] else None,
    } for r in cur.fetchall()]


def _delete_scenario(conn, scenario_id):
    with conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM calculator_scenarios WHERE id = %s", (scenario_id,))


def _resp(status, body):
    return {"statusCode": status, "headers": CORS_HEADERS, "body": json.dumps(body, default=str)}


ADMIN_MIGRATION_SQL = """
CREATE TABLE IF NOT EXISTS calculator_scenarios (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    cloud_account_id  UUID         NOT NULL REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    calculator_type   VARCHAR(30)  NOT NULL DEFAULT 'compliance_cost',
    title             VARCHAR(255) NOT NULL,
    framework         VARCHAR(100),
    gap_snapshot      JSONB        NOT NULL,
    assumptions       JSONB        NOT NULL,
    results           JSONB        NOT NULL,
    created_by        VARCHAR(255),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS calculator_scenarios_account_idx ON calculator_scenarios(cloud_account_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON calculator_scenarios TO cspm_lambda;
"""


def handler(event, context):
    if event and event.get("migrate"):
        secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
        region = os.environ.get("SECRET_REGION", "eu-west-1")
        secret = json.loads(boto3.client("secretsmanager", region_name=region).get_secret_value(SecretId=secret_name)["SecretString"])
        conn = psycopg2.connect(
            host=secret["host"], port=secret.get("port", 5432), dbname=secret["database"],
            user=secret["username"], password=secret["password"], sslmode="require", connect_timeout=10,
        )
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(ADMIN_MIGRATION_SQL)
            return {"statusCode": 200, "body": json.dumps({"migrated": True})}
        finally:
            conn.close()

    if not event or "httpMethod" not in event:
        return {"statusCode": 400, "body": json.dumps({"error": "not an API Gateway event"})}

    method = event["httpMethod"]
    if method == "OPTIONS":
        return _resp(200, {})

    qs = event.get("queryStringParameters") or {}
    body = json.loads(event["body"]) if event.get("body") else {}

    conn = _get_connection()
    try:
        if method == "GET":
            with conn.cursor() as cur:
                if qs.get("gap_data"):
                    if not _is_uuid(qs.get("gap_data")):
                        return _resp(400, {"error": "cloud_account_id must be a valid UUID"})
                    if not qs.get("framework"):
                        return _resp(400, {"error": "framework required"})
                    return _resp(200, _gap_data(cur, qs["gap_data"], qs["framework"]))
                if qs.get("list_scenarios"):
                    if not _is_uuid(qs.get("list_scenarios")):
                        return _resp(400, {"error": "cloud_account_id must be a valid UUID"})
                    return _resp(200, {"scenarios": _list_scenarios(cur, qs["list_scenarios"])})
                account_id = qs.get("cloud_account_id")
                if not _is_uuid(account_id):
                    # Still real, still useful even with no/invalid account
                    # context — the framework list and cited benchmarks are
                    # static — but never crash on a bad account_id (e.g. the
                    # literal string "null" from a page loaded before login
                    # resolved an account).
                    return _resp(200, {
                        "framework_options": [{"value": k, "label": v} for k, v in FRAMEWORK_LABELS.items()],
                        "scenarios": [],
                        "benchmarks": REAL_BENCHMARKS,
                        "raw_severity_totals": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                    })
                return _resp(200, {
                    "framework_options": [{"value": k, "label": v} for k, v in FRAMEWORK_LABELS.items()],
                    "scenarios": _list_scenarios(cur, account_id),
                    "benchmarks": REAL_BENCHMARKS,
                    "raw_severity_totals": _raw_severity_totals(cur, account_id),
                })

        if method == "POST":
            action = body.get("action")

            if action == "save_scenario":
                if body.get("calculator_type") not in CALCULATOR_TYPES:
                    return _resp(400, {"error": f"calculator_type must be one of {CALCULATOR_TYPES}"})
                if not body.get("title"):
                    return _resp(400, {"error": "title is required"})
                scenario_id = _save_scenario(
                    conn, body["cloud_account_id"], body["calculator_type"], body["title"],
                    body.get("framework"), body.get("gap_snapshot", {}), body.get("assumptions", {}),
                    body.get("results", {}), body.get("created_by", "Admin"),
                )
                return _resp(200, {"id": scenario_id})

            if action == "delete_scenario":
                _delete_scenario(conn, body["scenario_id"])
                return _resp(200, {"deleted": True})

            return _resp(400, {"error": f"unknown action: {action}"})

        return _resp(405, {"error": "method not allowed"})
    except Exception as e:
        logger.exception("calculator_handler error")
        return _resp(500, {"error": str(e)})
    finally:
        conn.close()
