import json
import logging
import os

import boto3
import psycopg2
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)

# Mapped-compliance-framework names (findings.framework values written by the
# framework mapper Lambdas). Excluded here for the same reason they're
# excluded from the dashboard's headline score and severity cards
# (get-dashboard-data/lambda_function.py): each real misconfiguration gets
# one row per framework that also cites it, so counting every row here would
# report a client's total/passed/failed and by-severity numbers inflated by
# roughly the number of frameworks that happen to cite each check — this is
# what the monthly report emails and the dashboard's compliance_snapshots
# trend data are built from, so getting this wrong here means every scan
# snapshot and every emailed report carries the same inflated numbers.
MAPPED_FRAMEWORK_NAMES = (
    'ISO 27001:2022', 'NIST CSF v2.0', 'GDPR', 'SOC2', 'PCI DSS v4.0', 'NIS2', 'HIPAA',
    'NIST 800-53 Rev 5', 'BSI-C5', 'CSA CCM 4.0', 'FedRAMP Moderate Rev 4', 'ISO 42001',
    'ISO 27017', 'AWS FTR', 'MVSP', 'TISAX', 'HITRUST CSF', 'DORA', 'CRI Profile',
    'EU AI Act', 'NIST AI RMF', 'ISO 27701', 'ISO 27018', 'Microsoft SSPA',
    'CIS Controls v8.1', '23 NYCRR 500 (NYDFS)', 'NIST Privacy Framework',
)


def _get_credentials() -> dict:
    secret_name = os.environ.get("DB_SECRET_NAME", "cspm/database/credentials")
    sm   = boto3.client("secretsmanager")
    resp = sm.get_secret_value(SecretId=secret_name)
    return json.loads(resp["SecretString"])


class Database:

    def __init__(self):
        creds = _get_credentials()
        self.conn = psycopg2.connect(
            host            = creds["host"],
            dbname          = creds["database"],
            user            = creds["username"],
            password        = creds["password"],
            connect_timeout = 10,
        )
        self.conn.autocommit = False
        logger.info("Database: connected")

    # ── resources ─────────────────────────────────────────────────

    def upsert_resources(self, cloud_account_id: str, resources: list) -> dict:
        if not resources:
            return {}

        with self.conn.cursor() as cur:
            rows = execute_values(cur, """
                INSERT INTO resources
                    (cloud_account_id, resource_type, resource_id,
                     resource_name, region, config, last_scanned_at)
                VALUES %s
                ON CONFLICT (cloud_account_id, resource_id)
                DO UPDATE SET
                    resource_name   = EXCLUDED.resource_name,
                    region          = EXCLUDED.region,
                    config          = EXCLUDED.config,
                    last_scanned_at = clock_timestamp()
                RETURNING resource_id, id
            """, [(
                cloud_account_id,
                r["resource_type"],
                r["resource_id"],
                r.get("resource_name"),
                r.get("region"),
                json.dumps(r.get("config", {})),
            ) for r in resources],
            template="(%s, %s, %s, %s, %s, %s, clock_timestamp())", fetch=True)

        self.conn.commit()
        logger.info(f"Database: upserted {len(rows)} resources")
        return {row[0]: row[1] for row in rows}

    def current_timestamp(self):
        """Database clock (UTC, timestamp without time zone, like resources.last_scanned_at)."""
        with self.conn.cursor() as cur:
            cur.execute("SELECT clock_timestamp()::timestamp")
            now = cur.fetchone()[0]
        self.conn.rollback()  # end the read-only transaction; it must not stay open during the scan
        return now

    def prune_resources(self, cloud_account_id: str, resource_type: str, existing_ids, regions=None,
                        scan_started_at=None) -> list:
        """Deletes this account's resources of one type that AWS no longer lists.
        Findings go with them (findings.resource_id ON DELETE CASCADE). Only called by
        Scanner.run for a collector whose listing was complete and non-empty.
        regions: the regions that listing covered (None = global listing). A stored region
        may also be an availability zone of a covered region (older RDS rows: 'eu-west-1a').
        scan_started_at: only rows last seen BEFORE this scan began are pruned, so a resource
        that an overlapping scan inserted or refreshed meanwhile is never deleted."""
        if scan_started_at is None:
            raise ValueError("scan_started_at is required for pruning")
        with self.conn.cursor() as cur:
            cur.execute("""
                DELETE FROM resources
                WHERE cloud_account_id = %s AND resource_type = %s
                  AND NOT (resource_id = ANY(%s))
                  AND (%s::text[] IS NULL
                       OR region = ANY(%s::text[])
                       OR (region ~ '^[a-z]{2}(-[a-z]+)+-[0-9][a-z]$'
                           AND left(region, length(region) - 1) = ANY(%s::text[])))
                  AND last_scanned_at IS NOT NULL AND last_scanned_at < %s
                RETURNING resource_id, resource_name
            """, (cloud_account_id, resource_type, list(existing_ids),
                  None if regions is None else sorted(regions),
                  None if regions is None else sorted(regions),
                  None if regions is None else sorted(regions),
                  scan_started_at))
            rows = cur.fetchall()
        self.conn.commit()
        for resource_id, name in rows:
            logger.info(f"Database: pruned {resource_type} {name} ({resource_id}) — no longer listed by AWS")
        return [{"resource_id": r[0], "resource_name": r[1]} for r in rows]

    # ── findings ──────────────────────────────────────────────────

    def upsert_findings(self, findings: list):
        if not findings:
            return

        with self.conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO findings
                    (resource_id, check_id, framework, title,
                     remediation, severity, status, result, details)
                VALUES %s
                ON CONFLICT (resource_id, check_id)
                DO UPDATE SET
                    status      = EXCLUDED.status,
                    result      = EXCLUDED.result,
                    severity    = EXCLUDED.severity,
                    details     = EXCLUDED.details,
                    detected_at = NOW()
            """, [(
                f["resource_id"],
                f["check_id"],
                f.get("framework"),
                f["title"],
                f.get("remediation"),
                str(f["severity"]),
                "open" if f["result"] == "FAIL" else "pass",
                f["result"],
                json.dumps(f.get("details", {})),
            ) for f in findings])

        self.conn.commit()
        logger.info(f"Database: upserted {len(findings)} findings")

    # ── compliance score ───────────────────────────────────────────

    def update_compliance_score(self, cloud_account_id: str, score: dict):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE cloud_accounts
                SET compliance_score = %s,
                    last_scan_at     = NOW()
                WHERE id = %s
            """, (json.dumps(score), cloud_account_id))
        self.conn.commit()
        logger.info(f"Database: compliance score updated — {score}")

    # ── orchestrator ───────────────────────────────────────────────

    def get_active_accounts(self) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, role_arn, external_id, COALESCE(region, 'eu-west-1')
                FROM cloud_accounts
                WHERE status = 'active'
            """)
            rows = cur.fetchall()
        return [
            {"id": str(r[0]), "role_arn": r[1], "external_id": r[2], "region": r[3]}
            for r in rows
        ]

    def get_enabled_scanners(self) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT function_name, resource_type, description
                FROM scanners
                WHERE enabled = true
            """)
            rows = cur.fetchall()
        return [
            {"function_name": r[0], "resource_type": r[1], "description": r[2]}
            for r in rows
        ]

    def record_scanner_triggered(self, function_name: str):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE scanners
                SET last_triggered_at = NOW(),
                    last_status       = 'triggered',
                    total_runs        = total_runs + 1
                WHERE function_name = %s
            """, (function_name,))
        self.conn.commit()

    def record_scanner_failed(self, function_name: str, error: str):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE scanners
                SET last_triggered_at = NOW(),
                    last_status       = 'failed',
                    last_error        = %s,
                    total_runs        = total_runs + 1,
                    total_failures    = total_failures + 1
                WHERE function_name = %s
            """, (error, function_name))
        self.conn.commit()

    def record_scanner_completed(self, function_name: str):
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE scanners
                SET last_completed_at = NOW(),
                    last_status       = 'completed',
                    last_error        = NULL
                WHERE function_name = %s
            """, (function_name,))
        self.conn.commit()

    def touch_scan_at(self, cloud_account_id: str):
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE cloud_accounts SET last_scan_at = NOW() WHERE id = %s",
                (cloud_account_id,),
            )
        self.conn.commit()
        logger.info(f"Database: last_scan_at updated for {cloud_account_id}")

    def record_compliance_snapshot(self, cloud_account_id: str):
        """
        Records one 'scan' snapshot per completed orchestrator cycle — the
        full current pass/fail state, by severity, plus the exact set of
        currently-failing (check_id, resource_id) pairs. This is what lets
        the monthly report see everything that happened across the month
        (lowest point, highest point, mid-month regressions that got fixed
        again) instead of only comparing two single points a month apart.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT f.check_id, f.result, f.severity, f.title, r.id, r.resource_name
                FROM findings f
                JOIN resources r ON r.id = f.resource_id
                WHERE r.cloud_account_id = %s
                  AND (f.framework IS NULL OR f.framework NOT IN %s)
            """, (cloud_account_id, MAPPED_FRAMEWORK_NAMES))
            rows = cur.fetchall()

            total = len(rows)
            passed = sum(1 for r in rows if r[1] == "PASS")
            failed = total - passed

            by_severity = {}
            failing = []
            for check_id, result, severity, title, resource_id, resource_name in rows:
                sev = severity or "MEDIUM"
                by_severity.setdefault(sev, {"passed": 0, "failed": 0})
                by_severity[sev]["passed" if result == "PASS" else "failed"] += 1
                if result == "FAIL":
                    failing.append({
                        "check_id": check_id, "resource_id": str(resource_id),
                        "resource_name": resource_name, "severity": sev, "title": title,
                    })

            cur.execute("""
                INSERT INTO compliance_snapshots
                    (cloud_account_id, total_checks, passed, failed, by_severity, failing_keys, snapshot_type)
                VALUES (%s, %s, %s, %s, %s, %s, 'scan')
            """, (cloud_account_id, total, passed, failed, json.dumps(by_severity), json.dumps(failing)))

        self.conn.commit()
        logger.info(f"Database: compliance snapshot recorded for {cloud_account_id} ({passed}/{total})")

    # ── utils ──────────────────────────────────────────────────────

    def close(self):
        self.conn.close()
        logger.info("Database: connection closed")