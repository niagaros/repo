import json
import logging
import os

import boto3
import psycopg2
from psycopg2.extras import execute_values

logger = logging.getLogger(__name__)


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
                     resource_name, region, config)
                VALUES %s
                ON CONFLICT (cloud_account_id, resource_id)
                DO UPDATE SET
                    resource_name   = EXCLUDED.resource_name,
                    region          = EXCLUDED.region,
                    config          = EXCLUDED.config,
                    last_scanned_at = NOW()
                RETURNING resource_id, id
            """, [(
                cloud_account_id,
                r["resource_type"],
                r["resource_id"],
                r.get("resource_name"),
                r.get("region"),
                json.dumps(r.get("config", {})),
            ) for r in resources], fetch=True)

        self.conn.commit()
        logger.info(f"Database: upserted {len(rows)} resources")
        return {row[0]: row[1] for row in rows}

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
            """, (cloud_account_id,))
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