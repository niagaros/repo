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
    """
    Handles all database operations.
    Uses upsert so re-running a scan updates existing records
    instead of creating duplicates.
    """

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
        """
        Insert or update resources.
        Returns mapping of resource_id -> database UUID.
        """
        if not resources:
            return {}

        with self.conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO resources
                    (cloud_account_id, resource_type, resource_id,
                     resource_name, region, config)
                VALUES %s
                ON CONFLICT (cloud_account_id, resource_type, resource_id)
                DO UPDATE SET
                    resource_name = EXCLUDED.resource_name,
                    region        = EXCLUDED.region,
                    config        = EXCLUDED.config,
                    discovered_at = NOW()
                RETURNING resource_id, id
            """, [(
                cloud_account_id,
                r["resource_type"],
                r["resource_id"],
                r.get("resource_name"),
                r.get("region"),
                json.dumps(r.get("config", {})),
            ) for r in resources], fetch=True)
            rows = cur.fetchall()

        self.conn.commit()
        logger.info(f"Database: upserted {len(rows)} resources")
        return {row[0]: row[1] for row in rows}

    # ── findings ──────────────────────────────────────────────────

    def upsert_findings(self, findings: list):
        """
        Insert or update findings.
        Re-running a scan updates status instead of duplicating rows.
        """
        if not findings:
            return

        with self.conn.cursor() as cur:
            execute_values(cur, """
                INSERT INTO findings
                    (resource_id, check_id, framework, title,
                     description, remediation, severity, status, details)
                VALUES %s
                ON CONFLICT (resource_id, check_id)
                DO UPDATE SET
                    status   = EXCLUDED.status,
                    severity = EXCLUDED.severity,
                    details  = EXCLUDED.details,
                    found_at = NOW()
            """, [(
                f["resource_id"],
                f["check_id"],
                str(f["framework"]),
                f["title"],
                f.get("description"),
                f.get("remediation"),
                str(f["severity"]),
                f["status"],
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

    def close(self):
        self.conn.close()
        logger.info("Database: connection closed")