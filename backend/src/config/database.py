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

    # ── account connectivity (issue #269, acceptance criterion #4) ──
    # "Given a cloud credential is revoked or expired, when detection
    #  occurs, then ingestion is paused and admin is notified."

    def mark_account_disconnected(self, cloud_account_id: str, reason: str):
        """
        Flips a cloud_accounts row to status='disconnected' so that
        get_active_accounts() (WHERE status = 'active') stops picking it
        up — this is what "pauses ingestion" for the account.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE cloud_accounts SET status = 'disconnected' WHERE id = %s",
                (cloud_account_id,),
            )
        self.conn.commit()
        logger.warning(
            f"Database: marked cloud_account_id={cloud_account_id} as disconnected — {reason}"
        )

    def get_account_contact(self, cloud_account_id: str) -> dict | None:
        """
        Returns {"owner_email": ..., "aws_account_id": ...} for notification
        purposes, or None if the account no longer exists.

        Note: uses cloud_accounts.owner_email directly, matching the column
        actually queried by get-dashboard-data/lambda_function.py in
        production — not the users.id join described in aws_rds.md, which
        appears to be out of date. Worth reconciling the docs separately.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT owner_email, account_id FROM cloud_accounts WHERE id = %s",
                (cloud_account_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"owner_email": row[0], "aws_account_id": row[1]}

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

    # ── team (issue #265, "Invite Team") ─────────────────────────────

    def get_user_by_email(self, email: str) -> dict | None:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, email, full_name, organization_id, role, status
                FROM users
                WHERE email = %s
            """, (email,))
            row = cur.fetchone()
        if not row:
            return None
        return {
            "id": str(row[0]), "email": row[1], "full_name": row[2],
            "organization_id": str(row[3]), "role": row[4], "status": row[5],
        }

    def get_organization(self, organization_id: str) -> dict | None:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, mfa_required FROM organizations WHERE id = %s",
                (organization_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"id": str(row[0]), "name": row[1], "mfa_required": row[2]}

    def set_organization_mfa_policy(self, organization_id: str, required: bool) -> bool:
        """Issue #265, acceptance criterion #3 — the policy half."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE organizations SET mfa_required = %s WHERE id = %s",
                (required, organization_id),
            )
            updated = cur.rowcount
        self.conn.commit()
        return updated > 0

    def get_organization_members(self, organization_id: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, email, full_name, role, status, created_at
                FROM users
                WHERE organization_id = %s
                ORDER BY created_at
            """, (organization_id,))
            rows = cur.fetchall()
        return [
            {
                "id": str(r[0]), "email": r[1], "full_name": r[2],
                "role": r[3], "status": r[4], "created_at": str(r[5]),
            }
            for r in rows
        ]

    def create_team_invite(self, organization_id: str, email: str, role: str, invited_by: str) -> str:
        """
        Raises psycopg2.errors.UniqueViolation (caller's responsibility to
        catch) if `email` already has a pending/accepted invite for this
        organization — team_invites(organization_id, email) is UNIQUE.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO team_invites (organization_id, email, role, invited_by)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (organization_id, email, role, invited_by))
            invite_id = cur.fetchone()[0]
        self.conn.commit()
        logger.info(f"Database: created team invite {invite_id} for {email} (role={role})")
        return str(invite_id)

    def list_pending_invites(self, organization_id: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, email, role, created_at
                FROM team_invites
                WHERE organization_id = %s AND status = 'pending'
                ORDER BY created_at
            """, (organization_id,))
            rows = cur.fetchall()
        return [
            {"id": str(r[0]), "email": r[1], "role": r[2], "created_at": str(r[3])}
            for r in rows
        ]

    def revoke_team_invite(self, invite_id: str, organization_id: str) -> bool:
        """
        Scoped to organization_id so one org can't revoke another org's
        invite by guessing/enumerating an invite id.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE team_invites
                SET status = 'revoked'
                WHERE id = %s AND organization_id = %s AND status = 'pending'
            """, (invite_id, organization_id))
            updated = cur.rowcount
        self.conn.commit()
        return updated > 0

    def accept_pending_invite(self, user_id: str, email: str) -> dict | None:
        """
        Issue #265, acceptance criterion #1: "Given an administrator
        invites a new user, when the invitation is accepted, then the
        user is provisioned with the assigned role and team."

        Called once after a user's first login (see useRequireAuth.ts).
        The user already exists by then (Cognito's own, untouched
        post-confirmation flow created them, landing them in their own
        auto-created solo organization — see the trigger in
        002_organizations_and_team.sql). This looks for a pending invite
        matching their email and, if found, moves them into that invite's
        organization/role and marks it accepted.

        Returns the new {"organization_id", "role"}, or None if there was
        no pending invite (the normal case for anyone who signed up
        without being invited — a harmless no-op, not an error).
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, organization_id, role FROM team_invites
                WHERE email = %s AND status = 'pending'
                ORDER BY created_at
                LIMIT 1
            """, (email,))
            invite = cur.fetchone()
            if not invite:
                return None
            invite_id, organization_id, role = invite

            cur.execute(
                "UPDATE users SET organization_id = %s, role = %s WHERE id = %s",
                (organization_id, role, user_id),
            )
            cur.execute(
                "UPDATE team_invites SET status = 'accepted', accepted_at = NOW() WHERE id = %s",
                (invite_id,),
            )
        self.conn.commit()
        logger.info(f"Database: user {user_id} accepted invite {invite_id} into organization {organization_id}")
        return {"organization_id": str(organization_id), "role": role}

    def update_user_role(self, user_id: str, organization_id: str, new_role: str) -> bool:
        """Issue #265, acceptance criterion #2, the 'updated immediately' half."""
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET role = %s WHERE id = %s AND organization_id = %s",
                (new_role, user_id, organization_id),
            )
            updated = cur.rowcount
        self.conn.commit()
        return updated > 0

    def log_audit_event(
        self, organization_id: str, actor_user_id: str, action: str,
        target_user_id: str | None = None, details: dict | None = None,
    ):
        """
        Issue #265, acceptance criterion #2, the 'and logged' half (and the
        groundwork for criterion #6's broader audit log). Generic on
        purpose — see the comment in 003_role_changes_audit_log.sql for why
        `action` is free text rather than one column per event type.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO team_audit_log
                    (organization_id, actor_user_id, action, target_user_id, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (organization_id, actor_user_id, action, target_user_id, json.dumps(details or {})))
        self.conn.commit()

    def get_user_by_id(self, user_id: str, organization_id: str) -> dict | None:
        """
        Scoped to organization_id — same cross-tenant protection as every
        other team_handler.py query, so one company can't look up another
        company's user by guessing/enumerating a user_id.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, email, cognito_sub, role, status FROM users
                WHERE id = %s AND organization_id = %s
            """, (user_id, organization_id))
            row = cur.fetchone()
        if not row:
            return None
        return {"id": str(row[0]), "email": row[1], "cognito_sub": row[2], "role": row[3], "status": row[4]}

    def reassign_owned_cloud_accounts(self, from_email: str, to_email: str) -> int:
        """
        Issue #265, acceptance criterion #4, the 'owned resources are
        reassigned' half. Only covers cloud_accounts — the PVA's broader
        'Shared Resources' list (dashboards, reports, API keys, ...) is a
        much bigger, separate feature area that's out of scope here.
        Returns how many accounts were moved.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE cloud_accounts SET owner_email = %s WHERE owner_email = %s",
                (to_email, from_email),
            )
            count = cur.rowcount
        self.conn.commit()
        return count

    def deactivate_user(self, user_id: str, organization_id: str) -> bool:
        """
        Soft-remove: flips status rather than deleting the row, so past
        findings/audit entries tied to this user_id stay intact. Scoped to
        organization_id for the same reason as revoke_team_invite.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET status = 'deactivated'
                WHERE id = %s AND organization_id = %s
            """, (user_id, organization_id))
            updated = cur.rowcount
        self.conn.commit()
        logger.warning(f"Database: deactivated user {user_id} in organization {organization_id}")
        return updated > 0

    # ── utils ──────────────────────────────────────────────────────

    def close(self):
        self.conn.close()
        logger.info("Database: connection closed")