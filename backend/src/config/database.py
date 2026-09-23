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

    def revoke_team_invite(self, invite_id: str, organization_id: str) -> str | None:
        """
        Scoped to organization_id so one org can't revoke another org's
        invite by guessing/enumerating an invite id.

        Returns the invited email on success (needed by the caller to log
        an invite_revoked audit event — issue #265 AC6) or None if there
        was no matching pending invite.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE team_invites
                SET status = 'revoked'
                WHERE id = %s AND organization_id = %s AND status = 'pending'
                RETURNING email
            """, (invite_id, organization_id))
            row = cur.fetchone()
        self.conn.commit()
        return row[0] if row else None

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

    def list_organization_cloud_accounts(self, organization_id: str) -> list:
        """
        cloud_accounts has no organization_id of its own (see the note on
        get_account_contact) — it's linked by owner_email to a user, so
        organization scoping has to go through users. Only 'active'
        accounts are offered for sharing; a disconnected account has no
        working dashboard to share.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT ca.id, ca.account_name, ca.account_id
                FROM cloud_accounts ca
                JOIN users u ON u.email = ca.owner_email
                WHERE u.organization_id = %s AND ca.status = 'active'
                ORDER BY ca.created_at
            """, (organization_id,))
            rows = cur.fetchall()
        return [
            {"id": str(r[0]), "account_name": r[1], "account_id": r[2]}
            for r in rows
        ]

    def create_shared_resource(self, organization_id: str, resource_name: str, created_by: str, cloud_account_id: str) -> str:
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO shared_resources (organization_id, resource_name, created_by, cloud_account_id)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (organization_id, resource_name, created_by, cloud_account_id))
            resource_id = cur.fetchone()[0]
        self.conn.commit()
        return str(resource_id)

    def list_shared_resources(self, organization_id: str) -> list:
        """
        Issue #265, acceptance criterion #5. Deliberately no join against
        who currently has "access" — every ACTIVE member of the
        organization can see every shared resource, computed fresh on
        every call. There is nothing to update when membership changes;
        the next read is simply correct.

        cloud_account_id is returned so the frontend can link straight to
        the real dashboard (niagaros-dashboard.html?account_id=...)
        instead of the share being just a name with nothing behind it.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, resource_name, resource_type, created_at, cloud_account_id
                FROM shared_resources
                WHERE organization_id = %s
                ORDER BY created_at DESC
            """, (organization_id,))
            rows = cur.fetchall()
        return [
            {
                "id": str(r[0]), "resource_name": r[1], "resource_type": r[2],
                "created_at": str(r[3]), "cloud_account_id": str(r[4]) if r[4] else None,
            }
            for r in rows
        ]

    def delete_shared_resource(self, resource_id: str, organization_id: str) -> bool:
        with self.conn.cursor() as cur:
            cur.execute(
                "DELETE FROM shared_resources WHERE id = %s AND organization_id = %s",
                (resource_id, organization_id),
            )
            deleted = cur.rowcount
        self.conn.commit()
        return deleted > 0

    def get_audit_log(self, organization_id: str, limit: int = 100) -> list:
        """
        Issue #265, acceptance criterion #6: "all user, role, and
        permission changes are available with timestamps and actor
        information." Resolves actor_user_id/target_user_id to email
        addresses via a LEFT JOIN (not an inner join — an actor who has
        since been deactivated, or a target who was never a real user
        yet, like an invite_created event, must not make the whole row
        disappear).
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT
                    al.action, al.details, al.created_at,
                    actor.email  AS actor_email,
                    target.email AS target_email
                FROM team_audit_log al
                LEFT JOIN users actor  ON actor.id  = al.actor_user_id
                LEFT JOIN users target ON target.id = al.target_user_id
                WHERE al.organization_id = %s
                ORDER BY al.created_at DESC
                LIMIT %s
            """, (organization_id, limit))
            rows = cur.fetchall()
        return [
            {
                "action": r[0], "details": r[1], "created_at": str(r[2]),
                "actor_email": r[3], "target_email": r[4],
            }
            for r in rows
        ]

    # ── audit engagements (issue #266, "Invite Auditors") ────────────

    def create_audit_engagement(
        self, organization_id: str, name: str, end_date: str, created_by: str,
        cloud_account_ids: list, auditor_emails: list,
    ) -> str:
        """Issue #266, acceptance criterion #1 — the write side."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_engagements (organization_id, name, end_date, created_by)
                VALUES (%s, %s, %s, %s)
                RETURNING id
            """, (organization_id, name, end_date, created_by))
            engagement_id = cur.fetchone()[0]
            for cloud_account_id in cloud_account_ids:
                cur.execute(
                    "INSERT INTO engagement_scope (engagement_id, cloud_account_id) VALUES (%s, %s)",
                    (engagement_id, cloud_account_id),
                )
            for email in auditor_emails:
                cur.execute(
                    "INSERT INTO engagement_auditors (engagement_id, email) VALUES (%s, %s)",
                    (engagement_id, email.strip().lower()),
                )
        self.conn.commit()
        return str(engagement_id)

    def get_engagement(self, engagement_id: str, organization_id: str) -> dict | None:
        """
        Ownership check reused by every admin-facing engagement
        sub-resource endpoint (evidence requests, activity log). Without
        this, an admin from one organization could pass another
        organization's engagement_id straight through to
        list_evidence_requests / resolve_evidence_request /
        get_engagement_activity — none of which filter by organization_id
        themselves — and read or mutate that organization's data.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT id, name, end_date FROM audit_engagements WHERE id = %s AND organization_id = %s",
                (engagement_id, organization_id),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {"id": str(row[0]), "name": row[1], "end_date": str(row[2])}

    def list_organization_engagements(self, organization_id: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, name, start_date, end_date, (end_date >= CURRENT_DATE)
                FROM audit_engagements
                WHERE organization_id = %s
                ORDER BY created_at DESC
            """, (organization_id,))
            rows = cur.fetchall()
        return [
            {
                "id": str(r[0]), "name": r[1], "start_date": str(r[2]),
                "end_date": str(r[3]), "active": bool(r[4]),
            }
            for r in rows
        ]

    def get_active_engagement_for_auditor(self, email: str) -> dict | None:
        """
        Issue #266, acceptance criterion #3's actual mechanism — same
        pattern as team_handler._get_caller's status check for issue #265
        AC5: access is computed live from end_date >= CURRENT_DATE on
        every call, so closing an engagement needs no separate revocation
        step. If an auditor somehow has more than one active engagement,
        the one ending soonest wins — the most conservative choice.
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT ae.id, ae.organization_id, ae.name, ae.end_date
                FROM engagement_auditors ea
                JOIN audit_engagements ae ON ae.id = ea.engagement_id
                WHERE ea.email = %s AND ae.end_date >= CURRENT_DATE
                ORDER BY ae.end_date ASC
                LIMIT 1
            """, (email,))
            row = cur.fetchone()
        if not row:
            return None
        return {"id": str(row[0]), "organization_id": str(row[1]), "name": row[2], "end_date": str(row[3])}

    def list_engagement_scope(self, engagement_id: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT ca.id, ca.account_name, ca.account_id
                FROM engagement_scope es
                JOIN cloud_accounts ca ON ca.id = es.cloud_account_id
                WHERE es.engagement_id = %s
            """, (engagement_id,))
            rows = cur.fetchall()
        return [{"id": str(r[0]), "account_name": r[1], "account_id": r[2]} for r in rows]

    def get_cloud_account_compliance(self, cloud_account_id: str) -> dict | None:
        """
        Issue #266, acceptance criterion #4's "evidence": the same
        compliance_score issue #269 already computes and stores per
        cloud account, not a fabricated document.
        """
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT account_name, compliance_score, last_scan_at FROM cloud_accounts WHERE id = %s",
                (cloud_account_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "account_name": row[0], "compliance_score": row[1],
            "last_scan_at": str(row[2]) if row[2] else None,
        }

    def is_cloud_account_in_engagement_scope(self, engagement_id: str, cloud_account_id: str) -> bool:
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM engagement_scope WHERE engagement_id = %s AND cloud_account_id = %s",
                (engagement_id, cloud_account_id),
            )
            return cur.fetchone() is not None

    def create_evidence_request(self, engagement_id: str, auditor_email: str, cloud_account_id: str) -> str:
        """Issue #266, acceptance criterion #2 — the request half."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO engagement_evidence_requests (engagement_id, auditor_email, cloud_account_id)
                VALUES (%s, %s, %s)
                RETURNING id
            """, (engagement_id, auditor_email, cloud_account_id))
            request_id = cur.fetchone()[0]
        self.conn.commit()
        return str(request_id)

    def list_evidence_requests(self, engagement_id: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT id, auditor_email, cloud_account_id, status, created_at
                FROM engagement_evidence_requests
                WHERE engagement_id = %s
                ORDER BY created_at DESC
            """, (engagement_id,))
            rows = cur.fetchall()
        return [
            {
                "id": str(r[0]), "auditor_email": r[1], "cloud_account_id": str(r[2]),
                "status": r[3], "created_at": str(r[4]),
            }
            for r in rows
        ]

    def resolve_evidence_request(self, request_id: str, engagement_id: str, approve: bool) -> bool:
        """
        Issue #266, acceptance criterion #2 — the approval half.
        Approving adds the requested cloud_account_id to engagement_scope,
        so the auditor's already-existing scope view (list_engagement_scope)
        grows by exactly that one account and nothing else — denying
        leaves scope untouched. Only a still-'pending' request can be
        resolved, so double-approving can't add the same account twice
        through this path (the INSERT below still no-ops safely either way).
        """
        with self.conn.cursor() as cur:
            cur.execute("""
                UPDATE engagement_evidence_requests
                SET status = %s, resolved_at = NOW()
                WHERE id = %s AND engagement_id = %s AND status = 'pending'
                RETURNING cloud_account_id
            """, ("approved" if approve else "denied", request_id, engagement_id))
            row = cur.fetchone()
            if not row:
                return False
            if approve:
                cur.execute("""
                    INSERT INTO engagement_scope (engagement_id, cloud_account_id)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (engagement_id, row[0]))
        self.conn.commit()
        return True

    def log_engagement_activity(
        self, engagement_id: str, auditor_email: str, action: str, details: dict | None = None,
    ):
        """Issue #266, acceptance criterion #4 — every auditor action
        (download, evidence request, ...) lands here, feeding directly
        into acceptance criterion #5's activity dashboard."""
        with self.conn.cursor() as cur:
            cur.execute("""
                INSERT INTO engagement_activity_log (engagement_id, auditor_email, action, details)
                VALUES (%s, %s, %s, %s)
            """, (engagement_id, auditor_email, action, json.dumps(details or {})))
        self.conn.commit()

    def get_engagement_activity(self, engagement_id: str, limit: int = 100) -> list:
        """Issue #266, acceptance criterion #5: "all logins, downloads,
        comments, and evidence requests are displayed" for an engagement."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT auditor_email, action, details, created_at
                FROM engagement_activity_log
                WHERE engagement_id = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (engagement_id, limit))
            rows = cur.fetchall()
        return [
            {"auditor_email": r[0], "action": r[1], "details": r[2], "created_at": str(r[3])}
            for r in rows
        ]

    # ── utils ──────────────────────────────────────────────────────

    def close(self):
        self.conn.close()
        logger.info("Database: connection closed")