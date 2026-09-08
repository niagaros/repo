# Disaster Recovery Scanning

How Niagaros checks a customer's backup/recovery posture, and how the evidence shown on the dashboard is produced. Covers RDS and DynamoDB today.

## Two different things, not one

**1. Continuous health checks — run on every scan, free, safe**

These are ordinary `BaseCheck` classes, auto-discovered by `engine/scanner.py` exactly like the S3/IAM checks. They read configuration only — no new AWS resources are created, nothing is restored.

| Check | Resource | What it verifies |
|---|---|---|
| `RDS.DR.1` | RDS instance | Automated backups enabled, retention ≥ 7 days |
| `RDS.DR.2` | RDS instance | Multi-AZ enabled (automatic failover) |
| `RDS.DR.3` | RDS instance | Deletion protection enabled |
| `RDS.DR.4` | RDS instance | Point-in-time-recovery lag ≤ 5 minutes ("backup freshness") |
| `DynamoDB.DR.1` | DynamoDB table | Point-in-time recovery enabled |
| `DynamoDB.DR.2` | DynamoDB table | Deletion protection enabled |
| `DynamoDB.DR.3` | DynamoDB table | Point-in-time-recovery lag ≤ 5 minutes ("backup freshness") |

`RDS.DR.4` / `DynamoDB.DR.3` are the important ones for ongoing assurance: they read `LatestRestorableTime` (RDS) / `LatestRestorableDateTime` (DynamoDB) and compare it to "now". A healthy, continuously-streaming backup keeps this gap in the range of seconds to a few minutes. If the underlying backup mechanism ever actually stops working, this gap grows to hours or days and the check fails persistently — that is the signal that something is broken, without ever needing to perform a real restore. This is safe to show customers on every scan.

Collector source: `backend/src/collectors/aws/rds/collector.py`, `backend/src/collectors/aws/dynamoDB/collector.py` (folder is capitalized `dynamoDB` to match a pre-existing placeholder directory — Windows treats that as identical to `dynamodb`, Python's import system and Linux in production do not, so keep the casing consistent if touching this).

**Known limitation:** `Scanner` does not currently thread a per-account region into collectors (`AWSSession.get_client()` defaults to `us-east-1`). Both collectors currently hardcode a small list of regions actually seen in practice (`eu-west-1`, `eu-north-1`). A real multi-region customer account would need this fixed properly — checking every region is a bigger change, not attempted here.

**2. Full restore tests — periodic, not free, must be scheduled deliberately**

A real point-in-time restore to a brand-new, isolated resource (never the original), with wall-clock RTO measured and item/row counts compared for integrity. This is the only way to prove a restore actually works end-to-end, but it is not something to run on every scan:

- RDS: creates a whole new `db.t3.micro`-class instance, took ~29 minutes in practice, costs money for as long as the test instance exists.
- DynamoDB: creates a new table, took ~3–3.5 minutes in practice, cheaper but still a real resource that must be cleaned up.

Results of every real restore test performed are recorded in the `dr_test_results` table (migration `backend/migrations/003_dr_test_results.sql`):

```sql
dr_test_results (
    id, cloud_account_id, resource_type, resource_name,
    rpo_seconds, rto_seconds, data_integrity_match, method, tested_at
)
```

`get-dashboard-data` returns the full history for the current account (`dr_test_results` in the response, ordered newest first); the frontend renders one card per test, tagging the newest per resource as "Most recent" — this is a timeline, not a single hardcoded snapshot.

**No automatic recurring job exists yet.** Every row currently in the table was inserted manually after a real, manually-triggered restore test. A proposed (not yet built) next step: a separate scheduled job — weekly for DynamoDB, monthly for RDS given the cost/time difference — that performs the restore, measures RPO/RTO, verifies integrity, inserts the row, and tears down the test resource itself.

## Why item/row counts can legitimately not match

For a table that holds transient data (e.g., a WebSocket-connections table), a restore reflects the state *at the restore point in time*, not the current live state. Comparing "current live count" vs "restored count" will show a mismatch whenever the source has changed since the restore point — that is expected, not a data-integrity failure. For a genuinely static/append-heavy resource (like the CSPM platform's own `cspm-db`), comparing counts at the same instant is meaningful and was done that way.

## Dashboard wiring

- `frontend/public/niagaros-dashboard.html` and `frontend/niagaros-dashboard.html` (kept in sync manually — see note below) both have:
  - A "Databases" option added to the `f-svc` filter dropdown and the `rcfg` resource-category grid (previously hardcoded to S3/IAM/CloudWatch/KMS only).
  - A `#dr-evidence-banner` panel, shown only when filtering to "Databases", with two sections: `#dr-tested-section` (real restore-test history, green cards) and `#dr-checks-grid` (live PASS/FAIL counts for the checks table above, computed client-side from the scan's own findings — nothing hardcoded).
- `get-dashboard-data/lambda_function.py` maps `RDS%` and `DynamoDB%` check-id prefixes into the same `'RDS'` service bucket (labeled "Databases" in the UI) in both the per-service-stats query and the all-findings query, and queries `dr_test_results` for the current account.

**Known drift risk:** `frontend/public/niagaros-dashboard.html` is the one Vite actually bundles; `frontend/niagaros-dashboard.html` (repo root) is a separate, previously-more-advanced copy. Both were kept in sync for every change described here, but nothing enforces that automatically — check both files when touching this panel again.

## Real example (for context, not a template to copy customer data into public docs)

Our own account (`cspm-db`, RDS): RPO 3m12s, RTO 28m34s, both restores fully verified against a real 192-resource/7,716-finding dataset. See `docs/public/security/data_protection/disaster_recovery.md` for the published version of this.
