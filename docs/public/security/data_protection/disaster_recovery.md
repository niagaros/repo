# Disaster Recovery

Niagaros runs its backend on AWS's serverless services (Lambda, API Gateway), which removes most compute-layer failure modes by design. The one stateful component that a serverless architecture does not make resilient by itself is the database, so this page documents — concretely, with dated evidence — how Niagaros recovers its primary database (`cspm-db`, Amazon RDS for PostgreSQL) if it is lost or corrupted.

This page exists to close a specific gap identified in an external review of Niagaros: recovery objectives and recovery testing were not demonstrated publicly. What follows is not a policy statement — it is the actual configuration and the actual result of a real recovery test.

## Recovery objectives

| Objective | Target | Basis |
|---|---|---|
| **RPO** (Recovery Point Objective) | ≤ 5 minutes | RDS automated backups continuously ship the transaction log, enabling point-in-time recovery to any second within the retention window. 5 minutes is AWS's documented typical replication lag for this mechanism — no additional infrastructure is required to meet it. |
| **RTO** (Recovery Time Objective) | ≤ 30 minutes | Set from the measured restore below (28m 34s), rounded up with headroom. |

## Backup configuration (as deployed today)

- **Mechanism:** Amazon RDS automated backups with point-in-time recovery (PITR).
- **Retention:** 7 days.
- **Scope:** full database (`cspm-db`), all tables.

## Test results

**Test date:** 31 August 2026

**RPO — live-measured, not estimated:** at the moment of this test, the gap between "now" and RDS's `LatestRestorableTime` on `cspm-db` was **3 minutes 12 seconds**. This is the real, observed point-in-time-recovery lag, confirming the ≤5-minute target above is realistic under normal load.

**Command used** (no proprietary tooling — reproducible by anyone with equivalent RDS access):
```
aws rds restore-db-instance-to-point-in-time \
  --source-db-instance-identifier cspm-db \
  --target-db-instance-identifier cspm-db-dr-test-20260831 \
  --use-latest-restorable-time \
  --db-instance-class db.t3.micro \
  --db-subnet-group-name default \
  --vpc-security-group-ids sg-0f5e665d86c655f0b
```

**RTO — measured, wall-clock:**

| | Time (UTC) |
|---|---|
| Restore started | 20:34:28 |
| Restored instance reached `available` | 21:03:02 |
| **Measured recovery time** | **28 minutes 34 seconds** |

**Data integrity check:** row counts compared between the source (`cspm-db`) and the restored instance (`cspm-db-dr-test-20260831`) immediately after restore:

| Table | Source | Restored | Match |
|---|---|---|---|
| `resources` | 192 | 192 | ✅ |
| `findings` | 7,716 | 7,716 | ✅ |
| `cloud_accounts` | 3 | 3 | ✅ |

The restored instance was a temporary, isolated resource used only for this test and was torn down afterward — it was never used to serve traffic, and `cspm-db` itself was never modified or interrupted at any point during this test.

## What this does not yet cover

- `cspm-db` currently runs single-AZ (no Multi-AZ automatic failover). A regional/AZ outage would require a manual restore rather than an automatic failover. Enabling Multi-AZ is a recommended follow-up — it changes the live production instance and is a separate decision from this test.
- This page covers the database only. It does not cover a full application-level DR runbook (DNS, API Gateway, Lambda redeploy) since those are serverless/stateless and are not the gap this page addresses.
