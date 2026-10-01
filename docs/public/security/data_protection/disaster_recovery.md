# Disaster Recovery

Niagaros runs its backend on AWS's serverless services (Lambda, API Gateway), which removes most compute-layer failure modes by design. The one stateful component that a serverless architecture does not make resilient by itself is the database, so this page documents — concretely, with dated evidence — how Niagaros recovers its primary database (`cspm-db`, Amazon RDS for PostgreSQL) if it is lost or corrupted.

This page exists to close a specific gap identified in an external review of Niagaros: recovery objectives and recovery testing were not demonstrated publicly. What follows is not a policy statement — it is the actual configuration and the actual result of a real recovery test.

## Recovery objectives

| Objective | Target | Basis |
|---|---|---|
| **RPO** (Recovery Point Objective) | ≤ 15 minutes | RDS uploads the transaction log to S3 every five minutes ([AWS documentation](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html)), and the latest restorable time moves forward only after an upload has been published. Measured on `cspm-db` on 1 October 2026 (40 samples, every 30 s): the gap between "now" and the latest restorable point ranged from **3m 20s to 8m 57s** (mean 6m 6s) under normal operation. 15 minutes is that normal worst case plus one full missed upload cycle. |
| **RTO** (Recovery Time Objective) | ≤ 30 minutes | Set from the measured restore below (28m 34s), rounded up with headroom. |

## Backup configuration (as deployed today)

- **Mechanism:** Amazon RDS automated backups with point-in-time recovery (PITR).
- **Retention:** 7 days.
- **Scope:** full database (`cspm-db`), all tables.

## Test results

**Test date:** 31 August 2026

**RPO — live-measured, not estimated:** at the moment of this test, the gap between "now" and RDS's `LatestRestorableTime` on `cspm-db` was **3 minutes 12 seconds**. This is a single observation: because the transaction log is uploaded every five minutes, the gap rises and falls between roughly 3 and 9 minutes (see the RPO row above), which is why the target is ≤ 15 minutes rather than ≤ 5.

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

- `cspm-db` runs Multi-AZ since 1 October 2026 (primary in `eu-west-1a`, synchronous standby in `eu-west-1c`), so the loss of one availability zone fails over automatically. A failover has not been tested yet, so no failover time is claimed here. A full regional outage would still require a restore in another region.
- This page covers the database only. It does not cover a full application-level DR runbook (DNS, API Gateway, Lambda redeploy) since those are serverless/stateless and are not the gap this page addresses.

## The same check runs against the environments we scan

The methodology on this page — a continuous, near-zero-cost check of backup freshness (comparing "now" to the latest restorable point on every scan) plus periodic, fully isolated restore tests with measured RTO and verified data integrity — is not unique to our own infrastructure. It is the same check the Niagaros platform runs against RDS and DynamoDB resources in any AWS account it scans, surfaced on the customer's own dashboard under "Databases". We hold our own infrastructure to the same standard we check for.
