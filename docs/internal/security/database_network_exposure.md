# Database network exposure — accepted risk (2026-09-22)

## The fact

`cspm-db` (Postgres, `db.t3.micro`) has `PubliclyAccessible: true` and its security group (`sg-0f5e665d86c655f0b`) allows inbound TCP 5432 from `0.0.0.0/0`. The database is reachable from the public internet by address; it is not reachable *without credentials* (see compensating controls below).

## Why it is this way, and why it is not simply fixed

Every Lambda function that reads or writes `cspm-db` runs **outside a VPC**. AWS Lambda functions without a VPC config make outbound connections from dynamically assigned addresses within AWS's own public IP space for the region — there is no fixed IP or narrow CIDR to allow instead of `0.0.0.0/0`. This was proven the hard way on 2026-09-22: removing the open rule immediately broke every Lambda's database connectivity (a ~6 minute live outage), because there was no narrower rule that also worked.

The only way to put the database behind a private network boundary is to move every Lambda into a VPC. That in turn requires outbound internet access from inside the VPC for everything those Lambdas already depend on — Cognito (every authenticated request), SES (all notification/invitation email), SNS (SMS), Secrets Manager, the Groq API (AI Agent), and (from 2026-09-22) Jira/Monday, GitHub OAuth, and Stripe. That requires a NAT gateway (~€30-35/month) or a self-managed NAT instance (~€3-4/month) — there is no free way to give a VPC-bound Lambda internet access at the scale this product already uses it.

**Decision (2026-09-22, explicit, with the user):** given a €0 budget, full network isolation is deferred. Compensating controls are applied instead.

## Compensating controls in place

1. **TLS is mandatory at the database, not just the app.** `rds.force_ssl = 1` on the parameter group. Verified live: a non-SSL connection attempt is rejected by `pg_hba.conf` matching *before* password authentication is even attempted; an SSL connection reaches the password-check stage. A network sniffer sees only encrypted traffic; credentials never cross the wire in the clear.
2. **Credentials are strong, rotated-capable, and never hard-coded** — issued from AWS Secrets Manager (`cspm/database/credentials`), least-privilege database role (`cspm_lambda`, table-level `GRANT`s only, no superuser).
3. **`DeletionProtection: true`** and **7-day automated backups with point-in-time recovery** are already active (independent of this exposure — protects against a different failure mode, data loss).
4. **Live connection-count monitoring**, added 2026-09-22: `platform-smoke` (runs every 30 minutes in AWS, plus right after every deployment) reads the real `AWS/RDS DatabaseConnections` metric via `cloudwatch:GetMetricData` (a permission the shared Lambda role already had — no new grant needed) and alerts by email if concurrent connections exceed 30. Real 7-day baseline traffic on this instance peaks at 1-2 connections, so 30 is a wide margin that will not fire on legitimate load but will catch a genuine brute-force/exhaustion attempt against the open port. Verified live on 2026-09-22: real reading was 0 connections, check passed, no false alarm.

## What would close this properly, and its real cost

Move every Lambda that touches `cspm-db` into a VPC with private subnets, plus one NAT path for their existing internet-bound calls (Cognito, SES, SNS, Secrets Manager, Groq, Jira/Monday, GitHub, Stripe):

| Option | Monthly cost | Notes |
|---|---|---|
| Self-managed NAT instance (t4g.nano) | ~€3-4 | Cheapest; one more resource to patch/monitor yourself |
| Managed NAT Gateway | ~€30-35 + data | AWS-standard, lowest maintenance |

Until one of those is funded, this document is the honest record of the residual risk and what specifically limits its impact.
