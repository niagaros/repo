# CSPM Database Schema – Current MVP (Aurora PostgreSQL on AWS RDS)

This document describes the **current, active** CSPM database schema running on Aurora PostgreSQL in AWS RDS.  
It focuses on how data is structured today, not on how to install the database (see `aws_rds_installation.md` for installation details).

The schema consists of four core tables:
- `users`
- `cloud_accounts`
- `resources`
- `findings`

They are related exactly as shown in the ERD (`docs/Images/aws_ERD_v1.png`):
`users → cloud_accounts → resources → findings`.

---

## `users` – Cognito users in the CSPM platform

Each record in `users` represents one person authenticated via Amazon Cognito.

| Column       | Type      | Constraints       | Description                       |
|-------------|-----------|-------------------|-----------------------------------|
| `id`        | `uuid`    | PK                | Internal user ID                  |
| `cognito_sub` | `varchar` | UNIQUE, NOT NULL | Cognito User ID (`sub` claim)     |
| `email`     | `varchar` | UNIQUE, NOT NULL  | User email address                |
| `full_name` | `varchar` | nullable          | Display name                      |
| `created_at`| `timestamp` | default `now()` | When the user was created         |

**How it is used now**
- Filled by the **Cognito Post‑Confirmation Lambda** when a user signs up.
- `cognito_sub` links JWTs from Cognito to internal data.
- `email` is used for dashboards and filtering (e.g. “my stats”).

**Relationship**
- One `user` **owns many** `cloud_accounts` (`cloud_accounts.user_id` FK → `users.id`). 

---

## `cloud_accounts` – Customer AWS accounts to scan

Each record represents one AWS account that a user has connected for CSPM scanning.

| Column         | Type      | Constraints       | Description                                      |
|----------------|-----------|-------------------|--------------------------------------------------|
| `id`           | `uuid`    | PK                | Internal ID for the connected AWS account       |
| `user_id`      | `uuid`    | FK → `users.id`   | Owner in the CSPM platform                       |
| `account_id`   | `varchar` | NOT NULL          | AWS Account ID (12‑digit)                        |
| `account_name` | `varchar` | nullable          | Friendly name (e.g. “Prod – EU”)                 |
| `role_arn`     | `varchar` | NOT NULL          | IAM role ARN used for cross‑account scanning     |
| `external_id`  | `varchar` | nullable          | Security token for the IAM trust policy          |
| `status`       | `varchar` | default `active`  | `active` / `error` / `disconnected`              |
| `last_scan_at` | `timestamp` | nullable        | When this account was last scanned               |
| `created_at`   | `timestamp` | default `now()` | When the account link was created                |

**How it is used now**
- The scanner assumes **one row per AWS account per user**.
- `status` indicates whether scanning is currently healthy for that account.
- `last_scan_at` is updated after a successful scan run.

**Relationship**
- One `cloud_accounts` record **contains many** `resources` (`resources.cloud_account_id` FK → `cloud_accounts.id`). 

---

## `resources` – Discovered AWS resources

`resources` stores every scanned AWS resource (S3, EC2, RDS, etc.) in a generic way.

| Column            | Type      | Constraints                | Description                                   |
|-------------------|-----------|----------------------------|-----------------------------------------------|
| `id`              | `uuid`    | PK                         | Internal resource ID                          |
| `cloud_account_id`| `uuid`    | FK → `cloud_accounts.id`   | AWS account that owns this resource          |
| `resource_type`   | `varchar` | NOT NULL                   | Resource type (e.g. `s3-bucket`, `ec2-instance`, `rds-database`) |
| `resource_id`     | `varchar` | UNIQUE per account         | Usually the AWS ARN                           |
| `resource_name`   | `varchar` | nullable                   | Friendly name / tag                           |
| `region`          | `varchar` | nullable                   | AWS region (e.g. `eu-west-1`)                 |
| `config`          | `jsonb`   | NOT NULL                   | Full current configuration snapshot           |
| `last_scanned_at` | `timestamp` | nullable                 | Last time this specific resource was scanned  |

**How it is used now**
- The scanner writes/updates one row per discovered resource.
- `resource_type` drives which checks are run (e.g. S3‑specific vs EC2‑specific checks).
- `config` is the **source of truth** for security checks; it mirrors AWS APIs (e.g. S3 bucket policy, encryption flags, public access settings).

**Relationship**
- One `resource` **has many** `findings` (`findings.resource_id` FK → `resources.id`).

---

## `findings` – Security issues on resources

`findings` stores the output of all security checks run against resources.

| Column        | Type      | Constraints              | Description                                      |
|---------------|-----------|--------------------------|--------------------------------------------------|
| `id`          | `uuid`    | PK                       | Internal finding ID                              |
| `resource_id` | `uuid`    | FK → `resources.id`      | Resource on which this finding was detected      |
| `check_id`    | `varchar` | UNIQUE per `resource_id` | Identifier of the security check (e.g. `AWS-S3-001`) |
| `title`       | `varchar` | NOT NULL                 | Short title (e.g. “S3 bucket is public”)        |
| `description` | `text`    | nullable                 | Detailed explanation and remediation hints      |
| `severity`    | `varchar` | NOT NULL                 | `critical` / `high` / `medium` / `low`          |
| `status`      | `varchar` | default `open`           | `open` / `resolved`                             |
| `detected_at` | `timestamp` | default `now()`        | When this finding was first detected            |

**How it is used now**
- Each check produces at most **one row per resource + check** (enforced via `UNIQUE(resource_id, check_id)`).
- Dashboards and APIs filter primarily on `status = 'open'` and higher `severity` levels.
- When an issue is fixed or suppressed, `status` is set to `resolved` (the row is kept for history/metrics).

---

## End‑to‑end example (based on the ERD)

From the ERD image (`aws_ERD_v1.png`), a typical flow looks like this:
1. A Cognito user signs up → a row is created in `users`.
2. That user connects their AWS account → a row in `cloud_accounts` with `role_arn` and `external_id`.
3. The scanner enumerates resources in that AWS account → multiple rows in `resources` (S3 buckets, EC2 instances, RDS databases, …) with detailed JSON `config`.
4. Security checks run on each resource → zero or more rows in `findings` for every misconfiguration, tagged with `check_id`, `severity` and `status`.

This is the **only schema that is live right now** for CSPM data: no job, history, or remediation tables are active yet. Future iterations can extend this ERD, but all core dashboards and scans today are powered by these four tables and their relationships.
