# CSPM Platform — S3 Scanner Complete Documentation

**Framework:** CIS AWS Foundations Benchmark v6.0.0  
**Status:** ✅ Deployed and verified  
**Last scan:** 23 resources collected, 184 checks run, 49.5% compliance score

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Repository Structure](#2-repository-structure)
3. [Database Schema](#3-database-schema)
4. [Components](#4-components)
5. [CIS 6.0.0 S3 Rules](#5-cis-600-s3-rules)
6. [Deployment](#6-deployment)
7. [Testing](#7-testing)
8. [Files to Remove](#8-files-to-remove)
9. [Scan Results](#9-scan-results)
10. [Next Steps](#10-next-steps)

---

## 1. Architecture Overview

The scanner runs as an AWS Lambda function. On each invocation it:

1. Receives a `cloud_account_id`, `role_arn` and `external_id` in the event payload
2. Assumes the customer's IAM role via STS (cross-account)
3. Collects all S3 buckets and their configuration from the customer account
4. Runs all CIS 6.0.0 S3 rules against every collected bucket
5. Persists resources and findings to PostgreSQL via upsert (re-runs never duplicate)
6. Calculates a compliance score and writes it back to the `cloud_accounts` table

```
Lambda Event
    │
    ▼
lambda_handler.py
    │
    ▼
Scanner (engine/scanner.py)
    ├── AWSSession → assume CSPMScannerRole in customer account
    ├── S3Collector → list buckets, collect config
    ├── CIS Rules (8 checks per bucket)
    ├── Database → upsert resources + findings
    └── Scoring → calculate + store compliance score
```

---

## 2. Repository Structure

```
backend/
├── src/
│   ├── api/
│   │   ├── __init__.py
│   │   └── lambda_handler.py          # Lambda entry point
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base_collector.py          # Abstract base class
│   │   └── aws/
│   │       ├── __init__.py
│   │       └── s3/
│   │           ├── __init__.py
│   │           └── collector.py       # S3 collector
│   ├── config/
│   │   ├── __init__.py
│   │   └── database.py                # DB persistence layer
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── aws_session.py             # STS cross-account session
│   │   └── scanner.py                 # Main orchestrator
│   ├── postprocess/
│   │   ├── __init__.py
│   │   └── scoring.py                 # Compliance score calculator
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── base_check.py              # Abstract base class
│   │   └── cis/
│   │       ├── __init__.py
│   │       └── s3/
│   │           ├── __init__.py
│   │           ├── s3_2_1.py
│   │           ├── s3_2_2.py
│   │           ├── s3_2_3.py
│   │           ├── s3_2_4.py
│   │           ├── s3_3_1.py
│   │           ├── s3_3_2.py
│   │           ├── s3_3_3.py
│   │           └── s3_3_4.py
│   └── standards/
│       ├── __init__.py
│       └── enums.py                   # Severity, Framework, ResourceType enums
├── package/                           # Lambda deployment package (generated)
├── cspm-scanner.zip                   # Lambda zip (generated)
├── payload.json                       # Test invoke payload
└── requirements.txt
```

---

## 3. Database Schema

### Migrations applied

These columns were added to the existing schema before deployment:

```sql
ALTER TABLE findings ADD COLUMN result       VARCHAR(10)  CHECK (result IN ('PASS','FAIL'));
ALTER TABLE findings ADD COLUMN framework    VARCHAR(100);
ALTER TABLE findings ADD COLUMN remediation  TEXT;
ALTER TABLE findings ADD COLUMN details      JSONB;
ALTER TABLE cloud_accounts ADD COLUMN compliance_score JSONB;
```

### How each table is used

| Table | What we write |
|---|---|
| `resources` | One row per S3 bucket. Upsert on `(cloud_account_id, resource_id)`. Updates `config` and `last_scanned_at` on re-scan. |
| `findings` | One row per bucket per CIS check. Upsert on `(resource_id, check_id)`. Updates `result`, `status`, `severity`, `details`, `detected_at` on re-scan. |
| `cloud_accounts` | Updates `compliance_score` (JSONB) and `last_scan_at` after every scan. |

### Status mapping

| Rule result | DB `result` | DB `status` |
|---|---|---|
| PASS | `PASS` | `pass` |
| FAIL | `FAIL` | `open` |

---

## 4. Components

### lambda_handler.py

Entry point. Reads `cloud_account_id`, `role_arn`, `external_id` from the event, calls `Scanner.run()`, returns the result.

**Event payload:**
```json
{
    "cloud_account_id": "846e9e1b-c011-43ef-a38c-4762cc9b0f5a",
    "role_arn":         "arn:aws:iam::115462458880:role/CSPMScannerRole",
    "external_id":      "dd3c0021-e4ba-4b5e-8593-9d385ea89a84"
}
```

**Response:**
```json
{
    "statusCode": 200,
    "body": {
        "cloud_account_id":    "846e9e1b-c011-43ef-a38c-4762cc9b0f5a",
        "resources_collected": 23,
        "checks_run":          184,
        "findings_failed":     93,
        "compliance_score": {
            "overall": 49.5,
            "passed":  91,
            "failed":  93,
            "total":   184,
            "by_severity": {
                "CRITICAL": {"passed": 22, "failed": 1,  "total": 23},
                "HIGH":     {"passed": 66, "failed": 26, "total": 92},
                "MEDIUM":   {"passed": 3,  "failed": 66, "total": 69}
            }
        }
    }
}
```

---

### aws_session.py

Assumes the customer's `CSPMScannerRole` via STS using `role_arn` and `external_id`. Returns temporary credentials scoped to that account. Credentials expire automatically after 1 hour.

---

### base_collector.py

Abstract base class all collectors extend. Enforces a consistent resource dict structure:

```python
{
    "resource_type": "s3-bucket",
    "resource_id":   "arn:aws:s3:::bucket-name",
    "resource_name": "bucket-name",
    "region":        "eu-west-1",
    "config":        { ... }
}
```

---

### S3 collector (collectors/aws/s3/collector.py)

Collects all S3 buckets in the customer account and the config fields needed for every CIS check:

| Config key | CIS checks | What it captures |
|---|---|---|
| `public_access_block` | S3.2.1, S3.2.2, S3.2.3, S3.2.4 | All 4 public access block settings |
| `is_public_acl` | S3.3.1 | Whether AllUsers grant exists on ACL |
| `ssl_required` | S3.3.2 | Whether bucket policy denies HTTP |
| `versioning` | S3.3.3 | Whether versioning is enabled |
| `mfa_delete` | S3.3.4 | Whether MFA delete is enabled |

Each API call is wrapped in a try/except so one failed bucket never stops the rest from being collected.

---

### base_check.py

Abstract base class all rules extend. Every check must implement:

- `get_metadata()` — returns check_id, framework, resource_type, severity, title, remediation
- `run(resource)` — returns a `CheckResult` with `status` (PASS/FAIL) and `details` dict

---

### scanner.py

Main orchestrator. Uses `pkgutil.walk_packages` to auto-discover all collectors and rules at runtime — no manual registration needed. Dropping a new file in the right folder is enough to include it in the next scan.

**Flow:**
1. Discover and run all collectors → `all_resources`
2. Upsert resources to DB → `id_map` (ARN → UUID)
3. Discover and run all checks against matching resources → `all_findings`
4. Upsert findings to DB
5. Calculate score → update `cloud_accounts`

---

### database.py

All DB operations. Uses `psycopg2` with `execute_values` for bulk upserts. Credentials are fetched from AWS Secrets Manager at runtime — never hardcoded.

**Secret name:** `cspm/database/credentials`  
**Secret format:**
```json
{
    "host":     "cspm-db.cdmg60gykykz.eu-west-1.rds.amazonaws.com",
    "database": "cspm_production",
    "username": "cspm_admin",
    "password": "..."
}
```

---

### scoring.py

Calculates overall compliance score as percentage of passed findings. Also breaks down by severity. Uses `f["result"]` key (PASS/FAIL) from the findings list.

---

## 5. CIS 6.0.0 S3 Rules

| Check ID | Title | Severity | Config key | FAIL condition |
|---|---|---|---|---|
| S3.2.1 | Block public ACLs | HIGH | `public_access_block.block_public_acls` | Setting is False |
| S3.2.2 | Ignore public ACLs | HIGH | `public_access_block.ignore_public_acls` | Setting is False |
| S3.2.3 | Block public bucket policies | HIGH | `public_access_block.block_public_policy` | Setting is False |
| S3.2.4 | Restrict public buckets | HIGH | `public_access_block.restrict_public_buckets` | Setting is False |
| S3.3.1 | Prohibit public read ACL | CRITICAL | `is_public_acl` | AllUsers grant exists |
| S3.3.2 | Require SSL | MEDIUM | `ssl_required` | No policy denying HTTP |
| S3.3.3 | Enable versioning | MEDIUM | `versioning` | Versioning not enabled |
| S3.3.4 | Enable MFA delete | MEDIUM | `mfa_delete` | MFA delete not enabled |

---

## 6. Deployment

### AWS accounts

| Account | ID | Role |
|---|---|---|
| CSPM platform | `225989360315` | Runs Lambda |
| Customer (Domits) | `115462458880` | Scanned by Lambda |

### Lambda configuration

| Setting | Value |
|---|---|
| Function name | `CSPMScanner` |
| Runtime | Python 3.9 |
| Handler | `api.lambda_handler.lambda_handler` |
| Timeout | 300 seconds |
| Memory | 512 MB |
| Region | eu-west-1 |
| Execution role | `arn:aws:iam::225989360315:role/CSPMScannerLambdaRole` |
| Environment variable | `DB_SECRET_NAME=cspm/database/credentials` |

### Lambda role policies

| Policy | Type | Purpose |
|---|---|---|
| `AWSLambdaBasicExecutionRole` | Managed | CloudWatch logs |
| `CSPMSecretsAccess` | Inline | Read `cspm/*` secrets |
| `CSPMAssumeRolePolicy` | Inline | `sts:AssumeRole` on `*/CSPMScannerRole` |

### Customer role (CSPMScannerRole in account 115462458880)

Trust policy allows account `225989360315` to assume it with ExternalId `dd3c0021-e4ba-4b5e-8593-9d385ea89a84`.

Permissions: S3 read-only (ListAllMyBuckets, GetBucketLocation, GetBucketPublicAccessBlock, GetBucketAcl, GetBucketPolicy, GetBucketVersioning).

### Repackage and redeploy commands

Run from `backend/` in PowerShell:

```powershell
# Clean and rebuild package
Remove-Item -Recurse -Force package/
New-Item -ItemType Directory -Force -Path package/

pip install boto3 psycopg2-binary -t package/ `
    --platform manylinux2014_x86_64 `
    --python-version 3.9 `
    --only-binary=:all: --upgrade

Copy-Item -Recurse src/api         package/ -Force
Copy-Item -Recurse src/collectors  package/ -Force
Copy-Item -Recurse src/config      package/ -Force
Copy-Item -Recurse src/engine      package/ -Force
Copy-Item -Recurse src/postprocess package/ -Force
Copy-Item -Recurse src/rules       package/ -Force
Copy-Item -Recurse src/standards   package/ -Force

cd package
Compress-Archive -Path * -DestinationPath ../cspm-scanner.zip -Force
cd ..

aws lambda update-function-code `
    --function-name CSPMScanner `
    --region eu-west-1 `
    --zip-file fileb://cspm-scanner.zip
```

---

## 7. Testing

### Local rule testing

Before deploying, all rules are tested locally with mock data using `test_rules.py`.

**Run from `backend/src/`:**
```bash
python test_rules.py
```

**Expected output:**
```
=== COMPLIANT ===
✅ PASS  S3.2.1    S3 buckets should block public ACLs
✅ PASS  S3.2.2    S3 buckets should ignore public ACLs
✅ PASS  S3.2.3    S3 buckets should block public bucket policies
✅ PASS  S3.2.4    S3 buckets should restrict public bucket access
✅ PASS  S3.3.1    S3 buckets should not be publicly readable via ACL
✅ PASS  S3.3.2    S3 buckets should deny HTTP requests
✅ PASS  S3.3.3    S3 buckets should have versioning enabled
✅ PASS  S3.3.4    S3 buckets should have MFA delete enabled

=== NON-COMPLIANT ===
❌ FAIL  S3.2.1    S3 buckets should block public ACLs
❌ FAIL  S3.2.2    S3 buckets should ignore public ACLs
❌ FAIL  S3.2.3    S3 buckets should block public bucket policies
❌ FAIL  S3.2.4    S3 buckets should restrict public bucket access
❌ FAIL  S3.3.1    S3 buckets should not be publicly readable via ACL
❌ FAIL  S3.3.2    S3 buckets should deny HTTP requests
❌ FAIL  S3.3.3    S3 buckets should have versioning enabled
❌ FAIL  S3.3.4    S3 buckets should have MFA delete enabled
```

### Lambda invoke test

**payload.json** (kept in `backend/` for testing):
```json
{
    "cloud_account_id": "846e9e1b-c011-43ef-a38c-4762cc9b0f5a",
    "role_arn":         "arn:aws:iam::115462458880:role/CSPMScannerRole",
    "external_id":      "dd3c0021-e4ba-4b5e-8593-9d385ea89a84"
}
```

**Invoke command:**
```powershell
aws lambda invoke `
    --function-name CSPMScanner `
    --region eu-west-1 `
    --payload fileb://payload.json `
    response.json

Get-Content response.json
```

### Database verification queries

```sql
-- 1. Resources collected
SELECT resource_name, region, last_scanned_at
FROM resources
WHERE cloud_account_id = '846e9e1b-c011-43ef-a38c-4762cc9b0f5a'
ORDER BY resource_name;

-- 2. Findings breakdown per check
SELECT f.check_id, f.severity, f.result, count(*)
FROM findings f
JOIN resources r ON f.resource_id = r.id
WHERE r.cloud_account_id = '846e9e1b-c011-43ef-a38c-4762cc9b0f5a'
GROUP BY f.check_id, f.severity, f.result
ORDER BY f.severity, f.check_id;

-- 3. Compliance score
SELECT compliance_score, last_scan_at
FROM cloud_accounts
WHERE id = '846e9e1b-c011-43ef-a38c-4762cc9b0f5a';

-- 4. Check for duplicates (should always return 0)
SELECT resource_id, check_id, count(*)
FROM findings
GROUP BY resource_id, check_id
HAVING count(*) > 1;
```

---

## 8. Files to Remove

These files were used during development and testing only. They should not be committed to the main branch or left in production.

| File | Location | Reason |
|---|---|---|
| `test_rules.py` | `backend/src/test_rules.py` | Local test script, not needed in Lambda |
| `TestRulesRobin.py` | `backend/src/TestRulesRobin.py` | Local test script, not needed in Lambda |
| `payload.json` | `backend/payload.json` | Contains real account ID, role ARN and external ID — do not commit |
| `response.json` | `backend/response.json` | Lambda invoke output, not needed |
| `package/` | `backend/package/` | Generated deployment folder — should be in `.gitignore` |
| `cspm-scanner.zip` | `backend/cspm-scanner.zip` | Generated deployment zip — should be in `.gitignore` |

### Add to .gitignore

Make sure `backend/.gitignore` contains:

```
package/
cspm-scanner.zip
response.json
payload.json
__pycache__/
*.pyc
*.pyo
.env
```

---

## 9. Scan Results

First real scan against Domits AWS account (`115462458880`):

| Metric | Value |
|---|---|
| Buckets scanned | 23 |
| Total checks run | 184 (23 × 8) |
| Passed | 91 |
| Failed | 93 |
| Overall score | 49.5% |

**By severity:**

| Severity | Passed | Failed | Total |
|---|---|---|---|
| CRITICAL | 22 | 1 | 23 |
| HIGH | 66 | 26 | 92 |
| MEDIUM | 3 | 66 | 69 |

**Key findings:**
- 1 bucket is publicly readable via ACL (S3.3.1 CRITICAL)
- 6-7 buckets have public access block settings disabled (S3.2.1–S3.2.4)
- All 23 buckets fail SSL enforcement (S3.3.2) — no bucket policies denying HTTP
- 20 out of 23 buckets have versioning disabled (S3.3.3)
- All 23 buckets have MFA delete disabled (S3.3.4)

---

## 10. Next Steps

| Priority | What | Why |
|---|---|---|
| High | Build IAM collector + CIS IAM rules | Next compliance domain after S3 |
| High | Add CloudTrail collector | Needed for S3.3.3 object-level logging checks |
| Medium | Add EventBridge schedule | Trigger scans automatically on a schedule |
| Medium | Add multi-account support | Scan all active accounts in one engine invocation |
| Low | Add EC2 collector + CIS EC2 rules | Expand coverage |
| Low | Add SNS/Slack notifications | Alert on new CRITICAL findings |