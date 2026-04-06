# Scanner Lambda

**Example function:** `cis_s3_scanner`  
**Region:** `eu-west-1` (CSPM platform account)  
**Runtime:** Python 3.9  
**Timeout:** 300s  
**Memory:** 512MB

---

## What it does

Each scanner Lambda is responsible for one AWS service. It receives a payload from the orchestrator, assumes a read-only role in the customer account, collects resources, evaluates CIS rules against them, and writes findings to the database.

---

## Input payload

The orchestrator always sends this payload:

```json
{
  "cloud_account_id": "846e9e1b-c011-43ef-a38c-4762cc9b0f5a",
  "role_arn": "arn:aws:iam::115462458880:role/CSPMScannerRole",
  "external_id": "dd3c0021-e4ba-4b5e-8593-9d385ea89a84",
  "region": "eu-north-1"
}
```

| Field | Purpose |
|---|---|
| `cloud_account_id` | Internal UUID of the customer account in the database |
| `role_arn` | IAM role to assume in the customer account |
| `external_id` | Security token required by the trust policy |
| `region` | AWS region to scan — set by orchestrator from the resources table |

---

## Four-step pipeline

### Step 1 — Assume role

The scanner uses AWS STS to assume `CSPMScannerRole` in the customer account:

```python
sts = boto3.client("sts")
creds = sts.assume_role(
    RoleArn=role_arn,
    RoleSessionName="cspm-scanner",
    ExternalId=external_id
)["Credentials"]

session = boto3.Session(
    aws_access_key_id=creds["AccessKeyId"],
    aws_secret_access_key=creds["SecretAccessKey"],
    aws_session_token=creds["SessionToken"],
    region_name=region
)
```

This session has read-only access to the customer account. No write permissions.

### Step 2 — Collect resources

The engine auto-discovers all collector classes in `collectors/aws/<service>/` at runtime using `pkgutil`. No manual registration needed.

Each collector returns a list of resource dictionaries:

```python
{
    "resource_id": "arn:aws:s3:::my-bucket",
    "resource_name": "my-bucket",
    "resource_type": "s3-bucket",
    "region": "eu-north-1",
    "config": {
        "public_access_block": {...},
        "versioning": "Enabled",
        "acl": {...},
        ...
    }
}
```

Each API call inside the collector is individually wrapped in `try/except` — a failed API call on one attribute does not stop the rest of the bucket from being collected.

### Step 3 — Persist resources

Resources are written to the `resources` table using an upsert keyed on `(cloud_account_id, resource_id)`:

```sql
INSERT INTO resources (cloud_account_id, resource_type, resource_id, resource_name, region, config)
VALUES (...)
ON CONFLICT (cloud_account_id, resource_id)
DO UPDATE SET
    config = EXCLUDED.config,
    last_scanned_at = EXCLUDED.last_scanned_at
```

Re-running a scan updates existing records rather than creating duplicates.

### Step 4 — Evaluate rules

The engine auto-discovers all rule classes in `rules/cis/<service>/` at runtime. Each rule class implements:

- `get_metadata()` — returns check_id, severity, title, remediation
- `run(resource)` — returns a `CheckResult` with status (PASS/FAIL) and details dict

Rules are only applied to resources of the matching resource type. S3 rules never run against IAM resources.

### Step 5 — Persist findings

Findings are written to the `findings` table using an upsert keyed on `(resource_id, check_id)`:

```sql
INSERT INTO findings (resource_id, check_id, title, severity, result, details, remediation)
VALUES (...)
ON CONFLICT (resource_id, check_id)
DO UPDATE SET
    result = EXCLUDED.result,
    details = EXCLUDED.details,
    severity = EXCLUDED.severity,
    detected_at = EXCLUDED.detected_at
```

**Important:** `result`, `details`, and `severity` must all be in the `DO UPDATE SET` clause. If `result` is missing the finding will never update from FAIL to PASS even when the configuration is fixed.

### Step 6 — Score

After all findings are written the scanner calculates a compliance score and writes it to `cloud_accounts`:

```json
{
  "score": 49.5,
  "total": 184,
  "passed": 91,
  "failed": 93,
  "by_severity": {
    "CRITICAL": {"passed": 22, "failed": 1},
    "HIGH": {"passed": 66, "failed": 26},
    "MEDIUM": {"passed": 3, "failed": 66}
  }
}
```

---

## Adding a new scanner

1. Create `backend/src/collectors/aws/<service>/collector.py` — inherits `BaseCollector`, implements `collect()`
2. Create rule files under `backend/src/rules/cis/<service>/` — one file per CIS control, inherits `BaseCheck`, implements `get_metadata()` and `run(resource)`
3. Deploy as a new Lambda function in the CSPM platform account
4. Insert a row in the `scanners` table:

```sql
INSERT INTO scanners (function_name, resource_type, description, standard_version)
VALUES ('my-new-scanner', 'my-resource-type', 'Description', 'CIS-6.0.0');
```

5. Insert a row in `account_resources` for the customer account so the orchestrator knows resources of that type exist:

```sql
INSERT INTO account_resources (cloud_account_id, resource_type, resource_count)
VALUES ('846e9e1b-c011-43ef-a38c-4762cc9b0f5a', 'my-resource-type', 1)
ON CONFLICT (cloud_account_id, resource_type) DO NOTHING;
```

No changes to the engine or orchestrator needed.

---

## Deploy (S3 scanner example)

From `backend/` in PowerShell:

```powershell
Copy-Item -Recurse src/api package/ -Force
Copy-Item -Recurse src/collectors package/ -Force
Copy-Item -Recurse src/config package/ -Force
Copy-Item -Recurse src/engine package/ -Force
Copy-Item -Recurse src/postprocess package/ -Force
Copy-Item -Recurse src/rules package/ -Force
Copy-Item -Recurse src/standards package/ -Force

cd package
Compress-Archive -Path * -DestinationPath ../cspm-scanner.zip -Force
cd ..

aws lambda update-function-code `
    --function-name cis_s3_scanner `
    --region eu-west-1 `
    --zip-file fileb://cspm-scanner.zip
```

---

## Cross-account IAM role

**Role name:** `CSPMScannerRole` (lives in the customer account)  
**Policy:** `CSPMReadOnlyPolicy`

The scanner assumes this role via STS. The role has read-only permissions scoped to exactly the APIs each collector needs. No write permissions anywhere.

Trust policy requires:
- Principal: CSPM platform account (225989360315)
- ExternalId: customer-specific UUID stored in `cloud_accounts.external_id`

---

## Troubleshooting

**Finding shows old FAIL after fix was deployed**  
Check the upsert in `db_writer.py` or `database.py`. The `DO UPDATE SET` clause must include `result = EXCLUDED.result`. If it only updates `detected_at` the result never changes.

**Scanner runs but collects 0 resources**  
The region in the payload does not match where the resources exist. Check what region is stored in the `resources` table and compare to what the orchestrator is sending.

**Scanner errors on one bucket but continues**  
Expected behaviour. Each API call in the collector is individually try/excepted. Check CloudWatch logs for the specific error and which bucket caused it.