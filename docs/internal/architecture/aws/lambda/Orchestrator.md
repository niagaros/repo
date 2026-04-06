# Orchestrator Lambda

**Function name:** `cspm_orchestrator`  
**Region:** `eu-west-1`  
**Runtime:** Python 3.9  
**Timeout:** 60s  
**Memory:** 256MB  
**Trigger:** Amazon EventBridge — daily cron at 02:00 UTC

---

## What it does

The orchestrator is a lightweight coordinator. It does not scan anything itself. Its only job is to:

1. Read all active customer accounts from the database
2. Read all enabled scanners from the database
3. Look up which regions each resource type exists in
4. Invoke the correct scanner Lambda once per account per region
5. Record the trigger status back to the database

---

## How it works

### Step 1 — Load accounts and scanners

```python
accounts = db.get_active_accounts()
scanners = db.get_enabled_scanners()
```

- `get_active_accounts()` queries the `cloud_accounts` table for all rows where `status = 'active'`
- `get_enabled_scanners()` queries the `scanners` table for all rows where `enabled = true`

### Step 2 — Get regions per resource type

```python
regions = db.get_resource_regions(account["id"], scanner["resource_type"])
```

Queries the `resources` table for all distinct regions where that resource type has been seen for that account. This means the orchestrator only scans regions where resources actually exist.

Special cases:
- If no regions found yet → falls back to `eu-west-1`
- If regions is `["global"]` (IAM) → converted to `eu-west-1` for the API call region

### Step 3 — Invoke the scanner

For each account × scanner × region combination:

```python
client.invoke(
    FunctionName   = scanner["function_name"],
    InvocationType = "Event",   # async, fire and forget
    Payload        = json.dumps({
        "cloud_account_id": account["id"],
        "role_arn":         account["role_arn"],
        "external_id":      account["external_id"],
        "region":           region,
    }),
)
```

Invocation is **async** (`InvocationType = "Event"`). The orchestrator does not wait for the scanner to finish. If the scanner crashes, the orchestrator does not know — check CloudWatch logs for each scanner function individually.

### Step 4 — Retry logic

Each invocation has up to 3 attempts with exponential backoff:

```
Attempt 1 → fail → wait 1s
Attempt 2 → fail → wait 2s
Attempt 3 → fail → record as failed
```

### Step 5 — Record result

After each scanner invocation:
- Success → `db.record_scanner_triggered(function_name)`
- All retries failed → `db.record_scanner_failed(function_name, error)`

This updates `last_triggered_at`, `last_status`, `total_runs`, and `total_failures` in the `scanners` table.

---

## Database tables used

| Table | Operation | Purpose |
|---|---|---|
| `cloud_accounts` | SELECT | Get active accounts with role_arn and external_id |
| `scanners` | SELECT | Get enabled scanner function names and resource types |
| `resources` | SELECT DISTINCT region | Get which regions to scan per resource type |
| `scanners` | UPDATE | Record trigger status and timestamps |

---

## Environment variables

| Variable | Value | Purpose |
|---|---|---|
| `DB_SECRET_NAME` | `cspm/database/credentials` | Secrets Manager secret for DB credentials |

---

## IAM role

**Role name:** `CSPMOrchestratorRole`  
**Policy:** `OrchestratorPolicy`

Permissions:
```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:eu-west-1:225989360315:secret:cspm/*"
    },
    {
      "Effect": "Allow",
      "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:eu-west-1:225989360315:function:*"
    }
  ]
}
```

---

## Deploy

From `backend/` in PowerShell:

```powershell
aws sso login --profile niagaros-cspm
$env:AWS_PROFILE = "niagaros-cspm"

Copy-Item -Recurse src/orchestrator package/ -Force
Copy-Item -Recurse src/config package/ -Force

cd package
Compress-Archive -Path * -DestinationPath ../cspm-orchestrator.zip -Force
cd ..

aws lambda update-function-code `
    --function-name cspm_orchestrator `
    --region eu-west-1 `
    --zip-file fileb://cspm-orchestrator.zip
```

---

## Invoke manually

```powershell
'{}' | Out-File -FilePath orchestrator-payload.json -Encoding utf8

aws lambda invoke `
    --function-name cspm_orchestrator `
    --region eu-west-1 `
    --payload fileb://orchestrator-payload.json `
    orchestrator-response.json ; Get-Content orchestrator-response.json
```

### Expected response

```json
{
  "accounts": 1,
  "scanners": 4,
  "triggered": 6,
  "failed": 0,
  "results": [
    {"scanner": "cis_s3_scanner", "resource_type": "s3-bucket", "region": "eu-north-1", "status": "triggered"},
    {"scanner": "cis_s3_scanner", "resource_type": "s3-bucket", "region": "eu-west-1", "status": "triggered"},
    {"scanner": "cis_s3_scanner", "resource_type": "s3-bucket", "region": "eu-west-2", "status": "triggered"},
    {"scanner": "cloudwatch-cis-scanner", "resource_type": "cloudwatch_trail", "region": "eu-north-1", "status": "triggered"},
    {"scanner": "Iam-cis-scanner", "resource_type": "iam-account", "region": "eu-west-1", "status": "triggered"},
    {"scanner": "kms-cis-scanner", "resource_type": "kms-key", "region": "eu-north-1", "status": "triggered"}
  ]
}
```

Note: triggered count is higher than scanner count because S3 fires once per region.

---

## Troubleshooting

**Scanner shows `last_triggered_at` but `last_completed_at` is empty**  
The orchestrator triggered it but the scanner errored. Check CloudWatch logs for that specific scanner Lambda.

**triggered count is lower than expected**  
A resource type has no rows in the `resources` table yet. The orchestrator falls back to `eu-west-1`. Run the scanner manually first to populate the resources table, then the orchestrator will pick up the correct region on the next run.

**All retries failed**  
Check the IAM policy on `CSPMOrchestratorRole` — the `lambda:InvokeFunction` permission must cover the scanner function name.