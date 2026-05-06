import json
import boto3
import psycopg2

CORS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def get_db_connection():
    client = boto3.client("secretsmanager", region_name="eu-west-1")
    secret = json.loads(
        client.get_secret_value(SecretId="cspm/database/credentials")["SecretString"]
    )
    return psycopg2.connect(
        host=secret["host"],
        port=secret.get("port", 5432),
        dbname=secret["database"],
        user=secret["username"],
        password=secret["password"],
        sslmode="require",
        connect_timeout=10,
    )


def get_authenticated_email(event):
    """Validate Cognito access token from Authorization header. Returns email or None."""
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    try:
        cognito = boto3.client("cognito-idp", region_name="eu-west-1")
        resp = cognito.get_user(AccessToken=token)
        for attr in resp["UserAttributes"]:
            if attr["Name"] == "email":
                return attr["Value"]
    except Exception:
        return None
    return None


def lambda_handler(event, context):
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": CORS, "body": ""}

    # Validate token — all requests must be authenticated
    authenticated_email = get_authenticated_email(event)
    if not authenticated_email:
        return {
            "statusCode": 401,
            "headers": {**CORS, "Content-Type": "application/json"},
            "body": json.dumps({"error": "Unauthorized"}),
        }

    qs = event.get("queryStringParameters") or {}

    # Email lookup (React app checks if user needs onboarding)
    if qs.get("email"):
        if qs["email"] != authenticated_email:
            return {
                "statusCode": 403,
                "headers": {**CORS, "Content-Type": "application/json"},
                "body": json.dumps({"error": "Forbidden"}),
            }
        try:
            conn_check = get_db_connection()
            with conn_check.cursor() as cur:
                cur.execute(
                    "SELECT id FROM cloud_accounts WHERE owner_email = %s LIMIT 1",
                    (authenticated_email,),
                )
                row = cur.fetchone()
            conn_check.close()
            if not row:
                return {
                    "statusCode": 200,
                    "headers": {**CORS, "Content-Type": "application/json"},
                    "body": json.dumps({"needs_onboarding": True}),
                }
            account_id = str(row[0])
        except Exception as e:
            return {
                "statusCode": 200,
                "headers": {**CORS, "Content-Type": "application/json"},
                "body": json.dumps({"needs_onboarding": True, "_debug": str(e)}),
            }
    else:
        account_id = qs.get("account_id") or None

    data = {
        "accounts": [],
        "last_scan_at": "Unknown",
        "account_name": account_id[:8] if account_id else "",
        "aws_account_id": "",
        "total": None,
        "services": [],
        "by_severity": {},
        "findings": [],
        "_debug": {},
    }

    try:
        conn = get_db_connection()
    except Exception as e:
        data["_debug"]["connection"] = str(e)
        return {
            "statusCode": 500,
            "headers": {**CORS, "Content-Type": "application/json"},
            "body": json.dumps(data),
        }

    try:
        with conn.cursor() as cur:

            # ── 1. Accounts — only accounts owned by this user ───────
            try:
                cur.execute("""
                    SELECT id, account_name, account_id, last_scan_at
                    FROM cloud_accounts
                    WHERE owner_email = %s
                    ORDER BY account_name
                """, (authenticated_email,))
                for row in cur.fetchall():
                    data["accounts"].append({
                        "id":             str(row[0]),
                        "name":           row[1] or str(row[0])[:8],
                        "aws_account_id": row[2] or "",
                        "last_scan_at":   str(row[3]) if row[3] else None,
                    })
            except Exception as e:
                data["_debug"]["accounts"] = str(e)
                conn.rollback()

            # Fall back to first owned account if none specified
            if not account_id and data["accounts"]:
                account_id = data["accounts"][0]["id"]

            if not account_id:
                conn.close()
                return {
                    "statusCode": 200,
                    "headers": {**CORS, "Content-Type": "application/json"},
                    "body": json.dumps({"needs_onboarding": True}),
                }

            # ── Ownership check ──────────────────────────────────────
            try:
                cur.execute(
                    "SELECT id FROM cloud_accounts WHERE id = %s AND owner_email = %s",
                    (account_id, authenticated_email),
                )
                if not cur.fetchone():
                    conn.close()
                    return {
                        "statusCode": 403,
                        "headers": {**CORS, "Content-Type": "application/json"},
                        "body": json.dumps({"error": "Access denied"}),
                    }
            except Exception as e:
                data["_debug"]["ownership"] = str(e)
                conn.rollback()

            # ── 2. Current account metadata ─────────────────────────
            try:
                cur.execute("""
                    SELECT last_scan_at, account_name, account_id
                    FROM cloud_accounts
                    WHERE id = %s
                """, (account_id,))
                row = cur.fetchone()
                if row:
                    data["last_scan_at"]   = str(row[0]) if row[0] else "Unknown"
                    data["account_name"]   = row[1] if row[1] else account_id[:8]
                    data["aws_account_id"] = row[2] if row[2] else ""
            except Exception as e:
                data["_debug"]["meta"] = str(e)
                conn.rollback()

            # ── 3. Per-service stats ─────────────────────────────────
            try:
                cur.execute("""
                    SELECT
                        COALESCE(service, 'TOTAL') AS service,
                        COUNT(*) AS total,
                        COUNT(*) FILTER (WHERE result = 'PASS') AS passed,
                        COUNT(*) FILTER (WHERE result = 'FAIL') AS failed,
                        ROUND(COUNT(*) FILTER (WHERE result = 'PASS') * 100.0 / COUNT(*), 1) AS score
                    FROM (
                        SELECT
                            CASE
                                WHEN f.check_id LIKE 'CloudWatch%%' THEN 'CloudWatch'
                                WHEN r.resource_type IN ('cloudwatch_trail','cloudwatch_account') THEN 'CloudWatch'
                                WHEN f.check_id LIKE 'IAM%%'        THEN 'IAM'
                                WHEN f.check_id LIKE 'S3%%'         THEN 'S3'
                                WHEN f.check_id LIKE 'KMS%%'        THEN 'KMS'
                                WHEN f.check_id LIKE 'Cognito%%'    THEN 'Cognito'
                                WHEN f.check_id LIKE 'github%%'     THEN 'GitHub'
                                WHEN r.resource_type IN ('github_repository','github_organization') THEN 'GitHub'
                                WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
                                WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
                                WHEN f.framework = 'GDPR'            THEN 'GDPR'
                                WHEN f.framework = 'SOC2'            THEN 'SOC2'
                                ELSE 'Other'
                            END AS service,
                            f.result
                        FROM findings f
                        JOIN resources r ON f.resource_id = r.id
                        WHERE r.cloud_account_id = %s
                    ) sub
                    GROUP BY ROLLUP(service)
                    ORDER BY CASE COALESCE(service, 'TOTAL')
                        WHEN 'TOTAL'      THEN 0
                        WHEN 'CloudWatch' THEN 1
                        WHEN 'S3'         THEN 2
                        WHEN 'IAM'        THEN 3
                        WHEN 'KMS'        THEN 4
                        WHEN 'Cognito'    THEN 5
                        WHEN 'GitHub'     THEN 6
                        WHEN 'ISO27001'   THEN 7
                        WHEN 'NIST'       THEN 8
                        WHEN 'GDPR'       THEN 9
                        WHEN 'SOC2'       THEN 10
                        ELSE 11
                    END
                """, (account_id,))
                for row in cur.fetchall():
                    entry = {
                        "service": row[0],
                        "total":   row[1],
                        "passed":  row[2],
                        "failed":  row[3],
                        "score":   float(row[4]),
                    }
                    if row[0] == "TOTAL":
                        data["total"] = entry
                    else:
                        data["services"].append(entry)
            except Exception as e:
                data["_debug"]["services"] = str(e)
                conn.rollback()

            # ── 4. Severity breakdown ────────────────────────────────
            try:
                cur.execute("""
                    SELECT UPPER(f.severity),
                        COUNT(*),
                        COUNT(*) FILTER (WHERE f.result = 'PASS'),
                        COUNT(*) FILTER (WHERE f.result = 'FAIL')
                    FROM findings f
                    JOIN resources r ON f.resource_id = r.id
                    WHERE r.cloud_account_id = %s
                    GROUP BY UPPER(f.severity)
                """, (account_id,))
                data["by_severity"] = {
                    row[0]: {"total": row[1], "passed": row[2], "failed": row[3]}
                    for row in cur.fetchall()
                }
            except Exception as e:
                data["_debug"]["severity"] = str(e)
                conn.rollback()

            # ── 5. All findings ──────────────────────────────────────
            try:
                cur.execute("""
                    SELECT
                        f.check_id,
                        CASE
                            WHEN f.check_id LIKE 'CloudWatch%%' THEN 'CloudWatch'
                            WHEN r.resource_type IN ('cloudwatch_trail','cloudwatch_account') THEN 'CloudWatch'
                            WHEN f.check_id LIKE 'IAM%%'        THEN 'IAM'
                            WHEN f.check_id LIKE 'S3%%'         THEN 'S3'
                            WHEN f.check_id LIKE 'KMS%%'        THEN 'KMS'
                            WHEN f.check_id LIKE 'Cognito%%'    THEN 'Cognito'
                            WHEN f.check_id LIKE 'github%%'     THEN 'GitHub'
                            WHEN r.resource_type IN ('github_repository','github_organization') THEN 'GitHub'
                            WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
                            WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
                            WHEN f.framework = 'GDPR'            THEN 'GDPR'
                            WHEN f.framework = 'SOC2'            THEN 'SOC2'
                            ELSE r.resource_type
                        END AS service,
                        UPPER(f.severity) AS severity,
                        f.result,
                        f.title,
                        f.remediation,
                        r.resource_name,
                        r.resource_id,
                        f.framework
                    FROM findings f
                    JOIN resources r ON f.resource_id = r.id
                    WHERE r.cloud_account_id = %s
                    ORDER BY
                        CASE UPPER(f.severity)
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH'     THEN 2
                            WHEN 'MEDIUM'   THEN 3
                            WHEN 'LOW'      THEN 4
                            ELSE 5
                        END,
                        f.check_id
                """, (account_id,))
                data["findings"] = [
                    {
                        "check_id":      row[0],
                        "service":       row[1],
                        "severity":      row[2],
                        "result":        row[3],
                        "title":         row[4] or row[0],
                        "remediation":   row[5] or "",
                        "resource_name": row[6] or "",
                        "resource_id":   row[7] or "",
                        "framework":     row[8] or "",
                    }
                    for row in cur.fetchall()
                ]
            except Exception as e:
                data["_debug"]["findings"] = str(e)
                conn.rollback()

    except Exception as e:
        data["_debug"]["outer"] = str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    return {
        "statusCode": 200,
        "headers": {**CORS, "Content-Type": "application/json"},
        "body": json.dumps(data),
    }
