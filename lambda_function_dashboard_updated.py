import json
import boto3
import psycopg2


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


CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def lambda_handler(event, context):
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method", "")
    )
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": CORS_HEADERS, "body": ""}

    params = event.get("queryStringParameters") or {}
    account_id = params.get("account_id")

    try:
        conn = get_db_connection()
        data = {}

        with conn.cursor() as cur:

            # ── Resolve account ────────────────────────────────────────────────
            cur.execute("""
                SELECT id, role_arn, account_name, account_id
                FROM cloud_accounts
                WHERE status = 'active'
                ORDER BY created_at
            """)
            accounts = [
                {
                    "id":         str(r[0]),
                    "role_arn":   r[1],
                    "name":       r[2] or (str(r[0])[:8] + "…"),
                    "account_id": r[3] or "",
                }
                for r in cur.fetchall()
            ]
            data["accounts"] = accounts

            if account_id and any(a["id"] == account_id for a in accounts):
                acct_id = account_id
            elif accounts:
                acct_id = accounts[0]["id"]
            else:
                acct_id = None

            data["account_id"] = acct_id
            selected = next((a for a in accounts if a["id"] == acct_id), None)
            data["account_name"] = selected["name"] if selected else ""

            if not acct_id:
                conn.close()
                return {
                    "statusCode": 200,
                    "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
                    "body": json.dumps({**data, "error": "no active accounts"}),
                }

            # ── Last scan time ─────────────────────────────────────────────────
            cur.execute(
                "SELECT last_scan_at FROM cloud_accounts WHERE id = %s",
                (acct_id,),
            )
            row = cur.fetchone()
            data["last_scan_at"] = str(row[0]) if row and row[0] else "Unknown"

            # ── Per-service / framework stats ──────────────────────────────────
            cur.execute("""
                SELECT
                    COALESCE(service, 'TOTAL') AS service,
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE result = 'PASS') AS passed,
                    COUNT(*) FILTER (WHERE result = 'FAIL') AS failed,
                    ROUND(COUNT(*) FILTER (WHERE result = 'PASS') * 100.0 / NULLIF(COUNT(*), 0), 1) AS score
                FROM (
                    SELECT
                        CASE
                            WHEN check_id LIKE 'CloudWatch.%%' THEN 'CloudWatch'
                            WHEN check_id LIKE 'IAM.%%'        THEN 'IAM'
                            WHEN check_id LIKE 'S3.%%'         THEN 'S3'
                            WHEN check_id LIKE 'KMS.%%'        THEN 'KMS'
                            WHEN check_id LIKE 'github_%%'     THEN 'GitHub'
                            WHEN framework = 'ISO 27001:2022'  THEN 'ISO27001'
                            WHEN framework = 'NIST CSF v2.0'   THEN 'NIST'
                            WHEN framework = 'GDPR'            THEN 'GDPR'
                            WHEN framework = 'SOC 2'           THEN 'SOC2'
                            ELSE 'Other'
                        END AS service,
                        result
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
                    WHEN 'GitHub'     THEN 5
                    WHEN 'ISO27001'   THEN 6
                    WHEN 'NIST'       THEN 7
                    WHEN 'GDPR'       THEN 8
                    WHEN 'SOC2'       THEN 9
                    ELSE 10
                END
            """, (acct_id,))
            services = []
            total = None
            for r in cur.fetchall():
                entry = {
                    "service": r[0],
                    "total":   int(r[1]),
                    "passed":  int(r[2]),
                    "failed":  int(r[3]),
                    "score":   float(r[4]) if r[4] is not None else 0.0,
                }
                if r[0] == "TOTAL":
                    total = entry
                else:
                    services.append(entry)
            data["total"]    = total
            data["services"] = services

            # ── Severity breakdown ─────────────────────────────────────────────
            cur.execute("""
                SELECT UPPER(f.severity),
                    COUNT(*),
                    COUNT(*) FILTER (WHERE f.result = 'PASS'),
                    COUNT(*) FILTER (WHERE f.result = 'FAIL')
                FROM findings f
                JOIN resources r ON f.resource_id = r.id
                WHERE r.cloud_account_id = %s
                GROUP BY UPPER(f.severity)
            """, (acct_id,))
            data["by_severity"] = {
                r[0]: {"total": int(r[1]), "passed": int(r[2]), "failed": int(r[3])}
                for r in cur.fetchall()
            }

            # ── All findings ───────────────────────────────────────────────────
            cur.execute("""
                SELECT
                    f.check_id,
                    CASE
                        WHEN f.check_id LIKE 'CloudWatch.%%' THEN 'CloudWatch'
                        WHEN f.check_id LIKE 'IAM.%%'        THEN 'IAM'
                        WHEN f.check_id LIKE 'S3.%%'         THEN 'S3'
                        WHEN f.check_id LIKE 'KMS.%%'        THEN 'KMS'
                        WHEN f.check_id LIKE 'github_%%'     THEN 'GitHub'
                        WHEN f.framework = 'ISO 27001:2022'  THEN 'ISO27001'
                        WHEN f.framework = 'NIST CSF v2.0'   THEN 'NIST'
                        WHEN f.framework = 'GDPR'            THEN 'GDPR'
                        WHEN f.framework = 'SOC 2'           THEN 'SOC2'
                        ELSE r.resource_type
                    END AS service,
                    UPPER(f.severity) AS severity,
                    f.result,
                    f.title,
                    f.remediation,
                    r.resource_name,
                    r.id AS resource_id
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
            """, (acct_id,))
            data["findings"] = [
                {
                    "check_id":      r[0],
                    "service":       r[1],
                    "severity":      r[2],
                    "result":        r[3],
                    "title":         r[4] or r[0],
                    "remediation":   r[5] or "",
                    "resource_name": r[6] or "",
                    "resource_id":   str(r[7]) if r[7] else "",
                }
                for r in cur.fetchall()
            ]

            # ── Cross-Compliance Heatmap ───────────────────────────────────────
            cur.execute("""
                SELECT domain, fw, SUM(total_cnt) AS total, SUM(passed_cnt) AS passed
                FROM (
                    SELECT
                        CASE
                            WHEN f.check_id LIKE 'IAM.%%'
                              OR f.check_id IN ('A.5.15','A.5.17','A.5.18','A.8.2','A.8.3','A.8.4','A.8.5')
                              OR f.check_id LIKE 'PR.AC-%%'
                              OR f.check_id IN ('CC6.1','CC6.2','CC6.3')
                            THEN 'iam'
                            WHEN f.check_id LIKE 'S3.%%'
                              OR f.check_id = 'A.8.11'
                              OR f.check_id IN ('PR.DS-3','PR.DS-5')
                              OR f.check_id = 'PI1.5'
                              OR f.check_id = 'Art.25'
                            THEN 'storage'
                            WHEN f.check_id LIKE 'CloudWatch.%%'
                              OR f.check_id IN ('A.8.15','A.8.16')
                              OR f.check_id LIKE 'DE.%%'
                              OR f.check_id IN ('PR.PT-1','PR.PT-4')
                              OR f.check_id LIKE 'CC7.%%'
                              OR f.check_id = 'CC4.1'
                              OR f.check_id = 'Art.30'
                            THEN 'logging'
                            WHEN f.check_id LIKE 'KMS.%%'
                              OR f.check_id = 'A.8.24'
                              OR f.check_id IN ('PR.DS-1','PR.DS-2')
                              OR f.check_id IN ('CC6.7','CC6.8')
                              OR f.check_id = 'Art.32'
                            THEN 'encryption'
                            WHEN f.check_id LIKE 'github_%%'
                              OR f.check_id IN ('A.8.8','A.8.29','A.8.32')
                              OR f.check_id LIKE 'ID.%%'
                              OR f.check_id LIKE 'PR.IP-%%'
                              OR f.check_id IN ('CC8.1','CC2.2','CC3.2','CC1.3')
                            THEN 'appsec'
                            ELSE NULL
                        END AS domain,
                        CASE
                            WHEN f.framework LIKE '%%CIS%%' OR f.framework LIKE '%%Benchmark%%' THEN 'cis'
                            WHEN f.framework LIKE '%%ISO 27001%%' THEN 'iso'
                            WHEN f.framework LIKE '%%NIST%%' THEN 'nist'
                            WHEN f.framework LIKE '%%GDPR%%' THEN 'gdpr'
                            WHEN f.framework LIKE '%%SOC%%' THEN 'soc2'
                            ELSE NULL
                        END AS fw,
                        1 AS total_cnt,
                        CASE WHEN f.result = 'PASS' THEN 1 ELSE 0 END AS passed_cnt
                    FROM findings f
                    JOIN resources r ON f.resource_id = r.id
                    WHERE r.cloud_account_id = %s
                      AND f.framework IS NOT NULL
                ) sub
                WHERE domain IS NOT NULL AND fw IS NOT NULL
                GROUP BY domain, fw
            """, (acct_id,))

            # Pivot into matrix: domains × frameworks
            DOMAIN_ORDER = ['iam', 'storage', 'logging', 'encryption', 'appsec']
            DOMAIN_LABELS = {
                'iam':        'Identity & Access',
                'storage':    'Data Storage',
                'logging':    'Logging & Monitoring',
                'encryption': 'Encryption & Keys',
                'appsec':     'Applications & Code',
            }
            FW_ORDER = ['cis', 'iso', 'nist', 'gdpr', 'soc2']
            FW_LABELS = {
                'cis':  'CIS AWS',
                'iso':  'ISO 27001',
                'nist': 'NIST CSF',
                'gdpr': 'GDPR',
                'soc2': 'SOC 2',
            }

            matrix = {d: {fw: None for fw in FW_ORDER} for d in DOMAIN_ORDER}
            for row in cur.fetchall():
                domain, fw, total_count, passed_count = row[0], row[1], int(row[2]), int(row[3])
                if domain in matrix and fw in FW_ORDER:
                    score = round(passed_count * 100.0 / total_count, 1) if total_count else 0
                    matrix[domain][fw] = {"total": total_count, "passed": passed_count, "score": score}

            data["cross_compliance"] = {
                "frameworks": [{"id": fw, "label": FW_LABELS[fw]} for fw in FW_ORDER],
                "domains": [
                    {
                        "id":     d,
                        "label":  DOMAIN_LABELS[d],
                        "scores": [matrix[d][fw] for fw in FW_ORDER],
                    }
                    for d in DOMAIN_ORDER
                ],
            }

        conn.close()

        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
            "body": json.dumps(data),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": CORS_HEADERS,
            "body": json.dumps({"error": str(e)}),
        }
