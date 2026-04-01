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


def lambda_handler(event, context):
    try:
        conn = get_db_connection()
        data = {}

        with conn.cursor() as cur:

            # Last scan time
            cur.execute("""
                SELECT last_scan_at FROM cloud_accounts
                WHERE id = '846e9e1b-c011-43ef-a38c-4762cc9b0f5a'
            """)
            row = cur.fetchone()
            data["last_scan_at"] = str(row[0]) if row and row[0] else "Unknown"

            # Per service stats
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
                            WHEN check_id LIKE 'CloudWatch%' THEN 'CloudWatch'
                            WHEN check_id LIKE 'IAM%'        THEN 'IAM'
                            WHEN check_id LIKE 'S3%'         THEN 'S3'
                            WHEN check_id LIKE 'KMS%'        THEN 'KMS'
                            ELSE 'Other'
                        END AS service,
                        result
                    FROM findings
                ) sub
                GROUP BY ROLLUP(service)
                ORDER BY CASE COALESCE(service, 'TOTAL')
                    WHEN 'TOTAL'      THEN 0
                    WHEN 'CloudWatch' THEN 1
                    WHEN 'S3'         THEN 2
                    WHEN 'IAM'        THEN 3
                    WHEN 'KMS'        THEN 4
                    ELSE 5
                END
            """)
            services = []
            total = None
            for r in cur.fetchall():
                entry = {
                    "service": r[0],
                    "total":   r[1],
                    "passed":  r[2],
                    "failed":  r[3],
                    "score":   float(r[4]),
                }
                if r[0] == "TOTAL":
                    total = entry
                else:
                    services.append(entry)
            data["total"]    = total
            data["services"] = services

            # Severity breakdown
            cur.execute("""
                SELECT UPPER(severity),
                    COUNT(*),
                    COUNT(*) FILTER (WHERE result = 'PASS'),
                    COUNT(*) FILTER (WHERE result = 'FAIL')
                FROM findings
                GROUP BY UPPER(severity)
            """)
            data["by_severity"] = {
                r[0]: {"total": r[1], "passed": r[2], "failed": r[3]}
                for r in cur.fetchall()
            }

            # All findings
            cur.execute("""
                SELECT
                    f.check_id,
                    CASE
                        WHEN f.check_id LIKE 'CloudWatch%' THEN 'CloudWatch'
                        WHEN f.check_id LIKE 'IAM%'        THEN 'IAM'
                        WHEN f.check_id LIKE 'S3%'         THEN 'S3'
                        WHEN f.check_id LIKE 'KMS%'        THEN 'KMS'
                        ELSE r.resource_type
                    END AS service,
                    UPPER(f.severity) AS severity,
                    f.result,
                    f.title,
                    f.remediation
                FROM findings f
                JOIN resources r ON f.resource_id = r.id
                ORDER BY
                    CASE UPPER(f.severity)
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH'     THEN 2
                        WHEN 'MEDIUM'   THEN 3
                        WHEN 'LOW'      THEN 4
                        ELSE 5
                    END,
                    f.check_id
            """)
            data["findings"] = [
                {
                    "check_id":    r[0],
                    "service":     r[1],
                    "severity":    r[2],
                    "result":      r[3],
                    "title":       r[4] or r[0],
                    "remediation": r[5] or "",
                }
                for r in cur.fetchall()
            ]

        conn.close()

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
            "body": json.dumps(data),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Access-Control-Allow-Origin": "*"},
            "body": json.dumps({"error": str(e)}),
        }