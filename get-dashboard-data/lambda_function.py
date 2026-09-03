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
        "dr_test_results": [],
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
                                -- Mapped-framework findings must resolve to their own
                                -- framework FIRST — otherwise any framework's CloudWatch/
                                -- IAM/S3/etc-based control gets swallowed into the generic
                                -- raw-scan bucket below just because of its resource_type
                                -- or check_id prefix.
                                WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
                                WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
                                WHEN f.framework = 'GDPR'            THEN 'GDPR'
                                WHEN f.framework = 'SOC2'            THEN 'SOC2'
                                WHEN f.framework = 'PCI DSS v4.0'   THEN 'PCIDSS'
                                WHEN f.framework = 'NIS2'            THEN 'NIS2'
                                WHEN f.framework = 'HIPAA'           THEN 'HIPAA'
                                WHEN f.framework = 'NIST 800-53 Rev 5' THEN 'NIST80053'
                                WHEN f.framework = 'BSI-C5'          THEN 'BSIC5'
                                WHEN f.framework = 'CSA CCM 4.0'     THEN 'CSACCM'
                                WHEN f.framework = 'FedRAMP Moderate Rev 4' THEN 'FEDRAMP'
                                WHEN f.framework = 'ISO 42001'       THEN 'ISO42001'
                                WHEN f.framework = 'ISO 27017'       THEN 'ISO27017'
                                WHEN f.framework = 'AWS FTR'         THEN 'AWSFTR'
                                WHEN f.framework = 'MVSP'            THEN 'MVSP'
                                WHEN f.framework = 'TISAX'           THEN 'TISAX'
                                WHEN f.framework = 'HITRUST CSF'     THEN 'HITRUST'
                                WHEN f.framework = 'DORA'            THEN 'DORA'
                                WHEN f.framework = 'CRI Profile'     THEN 'CRIPROFILE'
                                WHEN f.framework = 'EU AI Act'       THEN 'EUAIACT'
                                WHEN f.framework = 'NIST AI RMF'     THEN 'NISTAIRMF'
                                WHEN f.framework = 'ISO 27701'       THEN 'ISO27701'
                                WHEN f.framework = 'ISO 27018'       THEN 'ISO27018'
                                WHEN f.framework = 'Microsoft SSPA'  THEN 'SSPA'
                                -- Raw CIS/FSBP scan findings (no mapped framework above)
                                -- fall back to service inferred from check_id/resource_type.
                                WHEN f.check_id LIKE 'CloudWatch%%' THEN 'CloudWatch'
                                WHEN r.resource_type IN ('cloudwatch_trail','cloudwatch_account') THEN 'CloudWatch'
                                WHEN f.check_id LIKE 'IAM%%'        THEN 'IAM'
                                WHEN f.check_id LIKE 'S3%%'         THEN 'S3'
                                WHEN f.check_id LIKE 'RDS%%'        THEN 'RDS'
                                WHEN f.check_id LIKE 'DynamoDB%%'   THEN 'RDS'
                                WHEN f.check_id LIKE 'KMS%%'        THEN 'KMS'
                                WHEN f.check_id LIKE 'Cognito%%'    THEN 'Cognito'
                                WHEN f.check_id LIKE 'github%%'     THEN 'GitHub'
                                WHEN r.resource_type IN ('github_repository','github_organization') THEN 'GitHub'
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
                        WHEN 'RDS'        THEN 4
                        WHEN 'KMS'        THEN 5
                        WHEN 'Cognito'    THEN 6
                        WHEN 'GitHub'     THEN 7
                        WHEN 'ISO27001'   THEN 8
                        WHEN 'NIST'       THEN 9
                        WHEN 'GDPR'       THEN 10
                        WHEN 'SOC2'       THEN 11
                        WHEN 'PCIDSS'     THEN 12
                        WHEN 'NIS2'       THEN 13
                        WHEN 'HIPAA'      THEN 14
                        WHEN 'NIST80053'  THEN 15
                        WHEN 'BSIC5'      THEN 16
                        WHEN 'CSACCM'     THEN 17
                        WHEN 'FEDRAMP'    THEN 18
                        WHEN 'ISO42001'   THEN 19
                        WHEN 'ISO27017'   THEN 20
                        WHEN 'AWSFTR'     THEN 21
                        WHEN 'MVSP'       THEN 22
                        WHEN 'TISAX'      THEN 23
                        WHEN 'HITRUST'    THEN 24
                        WHEN 'DORA'       THEN 25
                        WHEN 'CRIPROFILE' THEN 26
                        WHEN 'EUAIACT'    THEN 27
                        WHEN 'NISTAIRMF'  THEN 28
                        WHEN 'ISO27701'   THEN 29
                        WHEN 'ISO27018'   THEN 30
                        WHEN 'SSPA'       THEN 31
                        ELSE 32
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
                            -- Mapped-framework findings resolve to their own framework
                            -- first (see the identical fix in the per-service query above).
                            WHEN f.framework = 'ISO 27001:2022' THEN 'ISO27001'
                            WHEN f.framework = 'NIST CSF v2.0'  THEN 'NIST'
                            WHEN f.framework = 'GDPR'            THEN 'GDPR'
                            WHEN f.framework = 'SOC2'            THEN 'SOC2'
                            WHEN f.framework = 'PCI DSS v4.0'   THEN 'PCIDSS'
                            WHEN f.framework = 'NIS2'            THEN 'NIS2'
                            WHEN f.framework = 'HIPAA'           THEN 'HIPAA'
                            WHEN f.framework = 'NIST 800-53 Rev 5' THEN 'NIST80053'
                            WHEN f.framework = 'BSI-C5'          THEN 'BSIC5'
                            WHEN f.framework = 'CSA CCM 4.0'     THEN 'CSACCM'
                            WHEN f.framework = 'FedRAMP Moderate Rev 4' THEN 'FEDRAMP'
                            WHEN f.framework = 'ISO 42001'       THEN 'ISO42001'
                            WHEN f.framework = 'ISO 27017'       THEN 'ISO27017'
                            WHEN f.framework = 'AWS FTR'         THEN 'AWSFTR'
                            WHEN f.framework = 'MVSP'            THEN 'MVSP'
                            WHEN f.framework = 'TISAX'           THEN 'TISAX'
                            WHEN f.framework = 'HITRUST CSF'     THEN 'HITRUST'
                            WHEN f.framework = 'DORA'            THEN 'DORA'
                            WHEN f.framework = 'CRI Profile'     THEN 'CRIPROFILE'
                            WHEN f.framework = 'EU AI Act'       THEN 'EUAIACT'
                            WHEN f.framework = 'NIST AI RMF'     THEN 'NISTAIRMF'
                            WHEN f.framework = 'ISO 27701'       THEN 'ISO27701'
                            WHEN f.framework = 'ISO 27018'       THEN 'ISO27018'
                            WHEN f.framework = 'Microsoft SSPA'  THEN 'SSPA'
                            WHEN f.check_id LIKE 'CloudWatch%%' THEN 'CloudWatch'
                            WHEN r.resource_type IN ('cloudwatch_trail','cloudwatch_account') THEN 'CloudWatch'
                            WHEN f.check_id LIKE 'IAM%%'        THEN 'IAM'
                            WHEN f.check_id LIKE 'S3%%'         THEN 'S3'
                            WHEN f.check_id LIKE 'RDS%%'        THEN 'RDS'
                            WHEN f.check_id LIKE 'DynamoDB%%'   THEN 'RDS'
                            WHEN f.check_id LIKE 'KMS%%'        THEN 'KMS'
                            WHEN f.check_id LIKE 'Cognito%%'    THEN 'Cognito'
                            WHEN f.check_id LIKE 'github%%'     THEN 'GitHub'
                            WHEN r.resource_type IN ('github_repository','github_organization') THEN 'GitHub'
                            ELSE r.resource_type
                        END AS service,
                        UPPER(f.severity) AS severity,
                        f.result,
                        f.title,
                        f.description,
                        f.remediation,
                        r.resource_name,
                        r.resource_id,
                        f.framework,
                        f.details
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
                        "description":   row[5] or "",
                        "remediation":   row[6] or "",
                        "resource_name": row[7] or "",
                        "resource_id":   row[8] or "",
                        "framework":     row[9] or "",
                        "details":       row[10] or "",
                    }
                    for row in cur.fetchall()
                ]
            except Exception as e:
                data["_debug"]["findings"] = str(e)
                conn.rollback()

            # ── 6. Cross-compliance heatmap ──────────────────────────
            try:
                COMPLIANCE_FWS = [
                    ("ISO 27001:2022",     "ISO27001",  "ISO 27001:2022"),
                    ("NIST CSF v2.0",      "NIST",      "NIST CSF v2.0"),
                    ("GDPR",               "GDPR",      "GDPR"),
                    ("SOC2",               "SOC2",      "SOC 2"),
                    ("PCI DSS v4.0",       "PCIDSS",    "PCI DSS v4.0"),
                    ("NIS2",               "NIS2",      "NIS2"),
                    ("HIPAA",              "HIPAA",     "HIPAA"),
                    ("NIST 800-53 Rev 5",  "NIST80053", "NIST SP 800-53"),
                    ("BSI-C5",             "BSIC5",     "BSI C5"),
                    ("CSA CCM 4.0",        "CSACCM",    "CSA CCM 4.0"),
                    ("FedRAMP Moderate Rev 4", "FEDRAMP", "FedRAMP Moderate"),
                    ("ISO 42001",          "ISO42001",  "ISO 42001:2023"),
                    ("ISO 27017",          "ISO27017",  "ISO 27017:2015"),
                    ("AWS FTR",            "AWSFTR",    "AWS Foundational Technical Review"),
                    ("MVSP",               "MVSP",      "Minimum Viable Secure Product"),
                    ("TISAX",              "TISAX",     "TISAX (VDA ISA)"),
                    ("HITRUST CSF",        "HITRUST",   "HITRUST CSF"),
                    ("DORA",               "DORA",      "DORA"),
                    ("CRI Profile",        "CRIPROFILE","CRI Profile"),
                    ("EU AI Act",          "EUAIACT",   "EU AI Act"),
                    ("NIST AI RMF",        "NISTAIRMF", "NIST AI RMF"),
                    ("ISO 27701",          "ISO27701",  "ISO 27701"),
                    ("ISO 27018",          "ISO27018",  "ISO 27018"),
                    ("Microsoft SSPA",     "SSPA",      "Microsoft SSPA"),
                ]
                fw_name_to_id    = {fw[0]: fw[1] for fw in COMPLIANCE_FWS}
                fw_id_to_label   = {fw[1]: fw[2] for fw in COMPLIANCE_FWS}
                fw_names_tuple   = tuple(fw[0] for fw in COMPLIANCE_FWS)

                cur.execute("""
                    SELECT
                        CASE
                            WHEN r.resource_type LIKE 'iam%%'       OR r.resource_type LIKE 'cognito%%'
                                THEN 'Access & Identity'
                            WHEN r.resource_type LIKE 'kms%%'
                                THEN 'Cryptography & Keys'
                            WHEN r.resource_type LIKE 'cloudwatch%%'
                                THEN 'Logging & Monitoring'
                            WHEN r.resource_type LIKE 's3%%'
                                THEN 'Data & Storage'
                            ELSE 'Other Controls'
                        END                                         AS domain,
                        f.framework                                  AS fw_name,
                        COUNT(*)                                     AS total,
                        COUNT(*) FILTER (WHERE f.result = 'PASS')   AS passed
                    FROM findings f
                    JOIN resources r ON f.resource_id = r.id
                    WHERE r.cloud_account_id = %s
                      AND f.framework IN %s
                    GROUP BY 1, 2
                """, (account_id, fw_names_tuple))

                domain_data = {}
                for domain, fw_name, total, passed in cur.fetchall():
                    fw_id = fw_name_to_id.get(fw_name)
                    if not fw_id:
                        continue
                    if domain not in domain_data:
                        domain_data[domain] = {}
                    domain_data[domain][fw_id] = {"total": int(total), "passed": int(passed)}

                active_fws = [
                    {"id": fw[1], "label": fw[2]}
                    for fw in COMPLIANCE_FWS
                    if any(fw[1] in d for d in domain_data.values())
                ]

                DOMAIN_ORDER = [
                    "Access & Identity",
                    "Cryptography & Keys",
                    "Logging & Monitoring",
                    "Data & Storage",
                    "Other Controls",
                ]
                domains_out = []
                for domain in DOMAIN_ORDER:
                    if domain not in domain_data:
                        continue
                    scores = []
                    for fw in active_fws:
                        d = domain_data[domain].get(fw["id"])
                        if d and d["total"] > 0:
                            scores.append({
                                "score":  round(d["passed"] / d["total"] * 100),
                                "passed": d["passed"],
                                "total":  d["total"],
                            })
                        else:
                            scores.append(None)
                    if any(s is not None for s in scores):
                        domains_out.append({"label": domain, "scores": scores})

                data["cross_compliance"] = {
                    "frameworks": active_fws,
                    "domains":    domains_out,
                }
            except Exception as e:
                data["_debug"]["cross_compliance"] = str(e)
                conn.rollback()

            # ── 7. Disaster-recovery restore-test results ────────────
            try:
                cur.execute("""
                    SELECT resource_type, resource_name, rpo_seconds, rto_seconds,
                           data_integrity_match, tested_at
                    FROM dr_test_results
                    WHERE cloud_account_id = %s
                    ORDER BY tested_at DESC
                """, (account_id,))
                data["dr_test_results"] = [
                    {
                        "resource_type":        row[0],
                        "resource_name":        row[1],
                        "rpo_seconds":          row[2],
                        "rto_seconds":          row[3],
                        "data_integrity_match": row[4],
                        "tested_at":            str(row[5]) if row[5] else None,
                    }
                    for row in cur.fetchall()
                ]
            except Exception as e:
                data["_debug"]["dr_test_results"] = str(e)
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
