import json

from db import get_connection
from collectors.aws.assume_role import assume_role
from collectors.aws.iam.collector import IAMCollector

from rules.cis.iam.iam_1_4 import check as check_1_4
from rules.cis.iam.iam_1_5 import check as check_1_5
from rules.cis.iam.iam_1_6 import check as check_1_6
from rules.cis.iam.iam_1_8 import check as check_1_8
from rules.cis.iam.iam_1_9 import check as check_1_9
from rules.cis.iam.iam_1_10 import check as check_1_10
from rules.cis.iam.iam_1_11 import check as check_1_11
from rules.cis.iam.iam_1_15 import check as check_1_15
from rules.cis.iam.iam_1_16 import check as check_1_16
from rules.cis.iam.iam_1_17 import check as check_1_17
from rules.cis.iam.iam_1_18 import check as check_1_18


def get_accounts_from_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, account_id, account_name, role_arn, external_id
        FROM cloud_accounts
        WHERE status = 'active'
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    accounts = []
    for row in rows:
        accounts.append({
            "cloud_account_id": str(row[0]),
            "account_id": row[1],
            "account_name": row[2] or row[1],
            "role_arn": row[3],
            "external_id": row[4],
        })

    return accounts


def save_resources(cloud_account_id, resources):
    conn = get_connection()
    cur = conn.cursor()

    for resource in resources:
        if not resource.get("resource_id"):
            print("Skipping resource without resource_id:", resource)
            continue

        cur.execute("""
            INSERT INTO resources (
                cloud_account_id,
                resource_type,
                resource_id,
                resource_name,
                region,
                config,
                last_scanned_at
            )
            VALUES (%s, %s, %s, %s, %s, %s::jsonb, NOW())
            ON CONFLICT (cloud_account_id, resource_id)
            DO UPDATE SET
                resource_type = EXCLUDED.resource_type,
                resource_name = EXCLUDED.resource_name,
                region = EXCLUDED.region,
                config = EXCLUDED.config,
                last_scanned_at = NOW()
        """, (
            cloud_account_id,
            resource.get("resource_type"),
            resource.get("resource_id"),
            resource.get("resource_name"),
            resource.get("region"),
            json.dumps(resource.get("config", {})),
        ))

    conn.commit()
    cur.close()
    conn.close()


def get_resource_id_map(cloud_account_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT resource_id, id
        FROM resources
        WHERE cloud_account_id = %s
    """, (cloud_account_id,))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return {row[0]: str(row[1]) for row in rows}


def run_checks(resources):
    checks = [
        check_1_4,
        check_1_5,
        check_1_6,
        check_1_8,
        check_1_9,
        check_1_10,
        check_1_11,
        check_1_15,
        check_1_16,
        check_1_17,
        check_1_18,
    ]

    results = []

    for check in checks:
        try:
            result = check(resources)
            results.append(result)
        except Exception as e:
            results.append({
                "check": check.__name__,
                "status": "ERROR",
                "reason": str(e)
            })

    return results


def save_findings(cloud_account_id, resources, findings):
    resource_id_map = get_resource_id_map(cloud_account_id)

    if not resource_id_map:
        print("No resources in DB to attach findings")
        return

    account_resource_id = None
    for resource in resources:
        if resource.get("resource_type") == "iam-account" and resource.get("resource_id"):
            account_resource_id = resource.get("resource_id")
            break

    db_resource_id = None
    if account_resource_id:
        db_resource_id = resource_id_map.get(account_resource_id)

    if not db_resource_id and resource_id_map:
        db_resource_id = list(resource_id_map.values())[0]

    if not db_resource_id:
        print("WARNING: Could not resolve DB resource id for findings")
        return

    conn = get_connection()
    cur = conn.cursor()

    for finding in findings:
        check_id = finding.get("check", "UNKNOWN")
        status = finding.get("status", "ERROR")
        reason = finding.get("reason") or finding.get("error") or ""

        result = "PASS" if status == "PASS" else "FAIL"
        severity = "LOW" if result == "PASS" else "MEDIUM"

        cur.execute("""
            INSERT INTO findings (
                resource_id,
                check_id,
                title,
                description,
                severity,
                status,
                detected_at,
                result,
                framework,
                remediation,
                details
            )
            VALUES (%s, %s, %s, %s, %s, 'open', NOW(), %s, 'CIS AWS Foundations v1.5.0', %s, %s::jsonb)
            ON CONFLICT (resource_id, check_id)
            DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                severity = EXCLUDED.severity,
                detected_at = NOW(),
                result = EXCLUDED.result,
                framework = EXCLUDED.framework,
                remediation = EXCLUDED.remediation,
                details = EXCLUDED.details
        """, (
            db_resource_id,
            check_id,
            check_id,
            reason,
            severity,
            result,
            "Review IAM configuration according to CIS guidance",
            json.dumps(finding)
        ))

    conn.commit()
    cur.close()
    conn.close()


def update_compliance_score(cloud_account_id, findings):
    total = len(findings)
    passed = len([f for f in findings if f.get("status") == "PASS"])
    failed = len([f for f in findings if f.get("status") == "FAIL"])
    errors = len([f for f in findings if f.get("status") == "ERROR"])

    score = 0
    if total > 0:
        score = round((passed / total) * 100, 2)

    payload = {
        "framework": "CIS AWS Foundations v1.5.0",
        "score": score,
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "errors": errors
    }

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE cloud_accounts
        SET compliance_score = %s::jsonb
        WHERE id = %s
    """, (json.dumps(payload), cloud_account_id))

    conn.commit()
    cur.close()
    conn.close()


def update_last_scan(cloud_account_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE cloud_accounts
        SET last_scan_at = NOW()
        WHERE id = %s
    """, (cloud_account_id,))

    conn.commit()
    cur.close()
    conn.close()


def scan_account(account):
    print(f"Scanning account: {account['account_name']} ({account['cloud_account_id']})")

    session = assume_role(
        role_arn=account["role_arn"],
        external_id=account["external_id"],
        session_name="cspm-scan"
    )

    collector = IAMCollector(session=session)
    resources = collector.collect()

    print("Collected resources:", len(resources))
    for resource in resources:
        print(resource.get("resource_type"), resource.get("resource_id"))

    save_resources(account["cloud_account_id"], resources)

    findings = run_checks(resources)
    save_findings(account["cloud_account_id"], resources, findings)
    update_compliance_score(account["cloud_account_id"], findings)
    update_last_scan(account["cloud_account_id"])

    return {
        "cloud_account_id": account["cloud_account_id"],
        "account_name": account["account_name"],
        "resource_count": len(resources),
        "finding_count": len(findings),
        "status": "success"
    }


def main():
    accounts = get_accounts_from_db()
    results = []

    for account in accounts:
        try:
            result = scan_account(account)
            results.append(result)
        except Exception as e:
            results.append({
                "cloud_account_id": account["cloud_account_id"],
                "account_name": account["account_name"],
                "resource_count": 0,
                "finding_count": 0,
                "status": "failed",
                "error": str(e)
            })

    print("\nSCAN RESULTS")
    for result in results:
        print(result)


if __name__ == "__main__":
    main()