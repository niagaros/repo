# NOTE: deployed as the Iam-cis-scanner Lambda's own independent zip, where this
# file and db_writer.py both physically live under collectors/aws/scanner/ inside
# that package (a naming collision with the unrelated CloudWatch db_writer.py that
# already exists at that same path in this repo's cloudwatch-cis-scanner tree).
# Colocated here under collectors/aws/iam/ instead so both can exist in one repo;
# the import below is adjusted to match — repackage from here, not scanner/, if
# redeploying from this repo.
import logging
import os
import boto3

from collectors.aws.iam.collector import IAMCollector
from rules.aws.iam.iam_2 import check as check_2
from rules.aws.iam.iam_3 import check as check_3
from rules.aws.iam.iam_4 import check as check_4
from rules.aws.iam.iam_5 import check as check_5
from rules.aws.iam.iam_6 import check as check_6
from rules.aws.iam.iam_9 import check as check_9
from rules.aws.iam.iam_15 import check as check_15
from rules.aws.iam.iam_16 import check as check_16
from rules.aws.iam.iam_18 import check as check_18
from rules.aws.iam.iam_22 import check as check_22
from rules.aws.iam.iam_26 import check as check_26
from rules.aws.iam.iam_27 import check as check_27
from rules.aws.iam.iam_28 import check as check_28
from collectors.aws.iam.db_writer import save_scan_results

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CHECKS = [
    check_2,
    check_3,
    check_4,
    check_5,
    check_6,
    check_9,
    check_15,
    check_16,
    check_18,
    check_22,
    check_26,
    check_27,
    check_28,
]




def _assume_role(role_arn: str, external_id: str, region: str) -> boto3.Session:
    sts = boto3.client("sts", region_name="eu-west-1")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="iam-cis-scanner",
        ExternalId=external_id,
    )["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def handler(event, context):
    region = event.get("region", os.environ.get("AWS_REGION", "eu-west-1"))
    role_arn = event.get("role_arn") or os.environ.get("ASSUME_ROLE_ARN")
    external_id = event.get("external_id") or os.environ.get("EXTERNAL_ID", "")
    cloud_account_id = event.get("cloud_account_id") or os.environ.get("CLOUD_ACCOUNT_ID", "")

    session = _assume_role(role_arn, external_id, region) if role_arn else None

    # 1. Collect
    logger.info("Starting IAM collection")
    collector = IAMCollector(session=session)
    resources = collector.collect()

    snapshot = {
        "resources": resources,
        "account_id": next((r.get("account_id") for r in resources if r.get("account_id")), None),
        "collected_at": None,
        "region": region,
    }

    # 2. Evaluate
    results = []
    for check in CHECKS:
        try:
            result = check(resources)
            results.append(result)
        except Exception as e:
            logger.error("Check %s failed: %s", check.__name__, str(e))
            results.append({
                "check": check.__name__,
                "status": "ERROR",
                "reason": str(e)
            })

    # 3. Summary
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    logger.info("Scan complete: total=%d passed=%d failed=%d", total, passed, failed)

    # 4. Persist
    db_stats = {"resources_upserted": 0, "findings_upserted": 0, "error": None}
    try:
        db_stats = save_scan_results(
            snapshot=snapshot,
            results=results,
            cloud_account_id=event.get("cloud_account_id") or os.environ.get("CLOUD_ACCOUNT_ID", ""),
        )
        logger.info("DB write complete: %s", db_stats)
    except Exception as e:
        logger.error("DB write failed: %s", str(e))
        db_stats["error"] = str(e)

    return {
        "statusCode": 200,
        "body": {
            "account_id": snapshot.get("account_id"),
            "region": region,
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
            },
            "db": db_stats,
            "results": results,
        },
    }