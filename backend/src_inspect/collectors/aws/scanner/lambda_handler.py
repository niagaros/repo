import json
import logging
import os
import boto3

from collectors.aws.cloudwatch.cloudwatch_collector import CloudWatchCollector
from rules.aws.cloudwatch.cloudwatch_1 import CloudWatch1Check
from rules.aws.cloudwatch.cloudwatch_2 import CloudWatch2Check
from rules.aws.cloudwatch.cloudwatch_3 import CloudWatch3Check
from rules.aws.cloudwatch.cloudwatch_4 import CloudWatch4Check
from rules.aws.cloudwatch.cloudwatch_5 import CloudWatch5Check
from rules.aws.cloudwatch.cloudwatch_6 import CloudWatch6Check
from rules.aws.cloudwatch.cloudwatch_7 import CloudWatch7Check
from rules.aws.cloudwatch.cloudwatch_8 import CloudWatch8Check
from rules.aws.cloudwatch.cloudwatch_9 import CloudWatch9Check
from rules.aws.cloudwatch.cloudwatch_10 import CloudWatch10Check
from rules.aws.cloudwatch.cloudwatch_11 import CloudWatch11Check
from rules.aws.cloudwatch.cloudwatch_12 import CloudWatch12Check
from rules.aws.cloudwatch.cloudwatch_13 import CloudWatch13Check
from rules.aws.cloudwatch.cloudwatch_14 import CloudWatch14Check
from collectors.aws.scanner.db_writer import save_scan_results

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CHECKS = [
    CloudWatch1Check, CloudWatch2Check, CloudWatch3Check,
    CloudWatch4Check, CloudWatch5Check, CloudWatch6Check,
    CloudWatch7Check, CloudWatch8Check, CloudWatch9Check,
    CloudWatch10Check, CloudWatch11Check, CloudWatch12Check,
    CloudWatch13Check, CloudWatch14Check,
]

CLOUD_ACCOUNT_ID = os.environ.get(
    "CLOUD_ACCOUNT_ID",
    "846e9e1b-c011-43ef-a38c-4762cc9b0f5a"
)


def _assume_role(role_arn: str, region: str) -> boto3.Session:
    sts = boto3.client("sts", region_name="eu-west-1")
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="cloudwatch-cis-scanner",
        ExternalId=os.environ.get("EXTERNAL_ID"),
    )["Credentials"]

    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def handler(event, context):
    region = event.get("region", os.environ.get("AWS_REGION", "eu-north-1"))
    role_arn = os.environ.get("ASSUME_ROLE_ARN")

    session = _assume_role(role_arn, region) if role_arn else None

    # 1. Collect
    logger.info("Starting CloudWatch collection for region=%s", region)
    collector = CloudWatchCollector(region=region, session=session)
    snapshot = collector.collect()

    # 2. Evaluate
    results = []
    for Check in CHECKS:
        result = Check().evaluate(snapshot)
        results.append(result.to_dict())

    # 3. Summary
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = total - passed
    logger.info("Scan complete: total=%d passed=%d failed=%d", total, passed, failed)

    # 4. Persist to database
    db_stats = {"resources_upserted": 0, "findings_upserted": 0, "error": None}
    try:
        db_stats = save_scan_results(
            snapshot=snapshot,
            results=results,
            cloud_account_id=CLOUD_ACCOUNT_ID,
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
            "collected_at": snapshot.get("collected_at"),
            "summary": {
                "total": total,
                "passed": passed,
                "failed": failed,
            },
            "db": db_stats,
            "results": results,
        },
    }