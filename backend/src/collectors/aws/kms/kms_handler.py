import logging
import os
from datetime import datetime

from collectors.aws.kms.kms_collector import KMSCollector

from rules.cis.kms.kms_1_rotation_enabled import KMS1RotationEnabled
from rules.cis.kms.kms_2_no_wildcard_principal import KMS2NoWildcardPrincipal
from rules.cis.kms.kms_3_no_wildcard_action import KMS3NoWildcardAction
from rules.cis.kms.kms_4_key_not_disabled import KMS4KeyNotDisabled
from rules.cis.kms.kms_5_key_not_pending_deletion import KMS5KeyNotPendingDeletion
from rules.cis.kms.kms_6_no_risky_grants import KMS6NoRiskyGrants

from collectors.aws.scanner.db_writer_kms import (
    save_kms_results,
    update_scanner_status
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CHECKS = [
    KMS1RotationEnabled,
    KMS2NoWildcardPrincipal,
    KMS3NoWildcardAction,
    KMS4KeyNotDisabled,
    KMS5KeyNotPendingDeletion,
    KMS6NoRiskyGrants,
]


def handler(event, context):

    function_name = "kms-cis-scanner"

    # ✅ Alleen triggered zetten
    update_scanner_status(function_name, "triggered")

    region = event.get("region", os.environ.get("SCAN_REGION", "eu-north-1"))
    role_arn = event.get("role_arn") or os.environ.get("ASSUME_ROLE_ARN")
    external_id = event.get("external_id") or os.environ.get("EXTERNAL_ID", "")
    cloud_account_id = event.get("cloud_account_id") or os.environ.get("CLOUD_ACCOUNT_ID", "")

    collector = KMSCollector(
        role_arn=role_arn,
        external_id=external_id,
        region=region
    )

    kms_data = collector.collect()

    results = []
    for Check in CHECKS:
        rule = Check()
        results.extend(rule.evaluate(kms_data))

    save_kms_results(
        snapshot={
            "region": region,
            "collected_at": datetime.utcnow().isoformat(),
            "kms_keys": kms_data
        },
        results=results,
        cloud_account_id=cloud_account_id
    )

    # ❌ Geen success update meer

    return {
        "statusCode": 200,
        "body": {
            "total": len(results)
        }
    }