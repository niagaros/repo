import json
import logging

from engine.scanner import Scanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def lambda_handler(event, context):
    """
    Lambda entry point.

    Expected event:
    {
        "cloud_account_id": "846e9e1b-c011-43ef-a38c-4762cc9b0f5a",
        "role_arn":         "arn:aws:iam::115462458880:role/CSPMScannerRole",
        "external_id":      "dd3c0021-e4ba-4b5e-8593-9d385ea89a84"
    }

    Returns:
    {
        "statusCode": 200,
        "body": {
            "cloud_account_id":    "...",
            "resources_collected": 12,
            "checks_run":          72,
            "findings_failed":     5,
            "compliance_score": {
                "overall": 93.1,
                "passed":  67,
                "failed":  5,
                "total":   72,
                "by_severity": {...}
            }
        }
    }
    """
    try:
        cloud_account_id = event["cloud_account_id"]
        role_arn         = event["role_arn"]
        external_id      = event["external_id"]

        logger.info(f"Lambda: starting scan for account {cloud_account_id}")

        result = Scanner(cloud_account_id, role_arn, external_id).run()

        logger.info(f"Lambda: scan complete — {result}")
        return {"statusCode": 200, "body": json.dumps(result)}

    except KeyError as e:
        logger.error(f"Lambda: missing required field — {e}")
        return {"statusCode": 400, "body": json.dumps({"error": f"Missing field: {e}"})}

    except Exception as e:
        logger.error(f"Lambda: scan failed — {e}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}