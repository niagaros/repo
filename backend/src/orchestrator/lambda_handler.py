import json
import logging
import time
import boto3

from config.database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REGION      = "eu-west-1"
MAX_RETRIES = 3


def lambda_handler(event, context):
    db = None

    try:
        db       = Database()
        accounts = db.get_active_accounts()
        scanners = db.get_enabled_scanners()

        logger.info(f"Orchestrator: {len(accounts)} active accounts, {len(scanners)} enabled scanners")

        if not accounts:
            logger.warning("Orchestrator: no active accounts found")
            return {"statusCode": 200, "body": json.dumps({"message": "no active accounts"})}

        if not scanners:
            logger.warning("Orchestrator: no enabled scanners found")
            return {"statusCode": 200, "body": json.dumps({"message": "no enabled scanners"})}

        client  = boto3.client("lambda", region_name=REGION)
        results = []

        for account in accounts:

            if context and hasattr(context, 'get_remaining_time_in_millis') and context.get_remaining_time_in_millis() < 10000:
                logger.warning("Orchestrator: approaching timeout, stopping early")
                break

            for scanner in scanners:
                triggered  = False
                last_error = None

                for attempt in range(MAX_RETRIES):
                    try:
                        client.invoke(
                            FunctionName   = scanner["function_name"],
                            InvocationType = "Event",
                            Payload        = json.dumps({
                                "cloud_account_id": account["id"],
                                "role_arn":         account["role_arn"],
                                "external_id":      account["external_id"],
                            }),
                        )
                        triggered = True
                        logger.info(f"Orchestrator: triggered {scanner['function_name']} for account {account['id']} (attempt {attempt + 1})")
                        break

                    except Exception as e:
                        last_error = str(e)
                        logger.warning(f"Orchestrator: attempt {attempt + 1} failed for {scanner['function_name']} — {e}")
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(2 ** attempt)

                try:
                    if triggered:
                        db.record_scanner_triggered(scanner["function_name"])
                        results.append({
                            "account_id":    account["id"],
                            "scanner":       scanner["function_name"],
                            "resource_type": scanner["resource_type"],
                            "status":        "triggered",
                        })
                    else:
                        db.record_scanner_failed(scanner["function_name"], last_error)
                        results.append({
                            "account_id":    account["id"],
                            "scanner":       scanner["function_name"],
                            "resource_type": scanner["resource_type"],
                            "status":        "failed",
                            "error":         last_error,
                        })
                except Exception as e:
                    logger.error(f"Orchestrator: failed to update scanner record — {e}")

        triggered_count = len([r for r in results if r["status"] == "triggered"])
        failed_count    = len([r for r in results if r["status"] == "failed"])

        logger.info(f"Orchestrator: done — {triggered_count} triggered, {failed_count} failed")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "accounts":  len(accounts),
                "scanners":  len(scanners),
                "triggered": triggered_count,
                "failed":    failed_count,
                "results":   results,
            })
        }

    except Exception as e:
        logger.error(f"Orchestrator: fatal error — {e}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    finally:
        if db:
            db.close()