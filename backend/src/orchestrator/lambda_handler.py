import json
import logging
import time
import boto3

from config.database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

REGION      = "eu-west-1"
MAX_RETRIES = 3

# resource_type used to identify compliance mappers in the scanners table
MAPPER_RESOURCE_TYPE = "compliance"


def _invoke(client, function_name: str, payload: dict, synchronous: bool) -> tuple:
    """
    Invoke a Lambda with retries. Returns (triggered, last_error).

    For synchronous calls, a successful `client.invoke()` only means the
    invocation happened — it does NOT mean the scan succeeded. The invoked
    Lambda can still return statusCode >= 400 in its payload (e.g. when a
    cross-account IAM role can no longer be assumed, see
    api/lambda_handler.py's credential-failure handling for issue #269).
    Without inspecting that payload, a broken/disconnected account would
    be recorded as "triggered" every run and the orchestrator would never
    notice ingestion had effectively stopped for it.
    """
    invocation_type = "RequestResponse" if synchronous else "Event"
    last_error = None

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.invoke(
                FunctionName   = function_name,
                InvocationType = invocation_type,
                Payload        = json.dumps(payload),
            )

            if synchronous:
                raw = resp["Payload"].read()
                try:
                    parsed = json.loads(raw) if raw else {}
                except (TypeError, ValueError):
                    parsed = {}

                if resp.get("FunctionError") or parsed.get("statusCode", 200) >= 400:
                    last_error = parsed.get("body") or resp.get("FunctionError") or "non-200 response"
                    logger.warning(f"Orchestrator: {function_name} returned an error — {last_error}")
                    return False, last_error

            logger.info(f"Orchestrator: invoked {function_name} ({invocation_type}, attempt {attempt + 1})")
            return True, None
        except Exception as e:
            last_error = str(e)
            logger.warning(f"Orchestrator: attempt {attempt + 1} failed for {function_name} -- {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)

    return False, last_error


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

        # Split scanners and mappers -- mappers must run after scanners have written findings
        regular_scanners = [s for s in scanners if s["resource_type"] != MAPPER_RESOURCE_TYPE]
        mappers          = [s for s in scanners if s["resource_type"] == MAPPER_RESOURCE_TYPE]

        logger.info(f"Orchestrator: {len(regular_scanners)} scanners, {len(mappers)} mappers")

        client  = boto3.client("lambda", region_name=REGION)
        results = []

        # -- Wave 1: run regular scanners synchronously (wait for each to finish) --
        for account in accounts:

            if context and hasattr(context, 'get_remaining_time_in_millis') and context.get_remaining_time_in_millis() < 30000:
                logger.warning("Orchestrator: approaching timeout before scanner wave, stopping early")
                break

            for scanner in regular_scanners:
                triggered, last_error = _invoke(client, scanner["function_name"], {
                    "cloud_account_id": account["id"],
                    "role_arn":         account["role_arn"],
                    "external_id":      account["external_id"],
                    "region":           account.get("region", "eu-west-1"),
                }, synchronous=True)

                try:
                    if triggered:
                        db.record_scanner_triggered(scanner["function_name"])
                        results.append({"account_id": account["id"], "scanner": scanner["function_name"],
                                        "resource_type": scanner["resource_type"], "status": "triggered"})
                    else:
                        db.record_scanner_failed(scanner["function_name"], last_error)
                        results.append({"account_id": account["id"], "scanner": scanner["function_name"],
                                        "resource_type": scanner["resource_type"], "status": "failed",
                                        "error": last_error})
                except Exception as e:
                    logger.error(f"Orchestrator: failed to update scanner record -- {e}")

        logger.info("Orchestrator: scanner wave complete, starting mapper wave")

        # -- Wave 2: run mappers synchronously (findings are now in the DB) --------
        for account in accounts:

            if context and hasattr(context, 'get_remaining_time_in_millis') and context.get_remaining_time_in_millis() < 30000:
                logger.warning("Orchestrator: approaching timeout before mapper wave, stopping early")
                break

            for mapper in mappers:
                triggered, last_error = _invoke(client, mapper["function_name"], {
                    "cloud_account_id": account["id"],
                    "role_arn":         account["role_arn"],
                    "external_id":      account["external_id"],
                    "region":           account.get("region", "eu-west-1"),
                }, synchronous=True)

                try:
                    if triggered:
                        db.record_scanner_triggered(mapper["function_name"])
                        results.append({"account_id": account["id"], "scanner": mapper["function_name"],
                                        "resource_type": mapper["resource_type"], "status": "triggered"})
                    else:
                        db.record_scanner_failed(mapper["function_name"], last_error)
                        results.append({"account_id": account["id"], "scanner": mapper["function_name"],
                                        "resource_type": mapper["resource_type"], "status": "failed",
                                        "error": last_error})
                except Exception as e:
                    logger.error(f"Orchestrator: failed to update mapper record -- {e}")

            # Both waves done for this account — mark scan complete so dashboard knows
            try:
                db.touch_scan_at(account["id"])
            except Exception as e:
                logger.error(f"Orchestrator: failed to touch scan_at for {account['id']} -- {e}")

        triggered_count = len([r for r in results if r["status"] == "triggered"])
        failed_count    = len([r for r in results if r["status"] == "failed"])

        logger.info(f"Orchestrator: done -- {triggered_count} triggered, {failed_count} failed")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "accounts":  len(accounts),
                "scanners":  len(regular_scanners),
                "mappers":   len(mappers),
                "triggered": triggered_count,
                "failed":    failed_count,
                "results":   results,
            })
        }

    except Exception as e:
        logger.error(f"Orchestrator: fatal error -- {e}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}

    finally:
        if db:
            db.close()
