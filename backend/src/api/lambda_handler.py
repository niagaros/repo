import json
import logging

from engine.scanner import Scanner
from config.database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCANNER_NAME = "cis_s3_scanner"


def lambda_handler(event, context):
    db = None
    try:
        cloud_account_id = event["cloud_account_id"]
        role_arn         = event["role_arn"]
        external_id      = event["external_id"]

        logger.info(f"Lambda: starting scan for account {cloud_account_id}")

        result = Scanner(cloud_account_id, role_arn, external_id).run()

        try:
            db = Database()
            db.record_scanner_completed(SCANNER_NAME)
        except Exception as e:
            logger.warning(f"Lambda: could not update scanner status — {e}")
        finally:
            if db:
                db.close()

        logger.info(f"Lambda: scan complete — {result}")
        return {"statusCode": 200, "body": json.dumps(result)}

    except KeyError as e:
        logger.error(f"Lambda: missing required field — {e}")
        return {"statusCode": 400, "body": json.dumps({"error": f"Missing field: {e}"})}

    except Exception as e:
        logger.error(f"Lambda: scan failed — {e}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}