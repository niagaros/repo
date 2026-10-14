import json
import logging

from botocore.exceptions import ClientError

from engine.scanner import Scanner
from config.database import Database
from notifications.email import send_account_disconnected_alert

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SCANNER_NAME = "cis_s3_scanner"

# STS error codes returned by sts:AssumeRole when the cross-account role is
# no longer assumable — deleted, trust policy changed, or the ExternalId no
# longer matches — as opposed to a transient AWS-side problem that a retry
# might fix.
CREDENTIAL_ERROR_CODES = {"AccessDenied", "InvalidClientTokenId", "ValidationError"}


def _handle_credential_failure(cloud_account_id: str, error: ClientError) -> dict:
    """
    Issue #269, acceptance criterion #4: "Given a cloud credential is
    revoked or expired, when detection occurs, then ingestion is paused
    and admin is notified."

    Marks the account disconnected (so the orchestrator's
    get_active_accounts() stops scanning it) and best-effort emails the
    account owner. Never raises — a DB or SES problem here must not mask
    the original credential error.
    """
    reason = error.response.get("Error", {}).get("Message", str(error))
    logger.warning(
        f"Lambda: cross-account role could not be assumed for "
        f"cloud_account_id={cloud_account_id} — {reason}"
    )

    db = None
    try:
        db = Database()
        db.mark_account_disconnected(cloud_account_id, reason)
        contact = db.get_account_contact(cloud_account_id)
        send_account_disconnected_alert(
            to_email=contact.get("owner_email") if contact else None,
            cloud_account_id=cloud_account_id,
            aws_account_id=contact.get("aws_account_id") if contact else None,
            reason=reason,
        )
    except Exception as e:
        logger.error(
            f"Lambda: failed to record/notify disconnected account "
            f"{cloud_account_id} — {e}"
        )
    finally:
        if db:
            db.close()

    return {
        "statusCode": 401,
        "body": json.dumps({
            "error": "credentials_revoked",
            "cloud_account_id": cloud_account_id,
            "message": "Scanning paused: the cross-account IAM role could not be assumed.",
        }),
    }


def lambda_handler(event, context):
    db = None
    try:
        cloud_account_id = event["cloud_account_id"]
        role_arn         = event["role_arn"]
        external_id      = event["external_id"]

        logger.info(f"Lambda: starting scan for account {cloud_account_id}")

        try:
            result = Scanner(cloud_account_id, role_arn, external_id).run()
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in CREDENTIAL_ERROR_CODES:
                return _handle_credential_failure(cloud_account_id, e)
            raise

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
        # Full detail goes to the logs only — returning str(e) to the
        # caller risks leaking internal details (e.g. database error
        # messages can include column/constraint names).
        logger.error(f"Lambda: scan failed — {e}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": "internal server error"})}