"""
email.py

Minimal SES-based notification helper for admin alerts.

Currently used for issue #269 acceptance criterion #4:
"Given a cloud credential is revoked or expired, when detection occurs,
then ingestion is paused and admin is notified."

IMPORTANT — infrastructure prerequisite this code cannot verify itself:
  - `ALERTS_FROM_EMAIL` must be a verified SES identity (domain or address)
    in the target region, or every send_email call will fail.
  - If the SES account is still in sandbox mode, the *recipient* address
    must also be verified, or sending will fail for real customer emails.
  These are AWS console/account settings, not something this module can
  configure — check them before relying on this in production.

Every function here is best-effort: a failure to send is logged, never
raised, so a notification problem can never take down the scan Lambda
that triggered it.
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

SENDER = os.environ.get("ALERTS_FROM_EMAIL", "alerts@niagaros.io")
REGION = os.environ.get("SES_REGION", "eu-west-1")


def send_account_disconnected_alert(
    to_email: str | None,
    cloud_account_id: str,
    aws_account_id: str | None,
    reason: str,
) -> bool:
    """
    Notifies the account owner that Niagaros lost access to their AWS
    account (the cross-account IAM role could no longer be assumed —
    deleted, trust policy changed, or the ExternalId no longer matches).

    Returns True if SES accepted the email, False otherwise (including
    when there is no recipient to notify). Never raises.
    """
    if not to_email:
        logger.warning(
            f"Notifications: no owner email on file for cloud_account_id="
            f"{cloud_account_id}, skipping disconnect alert"
        )
        return False

    account_label = aws_account_id or cloud_account_id
    subject = "Action required: Niagaros lost access to your AWS account"
    body = (
        f"Niagaros could no longer scan AWS account {account_label}.\n\n"
        f"Reason: {reason}\n\n"
        "Scanning has been paused for this account so no stale results are "
        "shown. To restore it, reconnect the account from Settings -> "
        "Cloud Infrastructure in the Niagaros dashboard.\n"
    )

    try:
        ses = boto3.client("ses", region_name=REGION)
        ses.send_email(
            Source=SENDER,
            Destination={"ToAddresses": [to_email]},
            Message={
                "Subject": {"Data": subject},
                "Body": {"Text": {"Data": body}},
            },
        )
        logger.info(f"Notifications: sent disconnect alert to {to_email}")
        return True
    except ClientError as e:
        logger.error(f"Notifications: SES rejected disconnect alert to {to_email} — {e}")
        return False
    except Exception as e:
        logger.error(f"Notifications: failed to send disconnect alert to {to_email} — {e}")
        return False
