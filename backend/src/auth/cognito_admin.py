"""
cognito_admin.py

Minimal Cognito admin-API helper for issue #265, acceptance criterion #4:
"Given a user leaves the organization, when offboarding is initiated,
then access is revoked, active sessions are terminated, and owned
resources are reassigned." This covers the "sessions are terminated" part.

IMPORTANT — infrastructure prerequisite this code cannot verify itself:
  - COGNITO_USER_POOL_ID must be set in the Lambda's environment, and its
    execution role needs cognito-idp:AdminUserGlobalSignOut permission on
    that pool. Neither is something this module can configure — check
    both before relying on this in production (same category of gap as
    notifications/email.py's SES prerequisite).

Best-effort, same pattern as notifications/email.py: a failure to sign
the user out everywhere is logged, never raised, so a Cognito problem
can never block the rest of offboarding (deactivation and resource
reassignment happen regardless).
"""

import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID")


def terminate_all_sessions(cognito_sub: str | None) -> bool:
    """
    Invalidates every refresh token for this user across every device and
    browser session (Cognito's AdminUserGlobalSignOut) — the actual
    mechanism behind "active sessions are terminated". Their current
    access token stays valid until it naturally expires (Cognito access
    tokens aren't individually revocable), but they cannot silently
    refresh past that point, and any *new* sign-in attempt still works
    only if their account is still active (see deactivate_user).

    Returns True on success, False otherwise — including when
    COGNITO_USER_POOL_ID isn't configured, or cognito_sub is missing.
    Never raises.
    """
    if not cognito_sub:
        logger.warning("cognito_admin: no cognito_sub on file, skipping global sign-out")
        return False
    if not USER_POOL_ID:
        logger.warning(
            f"cognito_admin: COGNITO_USER_POOL_ID not set, skipping global sign-out for {cognito_sub}"
        )
        return False

    try:
        cognito = boto3.client("cognito-idp")
        cognito.admin_user_global_sign_out(UserPoolId=USER_POOL_ID, Username=cognito_sub)
        logger.info(f"cognito_admin: terminated all sessions for {cognito_sub}")
        return True
    except ClientError as e:
        logger.error(f"cognito_admin: failed to terminate sessions for {cognito_sub} — {e}")
        return False
    except Exception as e:
        logger.error(f"cognito_admin: unexpected error terminating sessions for {cognito_sub} — {e}")
        return False
