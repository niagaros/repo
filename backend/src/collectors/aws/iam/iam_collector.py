import logging

from collectors.base_collector import BaseCollector
from standards.enums import ResourceType

logger = logging.getLogger(__name__)


class IAMCollector(BaseCollector):
    """
    Collects account-wide IAM posture: root account MFA status and the
    account's password policy. These CIS AWS Benchmark controls (1.5, 1.8)
    apply once per account rather than per user, so this returns a single
    synthetic resource per scan instead of one row per IAM user.

    Per-user checks (access key rotation, unused credentials — CIS 1.12,
    1.14) need the IAM credential report (generate/get_credential_report,
    which is an async, poll-until-ready CSV export) and are intentionally
    out of scope here; left for a follow-up collector.
    """

    def get_resource_type(self):
        return ResourceType.IAM_ACCOUNT

    def collect(self) -> list:
        iam = self.aws.get_client("iam")

        return [self._resource(
            resource_id = "iam-account-summary",
            name        = "IAM account summary",
            region      = "global",  # IAM is not region-scoped
            config      = {
                "root_mfa_enabled": self._get_root_mfa_enabled(iam),
                "password_policy":  self._get_password_policy(iam),
            },
        )]

    def _get_root_mfa_enabled(self, iam) -> bool:
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            return bool(summary.get("AccountMFAEnabled", 0))
        except Exception as e:
            logger.error(f"IAMCollector: get_account_summary failed — {e}")
            return False

    def _get_password_policy(self, iam) -> dict | None:
        """
        Returns None when no password policy is set at all — AWS raises
        NoSuchEntityException in that case, which is itself a CIS finding
        (no policy = FAIL), not an error to swallow silently.
        """
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
            return {
                "minimum_password_length":   policy.get("MinimumPasswordLength", 0),
                "require_symbols":           policy.get("RequireSymbols", False),
                "require_numbers":           policy.get("RequireNumbers", False),
                "require_uppercase":         policy.get("RequireUppercaseCharacters", False),
                "require_lowercase":         policy.get("RequireLowercaseCharacters", False),
                "max_password_age":          policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention"),
            }
        except iam.exceptions.NoSuchEntityException:
            return None
        except Exception as e:
            logger.error(f"IAMCollector: get_account_password_policy failed — {e}")
            return None
