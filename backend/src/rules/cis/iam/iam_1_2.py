from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

MIN_REQUIRED_LENGTH = 14


class IAM_1_2(BaseCheck):
    """CIS AWS Foundations Benchmark 1.8 — password policy minimum length."""

    def get_metadata(self):
        return {
            "check_id":      "IAM.1.2",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.IAM_ACCOUNT,
            "severity":      Severity.MEDIUM,
            "title":         f"IAM password policy should require a minimum length of {MIN_REQUIRED_LENGTH}",
            "remediation":   "IAM > Account settings > Password policy — set minimum length "
                              f"to {MIN_REQUIRED_LENGTH} or greater.",
        }

    def run(self, resource):
        policy = resource["config"].get("password_policy")

        # No password policy configured at all is itself a finding, not
        # something to skip — an account with no policy accepts any
        # password, including a 1-character one.
        if policy is None:
            return CheckResult("FAIL", {"password_policy": None})

        length = policy.get("minimum_password_length", 0)
        ok     = length >= MIN_REQUIRED_LENGTH
        return CheckResult("PASS" if ok else "FAIL", {"minimum_password_length": length})
