from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType


class IAM_1_1(BaseCheck):
    """CIS AWS Foundations Benchmark 1.5 — root account MFA."""

    def get_metadata(self):
        return {
            "check_id":      "IAM.1.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.IAM_ACCOUNT,
            "severity":      Severity.CRITICAL,
            "title":         "MFA should be enabled for the root account",
            "remediation":   "Sign in as root and enable a virtual or hardware MFA device "
                              "under IAM > My Security Credentials.",
        }

    def run(self, resource):
        enabled = resource["config"].get("root_mfa_enabled", False)
        return CheckResult("PASS" if enabled else "FAIL", {"root_mfa_enabled": enabled})
