from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_20_MFADelete(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.20
    S3 general purpose buckets should have MFA delete enabled.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.20",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 general purpose buckets should have MFA delete enabled",
            "description":   "MFA delete adds an additional layer of security by requiring MFA authentication before permanently deleting an object version or disabling versioning.",
            "remediation":   (
                "MFA delete can only be enabled by the root account user:\n"
                "aws s3api put-bucket-versioning "
                "--bucket BUCKET_NAME "
                "--versioning-configuration Status=Enabled,MFADelete=Enabled "
                "--mfa \"SERIAL_NUMBER MFA_CODE\""
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        mfa_delete = resource["config"].get("mfa_delete", False)

        if not mfa_delete:
            return CheckResult("FAIL", {"mfa_delete": False})

        return CheckResult("PASS", {"mfa_delete": True})