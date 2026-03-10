from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_3_4(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.3.4",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 buckets should have MFA delete enabled",
            "remediation":   "aws s3api put-bucket-versioning ... MFADelete=Enabled",
        }
    def run(self, resource):
        m = resource["config"].get("mfa_delete", False)
        return CheckResult("PASS" if m else "FAIL", {"mfa_delete": m})