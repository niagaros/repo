from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_2_4(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.2.4",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 buckets should restrict public bucket access",
            "remediation":   "aws s3api put-public-access-block ... RestrictPublicBuckets=true",
        }
    def run(self, resource):
        pab = resource["config"].get("public_access_block") or {}
        ok  = pab.get("restrict_public_buckets", False)
        return CheckResult("PASS" if ok else "FAIL", {"restrict_public_buckets": ok})