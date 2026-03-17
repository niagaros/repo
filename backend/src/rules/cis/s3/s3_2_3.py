from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_2_3(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.2.3",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 buckets should block public bucket policies",
            "remediation":   "aws s3api put-public-access-block ... BlockPublicPolicy=true",
        }
    def run(self, resource):
        pab = resource["config"].get("public_access_block") or {}
        ok  = pab.get("block_public_policy", False)
        return CheckResult("PASS" if ok else "FAIL", {"block_public_policy": ok})