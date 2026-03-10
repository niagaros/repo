from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_3_3(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.3.3",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 buckets should have versioning enabled",
            "remediation":   "aws s3api put-bucket-versioning ... Status=Enabled",
        }
    def run(self, resource):
        v = resource["config"].get("versioning", False)
        return CheckResult("PASS" if v else "FAIL", {"versioning": v})