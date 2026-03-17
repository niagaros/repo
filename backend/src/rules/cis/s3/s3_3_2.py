from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_3_2(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.3.2",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 buckets should deny HTTP requests",
            "remediation":   "Add bucket policy denying aws:SecureTransport=false",
        }
    def run(self, resource):
        ssl = resource["config"].get("ssl_required", False)
        return CheckResult("PASS" if ssl else "FAIL", {"ssl_required": ssl})