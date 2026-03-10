from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_3_1(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.3.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.CRITICAL,
            "title":         "S3 buckets should not be publicly readable via ACL",
            "remediation":   "Remove AllUsers grant from bucket ACL",
        }
    def run(self, resource):
        is_public = resource["config"].get("is_public_acl", False)
        return CheckResult("FAIL" if is_public else "PASS", {"is_public_acl": is_public})