from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_2_2(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.2.2",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 buckets should ignore public ACLs",
            "remediation":   "aws s3api put-public-access-block ... IgnorePublicAcls=true",
        }
    def run(self, resource):
        pab = resource["config"].get("public_access_block") or {}
        ok  = pab.get("ignore_public_acls", False)
        return CheckResult("PASS" if ok else "FAIL", {"ignore_public_acls": ok})