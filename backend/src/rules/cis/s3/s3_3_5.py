from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class S3_3_5(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "S3.3.5",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 buckets should have default (server-side) encryption enabled",
            "remediation":   "aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'",
        }
    def run(self, resource):
        enabled = resource["config"].get("encryption_enabled", False)
        algo = resource["config"].get("encryption_algorithm")
        return CheckResult("PASS" if enabled else "FAIL", {"encryption_enabled": enabled, "encryption_algorithm": algo})
