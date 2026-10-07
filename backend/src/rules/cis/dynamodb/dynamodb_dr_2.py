from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class DynamoDB_DR_2(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "DynamoDB.DR.2",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.DYNAMODB_TABLE,
            "severity":      Severity.MEDIUM,
            "title":         "DynamoDB tables should have deletion protection enabled",
            "remediation":   "aws dynamodb update-table --table-name <name> --deletion-protection-enabled",
        }
    def run(self, resource):
        enabled = resource["config"].get("deletion_protection_enabled", False)
        return CheckResult("PASS" if enabled else "FAIL", {"deletion_protection_enabled": enabled})
