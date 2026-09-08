from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class DynamoDB_DR_1(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "DynamoDB.DR.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.DYNAMODB_TABLE,
            "severity":      Severity.HIGH,
            "title":         "DynamoDB tables should have point-in-time recovery enabled",
            "remediation":   "aws dynamodb update-continuous-backups --table-name <name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
        }
    def run(self, resource):
        enabled = resource["config"].get("point_in_time_recovery_enabled", False)
        return CheckResult("PASS" if enabled else "FAIL", {"point_in_time_recovery_enabled": enabled})
