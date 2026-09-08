from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class RDS_DR_3(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "RDS.DR.3",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.RDS_INSTANCE,
            "severity":      Severity.MEDIUM,
            "title":         "RDS instances should have deletion protection enabled",
            "remediation":   "aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection",
        }
    def run(self, resource):
        protected = resource["config"].get("deletion_protection", False)
        return CheckResult("PASS" if protected else "FAIL", {"deletion_protection": protected})
