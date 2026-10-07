from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class RDS_DR_2(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "RDS.DR.2",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.RDS_INSTANCE,
            "severity":      Severity.MEDIUM,
            "title":         "RDS instances should have Multi-AZ enabled for automatic failover",
            "remediation":   "aws rds modify-db-instance --db-instance-identifier <id> --multi-az --apply-immediately",
        }
    def run(self, resource):
        multi_az = resource["config"].get("multi_az", False)
        return CheckResult("PASS" if multi_az else "FAIL", {"multi_az": multi_az})
