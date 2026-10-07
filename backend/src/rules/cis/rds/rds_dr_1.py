from rules.base_check import BaseCheck, CheckResult
from standards.enums import Severity, Framework, ResourceType

class RDS_DR_1(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "RDS.DR.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.RDS_INSTANCE,
            "severity":      Severity.HIGH,
            "title":         "RDS instances should have automated backups enabled with at least 7 days retention",
            "remediation":   "aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period 7",
        }
    def run(self, resource):
        retention = resource["config"].get("backup_retention_period", 0)
        ok = retention >= 7
        return CheckResult("PASS" if ok else "FAIL", {"backup_retention_period": retention})
