from rules.base_check import BaseCheck
from rules.pitr_lag import evaluate_pitr_lag
from standards.enums import Severity, Framework, ResourceType

RPO_TARGET_SECONDS = 5 * 60  # 5 minutes

class RDS_DR_4(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "RDS.DR.4",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.RDS_INSTANCE,
            "severity":      Severity.MEDIUM,
            "title":         "RDS point-in-time-recovery lag should stay within the 5-minute RPO target",
            "remediation":   "Investigate transaction log shipping delay — usually caused by high write load or an undersized instance class.",
        }
    def run(self, resource):
        return evaluate_pitr_lag(
            resource["config"], RPO_TARGET_SECONDS,
            missing_reason="no LatestRestorableTime available — PITR may not be enabled",
        )
