from rules.base_check import BaseCheck
from rules.pitr_lag import evaluate_pitr_lag
from standards.enums import Severity, Framework, ResourceType

# RDS ships transaction logs to S3 every 5 minutes and LatestRestorableTime only moves
# forward when an upload has completed and been published (~3.5-4.5 min later). The
# measured lag on cspm-db therefore saw-tooths between ~3.5 and ~9.5 minutes under normal,
# healthy operation (40 samples on 2026-10-01: min 200 s, max 537 s, 70% above 300 s).
# A 5-minute limit failed on a healthy database most of the time. 15 minutes = the normal
# worst case plus one full missed upload cycle, so a FAIL means log shipping is really behind.
RPO_TARGET_SECONDS = 15 * 60  # 15 minutes

class RDS_DR_4(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "RDS.DR.4",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.RDS_INSTANCE,
            "severity":      Severity.MEDIUM,
            "title":         "RDS point-in-time-recovery lag should stay within the 15-minute RPO target",
            "remediation":   "Investigate transaction log shipping delay — usually caused by high write load or an undersized instance class.",
        }
    def run(self, resource):
        return evaluate_pitr_lag(
            resource["config"], RPO_TARGET_SECONDS,
            missing_reason="no LatestRestorableTime available — PITR may not be enabled",
        )
