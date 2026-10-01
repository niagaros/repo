from rules.base_check import BaseCheck
from rules.pitr_lag import evaluate_pitr_lag
from standards.enums import Severity, Framework, ResourceType

RPO_TARGET_SECONDS = 5 * 60  # 5 minutes

class DynamoDB_DR_3(BaseCheck):
    def get_metadata(self):
        return {
            "check_id":      "DynamoDB.DR.3",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.DYNAMODB_TABLE,
            "severity":      Severity.MEDIUM,
            "title":         "DynamoDB point-in-time-recovery lag should stay within the 5-minute RPO target",
            "remediation":   "Investigate continuous-backup lag — usually caused by very high write throughput.",
        }
    def run(self, resource):
        return evaluate_pitr_lag(
            resource["config"], RPO_TARGET_SECONDS,
            missing_reason="no LatestRestorableDateTime available — PITR may not be enabled",
        )
