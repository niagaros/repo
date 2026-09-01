import datetime
from rules.base_check import BaseCheck, CheckResult
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
        latest_restorable_str = resource["config"].get("latest_restorable_time")
        if not latest_restorable_str:
            return CheckResult("FAIL", {"reason": "no LatestRestorableDateTime available — PITR may not be enabled"})

        latest_restorable = datetime.datetime.fromisoformat(latest_restorable_str)
        now = datetime.datetime.now(datetime.timezone.utc)
        lag_seconds = (now - latest_restorable).total_seconds()
        ok = lag_seconds <= RPO_TARGET_SECONDS
        return CheckResult("PASS" if ok else "FAIL", {
            "measured_rpo_seconds": round(lag_seconds),
            "target_seconds": RPO_TARGET_SECONDS,
        })
