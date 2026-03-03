from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_22_LogObjectLevelWriteEvents(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.22
    S3 general purpose buckets should log object-level write events.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.22",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 general purpose buckets should log object-level write events",
            "description":   "Logging object-level write events provides a full audit trail of who wrote, deleted, or modified objects in the bucket.",
            "remediation":   (
                "Enable CloudTrail S3 data events for write operations:\n"
                "aws cloudtrail put-event-selectors "
                "--trail-name TRAIL_NAME "
                "--event-selectors '[{"
                "\"ReadWriteType\": \"WriteOnly\","
                "\"IncludeManagementEvents\": true,"
                "\"DataResources\": [{"
                "\"Type\": \"AWS::S3::Object\","
                "\"Values\": [\"arn:aws:s3:::BUCKET_NAME/\"]"
                "}]}]'"
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        object_write_logging = resource["config"].get("object_level_write_logging", False)

        if not object_write_logging:
            return CheckResult("FAIL", {"object_level_write_logging": False})

        return CheckResult("PASS", {"object_level_write_logging": True})