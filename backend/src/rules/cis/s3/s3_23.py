from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_23_LogObjectLevelReadEvents(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.23
    S3 general purpose buckets should log object-level read events.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.23",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 general purpose buckets should log object-level read events",
            "description":   "Logging object-level read events provides a full audit trail of who accessed objects in the bucket.",
            "remediation":   (
                "Enable CloudTrail S3 data events for read operations:\n"
                "aws cloudtrail put-event-selectors "
                "--trail-name TRAIL_NAME "
                "--event-selectors '[{"
                "\"ReadWriteType\": \"ReadOnly\","
                "\"IncludeManagementEvents\": true,"
                "\"DataResources\": [{"
                "\"Type\": \"AWS::S3::Object\","
                "\"Values\": [\"arn:aws:s3:::BUCKET_NAME/\"]"
                "}]}]'"
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        object_read_logging = resource["config"].get("object_level_read_logging", False)

        if not object_read_logging:
            return CheckResult("FAIL", {"object_level_read_logging": False})

        return CheckResult("PASS", {"object_level_read_logging": True})