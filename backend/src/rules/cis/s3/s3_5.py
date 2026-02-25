from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_5_RequireSSL(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.5
    S3 general purpose buckets should require requests to use SSL.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.5",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.MEDIUM,
            "title":         "S3 general purpose buckets should require requests to use SSL",
            "description":   "Requiring SSL ensures data in transit is encrypted and prevents man-in-the-middle attacks.",
            "remediation":   (
                "Add a bucket policy that denies any request where "
                "aws:SecureTransport is false:\n"
                "{\n"
                "  \"Effect\": \"Deny\",\n"
                "  \"Principal\": \"*\",\n"
                "  \"Action\": \"s3:*\",\n"
                "  \"Resource\": [\"arn:aws:s3:::BUCKET_NAME/*\"],\n"
                "  \"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}\n"
                "}"
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        ssl_required = resource["config"].get("ssl_required", False)

        if not ssl_required:
            return CheckResult("FAIL", {"ssl_required": False})

        return CheckResult("PASS", {"ssl_required": True})