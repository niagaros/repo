from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_1_BlockPublicAccessSettings(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.1
    S3 general purpose buckets should have block public access settings enabled.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 general purpose buckets should have block public access settings enabled",
            "description":   "Enabling block public access settings prevents public access to the bucket through access control lists or bucket policies.",
            "remediation":   (
                "aws s3api put-public-access-block "
                "--bucket BUCKET_NAME "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        pab = resource["config"].get("public_access_block") or {}

        block_public_acls       = pab.get("block_public_acls",       False)
        ignore_public_acls      = pab.get("ignore_public_acls",      False)
        block_public_policy     = pab.get("block_public_policy",     False)
        restrict_public_buckets = pab.get("restrict_public_buckets", False)

        all_enabled = all([
            block_public_acls,
            ignore_public_acls,
            block_public_policy,
            restrict_public_buckets,
        ])

        if not all_enabled:
            return CheckResult("FAIL", {
                "block_public_acls":       block_public_acls,
                "ignore_public_acls":      ignore_public_acls,
                "block_public_policy":     block_public_policy,
                "restrict_public_buckets": restrict_public_buckets,
            })

        return CheckResult("PASS", {"public_access_block": pab})