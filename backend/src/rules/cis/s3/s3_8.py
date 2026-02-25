from backend.rules.base_check import BaseCheck, CheckResult
from backend.standards.enums import Framework, ResourceType, Severity


class S3_8_BlockPublicAccess(BaseCheck):
    """
    CIS AWS Foundations Benchmark v5.0.0 — S3.8
    S3 general purpose buckets should block public access.
    """

    def get_metadata(self) -> dict:
        return {
            "check_id":      "S3.8",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "S3 general purpose buckets should block public access",
            "description":   "Blocking public access at the bucket level prevents accidental or malicious exposure of data.",
            "remediation":   (
                "aws s3api put-public-access-block "
                "--bucket BUCKET_NAME "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,"
                "BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ),
        }

    def run(self, resource: dict) -> CheckResult:
        pab        = resource["config"].get("public_access_block") or {}
        is_public  = resource["config"].get("is_public_acl", False)

        fully_blocked = all([
            pab.get("block_public_acls",       False),
            pab.get("ignore_public_acls",      False),
            pab.get("block_public_policy",     False),
            pab.get("restrict_public_buckets", False),
        ])

        if not fully_blocked or is_public:
            return CheckResult("FAIL", {
                "public_access_block": pab,
                "is_public_acl":       is_public,
            })

        return CheckResult("PASS", {
            "public_access_block": pab,
            "is_public_acl":       is_public,
        })