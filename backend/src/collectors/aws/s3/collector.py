import logging
import json
from backend.collectors.base_collector import BaseCollector
from backend.standards.enums import ResourceType

logger = logging.getLogger(__name__)


class S3Collector(BaseCollector):
    """
    Collects all S3 buckets and their configuration.
    Covers all fields needed for CIS v5.0.0 S3 checks:
        S3.1, S3.5, S3.8, S3.20, S3.22, S3.23
    """

    def get_resource_type(self) -> str:
        return ResourceType.S3_BUCKET

    def collect(self) -> list:
        s3        = self.aws.get_client("s3")
        buckets   = s3.list_buckets().get("Buckets", [])
        resources = []

        logger.info(f"S3Collector: found {len(buckets)} buckets")

        for bucket in buckets:
            name = bucket["Name"]
            try:
                region = self._get_region(s3, name)
                config = self._get_config(s3, name)
                resources.append(
                    self._resource(
                        resource_id = f"arn:aws:s3:::{name}",
                        name        = name,
                        region      = region,
                        config      = config,
                    )
                )
                logger.info(f"S3Collector: collected {name}")
            except Exception as e:
                logger.error(f"S3Collector: failed on {name} — {e}")

        return resources

    # ── private helpers ───────────────────────────────────────────

    def _get_region(self, s3, name: str) -> str:
        try:
            resp = s3.get_bucket_location(Bucket=name)
            return resp["LocationConstraint"] or "us-east-1"
        except Exception:
            return "unknown"

    def _get_config(self, s3, name: str) -> dict:
        config = {}

        # S3.8 / S3.1 — public access block
        try:
            pab    = s3.get_public_access_block(Bucket=name)
            c      = pab["PublicAccessBlockConfiguration"]
            config["public_access_block"] = {
                "block_public_acls":       c.get("BlockPublicAcls",       False),
                "ignore_public_acls":      c.get("IgnorePublicAcls",      False),
                "block_public_policy":     c.get("BlockPublicPolicy",     False),
                "restrict_public_buckets": c.get("RestrictPublicBuckets", False),
            }
        except Exception:
            config["public_access_block"] = None

        # S3.8 — ACL public check
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            config["is_public_acl"] = any(
                g.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                for g in acl.get("Grants", [])
            )
        except Exception:
            config["is_public_acl"] = False

        # S3.5 — SSL required (bucket policy check)
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            statements = json.loads(policy["Policy"]).get("Statement", [])
            ssl_denied = any(
                s.get("Effect") == "Deny"
                and "s3:*" in (
                s.get("Action") if isinstance(s.get("Action"), list)
                else [s.get("Action")]
                )
                and s.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
                for s in statements
            )
            config["ssl_required"] = ssl_denied
        except Exception:
            config["ssl_required"] = False

        # S3.20 — MFA delete
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            config["versioning"]  = v.get("Status") == "Enabled"
            config["mfa_delete"]  = v.get("MFADelete") == "Enabled"
        except Exception:
            config["versioning"] = False
            config["mfa_delete"] = False

        # S3.22 / S3.23 — object level logging via CloudTrail
        # These are account-level CloudTrail settings, not bucket-level.
        # The collector marks them False by default.
        # A dedicated CloudTrail collector will evaluate these properly.
        config["object_level_write_logging"] = False
        config["object_level_read_logging"]  = False

        return config