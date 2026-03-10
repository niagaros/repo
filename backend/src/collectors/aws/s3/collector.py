import json
import logging
from collectors.base_collector import BaseCollector
from standards.enums import ResourceType

logger = logging.getLogger(__name__)

class S3Collector(BaseCollector):
    def get_resource_type(self):
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
                resources.append(self._resource(
                    resource_id = f"arn:aws:s3:::{name}",
                    name        = name,
                    region      = region,
                    config      = config,
                ))
                logger.info(f"S3Collector: collected {name}")
            except Exception as e:
                logger.error(f"S3Collector: failed on {name} — {e}")
        return resources

    def _get_region(self, s3, name: str) -> str:
        try:
            resp = s3.get_bucket_location(Bucket=name)
            return resp["LocationConstraint"] or "us-east-1"
        except Exception:
            return "unknown"

    def _get_config(self, s3, name: str) -> dict:
        c = {}

        # S3.2.1 / S3.2.2 / S3.2.3 / S3.2.4 — public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)
            b   = pab["PublicAccessBlockConfiguration"]
            c["public_access_block"] = {
                "block_public_acls":       b.get("BlockPublicAcls",       False),
                "ignore_public_acls":      b.get("IgnorePublicAcls",      False),
                "block_public_policy":     b.get("BlockPublicPolicy",     False),
                "restrict_public_buckets": b.get("RestrictPublicBuckets", False),
            }
        except Exception:
            c["public_access_block"] = None

        # S3.3.1 — ACL public check
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            c["is_public_acl"] = any(
                g.get("Grantee", {}).get("URI", "").endswith("AllUsers")
                for g in acl.get("Grants", [])
            )
        except Exception:
            c["is_public_acl"] = False

        # S3.3.2 — SSL required via bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            stmts  = json.loads(policy["Policy"]).get("Statement", [])
            c["ssl_required"] = any(
                s.get("Effect") == "Deny"
                and "s3:*" in (
                    s.get("Action") if isinstance(s.get("Action"), list)
                    else [s.get("Action")]
                )
                and s.get("Condition", {}).get("Bool", {}).get("aws:SecureTransport") == "false"
                for s in stmts
            )
        except Exception:
            c["ssl_required"] = False

        # S3.3.3 / S3.3.4 — versioning + MFA delete
        try:
            v = s3.get_bucket_versioning(Bucket=name)
            c["versioning"] = v.get("Status") == "Enabled"
            c["mfa_delete"] = v.get("MFADelete") == "Enabled"
        except Exception:
            c["versioning"] = False
            c["mfa_delete"] = False

        return c