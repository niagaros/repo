import logging
from datetime import datetime, timezone
from collectors.base_collector import BaseCollector
from standards.enums import ResourceType

logger = logging.getLogger(__name__)

class RDSCollector(BaseCollector):
    def get_resource_type(self):
        return ResourceType.RDS_INSTANCE

    def collect(self) -> list:
        # NOTE: AWSSession.get_client() defaults to us-east-1, and RDS results are
        # region-scoped (unlike S3's list_buckets). Scanner does not currently pass
        # a per-account region into collectors, so this is pinned to eu-west-1 to
        # match every account onboarded so far — a real limitation, not a full
        # multi-region scan, until region is threaded through Scanner.
        region = "eu-west-1"
        rds = self.aws.get_client("rds", region=region)
        resources = []

        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            # Moment of the API answer: the RPO rule measures restore-point lag
            # against this, not against the (later) moment the rule runs.
            observed_at = datetime.now(timezone.utc).isoformat()
            instances.extend((db, observed_at) for db in page.get("DBInstances", []))
        # The paginator raises on failure, so reaching this line means the listing is complete.
        # Stored rows are keyed by DBInstanceArn: without it for every instance, prune nothing.
        self.listed_regions = {region}
        self.existing_ids = {db["DBInstanceArn"] for db, _ in instances if db.get("DBInstanceArn")}
        if len(self.existing_ids) != len(instances):
            self.listing_complete = False

        logger.info(f"RDSCollector: found {len(instances)} instances")

        for db, observed_at in instances:
            identifier = db.get("DBInstanceIdentifier")
            try:
                config = {
                    "publicly_accessible":     db.get("PubliclyAccessible", False),
                    "storage_encrypted":       db.get("StorageEncrypted", False),
                    "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                    "multi_az":                db.get("MultiAZ", False),
                    "deletion_protection":     db.get("DeletionProtection", False),
                    "engine":                  db.get("Engine"),
                    "latest_restorable_time":  db["LatestRestorableTime"].isoformat() if db.get("LatestRestorableTime") else None,
                    "observed_at":             observed_at,
                    "availability_zone":       db.get("AvailabilityZone"),
                }
                resources.append(self._resource(
                    resource_id = db.get("DBInstanceArn", identifier),
                    name        = identifier,
                    region      = region,
                    config      = config,
                ))
                logger.info(f"RDSCollector: collected {identifier}")
            except Exception as e:
                logger.error(f"RDSCollector: failed on {identifier} — {e}")

        return resources
