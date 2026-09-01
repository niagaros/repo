import logging
from collectors.base_collector import BaseCollector
from standards.enums import ResourceType

logger = logging.getLogger(__name__)

class RDSCollector(BaseCollector):
    def get_resource_type(self):
        return ResourceType.RDS_INSTANCE

    def collect(self) -> list:
        rds = self.aws.get_client("rds")
        resources = []

        paginator = rds.get_paginator("describe_db_instances")
        instances = []
        for page in paginator.paginate():
            instances.extend(page.get("DBInstances", []))

        logger.info(f"RDSCollector: found {len(instances)} instances")

        for db in instances:
            identifier = db.get("DBInstanceIdentifier")
            try:
                config = {
                    "publicly_accessible":     db.get("PubliclyAccessible", False),
                    "storage_encrypted":       db.get("StorageEncrypted", False),
                    "backup_retention_period": db.get("BackupRetentionPeriod", 0),
                    "multi_az":                db.get("MultiAZ", False),
                    "deletion_protection":     db.get("DeletionProtection", False),
                    "engine":                  db.get("Engine"),
                    "latest_restorable_time":  db.get("LatestRestorableTime"),
                }
                resources.append(self._resource(
                    resource_id = db.get("DBInstanceArn", identifier),
                    name        = identifier,
                    region      = db.get("AvailabilityZone", "unknown"),
                    config      = config,
                ))
                logger.info(f"RDSCollector: collected {identifier}")
            except Exception as e:
                logger.error(f"RDSCollector: failed on {identifier} — {e}")

        return resources
