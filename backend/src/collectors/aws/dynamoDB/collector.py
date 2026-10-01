import logging
from datetime import datetime, timezone
from collectors.base_collector import BaseCollector
from standards.enums import ResourceType

logger = logging.getLogger(__name__)

# NOTE: same limitation as RDSCollector — Scanner does not thread a per-account
# region into collectors, and DynamoDB tables are region-scoped. Checking both
# regions seen in practice so far (eu-west-1 for our own account, eu-north-1
# for Domits) until region is threaded through Scanner properly.
REGIONS_TO_CHECK = ["eu-west-1", "eu-north-1"]

class DynamoDBCollector(BaseCollector):
    def get_resource_type(self):
        return ResourceType.DYNAMODB_TABLE

    def collect(self) -> list:
        resources = []
        self.existing_ids = set()
        self.listed_regions = set()

        for region in REGIONS_TO_CHECK:
            ddb = self.aws.get_client("dynamodb", region=region)
            try:
                table_names = []
                paginator = ddb.get_paginator("list_tables")
                for page in paginator.paginate():
                    table_names.extend(page.get("TableNames", []))
            except Exception as e:
                logger.error(f"DynamoDBCollector: failed to list tables in {region} — {e}")
                self.listing_complete = False
                continue
            self.listed_regions.add(region)

            for name in table_names:
                arn_known = False
                try:
                    table = ddb.describe_table(TableName=name)["Table"]
                    if table.get("TableArn"):
                        # Stored rows are keyed by TableArn; a name alone cannot protect them.
                        self.existing_ids.add(table["TableArn"])
                        arn_known = True
                    pitr = ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
                    observed_at = datetime.now(timezone.utc).isoformat()
                    pitr_desc = pitr.get("PointInTimeRecoveryDescription", {})
                    pitr_status = pitr_desc.get("PointInTimeRecoveryStatus")
                    latest_restorable = pitr_desc.get("LatestRestorableDateTime")

                    config = {
                        "region":                        region,
                        "deletion_protection_enabled":   table.get("DeletionProtectionEnabled", False),
                        "point_in_time_recovery_enabled": pitr_status == "ENABLED",
                        "billing_mode":                  table.get("BillingModeSummary", {}).get("BillingMode"),
                        "item_count":                    table.get("ItemCount", 0),
                        "latest_restorable_time":        latest_restorable.isoformat() if latest_restorable else None,
                        "observed_at":                   observed_at,
                    }
                    resources.append(self._resource(
                        resource_id = table.get("TableArn", name),
                        name        = name,
                        region      = region,
                        config      = config,
                    ))
                    logger.info(f"DynamoDBCollector: collected {name} ({region})")
                except Exception as e:
                    logger.error(f"DynamoDBCollector: failed on {name} — {e}")
                finally:
                    if not arn_known:
                        # No ARN for a table that exists: prune nothing this run.
                        self.listing_complete = False

        return resources
