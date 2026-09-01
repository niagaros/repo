import logging
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

        for region in REGIONS_TO_CHECK:
            ddb = self.aws.get_client("dynamodb", region=region)
            try:
                table_names = []
                paginator = ddb.get_paginator("list_tables")
                for page in paginator.paginate():
                    table_names.extend(page.get("TableNames", []))
            except Exception as e:
                logger.error(f"DynamoDBCollector: failed to list tables in {region} — {e}")
                continue

            for name in table_names:
                try:
                    table = ddb.describe_table(TableName=name)["Table"]
                    pitr = ddb.describe_continuous_backups(TableName=name)["ContinuousBackupsDescription"]
                    pitr_status = pitr.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus")

                    config = {
                        "region":                        region,
                        "deletion_protection_enabled":   table.get("DeletionProtectionEnabled", False),
                        "point_in_time_recovery_enabled": pitr_status == "ENABLED",
                        "billing_mode":                  table.get("BillingModeSummary", {}).get("BillingMode"),
                        "item_count":                    table.get("ItemCount", 0),
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

        return resources
