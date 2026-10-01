import importlib
import inspect
import logging
import pkgutil

import collectors.aws as collectors_pkg
import rules.cis      as rules_pkg
from collectors.base_collector import BaseCollector
from rules.base_check          import BaseCheck
from engine.aws_session        import AWSSession
from config.database           import Database
from postprocess.scoring       import calculate_score

logger = logging.getLogger(__name__)


def _discover(package, base_class: type) -> list:
    classes = []
    for _, name, _ in pkgutil.walk_packages(
        package.__path__,
        prefix=package.__name__ + ".",
    ):
        try:
            mod = importlib.import_module(name)
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                if issubclass(obj, base_class) and obj is not base_class:
                    classes.append(obj)
        except Exception as e:
            logger.error(f"Scanner: failed to import {name} — {e}")
    return classes


class Scanner:
    def __init__(
        self,
        cloud_account_id: str,
        role_arn:         str,
        external_id:      str,
    ):
        self.cloud_account_id = cloud_account_id
        self.aws = AWSSession(role_arn, external_id)
        self.db  = Database()

    def run(self) -> dict:

        # ── 1. collect resources ──────────────────────────────────
        scan_started_at   = self.db.current_timestamp()
        all_resources     = []
        prunable          = []   # (resource_type, existing_ids, regions) of complete listings
        collector_classes = _discover(collectors_pkg, BaseCollector)
        logger.info(f"Scanner: discovered {len(collector_classes)} collectors")

        for cls in collector_classes:
            try:
                collector = cls(self.aws)
                resources = collector.collect()
                logger.info(f"Scanner: {cls.__name__} collected {len(resources)} resources")
                all_resources.extend(resources)
                existing_ids = getattr(collector, "existing_ids", None)
                if existing_ids is not None:
                    rtype = collector.get_resource_type()
                    rtype = getattr(rtype, "value", rtype)
                    if not getattr(collector, "listing_complete", False):
                        logger.warning(f"Scanner: {cls.__name__} listing incomplete — nothing pruned for {rtype}")
                    elif not existing_ids:
                        # An empty listing is more likely a permission/region problem than
                        # "everything was deleted": never prune on it.
                        logger.warning(f"Scanner: {cls.__name__} listed 0 resources — nothing pruned for {rtype}")
                    else:
                        prunable.append((rtype, existing_ids, getattr(collector, "listed_regions", None)))
            except Exception as e:
                logger.error(f"Scanner: {cls.__name__} failed — {e}")

        # ── 2. persist resources, prune resources AWS no longer lists ──
        id_map = self.db.upsert_resources(self.cloud_account_id, all_resources)
        pruned = []
        for rtype, existing_ids, regions in prunable:
            try:
                pruned.extend(self.db.prune_resources(self.cloud_account_id, rtype, existing_ids, regions,
                                                      scan_started_at=scan_started_at))
            except Exception as e:
                logger.error(f"Scanner: pruning {rtype} failed — {e}")
                self.db.conn.rollback()

        # ── 3. run checks ─────────────────────────────────────────
        all_findings  = []
        check_classes = _discover(rules_pkg, BaseCheck)
        logger.info(f"Scanner: discovered {len(check_classes)} checks")

        for resource in all_resources:
            db_uuid = id_map.get(resource["resource_id"])
            if not db_uuid:
                continue

            for cls in check_classes:
                check = cls()
                meta  = check.get_metadata()

                if str(meta["resource_type"]) != str(resource["resource_type"]):
                    continue

                try:
                    result = check.run(resource)
                    all_findings.append({
                        "resource_id": db_uuid,
                        "check_id":    meta["check_id"],
                        "framework":   meta["framework"],
                        "title":       meta["title"],
                        "remediation": meta.get("remediation"),
                        "severity":    meta["severity"].value,
                        "result":      result.status,
                        "details":     result.details,
                    })
                except Exception as e:
                    logger.error(
                        f"Scanner: {cls.__name__} failed on "
                        f"{resource['resource_id']} — {e}"
                    )

        # ── 4. persist findings ───────────────────────────────────
        self.db.upsert_findings(all_findings)

        # ── 5. calculate and save score ───────────────────────────
        score = calculate_score(all_findings)
        self.db.update_compliance_score(self.cloud_account_id, score)
        self.db.close()

        logger.info(f"Scanner: done — {len(all_resources)} resources, {len(all_findings)} findings")

        return {
            "cloud_account_id":    self.cloud_account_id,
            "resources_collected": len(all_resources),
            "resources_pruned":    len(pruned),
            "checks_run":          len(all_findings),
            "findings_failed":     score["failed"],
            "compliance_score":    score,
        }