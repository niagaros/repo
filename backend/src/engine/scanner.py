import importlib
import inspect
import logging
import pkgutil

import backend.collectors.aws as collectors_pkg
import backend.rules.cis      as rules_pkg
from backend.collectors.base_collector import BaseCollector
from backend.rules.base_check          import BaseCheck
from backend.engine.aws_session        import AWSSession
from backend.config.database           import Database
from backend.postprocess.scoring       import calculate_score

logger = logging.getLogger(__name__)


def _discover(package, base_class: type) -> list:
    """
    Auto-discovers all concrete subclasses of base_class
    inside the given package — no manual registration needed.

    Adding a new collector = drop a file in collectors/aws/
    Adding a new rule      = drop a file in rules/cis/
    """
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
        all_resources     = []
        collector_classes = _discover(collectors_pkg, BaseCollector)
        logger.info(f"Scanner: discovered {len(collector_classes)} collectors")

        for cls in collector_classes:
            try:
                resources = cls(self.aws).collect()
                logger.info(f"Scanner: {cls.__name__} collected {len(resources)} resources")
                all_resources.extend(resources)
            except Exception as e:
                logger.error(f"Scanner: {cls.__name__} failed — {e}")

        # ── 2. persist resources ──────────────────────────────────
        id_map = self.db.upsert_resources(self.cloud_account_id, all_resources)

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
                        "description": meta.get("description"),
                        "remediation": meta.get("remediation"),
                        "severity":    meta["severity"],
                        "status":      result.status,
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
            "checks_run":          len(all_findings),
            "findings_failed":     score["failed"],
            "compliance_score":    score,
        }