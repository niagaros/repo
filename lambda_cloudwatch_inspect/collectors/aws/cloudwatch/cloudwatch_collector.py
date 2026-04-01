import datetime
from typing import Any, Dict, List, Optional, Set

import boto3
from botocore.config import Config


class CloudWatchCollector:
    """
    Collects AWS configuration required to evaluate CIS AWS Foundations Benchmark
    CloudWatch controls (CloudWatch.1 – CloudWatch.14).

    This collector does NOT evaluate PASS/FAIL. It only collects and normalizes data
    into a snapshot for the rule engine.
    """

    def __init__(self, region: str, session=None):
        self.region = region

        self._boto_config = Config(
            region_name=region,
            retries={"max_attempts": 10, "mode": "standard"},
        )

        _session = session or boto3.Session()

        self.cloudtrail = _session.client("cloudtrail", config=self._boto_config)
        self.logs = _session.client("logs", config=self._boto_config)
        self.cloudwatch = _session.client("cloudwatch", config=self._boto_config)
        self.sns = _session.client("sns", config=self._boto_config)
        self.sts = _session.client("sts", config=self._boto_config)

    @staticmethod
    def _now_iso() -> str:
        return datetime.datetime.now(datetime.timezone.utc).isoformat()

    @staticmethod
    def _extract_log_group_name_from_arn(log_group_arn: Optional[str]) -> Optional[str]:
        if not log_group_arn:
            return None
        marker = ":log-group:"
        if marker not in log_group_arn:
            return None
        tail = log_group_arn.split(marker, 1)[1]
        return tail.split(":")[0] or None

    @staticmethod
    def _strip_response_metadata(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: CloudWatchCollector._strip_response_metadata(v) for k, v in obj.items() if k != "ResponseMetadata"}
        if isinstance(obj, list):
            return [CloudWatchCollector._strip_response_metadata(x) for x in obj]
        return obj

    @staticmethod
    def _management_events_logged(selectors_resp: Dict[str, Any]) -> bool:
        if not selectors_resp:
            return False

        adv = selectors_resp.get("AdvancedEventSelectors") or []
        for selector in adv:
            for fs in selector.get("FieldSelectors", []) or []:
                if fs.get("Field") == "eventCategory":
                    equals = fs.get("Equals") or []
                    if "Management" in equals:
                        return True

        legacy = selectors_resp.get("EventSelectors") or []
        for selector in legacy:
            if selector.get("IncludeManagementEvents") is True:
                return True

        return False

    @staticmethod
    def _management_events_source(selectors_resp: Dict[str, Any]) -> Optional[str]:
        if not selectors_resp:
            return None
        if selectors_resp.get("AdvancedEventSelectors"):
            return "AdvancedEventSelectors"
        if selectors_resp.get("EventSelectors"):
            return "EventSelectors"
        return None

    def _paginate(self, client, operation: str, result_key: str, **kwargs) -> List[Dict[str, Any]]:
        paginator = client.get_paginator(operation)
        items: List[Dict[str, Any]] = []
        for page in paginator.paginate(**kwargs):
            items.extend(page.get(result_key, []) or [])
        return items

    @staticmethod
    def _collect_sns_topic_arns_from_alarms(alarms: List[Dict[str, Any]]) -> Set[str]:
        topic_arns: Set[str] = set()
        for a in alarms:
            for k in ("AlarmActions", "OKActions", "InsufficientDataActions"):
                for action in a.get(k, []) or []:
                    if isinstance(action, str) and action.startswith("arn:aws:sns:"):
                        topic_arns.add(action)
        return topic_arns

    def collect(self) -> Dict[str, Any]:
        caller = self.sts.get_caller_identity()
        account_id = caller.get("Account", "unknown")

        snapshot: Dict[str, Any] = {
            "snapshot_version": "cloudwatch-collector/v1",
            "account_id": account_id,
            "region": self.region,
            "collected_at": self._now_iso(),
            "errors": [],
            "cloudtrail": {"trails": []},
            "logs": {"log_groups": []},
            "cloudwatch": {"alarms": []},
            "sns": {"topics": []},
        }

        try:
            trails_resp = self.cloudtrail.describe_trails()
            raw_trails = trails_resp.get("trailList", []) or []
        except Exception as e:
            snapshot["errors"].append({"service": "cloudtrail", "api": "describeTrails", "message": str(e)})
            raw_trails = []

        normalized_trails: List[Dict[str, Any]] = []

        for t in raw_trails:
            trail_arn = t.get("TrailARN") or t.get("trailARN") or t.get("Name")
            if not trail_arn:
                continue

            try:
                status = self.cloudtrail.get_trail_status(Name=trail_arn)
                status = self._strip_response_metadata(status)
            except Exception as e:
                snapshot["errors"].append({"service": "cloudtrail", "api": "getTrailStatus", "resource": trail_arn, "message": str(e)})
                status = {}

            try:
                selectors = self.cloudtrail.get_event_selectors(TrailName=trail_arn)
                selectors = self._strip_response_metadata(selectors)
            except Exception as e:
                snapshot["errors"].append({"service": "cloudtrail", "api": "getEventSelectors", "resource": trail_arn, "message": str(e)})
                selectors = {}

            log_group_arn = t.get("CloudWatchLogsLogGroupArn")
            log_group_name = self._extract_log_group_name_from_arn(log_group_arn)

            normalized_trails.append(
                {
                    "name": t.get("Name"),
                    "trail_arn": t.get("TrailARN"),
                    "home_region": t.get("HomeRegion"),
                    "is_multi_region": t.get("IsMultiRegionTrail"),
                    "include_global_service_events": t.get("IncludeGlobalServiceEvents"),
                    "is_organization_trail": t.get("IsOrganizationTrail"),
                    "log_file_validation_enabled": t.get("LogFileValidationEnabled"),
                    "kms_key_id": t.get("KmsKeyId"),
                    "cloudwatch_logs_role_arn": t.get("CloudWatchLogsRoleArn"),
                    "cloudwatch_logs_log_group_arn": log_group_arn,
                    "cloudwatch_logs_log_group_name": log_group_name,
                    "logging_enabled": status.get("IsLogging"),
                    "management_events_logged": self._management_events_logged(selectors),
                    "management_events_source": self._management_events_source(selectors),
                    "evidence": {
                        "latest_delivery_time": status.get("LatestDeliveryTime"),
                        "latest_cloudwatch_logs_delivery_time": status.get("LatestCloudWatchLogsDeliveryTime"),
                    },
                }
            )

        normalized_trails.sort(key=lambda x: (x.get("name") or "", x.get("trail_arn") or ""))
        snapshot["cloudtrail"]["trails"] = normalized_trails

        referenced_log_group_names = sorted(
            {t.get("cloudwatch_logs_log_group_name") for t in normalized_trails if t.get("cloudwatch_logs_log_group_name")}
        )

        log_groups: List[Dict[str, Any]] = []
        for prefix in referenced_log_group_names:
            try:
                log_groups.extend(self._paginate(self.logs, "describe_log_groups", "logGroups", logGroupNamePrefix=prefix))
            except Exception as e:
                snapshot["errors"].append({"service": "logs", "api": "describeLogGroups", "resource": prefix, "message": str(e)})

        metric_filters_by_name: Dict[str, List[Dict[str, Any]]] = {}
        for lg_name in referenced_log_group_names:
            try:
                metric_filters_by_name[lg_name] = self._paginate(
                    self.logs, "describe_metric_filters", "metricFilters", logGroupName=lg_name
                )
            except Exception as e:
                snapshot["errors"].append({"service": "logs", "api": "describeMetricFilters", "resource": lg_name, "message": str(e)})
                metric_filters_by_name[lg_name] = []

        normalized_log_groups: List[Dict[str, Any]] = []
        for lg in log_groups:
            name = lg.get("logGroupName")
            normalized_log_groups.append(
                {
                    "log_group_name": name,
                    "arn": lg.get("arn"),
                    "retention_in_days": lg.get("retentionInDays"),
                    "kms_key_id": lg.get("kmsKeyId"),
                    "metric_filters": metric_filters_by_name.get(name, []),
                }
            )

        normalized_log_groups.sort(key=lambda x: x.get("log_group_name") or "")
        snapshot["logs"]["log_groups"] = normalized_log_groups

        try:
            alarms = self._paginate(self.cloudwatch, "describe_alarms", "MetricAlarms")
        except Exception as e:
            snapshot["errors"].append({"service": "cloudwatch", "api": "describeAlarms", "message": str(e)})
            alarms = []

        alarms_sorted = sorted(alarms, key=lambda x: x.get("AlarmName", ""))
        snapshot["cloudwatch"]["alarms"] = alarms_sorted

        topic_arns_used = self._collect_sns_topic_arns_from_alarms(alarms_sorted)

        try:
            all_topics = self._paginate(self.sns, "list_topics", "Topics")
        except Exception as e:
            snapshot["errors"].append({"service": "sns", "api": "listTopics", "message": str(e)})
            all_topics = []

        normalized_topics: List[Dict[str, Any]] = []

        for t in all_topics:
            topic_arn = t.get("TopicArn")
            if not topic_arn or topic_arn not in topic_arns_used:
                continue

            try:
                subs = self._paginate(self.sns, "list_subscriptions_by_topic", "Subscriptions", TopicArn=topic_arn)
            except Exception as e:
                snapshot["errors"].append({"service": "sns", "api": "listSubscriptionsByTopic", "resource": topic_arn, "message": str(e)})
                subs = []

            normalized_topics.append(
                {
                    "topic_arn": topic_arn,
                    "subscriptions": [
                        {
                            "subscription_arn": s.get("SubscriptionArn"),
                            "protocol": s.get("Protocol"),
                            "endpoint": s.get("Endpoint"),
                        }
                        for s in subs
                    ],
                }
            )

        normalized_topics.sort(key=lambda x: x.get("topic_arn") or "")
        snapshot["sns"]["topics"] = normalized_topics

        return snapshot