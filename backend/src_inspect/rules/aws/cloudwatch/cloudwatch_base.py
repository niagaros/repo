from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CheckResult:
    """
    Represents the result of a single CIS CloudWatch control evaluation.
    """
    control_id: str
    title: str
    severity: str
    status: str  # "PASS" or "FAIL"
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "reasons": self.reasons,
            "details": self.details,
            "remediation": self.remediation,
        }


class CloudWatchBaseCheck:
    """
    Base class for all CIS CloudWatch controls (CloudWatch.1 – CloudWatch.14).

    Each subclass must define:
        CONTROL_ID    : str  e.g. "CloudWatch.1"
        TITLE         : str  Human-readable control title
        SEVERITY      : str  "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        FILTER_PATTERN: str  The exact CIS-prescribed CloudWatch metric filter pattern
        REMEDIATION   : str  Herstelstappen om de finding op te lossen
    """

    CONTROL_ID: str = ""
    TITLE: str = ""
    SEVERITY: str = ""
    FILTER_PATTERN: str = ""
    REMEDIATION: str = "Refer to the CIS AWS Foundations Benchmark documentation for remediation steps."

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def evaluate(self, snapshot: Dict[str, Any]) -> CheckResult:
        """
        Evaluate the CIS control against the CloudWatchCollector snapshot.
        Returns a CheckResult with status PASS or FAIL and a list of reasons.
        """
        reasons: List[str] = []
        details: Dict[str, Any] = {}

        # Step 1 – CloudTrail must be enabled and logging management events
        trail = self._get_active_trail(snapshot)
        if trail is None:
            reasons.append("No active CloudTrail trail found that is logging management events.")
            return self._fail(reasons, details)

        details["trail_name"] = trail.get("name")
        details["trail_arn"] = trail.get("trail_arn")

        # Step 2 – CloudTrail must deliver logs to a CloudWatch Log Group
        log_group_name = trail.get("cloudwatch_logs_log_group_name")
        if not log_group_name:
            reasons.append(
                f"Trail '{trail.get('name')}' is not delivering logs to a CloudWatch Log Group."
            )
            return self._fail(reasons, details)

        details["log_group_name"] = log_group_name

        # Step 3 – A metric filter matching the CIS pattern must exist
        metric_filter = self._find_metric_filter(snapshot, log_group_name)
        if metric_filter is None:
            reasons.append(
                f"No metric filter matching the required pattern found on log group '{log_group_name}'.\n"
                f"  Required pattern : {self.FILTER_PATTERN}"
            )
            return self._fail(reasons, details)

        metric_name = self._extract_metric_name(metric_filter)
        details["metric_filter_name"] = metric_filter.get("filterName")
        details["metric_name"] = metric_name

        # Step 4 – A CloudWatch Alarm must exist for the metric
        alarm = self._find_alarm_for_metric(snapshot, metric_name)
        if alarm is None:
            reasons.append(
                f"No CloudWatch Alarm found for metric '{metric_name}'."
            )
            return self._fail(reasons, details)

        details["alarm_name"] = alarm.get("AlarmName")

        # Step 5 – The alarm must have an SNS topic as an action
        sns_topic_arn = self._find_sns_action(alarm)
        if sns_topic_arn is None:
            reasons.append(
                f"Alarm '{alarm.get('AlarmName')}' has no SNS topic configured as an action."
            )
            return self._fail(reasons, details)

        details["sns_topic_arn"] = sns_topic_arn

        # Step 6 – The SNS topic must have at least one active subscription
        if not self._has_active_subscription(snapshot, sns_topic_arn):
            reasons.append(
                f"SNS topic '{sns_topic_arn}' has no active subscriptions."
            )
            return self._fail(reasons, details)

        # All conditions met → PASS
        return CheckResult(
            control_id=self.CONTROL_ID,
            title=self.TITLE,
            severity=self.SEVERITY,
            status="PASS",
            reasons=["All conditions met."],
            details=details,
            remediation=self.REMEDIATION,
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _get_active_trail(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        trails = snapshot.get("cloudtrail", {}).get("trails", [])
        for trail in trails:
            if trail.get("logging_enabled") and trail.get("management_events_logged"):
                return trail
        return None

    def _find_metric_filter(
        self, snapshot: Dict[str, Any], log_group_name: str
    ) -> Optional[Dict[str, Any]]:
        log_groups = snapshot.get("logs", {}).get("log_groups", [])
        for lg in log_groups:
            if lg.get("log_group_name") != log_group_name:
                continue
            for mf in lg.get("metric_filters", []) or []:
                if self._pattern_matches(mf.get("filterPattern", "")):
                    return mf
        return None

    def _pattern_matches(self, candidate: str) -> bool:
        def normalise(p: str) -> str:
            return " ".join(p.lower().split())
        return normalise(self.FILTER_PATTERN) in normalise(candidate)

    @staticmethod
    def _extract_metric_name(metric_filter: Dict[str, Any]) -> Optional[str]:
        transformations = metric_filter.get("metricTransformations") or []
        if transformations:
            return transformations[0].get("metricName")
        return None

    @staticmethod
    def _find_alarm_for_metric(
        snapshot: Dict[str, Any], metric_name: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        if not metric_name:
            return None
        alarms = snapshot.get("cloudwatch", {}).get("alarms", [])
        for alarm in alarms:
            if alarm.get("MetricName") == metric_name:
                return alarm
        return None

    @staticmethod
    def _find_sns_action(alarm: Dict[str, Any]) -> Optional[str]:
        for key in ("AlarmActions", "OKActions", "InsufficientDataActions"):
            for action in alarm.get(key, []) or []:
                if isinstance(action, str) and action.startswith("arn:aws:sns:"):
                    return action
        return None

    @staticmethod
    def _has_active_subscription(
        snapshot: Dict[str, Any], topic_arn: str
    ) -> bool:
        topics = snapshot.get("sns", {}).get("topics", [])
        for topic in topics:
            if topic.get("topic_arn") != topic_arn:
                continue
            for sub in topic.get("subscriptions", []) or []:
                arn = sub.get("subscription_arn", "")
                if arn and arn != "PendingConfirmation" and arn != "Deleted":
                    return True
        return False

    def _fail(self, reasons: List[str], details: Dict[str, Any]) -> CheckResult:
        return CheckResult(
            control_id=self.CONTROL_ID,
            title=self.TITLE,
            severity=self.SEVERITY,
            status="FAIL",
            reasons=reasons,
            details=details,
            remediation=self.REMEDIATION,
        )