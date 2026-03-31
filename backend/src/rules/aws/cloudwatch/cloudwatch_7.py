from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch7Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.7"
    TITLE = "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of KMS CMKs"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventSource = kms.amazonaws.com) && "
        "(($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects disabling or scheduled deletion "
        "of KMS customer managed keys and attach a CloudWatch alarm that sends an SNS notification."
    )