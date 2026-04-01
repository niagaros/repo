from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch7Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.7"
    TITLE = "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of KMS CMKs"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventSource = kms.amazonaws.com) && "
        "(($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    )
    REMEDIATION = "Enable a CloudWatch alarm for KMS key disabling or deletion via a CloudTrail metric filter and notify via SNS."