from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch7Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.7
    Ensure a log metric filter and alarm exist for disabling or scheduled deletion of KMS CMKs.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.7"
    TITLE = "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of KMS CMKs"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventSource = kms.amazonaws.com) && '
        '(($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }'
    )