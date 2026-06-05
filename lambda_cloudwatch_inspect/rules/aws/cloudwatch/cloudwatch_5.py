from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch5Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.5
    Ensure a log metric filter and alarm exist for CloudTrail configuration changes.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.5"
    TITLE = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || '
        '($.eventName = DeleteTrail) || ($.eventName = StartLogging) || '
        '($.eventName = StopLogging) }'
    )