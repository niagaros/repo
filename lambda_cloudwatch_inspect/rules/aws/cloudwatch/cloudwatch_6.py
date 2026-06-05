from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch6Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.6
    Ensure a log metric filter and alarm exist for AWS Console authentication failures.

    Severity : MEDIUM
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.6"
    TITLE = "Ensure a log metric filter and alarm exist for AWS Console authentication failures"
    SEVERITY = "MEDIUM"

    FILTER_PATTERN = (
        '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
    )