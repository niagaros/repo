from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch1Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.1
    Ensure a log metric filter and alarm exist for unauthorized API calls.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.1"
    TITLE = "Ensure a log metric filter and alarm exist for unauthorized API calls"
    SEVERITY = "HIGH"

    # CIS-prescribed filter pattern for unauthorized API calls
    FILTER_PATTERN = (
        '{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }'
    )