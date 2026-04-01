from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck

class CloudWatch2Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.2
    Ensure a log metric filter and alarm exist for console login without MFA.

    Severity : CRITICAL
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.2"
    TITLE = "Ensure a log metric filter and alarm exist for console login without MFA"
    SEVERITY = "CRITICAL"

    # CIS-prescribed filter pattern for console login without MFA
    FILTER_PATTERN = (
        '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
    )










