from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch3Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.3
    Ensure a log metric filter and alarm exist for root account usage.

    Severity : CRITICAL
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.3"
    TITLE = "Ensure a log metric filter and alarm exist for root account usage"
    SEVERITY = "CRITICAL"

    FILTER_PATTERN = (
        '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
    )