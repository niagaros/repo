from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch12Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.12
    Ensure a log metric filter and alarm exist for changes to network gateways.

    Severity : MEDIUM
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.12"
    TITLE = "Ensure a log metric filter and alarm exist for changes to network gateways"
    SEVERITY = "MEDIUM"

    FILTER_PATTERN = (
        '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || '
        '($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || '
        '($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
    )