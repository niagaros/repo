from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch9Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.9
    Ensure a log metric filter and alarm exist for AWS Config configuration changes.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.9"
    TITLE = "Ensure a log metric filter and alarm exist for AWS Config configuration changes"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventSource = config.amazonaws.com) && '
        '(($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || '
        '($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }'
    )