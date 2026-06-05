from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch9Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.9"
    TITLE = "Ensure a log metric filter and alarm exist for AWS Config configuration changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventSource = config.amazonaws.com) && "
        "(($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || "
        "($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    )
    REMEDIATION = "Enable a CloudWatch alarm for AWS Config configuration changes via a CloudTrail metric filter and notify via SNS."