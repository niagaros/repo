from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch12Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.12"
    TITLE = "Ensure a log metric filter and alarm exist for changes to network gateways"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || "
        "($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || "
        "($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects network gateway changes "
        "(create, delete, attach and detach of internet gateways and customer gateways) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )

