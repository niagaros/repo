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
    REMEDIATION = "Enable a CloudWatch alarm for network gateway changes via a CloudTrail metric filter and notify via SNS."

