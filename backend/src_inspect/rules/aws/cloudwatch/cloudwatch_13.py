from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch13Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.13"
    TITLE = "Ensure a log metric filter and alarm exist for route table changes"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || "
        "($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || "
        "($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || "
        "($.eventName = DisassociateRouteTable) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects route table changes "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )