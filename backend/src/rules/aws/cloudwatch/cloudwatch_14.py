from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck

class CloudWatch14Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.14"
    TITLE = "Ensure a log metric filter and alarm exist for VPC changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || "
        "($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || "
        "($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || "
        "($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || "
        "($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || "
        "($.eventName = EnableVpcClassicLink) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects VPC changes "
        "(create, delete, modify VPCs and VPC peering connections) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )