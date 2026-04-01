from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck

class CloudWatch14Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.14
    Ensure a log metric filter and alarm exist for VPC changes.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.14"
    TITLE = "Ensure a log metric filter and alarm exist for VPC changes"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || '
        '($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || '
        '($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || '
        '($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || '
        '($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || '
        '($.eventName = EnableVpcClassicLink) }'
    )