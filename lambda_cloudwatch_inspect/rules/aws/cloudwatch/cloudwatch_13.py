from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch13Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.13
    Ensure a log metric filter and alarm exist for route table changes.

    Severity : MEDIUM
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.13"
    TITLE = "Ensure a log metric filter and alarm exist for route table changes"
    SEVERITY = "MEDIUM"

    FILTER_PATTERN = (
        '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || '
        '($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || '
        '($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || '
        '($.eventName = DisassociateRouteTable) }'
    )