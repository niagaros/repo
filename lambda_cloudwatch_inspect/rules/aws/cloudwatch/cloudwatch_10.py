from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch10Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.10
    Ensure a log metric filter and alarm exist for security group changes.

    Severity : MEDIUM
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.10"
    TITLE = "Ensure a log metric filter and alarm exist for security group changes"
    SEVERITY = "MEDIUM"

    FILTER_PATTERN = (
        '{ ($.eventName = AuthorizeSecurityGroupIngress) || '
        '($.eventName = AuthorizeSecurityGroupEgress) || '
        '($.eventName = RevokeSecurityGroupIngress) || '
        '($.eventName = RevokeSecurityGroupEgress) || '
        '($.eventName = CreateSecurityGroup) || '
        '($.eventName = DeleteSecurityGroup) }'
    )