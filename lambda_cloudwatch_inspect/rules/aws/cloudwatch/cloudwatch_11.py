from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch11Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.11
    Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACLs).

    Severity : MEDIUM
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.11"
    TITLE = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACLs)"
    SEVERITY = "MEDIUM"

    FILTER_PATTERN = (
        '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || '
        '($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || '
        '($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
    )