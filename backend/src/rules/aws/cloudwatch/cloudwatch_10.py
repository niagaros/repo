from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch10Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.10"
    TITLE = "Ensure a log metric filter and alarm exist for security group changes"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = (
        "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || "
        "($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || "
        "($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects security group changes "
        "(create, delete, and modification of inbound/outbound rules) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )