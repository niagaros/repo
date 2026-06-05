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
    REMEDIATION = "Enable a CloudWatch alarm for security group changes via a CloudTrail metric filter and notify via SNS."