from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch11Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.11"
    TITLE = "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACLs)"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || "
        "($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || "
        "($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    )
    REMEDIATION = "Enable a CloudWatch alarm for NACL changes via a CloudTrail metric filter and notify via SNS."