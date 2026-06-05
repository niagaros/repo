from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch4Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.4"
    TITLE = "Ensure a log metric filter and alarm exist for IAM policy changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || "
        "($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || "
        "($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || "
        "($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || "
        "($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || "
        "($.eventName = SetDefaultPolicyVersion) || ($.eventName = AttachRolePolicy) || "
        "($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || "
        "($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || "
        "($.eventName = DetachGroupPolicy) }"
    )
    REMEDIATION = "Enable a CloudWatch alarm for IAM policy changes via a CloudTrail metric filter and notify via SNS."