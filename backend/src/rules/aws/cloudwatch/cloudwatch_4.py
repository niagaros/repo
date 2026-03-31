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
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects all IAM policy changes "
        "(create, modify, delete, attach and detach of policies) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )