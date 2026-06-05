from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch4Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.4
    Ensure a log metric filter and alarm exist for IAM policy changes.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.4"
    TITLE = "Ensure a log metric filter and alarm exist for IAM policy changes"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || '
        '($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || '
        '($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || '
        '($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || '
        '($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || '
        '($.eventName = SetDefaultPolicyVersion) || ($.eventName = AttachRolePolicy) || '
        '($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || '
        '($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || '
        '($.eventName = DetachGroupPolicy) }'
    )