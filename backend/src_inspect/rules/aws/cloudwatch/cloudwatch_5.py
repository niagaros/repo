from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch5Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.5"
    TITLE = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || "
        "($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects changes to CloudTrail itself "
        "(create, update, delete, start and stop logging of trails) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )