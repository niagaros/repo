from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch5Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.5"
    TITLE = "Ensure a log metric filter and alarm exist for CloudTrail configuration changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || "
        "($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    )
    REMEDIATION = "Enable a CloudWatch alarm for CloudTrail configuration changes via a CloudTrail metric filter and notify via SNS."