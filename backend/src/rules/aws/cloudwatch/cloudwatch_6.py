from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch6Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.6"
    TITLE = "Ensure a log metric filter and alarm exist for AWS Console authentication failures"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
    REMEDIATION = "Enable a CloudWatch alarm for Console authentication failures via a CloudTrail metric filter and notify via SNS."