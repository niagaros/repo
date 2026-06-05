from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch6Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.6"
    TITLE = "Ensure a log metric filter and alarm exist for AWS Console authentication failures"
    SEVERITY = "MEDIUM"
    FILTER_PATTERN = '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }'
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group with the pattern "
        '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") } '
        "and attach a CloudWatch alarm that sends an SNS notification on repeated failed login attempts."
    )