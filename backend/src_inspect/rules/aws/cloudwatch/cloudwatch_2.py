from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck

class CloudWatch2Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.2"
    TITLE = "Ensure a log metric filter and alarm exist for console login without MFA"
    SEVERITY = "CRITICAL"
    FILTER_PATTERN = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }'
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group with the pattern "
        '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") } '
        "and attach a CloudWatch alarm that sends an SNS notification. "
        "Additionally, enforce MFA for all IAM users."
    )









