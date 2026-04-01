from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch3Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.3"
    TITLE = "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA"
    SEVERITY = "LOW"
    FILTER_PATTERN = '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }'
    REMEDIATION = "Enable a CloudWatch alarm for Console sign-ins without MFA via a CloudTrail metric filter and notify via SNS."