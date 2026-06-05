from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch2Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.2"
    TITLE = "Ensure a log metric filter and alarm exist for unauthorized API calls"
    SEVERITY = "LOW"
    FILTER_PATTERN = '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
    REMEDIATION = "Enable a CloudWatch alarm for unauthorized API calls via a CloudTrail metric filter and notify via SNS."