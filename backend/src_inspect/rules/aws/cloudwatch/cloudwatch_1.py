from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch1Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.1"
    TITLE = "Ensure a log metric filter and alarm exist for unauthorized API calls"
    SEVERITY = "HIGH"
    FILTER_PATTERN = '{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }'
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group with the pattern "
        '{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") } '
        "and attach a CloudWatch alarm that sends an SNS notification to an active subscription."
    )