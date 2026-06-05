from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch3Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.3"
    TITLE = "Ensure a log metric filter and alarm exist for root account usage"
    SEVERITY = "CRITICAL"
    FILTER_PATTERN = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects root account usage "
        "and attach a CloudWatch alarm that immediately sends an SNS notification. "
        "Avoid using the root account for day-to-day operations and enable MFA on the root account."
    )
