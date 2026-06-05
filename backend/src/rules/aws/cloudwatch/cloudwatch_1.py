from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch1Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.1"
    TITLE = "A log metric filter and alarm should exist for usage of the root user"
    SEVERITY = "LOW"
    FILTER_PATTERN = '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }'
    REMEDIATION = "Enable a CloudWatch alarm for root user activity via a CloudTrail metric filter and notify via SNS."