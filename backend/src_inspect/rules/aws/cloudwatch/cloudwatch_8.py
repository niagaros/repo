from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch8Check(CloudWatchBaseCheck):
    CONTROL_ID = "CloudWatch.8"
    TITLE = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    SEVERITY = "HIGH"
    FILTER_PATTERN = (
        "{ ($.eventSource = s3.amazonaws.com) && "
        "(($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || "
        "($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || "
        "($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || "
        "($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || "
        "($.eventName = DeleteBucketReplication)) }"
    )
    REMEDIATION = (
        "Create a metric filter on the CloudTrail log group that detects S3 bucket policy changes "
        "(PutBucketAcl, PutBucketPolicy, DeleteBucketPolicy, etc.) "
        "and attach a CloudWatch alarm that sends an SNS notification."
    )