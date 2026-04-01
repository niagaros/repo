from rules.aws.cloudwatch.cloudwatch_base import CloudWatchBaseCheck


class CloudWatch8Check(CloudWatchBaseCheck):
    """
    CIS CloudWatch Control CloudWatch.8
    Ensure a log metric filter and alarm exist for S3 bucket policy changes.

    Severity : HIGH
    Benchmark: CIS AWS Foundations Benchmark v1.4.0 / v1.2.0
    """

    CONTROL_ID = "CloudWatch.8"
    TITLE = "Ensure a log metric filter and alarm exist for S3 bucket policy changes"
    SEVERITY = "HIGH"

    FILTER_PATTERN = (
        '{ ($.eventSource = s3.amazonaws.com) && '
        '(($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || '
        '($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || '
        '($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || '
        '($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || '
        '($.eventName = DeleteBucketReplication)) }'
    )