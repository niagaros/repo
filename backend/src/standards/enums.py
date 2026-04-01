from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"


class Framework(str, Enum):
    CIS_AWS = "CIS AWS Foundations Benchmark v5.0.0"


class CloudProvider(str, Enum):
    AWS = "aws"


class ResourceType(str, Enum):
    S3_BUCKET    = "s3-bucket"
    IAM_USER     = "iam-user"      # ready for later
    EC2_INSTANCE = "ec2-instance"  # ready for later