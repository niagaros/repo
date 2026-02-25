import boto3
import logging

logger = logging.getLogger(__name__)


class AWSSession:
    """
    Assumes a role in the customer AWS account and
    provides boto3 clients scoped to that account.

    Usage:
        session = AWSSession(role_arn, external_id)
        s3      = session.get_client("s3")
        ec2     = session.get_client("ec2", region="eu-west-1")
    """

    def __init__(self, role_arn: str, external_id: str):
        self.role_arn    = role_arn
        self.external_id = external_id
        self._session    = None
        self._assume()

    def _assume(self):
        sts  = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn         = self.role_arn,
            RoleSessionName = "CSPMScan",
            ExternalId      = self.external_id,
        )
        creds = resp["Credentials"]
        self._session = boto3.Session(
            aws_access_key_id     = creds["AccessKeyId"],
            aws_secret_access_key = creds["SecretAccessKey"],
            aws_session_token     = creds["SessionToken"],
        )
        logger.info(f"AWSSession: assumed role {self.role_arn}")

    def get_client(self, service: str, region: str = "us-east-1"):
        return self._session.client(service, region_name=region)

    def list_regions(self) -> list:
        ec2 = self._session.client("ec2", region_name="us-east-1")
        return [r["RegionName"] for r in ec2.describe_regions()["Regions"]]