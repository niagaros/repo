from typing import Optional
import boto3
from boto3 import Session
from botocore.config import Config


def __init__(self, region: str, session=None):
    self.region = region

    self._boto_config = Config(
        region_name=region,
        retries={"max_attempts": 10, "mode": "standard"},
    )

    _session = session or boto3.Session()

    self.cloudtrail = _session.client("cloudtrail", config=self._boto_config)
    self.logs = _session.client("logs", config=self._boto_config)
    self.cloudwatch = _session.client("cloudwatch", config=self._boto_config)
    self.sns = _session.client("sns", config=self._boto_config)
    self.sts = _session.client("sts", config=self._boto_config)