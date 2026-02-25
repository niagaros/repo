from abc import ABC, abstractmethod


class BaseCollector(ABC):
    """
    Base class for all resource collectors.
    Each cloud provider + resource type gets its own collector.

    Example structure:
        collectors/aws/s3/collector.py    ← S3Collector
        collectors/aws/iam/collector.py   ← IAMCollector (future)
        collectors/aws/ec2/collector.py   ← EC2Collector (future)
    """

    def __init__(self, aws_session):
        self.aws = aws_session

    @abstractmethod
    def get_resource_type(self) -> str:
        """Return the resource type string e.g. 's3-bucket'"""

    @abstractmethod
    def collect(self) -> list:
        """Collect resources and return a list of resource dicts."""

    def _resource(
        self,
        resource_id: str,
        name:        str,
        region:      str,
        config:      dict,
    ) -> dict:
        return {
            "resource_type": self.get_resource_type(),
            "resource_id":   resource_id,
            "resource_name": name,
            "region":        region,
            "config":        config,
        }