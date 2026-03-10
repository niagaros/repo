from abc import ABC, abstractmethod

class BaseCollector(ABC):
    def __init__(self, aws_session):
        self.aws = aws_session

    @abstractmethod
    def get_resource_type(self) -> str:
        pass

    @abstractmethod
    def collect(self) -> list:
        pass

    def _resource(self, resource_id, name, region, config):
        return {
            "resource_type": self.get_resource_type(),
            "resource_id":   resource_id,
            "resource_name": name,
            "region":        region,
            "config":        config,
        }