from abc import ABC, abstractmethod

class CheckResult:
    def __init__(self, status: str, details: dict = None):
        assert status in ("PASS", "FAIL"), f"Invalid status: {status}"
        self.status  = status
        self.details = details or {}

class BaseCheck(ABC):
    @abstractmethod
    def get_metadata(self) -> dict:
        pass

    @abstractmethod
    def run(self, resource: dict) -> CheckResult:
        pass