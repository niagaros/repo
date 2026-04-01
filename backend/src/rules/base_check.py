from abc import ABC, abstractmethod


class CheckResult:
    def __init__(self, status: str, details: dict = None):
        assert status in ("PASS", "FAIL"), f"Invalid status: {status}"
        self.status  = status
        self.details = details or {}

    def to_dict(self) -> dict:
        return {"status": self.status, "details": self.details}


class BaseCheck(ABC):
    """
    Base class for all CIS benchmark checks.
    Each check file implements exactly one benchmark control.

    get_metadata() — returns check info (id, severity, title etc.)
    run()          — evaluates the resource and returns a CheckResult
    """

    @abstractmethod
    def get_metadata(self) -> dict:
        """
        Must return:
        {
            "check_id":      "S3.1",
            "framework":     Framework.CIS_AWS,
            "resource_type": ResourceType.S3_BUCKET,
            "severity":      Severity.HIGH,
            "title":         "...",
            "description":   "...",
            "remediation":   "...",
        }
        """

    @abstractmethod
    def run(self, resource: dict) -> CheckResult:
        """Evaluate the resource and return a CheckResult."""