"""
Tests for the new IAM account-level collector + CIS checks (issue #269,
AWS-only scope): IAMCollector, IAM_1_1 (root MFA) and IAM_1_2 (password
policy minimum length).

Run from the repo root with a venv that has boto3 and pytest installed:
    .venv-test/Scripts/python.exe -I -m pytest backend/tests -v

The -I (isolated mode) matters — see test_issue269_credential_detection.py
for why.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))

from collectors.aws.iam.iam_collector import IAMCollector
from rules.cis.iam.iam_1_1 import IAM_1_1
from rules.cis.iam.iam_1_2 import IAM_1_2


class _FakeNoSuchEntity(Exception):
    pass


def _make_iam_client(mfa_enabled: int, password_policy: dict | None):
    client = MagicMock()
    client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": mfa_enabled}}
    client.exceptions.NoSuchEntityException = _FakeNoSuchEntity

    if password_policy is None:
        client.get_account_password_policy.side_effect = _FakeNoSuchEntity("no policy set")
    else:
        client.get_account_password_policy.return_value = {"PasswordPolicy": password_policy}
    return client


class TestIAMCollector:
    def test_collects_single_resource_with_expected_shape(self):
        iam_client = _make_iam_client(mfa_enabled=1, password_policy={"MinimumPasswordLength": 14})
        aws_session = MagicMock()
        aws_session.get_client.return_value = iam_client

        resources = IAMCollector(aws_session).collect()

        assert len(resources) == 1
        resource = resources[0]
        assert resource["resource_type"] == "iam-account"
        assert resource["config"]["root_mfa_enabled"] is True
        assert resource["config"]["password_policy"]["minimum_password_length"] == 14
        aws_session.get_client.assert_called_once_with("iam")

    def test_root_mfa_disabled(self):
        iam_client = _make_iam_client(mfa_enabled=0, password_policy={"MinimumPasswordLength": 14})
        aws_session = MagicMock()
        aws_session.get_client.return_value = iam_client

        resource = IAMCollector(aws_session).collect()[0]

        assert resource["config"]["root_mfa_enabled"] is False

    def test_no_password_policy_set_returns_none_not_a_crash(self):
        iam_client = _make_iam_client(mfa_enabled=1, password_policy=None)
        aws_session = MagicMock()
        aws_session.get_client.return_value = iam_client

        resource = IAMCollector(aws_session).collect()[0]

        assert resource["config"]["password_policy"] is None

    def test_account_summary_failure_defaults_to_false_not_raised(self):
        iam_client = MagicMock()
        iam_client.get_account_summary.side_effect = Exception("boom")
        iam_client.exceptions.NoSuchEntityException = _FakeNoSuchEntity
        iam_client.get_account_password_policy.return_value = {"PasswordPolicy": {}}
        aws_session = MagicMock()
        aws_session.get_client.return_value = iam_client

        resource = IAMCollector(aws_session).collect()[0]  # must not raise

        assert resource["config"]["root_mfa_enabled"] is False


class TestIAM_1_1_RootMFA:
    def _resource(self, root_mfa_enabled: bool) -> dict:
        return {"config": {"root_mfa_enabled": root_mfa_enabled}}

    def test_pass_when_mfa_enabled(self):
        result = IAM_1_1().run(self._resource(True))
        assert result.status == "PASS"

    def test_fail_when_mfa_disabled(self):
        result = IAM_1_1().run(self._resource(False))
        assert result.status == "FAIL"

    def test_metadata_shape(self):
        meta = IAM_1_1().get_metadata()
        assert meta["check_id"] == "IAM.1.1"
        assert meta["resource_type"] == "iam-account"


class TestIAM_1_2_PasswordPolicyLength:
    def _resource(self, policy: dict | None) -> dict:
        return {"config": {"password_policy": policy}}

    def test_pass_when_length_meets_minimum(self):
        result = IAM_1_2().run(self._resource({"minimum_password_length": 14}))
        assert result.status == "PASS"

    def test_pass_when_length_exceeds_minimum(self):
        result = IAM_1_2().run(self._resource({"minimum_password_length": 20}))
        assert result.status == "PASS"

    def test_fail_when_length_below_minimum(self):
        result = IAM_1_2().run(self._resource({"minimum_password_length": 8}))
        assert result.status == "FAIL"

    def test_fail_when_no_policy_configured_at_all(self):
        result = IAM_1_2().run(self._resource(None))
        assert result.status == "FAIL"
        assert result.details == {"password_policy": None}
