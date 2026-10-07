"""
Tests for auth/cognito_admin.py (issue #265, acceptance criterion #4 —
the "active sessions are terminated" part).

Run from the repo root:
    .venv-test/Scripts/python.exe -I -m pytest backend/tests -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(BACKEND_SRC))


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "boom"}}, "AdminUserGlobalSignOut")


class TestTerminateAllSessions:
    def test_no_cognito_sub_is_a_no_op(self):
        from auth import cognito_admin
        assert cognito_admin.terminate_all_sessions(None) is False

    def test_missing_user_pool_id_skips_without_raising(self):
        from auth import cognito_admin
        with patch.object(cognito_admin, "USER_POOL_ID", None):
            assert cognito_admin.terminate_all_sessions("sub-123") is False

    def test_success_calls_admin_user_global_sign_out(self):
        from auth import cognito_admin
        mock_client = MagicMock()
        with patch.object(cognito_admin, "USER_POOL_ID", "eu-west-1_test"), \
             patch.object(cognito_admin.boto3, "client", return_value=mock_client):
            result = cognito_admin.terminate_all_sessions("sub-123")

        assert result is True
        mock_client.admin_user_global_sign_out.assert_called_once_with(
            UserPoolId="eu-west-1_test", Username="sub-123",
        )

    def test_client_error_is_swallowed_not_raised(self):
        from auth import cognito_admin
        mock_client = MagicMock()
        mock_client.admin_user_global_sign_out.side_effect = _client_error("UserNotFoundException")
        with patch.object(cognito_admin, "USER_POOL_ID", "eu-west-1_test"), \
             patch.object(cognito_admin.boto3, "client", return_value=mock_client):
            result = cognito_admin.terminate_all_sessions("sub-123")

        assert result is False  # must not raise
