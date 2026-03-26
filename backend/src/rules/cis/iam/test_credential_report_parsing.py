import pytest

from src.collectors.iam_collector import parse_credential_report_csv


SAMPLE_REPORT = b'''user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date
<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,true,2026-02-01T10:15:00+00:00,2026-01-01T00:00:00+00:00,N/A,true,true,2025-12-01T00:00:00+00:00,2026-02-10T11:00:00+00:00,false,N/A,N/A
test-user,arn:aws:iam::123456789012:user/test-user,2024-01-01T00:00:00+00:00,true,2026-02-01T10:15:00+00:00,2026-01-01T00:00:00+00:00,N/A,true,true,2025-12-01T00:00:00+00:00,2026-02-10T11:00:00+00:00,true,2025-11-01T00:00:00+00:00,2026-02-11T12:00:00+00:00
'''


def test_parse_credential_report_users_present():
    result = parse_credential_report_csv(SAMPLE_REPORT)
    assert "<root_account>" in result
    assert "test-user" in result


def test_parse_credential_report_root_values():
    result = parse_credential_report_csv(SAMPLE_REPORT)
    root = result["<root_account>"]
    assert root["mfa_active"] is True
    assert root["access_key_2_active"] is False
    assert root["password_last_used"].endswith("Z")


def test_parse_credential_report_user_values():
    result = parse_credential_report_csv(SAMPLE_REPORT)
    user = result["test-user"]
    assert user["password_enabled"] is True
    assert user["access_key_2_active"] is True
    assert user["access_key_2_last_used_date"].endswith("Z")