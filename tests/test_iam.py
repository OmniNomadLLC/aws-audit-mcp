"""Tests for the IAM audit tools, running fully offline against moto."""

from datetime import UTC, datetime, timedelta

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools import iam


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def frozen_now(monkeypatch):
    """Pin iam._now far in the future so moto-created keys read as old.

    moto stamps CreateDate with the real current time, so tests age keys by
    moving _now forward instead of moving CreateDate back.
    """
    def freeze(now):
        monkeypatch.setattr(iam, "_now", lambda: now)
    return freeze


def _client():
    return boto3.client("iam", region_name="us-east-1")


def _enable_mfa(client, user_name):
    serial = client.create_virtual_mfa_device(VirtualMFADeviceName=f"{user_name}-mfa")[
        "VirtualMFADevice"
    ]["SerialNumber"]
    client.enable_mfa_device(
        UserName=user_name,
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )


@mock_aws
def test_old_key_without_mfa_is_high(frozen_now):
    client = _client()
    client.create_user(UserName="alice")
    key_id = client.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    frozen_now(datetime.now(UTC) + timedelta(days=120))

    result = iam.audit_stale_access_keys(max_age_days=90)

    assert result["scanned"] == 1
    assert result["ok"] is False
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["check"] == "iam.stale_access_keys"
    assert f["severity"] == "HIGH"
    assert f["resource"] == "user/alice"
    assert f["detail"]["access_key_id"] == key_id
    assert f["detail"]["age_days"] >= 120
    assert f["detail"]["user_has_mfa"] is False


@mock_aws
def test_old_key_with_mfa_is_medium(frozen_now):
    client = _client()
    client.create_user(UserName="bob")
    client.create_access_key(UserName="bob")
    _enable_mfa(client, "bob")
    frozen_now(datetime.now(UTC) + timedelta(days=120))

    result = iam.audit_stale_access_keys(max_age_days=90)

    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "MEDIUM"
    assert result["findings"][0]["detail"]["user_has_mfa"] is True


@mock_aws
def test_fresh_key_is_not_flagged():
    client = _client()
    client.create_user(UserName="carol")
    client.create_access_key(UserName="carol")

    result = iam.audit_stale_access_keys(max_age_days=90)

    assert result["ok"] is True
    assert result["findings"] == []
    assert result["scanned"] == 1


@mock_aws
def test_inactive_old_key_is_not_flagged(frozen_now):
    client = _client()
    client.create_user(UserName="dave")
    key_id = client.create_access_key(UserName="dave")["AccessKey"]["AccessKeyId"]
    client.update_access_key(UserName="dave", AccessKeyId=key_id, Status="Inactive")
    frozen_now(datetime.now(UTC) + timedelta(days=365))

    result = iam.audit_stale_access_keys(max_age_days=90)

    assert result["ok"] is True
    assert result["findings"] == []


@mock_aws
def test_stale_keys_scanned_counts_all_users(frozen_now):
    client = _client()
    for name in ("u1", "u2", "u3"):
        client.create_user(UserName=name)
    frozen_now(datetime.now(UTC) + timedelta(days=120))

    result = iam.audit_stale_access_keys()

    assert result["scanned"] == 3
    assert result["findings"] == []


@mock_aws
def test_console_user_without_mfa_is_high():
    client = _client()
    client.create_user(UserName="erin")
    client.create_login_profile(UserName="erin", Password="Sup3r-Secret-Pw!")

    result = iam.audit_users_without_mfa()

    assert result["scanned"] == 1
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["check"] == "iam.users_without_mfa"
    assert f["severity"] == "HIGH"
    assert f["resource"] == "user/erin"
    assert f["detail"] == {"has_console": True}


@mock_aws
def test_console_user_with_mfa_is_not_flagged():
    client = _client()
    client.create_user(UserName="frank")
    client.create_login_profile(UserName="frank", Password="Sup3r-Secret-Pw!")
    _enable_mfa(client, "frank")

    result = iam.audit_users_without_mfa()

    assert result["ok"] is True
    assert result["findings"] == []
    assert result["scanned"] == 1


@mock_aws
def test_user_without_console_is_not_flagged():
    client = _client()
    client.create_user(UserName="grace")

    result = iam.audit_users_without_mfa()

    assert result["ok"] is True
    assert result["findings"] == []
    assert result["scanned"] == 1


@mock_aws
def test_root_posture_returns_report_envelope():
    _client().create_user(UserName="anyone")

    result = iam.audit_root_account_posture()

    assert set(result) >= {"check", "ok", "findings", "scanned"}
    assert result["check"] == "iam.root_account_posture"
    assert result["scanned"] == 1
    assert result["ok"] == (not result["findings"])
    for f in result["findings"]:
        assert f["resource"] == "root"
        assert f["severity"] in ("HIGH", "CRITICAL")
