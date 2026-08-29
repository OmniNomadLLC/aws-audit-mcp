"""Tests for the RDS instance posture audit, backed by moto (no network)."""

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.rds import audit_rds_posture


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _make_instance(identifier: str, **overrides):
    rds = boto3.client("rds", region_name="us-east-1")
    params = {
        "DBInstanceIdentifier": identifier,
        "DBInstanceClass": "db.t3.micro",
        "Engine": "postgres",
        "MasterUsername": "admin",
        "MasterUserPassword": "password123",
        "AllocatedStorage": 20,
    }
    params.update(overrides)
    rds.create_db_instance(**params)


@mock_aws
def test_empty_account_is_ok():
    result = audit_rds_posture()
    assert result["check"] == "rds.posture"
    assert result["ok"] is True
    assert result["findings"] == []
    assert result["scanned"] == 0


@mock_aws
def test_public_unencrypted_instance_flags_high_and_medium():
    _make_instance("bad-db", PubliclyAccessible=True, StorageEncrypted=False)
    result = audit_rds_posture()
    assert result["scanned"] == 1
    assert result["ok"] is False
    by_severity = {f["severity"]: f for f in result["findings"]}
    high = by_severity["HIGH"]
    assert high["title"] == "RDS instance is publicly accessible"
    assert high["resource"] == "db/bad-db"
    assert high["detail"]["engine"] == "postgres"
    assert high["detail"]["publicly_accessible"] is True
    assert high["detail"]["endpoint_address"]
    medium = by_severity["MEDIUM"]
    assert medium["title"] == "RDS storage is not encrypted"
    assert medium["resource"] == "db/bad-db"


@mock_aws
def test_private_encrypted_protected_instance_has_no_high_or_medium():
    _make_instance(
        "good-db",
        PubliclyAccessible=False,
        StorageEncrypted=True,
        DeletionProtection=True,
    )
    result = audit_rds_posture()
    assert result["scanned"] == 1
    severities = {f["severity"] for f in result["findings"]}
    assert "HIGH" not in severities
    assert "MEDIUM" not in severities


@mock_aws
def test_deletion_protection_disabled_is_low():
    _make_instance("unprotected-db", StorageEncrypted=True, DeletionProtection=False)
    result = audit_rds_posture()
    low = [f for f in result["findings"] if f["severity"] == "LOW"]
    assert len(low) == 1
    assert low[0]["title"] == "deletion protection disabled"
    assert low[0]["resource"] == "db/unprotected-db"
    assert low[0]["detail"]["deletion_protection"] is False


@mock_aws
def test_scanned_counts_all_instances():
    _make_instance("db-one")
    _make_instance("db-two")
    result = audit_rds_posture()
    assert result["scanned"] == 2
    for key in ("check", "ok", "findings", "scanned"):
        assert key in result
