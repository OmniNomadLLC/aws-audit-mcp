"""Tests for the EBS exposure audit, backed by moto (no network)."""

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.ebs import audit_ebs_exposure

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _ec2():
    return boto3.client("ec2", region_name=REGION)


def _make_volume(encrypted: bool) -> str:
    return _ec2().create_volume(
        AvailabilityZone=f"{REGION}a", Size=8, Encrypted=encrypted
    )["VolumeId"]


def _make_snapshot(volume_id: str, public: bool) -> str:
    ec2 = _ec2()
    snapshot_id = ec2.create_snapshot(VolumeId=volume_id)["SnapshotId"]
    if public:
        ec2.modify_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )
    return snapshot_id


def _findings_for(result: dict, resource: str) -> list[dict]:
    return [f for f in result["findings"] if f["resource"] == resource]


@mock_aws
def test_unencrypted_volume_is_medium():
    volume_id = _make_volume(encrypted=False)
    result = audit_ebs_exposure(region=REGION)
    [f] = _findings_for(result, f"volume/{volume_id}")
    assert f["severity"] == "MEDIUM"
    assert f["title"] == "EBS volume is not encrypted"


@mock_aws
def test_encrypted_volume_is_not_flagged():
    volume_id = _make_volume(encrypted=True)
    result = audit_ebs_exposure(region=REGION)
    assert _findings_for(result, f"volume/{volume_id}") == []


@mock_aws
def test_public_snapshot_is_critical():
    volume_id = _make_volume(encrypted=True)
    snapshot_id = _make_snapshot(volume_id, public=True)
    result = audit_ebs_exposure(region=REGION)
    [f] = _findings_for(result, f"snapshot/{snapshot_id}")
    assert f["severity"] == "CRITICAL"
    assert f["title"] == "EBS snapshot is public"


@mock_aws
def test_private_snapshot_is_not_flagged():
    volume_id = _make_volume(encrypted=True)
    snapshot_id = _make_snapshot(volume_id, public=False)
    result = audit_ebs_exposure(region=REGION)
    assert _findings_for(result, f"snapshot/{snapshot_id}") == []


@mock_aws
def test_scanned_counts_volumes_and_snapshots():
    # moto ignores OwnerIds=["self"] and returns its preloaded Amazon-owned
    # snapshots too (real AWS honors the filter), so assert on the delta.
    baseline = audit_ebs_exposure(region=REGION)["snapshots_scanned"]
    volume_id = _make_volume(encrypted=True)
    _make_snapshot(volume_id, public=False)
    _make_snapshot(volume_id, public=False)
    result = audit_ebs_exposure(region=REGION)
    assert result["volumes_scanned"] == 1
    assert result["snapshots_scanned"] == baseline + 2
    assert result["scanned"] == result["volumes_scanned"] + result["snapshots_scanned"]
