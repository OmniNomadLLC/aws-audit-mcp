"""Tests for the EC2 world-open security group audit, backed by moto (no network)."""

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.ec2 import audit_world_open_security_groups

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _make_group(name: str, permissions: list[dict]) -> str:
    ec2 = boto3.client("ec2", region_name=REGION)
    group_id = ec2.create_security_group(GroupName=name, Description=name)["GroupId"]
    if permissions:
        ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=permissions)
    return group_id


def _findings_for(result: dict, group_id: str) -> list[dict]:
    return [f for f in result["findings"] if f["resource"] == f"security-group/{group_id}"]


@mock_aws
def test_ssh_world_open_is_high():
    group_id = _make_group(
        "ssh-open",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    result = audit_world_open_security_groups(region=REGION)
    [f] = _findings_for(result, group_id)
    assert f["severity"] == "HIGH"
    assert f["detail"]["cidrs"] == ["0.0.0.0/0"]
    assert f["detail"]["from_port"] == 22


@mock_aws
def test_all_traffic_ipv6_is_high():
    group_id = _make_group(
        "all-traffic",
        [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
    )
    result = audit_world_open_security_groups(region=REGION)
    [f] = _findings_for(result, group_id)
    assert f["severity"] == "HIGH"
    assert f["detail"]["protocol"] == "-1"
    assert "::/0" in f["detail"]["cidrs"]


@mock_aws
def test_https_world_open_is_medium():
    group_id = _make_group(
        "https-open",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    result = audit_world_open_security_groups(region=REGION)
    [f] = _findings_for(result, group_id)
    assert f["severity"] == "MEDIUM"


@mock_aws
def test_scoped_cidr_is_not_flagged():
    group_id = _make_group(
        "internal-only",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    )
    result = audit_world_open_security_groups(region=REGION)
    assert _findings_for(result, group_id) == []


@mock_aws
def test_port_range_covering_sensitive_ports_is_high():
    group_id = _make_group(
        "wide-range",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 3000,
                "ToPort": 4000,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    result = audit_world_open_security_groups(region=REGION)
    [f] = _findings_for(result, group_id)
    assert f["severity"] == "HIGH"


@mock_aws
def test_scanned_counts_all_groups():
    _make_group("group-a", [])
    _make_group("group-b", [])
    result = audit_world_open_security_groups(region=REGION)
    # moto provides a default security group in addition to the two created here.
    assert result["scanned"] == 3
