"""Tests for the CloudTrail posture audit.

Tests may call mutating AWS APIs to build moto scenarios; the read-only rule
applies only to the tool code under src/.
"""

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.cloudtrail import audit_trail_posture

REGION = "us-east-1"


def _make_trail(name="test-trail"):
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=f"{name}-bucket")
    ct = boto3.client("cloudtrail", region_name=REGION)
    ct.create_trail(
        Name=name,
        S3BucketName=f"{name}-bucket",
        IsMultiRegionTrail=False,
        EnableLogFileValidation=False,
    )
    return ct


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@mock_aws
def test_no_trails_is_critical():
    result = audit_trail_posture(region=REGION)
    assert result["check"] == "cloudtrail.trail_posture"
    assert result["ok"] is False
    assert result["scanned"] == 0
    assert len(result["findings"]) == 1
    f = result["findings"][0]
    assert f["severity"] == "CRITICAL"
    assert f["resource"] == "account"
    assert f["title"] == "no CloudTrail trail exists"


@mock_aws
def test_logging_single_region_trail_yields_medium_findings():
    ct = _make_trail()
    ct.start_logging(Name="test-trail")

    result = audit_trail_posture(region=REGION)
    assert result["scanned"] == 1
    titles = {f["title"] for f in result["findings"]}
    assert "trail is not logging" not in titles
    assert "trail is not multi-region" in titles
    assert "log file validation is disabled" in titles
    assert "trail logs not encrypted with a CMK" in titles
    severities = {f["title"]: f["severity"] for f in result["findings"]}
    assert severities["trail is not multi-region"] == "MEDIUM"
    assert severities["log file validation is disabled"] == "MEDIUM"
    assert severities["trail logs not encrypted with a CMK"] == "LOW"
    assert all(f["resource"] == "trail/test-trail" for f in result["findings"])


@mock_aws
def test_stopped_trail_is_critical():
    ct = _make_trail()
    ct.start_logging(Name="test-trail")
    ct.stop_logging(Name="test-trail")

    result = audit_trail_posture(region=REGION)
    assert result["ok"] is False
    not_logging = [f for f in result["findings"] if f["title"] == "trail is not logging"]
    assert len(not_logging) == 1
    assert not_logging[0]["severity"] == "CRITICAL"
    assert not_logging[0]["resource"] == "trail/test-trail"
