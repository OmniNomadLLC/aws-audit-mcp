"""Tests for the S3 public exposure audit, backed by moto (no network)."""

import json

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.s3 import audit_public_buckets

FULL_PAB = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _make_bucket(name: str, pab: dict | None = FULL_PAB):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=name)
    if pab is not None:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=pab)
    return s3


@mock_aws
def test_clean_bucket_is_ok():
    _make_bucket("clean-bucket")
    result = audit_public_buckets()
    assert result["ok"] is True
    assert result["findings"] == []
    assert result["scanned"] == 1


@mock_aws
def test_missing_public_access_block_is_medium():
    _make_bucket("no-pab-bucket", pab=None)
    result = audit_public_buckets()
    assert result["ok"] is False
    [f] = result["findings"]
    assert f["severity"] == "MEDIUM"
    assert f["resource"] == "bucket/no-pab-bucket"
    assert f["detail"]["disabled_flags"] == "absent"


@mock_aws
def test_weakened_public_access_block_is_medium():
    _make_bucket("weak-pab-bucket", pab={**FULL_PAB, "BlockPublicPolicy": False})
    result = audit_public_buckets()
    [f] = result["findings"]
    assert f["severity"] == "MEDIUM"
    assert f["detail"]["disabled_flags"] == ["BlockPublicPolicy"]


@mock_aws
def test_wildcard_principal_policy_is_high():
    s3 = _make_bucket("open-policy-bucket")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::open-policy-bucket/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket="open-policy-bucket", Policy=json.dumps(policy))
    result = audit_public_buckets()
    policy_findings = [f for f in result["findings"] if "policy" in f["title"]]
    [f] = policy_findings
    assert f["severity"] == "HIGH"
    assert f["detail"]["actions"] == ["s3:GetObject"]
    assert f["detail"]["has_condition"] is False


@mock_aws
def test_scoped_principal_policy_is_not_flagged():
    s3 = _make_bucket("scoped-policy-bucket")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::scoped-policy-bucket/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket="scoped-policy-bucket", Policy=json.dumps(policy))
    result = audit_public_buckets()
    assert [f for f in result["findings"] if "policy" in f["title"]] == []


@mock_aws
def test_all_users_acl_grant_is_high():
    s3 = _make_bucket("acl-bucket")
    s3.put_bucket_acl(Bucket="acl-bucket", ACL="public-read")
    result = audit_public_buckets()
    acl_findings = [f for f in result["findings"] if "ACL" in f["title"]]
    assert acl_findings
    for f in acl_findings:
        assert f["severity"] == "HIGH"
        assert f["detail"]["grantee_uri"].endswith("/AllUsers")
        assert f["detail"]["permission"]


@mock_aws
def test_scanned_counts_all_buckets():
    _make_bucket("bucket-one")
    _make_bucket("bucket-two", pab=None)
    _make_bucket("bucket-three")
    result = audit_public_buckets()
    assert result["scanned"] == 3
    assert len(result["findings"]) == 1
