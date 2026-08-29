"""Tests for the account security summary.

Tests may call mutating AWS APIs to build moto scenarios; the read-only rule
applies only to the tool code under src/.
"""

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.account import account_security_summary

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@mock_aws
def test_envelope_structure_and_account_id():
    result = account_security_summary()
    assert result["check"] == "account.security_summary"
    assert isinstance(result["ok"], bool)
    assert isinstance(result["findings"], list)
    assert result["scanned"] == 1
    summary = result["summary"]
    account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    assert summary["account_id"] == account_id
    # moto's get_account_summary returns static counters; assert on structure
    # rather than specific values.
    assert "Users" in summary
    assert "AccountMFAEnabled" in summary
    assert "AccountAccessKeysPresent" in summary


@mock_aws
def test_missing_account_pab_is_medium_finding():
    result = account_security_summary()
    pab_findings = [
        f
        for f in result["findings"]
        if f["title"] == "account-level S3 public access block missing or weakened"
    ]
    assert len(pab_findings) == 1
    assert pab_findings[0]["severity"] == "MEDIUM"
    assert pab_findings[0]["resource"] == "account"


@mock_aws
def test_full_account_pab_clears_finding():
    account_id = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    s3control = boto3.client("s3control", region_name=REGION)
    s3control.put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    result = account_security_summary()
    titles = {f["title"] for f in result["findings"]}
    assert "account-level S3 public access block missing or weakened" not in titles
    assert result["summary"]["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
