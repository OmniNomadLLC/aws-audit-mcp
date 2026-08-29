"""Tests for the aggregated posture audit (tools/full.py), all under moto."""

import json

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.common import SEVERITIES
from aws_audit_mcp.tools import full
from aws_audit_mcp.tools.full import audit_full_posture

REGION = "us-east-1"

EXPECTED_CHECKS = {
    "audit_stale_access_keys",
    "audit_users_without_mfa",
    "audit_root_account_posture",
    "audit_public_buckets",
    "audit_world_open_security_groups",
    "audit_trail_posture",
    "account_security_summary",
}


def _build_bad_account():
    """Same misconfigurations as evals/test_scenario.py: user with a key and no
    MFA, public bucket without PAB, SSH open to the world, no trail."""
    iam = boto3.client("iam", region_name=REGION)
    iam.create_user(UserName="bad-user")
    iam.create_access_key(UserName="bad-user")
    iam.create_login_profile(UserName="bad-user", Password="Sup3r-Secret-Pass!")

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="wide-open-bucket")
    s3.put_bucket_policy(
        Bucket="wide-open-bucket",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::wide-open-bucket/*",
                    }
                ],
            }
        ),
    )

    ec2 = boto3.client("ec2", region_name=REGION)
    sg = ec2.create_security_group(GroupName="open-ssh", Description="world open ssh")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )


def test_empty_account_envelope_and_discovery():
    with mock_aws():
        result = audit_full_posture()

    for key in ("check", "ok", "findings", "scanned"):
        assert key in result
    assert result["check"] == "full.posture"
    assert result["ok"] == (result["findings"] == [])
    assert isinstance(result["scanned"], int)

    checks_run = set(result["checks_run"])
    assert checks_run >= EXPECTED_CHECKS
    assert not any("full" in name for name in checks_run)
    assert result["grade"] in "ABCDF"
    assert result["posture_score"] <= 100


def test_bad_account_scores_lower_and_aggregates():
    with mock_aws():
        empty_score = audit_full_posture()["posture_score"]

    with mock_aws():
        _build_bad_account()
        result = audit_full_posture()

        assert result["posture_score"] < empty_score
        assert result["findings"], "bad account must produce findings"
        assert sum(result["severity_counts"].values()) == len(result["findings"])
        assert set(result["severity_counts"]) == set(SEVERITIES)
        for f in result["findings"]:
            assert f["severity"] in SEVERITIES

        # findings must be the untouched concatenation of the sub-reports
        expected = []
        for func in full._discover_checks():
            expected.extend(func().get("findings", []))
        assert result["findings"] == expected


def test_failing_check_lands_in_errors(monkeypatch):
    from aws_audit_mcp.tools import cloudtrail

    def boom(region: str | None = None) -> dict:
        raise RuntimeError("simulated failure")

    # Discovery filters on __module__ and reports module.func names, so the
    # stand-in must look like it lives in the cloudtrail module.
    boom.__module__ = cloudtrail.__name__
    boom.__name__ = "audit_trail_posture"
    monkeypatch.setattr(cloudtrail, "audit_trail_posture", boom)

    with mock_aws():
        result = audit_full_posture()

    assert any(
        e["check"] == "cloudtrail.audit_trail_posture" and "simulated failure" in e["error"]
        for e in result["errors"]
    )
    assert "audit_trail_posture" not in result["checks_run"]
    remaining = EXPECTED_CHECKS - {"audit_trail_posture"}
    assert remaining <= set(result["checks_run"])


@pytest.mark.parametrize("score,grade", [(95, "A"), (80, "B"), (65, "C"), (45, "D"), (10, "F")])
def test_grade_bands(score, grade):
    assert full._grade(score) == grade
