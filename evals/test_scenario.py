"""Bad-account scenario eval.

Builds a deliberately misconfigured account inside moto, then asserts the
matching audit tool actually flags each misconfiguration. Entries for tool
modules that have not merged yet skip with a clear reason and activate
automatically once the module lands.
"""

import importlib
import json

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.common import SEVERITIES

REGION = "us-east-1"


def _build_bad_account():
    """One IAM user with a key and no MFA, one public bucket, one world-open
    security group, and deliberately no CloudTrail trail."""
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


def _severity_at_least(result, minimum):
    order = list(SEVERITIES)
    threshold = order.index(minimum)
    assert result["findings"], f"{result['check']}: expected findings, got none"
    assert any(order.index(f["severity"]) >= threshold for f in result["findings"]), (
        f"{result['check']}: no finding at severity {minimum} or above"
    )


def _envelope_valid(result, _minimum=None):
    for key in ("check", "ok", "findings", "scanned"):
        assert key in result


# tool function name -> (module, assertion, minimum severity)
SCENARIO = {
    "audit_public_buckets": ("s3", _severity_at_least, "HIGH"),
    "audit_world_open_security_groups": ("ec2", _severity_at_least, "HIGH"),
    "audit_trail_posture": ("cloudtrail", _severity_at_least, "CRITICAL"),
    "audit_users_without_mfa": ("iam", _severity_at_least, "MEDIUM"),
    # Key age cannot be forced through the API from here, so only the
    # envelope shape is checked for the stale-keys tool.
    "audit_stale_access_keys": ("iam", _envelope_valid, None),
    "account_security_summary": ("account", _envelope_valid, None),
}


@pytest.mark.parametrize("fn_name", sorted(SCENARIO), ids=sorted(SCENARIO))
def test_bad_account_is_flagged(fn_name):
    module_name, assertion, minimum = SCENARIO[fn_name]
    try:
        module = importlib.import_module(f"aws_audit_mcp.tools.{module_name}")
    except ModuleNotFoundError:
        pytest.skip(f"tool module {module_name!r} not merged yet; activates after merge")
    fn = getattr(module, fn_name, None)
    if fn is None:
        pytest.skip(f"{module_name} module present but {fn_name!r} not found yet")
    with mock_aws():
        _build_bad_account()
        result = fn()
    assertion(result, minimum)
