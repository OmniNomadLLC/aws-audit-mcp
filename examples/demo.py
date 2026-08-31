# ruff: noqa: E402  (env vars must be set before boto3 imports)
"""Try aws-audit-mcp in 60 seconds, no AWS account needed.

Builds a deliberately misconfigured AWS account in moto (an in-memory AWS
emulator, nothing leaves your machine), then runs the aggregated audit
against it. Requires the demo extra: pip install "aws-audit-mcp[demo]"

Run: python -m examples.demo   (from a checkout)
  or: python demo.py           (this file on its own)
"""

import json
import os

# Fake credentials so boto3 never looks for real ones. Set before boto3 use.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import boto3
from moto import mock_aws

from aws_audit_mcp.tools.full import audit_full_posture

BAD = "\033[91m"
GOOD = "\033[92m"
BOLD = "\033[1m"
END = "\033[0m"


def build_bad_account() -> None:
    """Every classic mistake in one account."""
    iam = boto3.client("iam")
    iam.create_user(UserName="forgotten-service-user")
    iam.create_access_key(UserName="forgotten-service-user")  # no MFA anywhere

    s3 = boto3.client("s3")
    s3.create_bucket(Bucket="customer-data-prod")  # no public access block
    s3.put_bucket_policy(
        Bucket="customer-data-prod",
        Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::customer-data-prod/*",
            }],
        }),
    )

    ec2 = boto3.client("ec2")
    sg = ec2.create_security_group(GroupName="web", Description="oops")
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    # And no CloudTrail trail at all: nobody is watching.


def main() -> None:
    with mock_aws():
        build_bad_account()
        print(f"{BOLD}Auditing a deliberately misconfigured (fake) AWS account...{END}\n")
        result = audit_full_posture()

    for finding in result["findings"]:
        color = BAD if finding["severity"] in ("HIGH", "CRITICAL") else ""
        print(f"  {color}[{finding['severity']:8s}]{END} {finding['title']}: {finding['resource']}")

    counts = ", ".join(f"{k}: {v}" for k, v in result["severity_counts"].items() if v)
    grade_color = GOOD if result["grade"] in ("A", "B") else BAD
    print(f"\n{BOLD}Checks run:{END} {result['scanned']}   {BOLD}Findings:{END} {counts}")
    print(f"{BOLD}Posture score:{END} {result['posture_score']}/100   "
          f"{BOLD}Grade: {grade_color}{result['grade']}{END}")
    print("\nEverything above came from read-only API calls against an in-memory")
    print("account. Point it at a real account with an AWS_PROFILE and the")
    print("least-privilege policy in examples/iam-policy.json.")


if __name__ == "__main__":
    main()
