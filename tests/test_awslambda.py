"""Tests for the Lambda resource policy audit, backed by moto (no network)."""

import io
import zipfile

import boto3
import pytest
from moto import mock_aws

from aws_audit_mcp.tools.awslambda import audit_lambda_resource_policies

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("handler.py", "def handler(event, context):\n    return event\n")
    return buffer.getvalue()


def _make_function(name: str) -> None:
    iam = boto3.client("iam", region_name=REGION)
    role_arn = iam.create_role(
        RoleName=f"{name}-role",
        AssumeRolePolicyDocument=(
            '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow",'
            ' "Principal": {"Service": "lambda.amazonaws.com"},'
            ' "Action": "sts:AssumeRole"}]}'
        ),
    )["Role"]["Arn"]
    boto3.client("lambda", region_name=REGION).create_function(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="handler.handler",
        Code={"ZipFile": _zip_bytes()},
    )


def _findings_for(result: dict, name: str) -> list[dict]:
    return [f for f in result["findings"] if f["resource"] == f"function/{name}"]


@mock_aws
def test_wildcard_principal_is_high():
    _make_function("open-func")
    boto3.client("lambda", region_name=REGION).add_permission(
        FunctionName="open-func",
        StatementId="allow-anyone",
        Action="lambda:InvokeFunction",
        Principal="*",
    )
    result = audit_lambda_resource_policies(region=REGION)
    [f] = _findings_for(result, "open-func")
    assert f["severity"] == "HIGH"
    assert f["title"] == "Lambda function is invocable by anyone"
    assert f["detail"]["sid"] == "allow-anyone"
    assert f["detail"]["has_condition"] is False


@mock_aws
def test_service_principal_with_source_arn_is_not_flagged():
    _make_function("s3-func")
    boto3.client("lambda", region_name=REGION).add_permission(
        FunctionName="s3-func",
        StatementId="allow-s3",
        Action="lambda:InvokeFunction",
        Principal="s3.amazonaws.com",
        SourceArn="arn:aws:s3:::my-bucket",
    )
    result = audit_lambda_resource_policies(region=REGION)
    assert _findings_for(result, "s3-func") == []


@mock_aws
def test_service_principal_without_condition_is_medium():
    _make_function("sns-func")
    boto3.client("lambda", region_name=REGION).add_permission(
        FunctionName="sns-func",
        StatementId="allow-sns",
        Action="lambda:InvokeFunction",
        Principal="sns.amazonaws.com",
    )
    result = audit_lambda_resource_policies(region=REGION)
    [f] = _findings_for(result, "sns-func")
    assert f["severity"] == "MEDIUM"
    assert f["title"] == "service principal without source condition"


@mock_aws
def test_function_without_policy_is_not_flagged():
    _make_function("quiet-func")
    result = audit_lambda_resource_policies(region=REGION)
    assert _findings_for(result, "quiet-func") == []
    assert result["ok"] is True


@mock_aws
def test_scanned_counts_functions():
    _make_function("func-a")
    _make_function("func-b")
    result = audit_lambda_resource_policies(region=REGION)
    assert result["scanned"] == 2
