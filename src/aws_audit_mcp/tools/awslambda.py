"""Lambda resource policy audit: functions invocable from outside the account.

Read-only: only ListFunctions and GetPolicy are called. The module is named
awslambda (not lambda) because lambda is a Python keyword.
"""

import json
from typing import Any

from botocore.exceptions import ClientError

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "lambda.resource_policies"

SOURCE_CONDITION_KEYS = ("sourcearn", "sourceaccount")


def _get_policy(client, function_name: str) -> dict | None:
    try:
        response = client.get_policy(FunctionName=function_name)
    except ClientError as error:
        if error.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise
    return json.loads(response["Policy"])


def _is_wildcard_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    return isinstance(principal, dict) and principal.get("AWS") == "*"


def _service_principal(principal: Any) -> str | None:
    if isinstance(principal, dict) and isinstance(principal.get("Service"), str):
        return principal["Service"]
    return None


def _has_source_condition(statement: dict) -> bool:
    for operator in statement.get("Condition", {}).values():
        if not isinstance(operator, dict):
            continue
        for key in operator:
            if any(key.lower().endswith(suffix) for suffix in SOURCE_CONDITION_KEYS):
                return True
    return False


def audit_lambda_resource_policies(region: str | None = None) -> dict:
    """Audit Lambda function resource policies for overly broad invoke access.

    Scans every Lambda function in the region (AWS_REGION or us-east-1
    when the region argument is omitted) and inspects its resource
    policy, if any. An Allow statement with a wildcard principal ("*"
    or {"AWS": "*"}) and no SourceArn/SourceAccount condition is HIGH:
    anyone can invoke the function. A service principal (for example
    s3.amazonaws.com) without any source condition is MEDIUM: any
    account's use of that service can invoke it. Service principals
    scoped by a SourceArn or SourceAccount condition are normal and
    are not flagged.

    Returns a dict {check, ok, findings, scanned} where ok is true only
    when no findings were produced, findings is a list of normalized
    finding dicts (detail includes the statement sid, the principal and
    whether a condition exists), and scanned is the number of functions
    examined.
    """
    client = aws_client("lambda", region)
    findings: list[dict[str, Any]] = []
    scanned = 0

    for page in client.get_paginator("list_functions").paginate():
        for function in page.get("Functions", []):
            scanned += 1
            name = function["FunctionName"]
            policy = _get_policy(client, name)
            if policy is None:
                continue
            statements = policy.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]
            for statement in statements:
                if statement.get("Effect") != "Allow":
                    continue
                principal = statement.get("Principal")
                has_condition = "Condition" in statement and bool(statement["Condition"])
                has_source_condition = _has_source_condition(statement)
                severity = None
                title = None
                if _is_wildcard_principal(principal) and not has_source_condition:
                    severity = "HIGH"
                    title = "Lambda function is invocable by anyone"
                elif _service_principal(principal) and not has_condition:
                    severity = "MEDIUM"
                    title = "service principal without source condition"
                if severity is None:
                    continue
                findings.append(
                    finding(
                        check=CHECK,
                        severity=severity,
                        title=title,
                        resource=f"function/{name}",
                        detail={
                            "sid": statement.get("Sid"),
                            "principal": principal,
                            "has_condition": has_condition,
                        },
                    )
                )

    return report(CHECK, findings, scanned=scanned)


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(audit_lambda_resource_policies)
