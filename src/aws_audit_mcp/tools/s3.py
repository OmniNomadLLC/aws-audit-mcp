"""S3 public exposure audit.

Checks every bucket in the account for the three ways a bucket becomes
publicly reachable: a missing or weakened Public Access Block, a bucket
policy that allows the wildcard principal, and ACL grants to the AllUsers
or AuthenticatedUsers groups. Read-only: only Get/List S3 APIs are called.
"""

import json
from typing import Any

from botocore.exceptions import ClientError

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "s3.public_buckets"

_PAB_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

_PUBLIC_GROUP_SUFFIXES = ("/AllUsers", "/AuthenticatedUsers")


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _audit_one_bucket(s3, name: str) -> list[dict[str, Any]]:
    resource = f"bucket/{name}"
    findings: list[dict[str, Any]] = []

    try:
        pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        disabled = [flag for flag in _PAB_FLAGS if not pab.get(flag, False)]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
        disabled = "absent"
    if disabled:
        findings.append(
            finding(
                check=CHECK,
                severity="MEDIUM",
                title="public access block missing or weakened",
                resource=resource,
                detail={"disabled_flags": disabled},
            )
        )

    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucketPolicy":
            raise
        policy = None
    if policy:
        statements = policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            if not _principal_is_wildcard(stmt.get("Principal")):
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            findings.append(
                finding(
                    check=CHECK,
                    severity="HIGH",
                    title="bucket policy allows wildcard principal",
                    resource=resource,
                    detail={"actions": actions, "has_condition": "Condition" in stmt},
                )
            )

    acl = s3.get_bucket_acl(Bucket=name)
    for grant in acl.get("Grants", []):
        uri = grant.get("Grantee", {}).get("URI", "")
        if uri.endswith(_PUBLIC_GROUP_SUFFIXES):
            findings.append(
                finding(
                    check=CHECK,
                    severity="HIGH",
                    title="bucket ACL grants access to a public group",
                    resource=resource,
                    detail={"grantee_uri": uri, "permission": grant.get("Permission")},
                )
            )

    return findings


def audit_public_buckets() -> dict:
    """Audit every S3 bucket in the account for public exposure.

    For each bucket this checks: the Public Access Block configuration
    (missing or any of the four flags disabled yields a MEDIUM finding),
    the bucket policy (any Allow statement with principal "*" or
    {"AWS": "*"} yields a HIGH finding), and the bucket ACL (grants to
    the AllUsers or AuthenticatedUsers groups yield a HIGH finding).

    Returns a dict {check, ok, findings, scanned} where ok is true only
    when no findings were produced, findings is a list of normalized
    finding dicts (check, severity, title, resource, detail), and
    scanned is the number of buckets examined. Buckets that raise an
    unexpected AWS error are skipped and reported under an extra
    "errors" key mapping bucket name to error code. Severity: HIGH means
    the bucket is likely publicly reachable right now; MEDIUM means a
    guardrail is missing.
    """
    s3 = aws_client("s3")
    buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    findings: list[dict[str, Any]] = []
    errors: dict[str, str] = {}
    for name in buckets:
        try:
            findings.extend(_audit_one_bucket(s3, name))
        except ClientError as exc:
            errors[name] = exc.response["Error"]["Code"]
    extra = {"errors": errors} if errors else {}
    return report(CHECK, findings, scanned=len(buckets), **extra)


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(audit_public_buckets)
