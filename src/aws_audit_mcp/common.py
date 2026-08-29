"""Shared contract for every audit tool module.

Every tool module in aws_audit_mcp.tools MUST:
- expose `register(mcp)` that attaches its tools via `@mcp.tool()`
- return findings built with `finding(...)` inside a `report(...)` envelope
- create AWS clients ONLY through `aws_client(...)` (read-only discipline:
  no tool in this project may import or call any mutating AWS API)
"""

import os
from typing import Any

import boto3
from botocore.config import Config
from mcp.types import ToolAnnotations

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Every tool in this server declares itself read-only to MCP clients.
# Usage in tool modules: @mcp.tool(annotations=READ_ONLY)
READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, open_world_hint=False)

# One retry config for every client: audits are interactive, fail fast.
_BOTO_CONFIG = Config(retries={"max_attempts": 3, "mode": "standard"}, read_timeout=15)


def aws_client(service: str, region: str | None = None):
    """Single factory for AWS clients.

    Honors AWS_PROFILE / AWS_REGION from the environment like every AWS tool.
    Keeping this in one place is what makes the read-only guarantee auditable:
    grep for `aws_client(` and you have every AWS touchpoint.
    """
    session = boto3.Session()
    return session.client(
        service,
        region_name=region or os.environ.get("AWS_REGION", "us-east-1"),
        config=_BOTO_CONFIG,
    )


def finding(
    *,
    check: str,
    severity: str,
    title: str,
    resource: str,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One normalized finding. Agents consume these, so the shape is stable API."""
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}")
    return {
        "check": check,
        "severity": severity,
        "title": title,
        "resource": resource,
        "detail": detail or {},
    }


def report(check: str, findings: list[dict[str, Any]], scanned: int, **extra) -> dict[str, Any]:
    """Envelope every tool returns: findings plus enough context to trust a zero.

    `scanned=0, findings=[]` and `scanned=200, findings=[]` are very different
    answers; agents (and humans) must be able to tell them apart.
    """
    return {
        "check": check,
        "ok": not findings,
        "findings": findings,
        "scanned": scanned,
        **extra,
    }
