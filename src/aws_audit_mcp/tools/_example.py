# Reference implementation and eval fixture; underscore prefix keeps it out of autodiscovery.
"""Minimal tool module that follows the shared contract exactly.

The eval suite registers this module explicitly so the contract tests always
have at least one tool to run against, even before any real tool module lands.
"""

from aws_audit_mcp.common import READ_ONLY, report


def example_audit() -> dict:
    """Example audit that scans nothing and returns an empty findings envelope.

    Demonstrates the contract every tool follows: a report() envelope with
    check, ok, findings and scanned, so agents can trust an empty result.
    """
    return report("example.audit", [], scanned=0)


def register(mcp) -> None:
    """Attach this module's tools to the server."""
    mcp.tool(annotations=READ_ONLY)(example_audit)
