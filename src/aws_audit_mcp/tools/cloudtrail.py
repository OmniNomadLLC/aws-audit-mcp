"""CloudTrail posture audit.

Read-only: uses only DescribeTrails and GetTrailStatus.
"""

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "cloudtrail.trail_posture"


def audit_trail_posture(region: str | None = None) -> dict:
    """Audit CloudTrail trail posture in the account.

    Checks, per trail (shadow trails included, so multi-region trails homed in
    another region are still seen):
    - trail exists at all (zero trails is a CRITICAL finding on its own)
    - the trail is actively logging (GetTrailStatus.IsLogging), CRITICAL if not
    - IsMultiRegionTrail, MEDIUM if single-region
    - LogFileValidationEnabled, MEDIUM if disabled
    - KmsKeyId present, LOW if logs are not encrypted with a customer managed key

    Args:
        region: AWS region to query (defaults to AWS_REGION or us-east-1).

    Returns:
        Report envelope: {check, ok, findings[], scanned}. `scanned` is the
        number of trails inspected; `ok` is true only when no findings exist.
        Each finding has {check, severity, title, resource, detail} with
        severity one of LOW/MEDIUM/HIGH/CRITICAL and resource "trail/<name>"
        (or "account" for the zero-trails finding).
    """
    client = aws_client("cloudtrail", region)
    trails = client.describe_trails(includeShadowTrails=True)["trailList"]

    if not trails:
        return report(
            CHECK,
            [
                finding(
                    check=CHECK,
                    severity="CRITICAL",
                    title="no CloudTrail trail exists",
                    resource="account",
                    detail={"trailList": []},
                )
            ],
            scanned=0,
        )

    findings = []
    for trail in trails:
        name = trail["Name"]
        resource = f"trail/{name}"

        status = client.get_trail_status(Name=trail.get("TrailARN", name))
        if not status.get("IsLogging"):
            findings.append(
                finding(
                    check=CHECK,
                    severity="CRITICAL",
                    title="trail is not logging",
                    resource=resource,
                    detail={"IsLogging": status.get("IsLogging", False)},
                )
            )
        if not trail.get("IsMultiRegionTrail"):
            findings.append(
                finding(
                    check=CHECK,
                    severity="MEDIUM",
                    title="trail is not multi-region",
                    resource=resource,
                    detail={"IsMultiRegionTrail": trail.get("IsMultiRegionTrail", False)},
                )
            )
        if not trail.get("LogFileValidationEnabled"):
            findings.append(
                finding(
                    check=CHECK,
                    severity="MEDIUM",
                    title="log file validation is disabled",
                    resource=resource,
                    detail={
                        "LogFileValidationEnabled": trail.get("LogFileValidationEnabled", False)
                    },
                )
            )
        if not trail.get("KmsKeyId"):
            findings.append(
                finding(
                    check=CHECK,
                    severity="LOW",
                    title="trail logs not encrypted with a CMK",
                    resource=resource,
                    detail={"KmsKeyId": trail.get("KmsKeyId")},
                )
            )

    return report(CHECK, findings, scanned=len(trails))


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(audit_trail_posture)
