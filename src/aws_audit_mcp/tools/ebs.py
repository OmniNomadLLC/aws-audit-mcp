"""EBS exposure audit: unencrypted volumes and publicly shared snapshots.

Read-only: only DescribeVolumes, DescribeSnapshots and
DescribeSnapshotAttribute are called.
"""

from typing import Any

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "ebs.exposure"


def audit_ebs_exposure(region: str | None = None) -> dict:
    """Audit EBS volumes and snapshots for exposure risks.

    Scans every EBS volume in the region (AWS_REGION or us-east-1 when
    the region argument is omitted) and flags unencrypted volumes as
    MEDIUM. Scans every snapshot owned by the account and checks its
    createVolumePermission attribute; a snapshot shared with the "all"
    group is public and is flagged CRITICAL.

    Returns a dict {check, ok, findings, scanned, volumes_scanned,
    snapshots_scanned} where ok is true only when no findings were
    produced, findings is a list of normalized finding dicts, and
    scanned is the total number of volumes plus snapshots examined.
    """
    ec2 = aws_client("ec2", region)
    findings: list[dict[str, Any]] = []
    volumes_scanned = 0
    snapshots_scanned = 0

    for page in ec2.get_paginator("describe_volumes").paginate():
        for volume in page.get("Volumes", []):
            volumes_scanned += 1
            if not volume.get("Encrypted", False):
                findings.append(
                    finding(
                        check=CHECK,
                        severity="MEDIUM",
                        title="EBS volume is not encrypted",
                        resource=f"volume/{volume['VolumeId']}",
                        detail={
                            "state": volume.get("State"),
                            "size_gib": volume.get("Size"),
                            "availability_zone": volume.get("AvailabilityZone"),
                        },
                    )
                )

    for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
        for snapshot in page.get("Snapshots", []):
            snapshots_scanned += 1
            snapshot_id = snapshot["SnapshotId"]
            attribute = ec2.describe_snapshot_attribute(
                SnapshotId=snapshot_id, Attribute="createVolumePermission"
            )
            permissions = attribute.get("CreateVolumePermissions", [])
            if any(p.get("Group") == "all" for p in permissions):
                findings.append(
                    finding(
                        check=CHECK,
                        severity="CRITICAL",
                        title="EBS snapshot is public",
                        resource=f"snapshot/{snapshot_id}",
                        detail={
                            "volume_id": snapshot.get("VolumeId"),
                            "encrypted": snapshot.get("Encrypted"),
                            "description": snapshot.get("Description"),
                        },
                    )
                )

    return report(
        CHECK,
        findings,
        scanned=volumes_scanned + snapshots_scanned,
        volumes_scanned=volumes_scanned,
        snapshots_scanned=snapshots_scanned,
    )


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(audit_ebs_exposure)
