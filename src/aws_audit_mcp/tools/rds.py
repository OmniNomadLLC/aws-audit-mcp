"""RDS audit tool: instance posture (public access, encryption, deletion protection)."""

from aws_audit_mcp.common import READ_ONLY, aws_client, finding, report


def audit_rds_posture(region: str | None = None) -> dict:
    """Audit RDS instance posture: public accessibility, storage encryption,
    and deletion protection.

    Scans every RDS DB instance in the region. A publicly accessible instance
    is a HIGH finding, unencrypted storage is MEDIUM, and disabled deletion
    protection is LOW. Returns the {check, ok, findings[], scanned} envelope
    where scanned is the number of DB instances examined; each finding carries
    the engine, the endpoint address when public, and the raw posture flags.
    """
    rds = aws_client("rds", region)
    findings = []
    scanned = 0
    for page in rds.get_paginator("describe_db_instances").paginate():
        for db in page["DBInstances"]:
            scanned += 1
            identifier = db["DBInstanceIdentifier"]
            resource = f"db/{identifier}"
            public = db.get("PubliclyAccessible", False)
            encrypted = db.get("StorageEncrypted", False)
            protected = db.get("DeletionProtection", False)
            detail = {
                "engine": db.get("Engine"),
                "publicly_accessible": public,
                "storage_encrypted": encrypted,
                "deletion_protection": protected,
            }
            if public:
                detail["endpoint_address"] = db.get("Endpoint", {}).get("Address")
                findings.append(
                    finding(
                        check="rds.posture",
                        severity="HIGH",
                        title="RDS instance is publicly accessible",
                        resource=resource,
                        detail=detail,
                    )
                )
            if not encrypted:
                findings.append(
                    finding(
                        check="rds.posture",
                        severity="MEDIUM",
                        title="RDS storage is not encrypted",
                        resource=resource,
                        detail=detail,
                    )
                )
            if not protected:
                findings.append(
                    finding(
                        check="rds.posture",
                        severity="LOW",
                        title="deletion protection disabled",
                        resource=resource,
                        detail=detail,
                    )
                )
    return report("rds.posture", findings, scanned=scanned)


def register(mcp):
    mcp.tool(annotations=READ_ONLY)(audit_rds_posture)
