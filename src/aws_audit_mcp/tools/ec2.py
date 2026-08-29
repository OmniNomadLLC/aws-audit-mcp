"""EC2 security group exposure audit.

Flags ingress rules open to the entire internet (0.0.0.0/0 or ::/0).
Read-only: only DescribeSecurityGroups is called.
"""

from typing import Any

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "ec2.world_open_security_groups"

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 9200, 27017}


def _world_open_cidrs(permission: dict[str, Any]) -> list[str]:
    cidrs = [r["CidrIp"] for r in permission.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
    cidrs += [
        r["CidrIpv6"] for r in permission.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"
    ]
    return cidrs


def _touches_sensitive_port(from_port: int | None, to_port: int | None) -> bool:
    if from_port is None or to_port is None:
        return True
    return any(from_port <= port <= to_port for port in SENSITIVE_PORTS)


def audit_world_open_security_groups(region: str | None = None) -> dict:
    """Audit EC2 security groups for ingress rules open to the world.

    Scans every security group in the region (AWS_REGION or us-east-1
    when the region argument is omitted) and flags each ingress rule
    whose source is 0.0.0.0/0 or ::/0. Rules allowing all traffic
    (protocol -1) or covering a sensitive port (SSH 22, RDP 3389,
    MySQL 3306, PostgreSQL 5432, Redis 6379, Elasticsearch 9200,
    MongoDB 27017) are HIGH; any other world-open port (for example
    80 or 443) is MEDIUM.

    Returns a dict {check, ok, findings, scanned} where ok is true only
    when no findings were produced, findings is a list of normalized
    finding dicts (check, severity, title, resource, detail with
    protocol, from_port, to_port, cidrs, group_name), and scanned is
    the number of security groups examined.
    """
    ec2 = aws_client("ec2", region)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for group in page.get("SecurityGroups", []):
            scanned += 1
            for permission in group.get("IpPermissions", []):
                cidrs = _world_open_cidrs(permission)
                if not cidrs:
                    continue
                protocol = permission.get("IpProtocol")
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if protocol == "-1" or _touches_sensitive_port(from_port, to_port):
                    severity = "HIGH"
                    title = "security group open to the world on a sensitive port or all traffic"
                else:
                    severity = "MEDIUM"
                    title = "security group open to the world"
                findings.append(
                    finding(
                        check=CHECK,
                        severity=severity,
                        title=title,
                        resource=f"security-group/{group['GroupId']}",
                        detail={
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                            "cidrs": cidrs,
                            "group_name": group.get("GroupName"),
                        },
                    )
                )
    return report(CHECK, findings, scanned=scanned)


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(audit_world_open_security_groups)
