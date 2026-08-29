"""IAM audit tools: stale access keys, missing MFA, root account posture."""

from datetime import UTC, datetime

from botocore.exceptions import ClientError

from aws_audit_mcp.common import READ_ONLY, aws_client, finding, report


def _now() -> datetime:
    """Current UTC time; a seam so tests can control key aging."""
    return datetime.now(UTC)


def _user_mfa_devices(iam, user_name: str) -> list[dict]:
    devices = []
    for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
        devices.extend(page["MFADevices"])
    return devices


def audit_stale_access_keys(max_age_days: int = 90) -> dict:
    """Audit IAM users for active access keys older than max_age_days.

    Scans every IAM user and flags each Active access key whose age exceeds
    max_age_days. Returns {check, ok, findings[], scanned} where scanned is the
    number of users examined. Severity is HIGH when the key's owner has no MFA
    device (a leaked key is the only factor), MEDIUM when the owner has MFA.
    """
    iam = aws_client("iam")
    findings = []
    scanned = 0
    now = _now()
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            scanned += 1
            name = user["UserName"]
            keys = []
            for key_page in iam.get_paginator("list_access_keys").paginate(UserName=name):
                keys.extend(key_page["AccessKeyMetadata"])
            stale = [
                k for k in keys
                if k["Status"] == "Active"
                and (now - k["CreateDate"]).days > max_age_days
            ]
            if not stale:
                continue
            has_mfa = bool(_user_mfa_devices(iam, name))
            for key in stale:
                age_days = (now - key["CreateDate"]).days
                findings.append(
                    finding(
                        check="iam.stale_access_keys",
                        severity="MEDIUM" if has_mfa else "HIGH",
                        title=f"Active access key is {age_days} days old (limit {max_age_days})",
                        resource=f"user/{name}",
                        detail={
                            "access_key_id": key["AccessKeyId"],
                            "age_days": age_days,
                            "user_has_mfa": has_mfa,
                        },
                    )
                )
    return report("iam.stale_access_keys", findings, scanned=scanned)


def audit_users_without_mfa() -> dict:
    """Audit IAM users that can log in to the console without MFA.

    Scans every IAM user, checks which ones have a console login profile, and
    flags those with no MFA device as HIGH severity. Returns {check, ok,
    findings[], scanned} where scanned is the number of users examined; users
    without console access are counted but never flagged.
    """
    iam = aws_client("iam")
    findings = []
    scanned = 0
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            scanned += 1
            name = user["UserName"]
            try:
                iam.get_login_profile(UserName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchEntity":
                    continue
                raise
            if _user_mfa_devices(iam, name):
                continue
            findings.append(
                finding(
                    check="iam.users_without_mfa",
                    severity="HIGH",
                    title=f"Console user {name} has no MFA device",
                    resource=f"user/{name}",
                    detail={"has_console": True},
                )
            )
    return report("iam.users_without_mfa", findings, scanned=scanned)


def audit_root_account_posture() -> dict:
    """Audit the root account for missing MFA and active root access keys.

    Reads the IAM account summary. No root MFA is a HIGH finding; any root
    access key present is a CRITICAL finding. Returns {check, ok, findings[],
    scanned} with scanned=1 (the single root identity) and the raw summary
    values in each finding's detail.
    """
    iam = aws_client("iam")
    summary = iam.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0)
    access_keys_present = summary.get("AccountAccessKeysPresent", 0)
    findings = []
    if mfa_enabled != 1:
        findings.append(
            finding(
                check="iam.root_account_posture",
                severity="HIGH",
                title="root account has no MFA",
                resource="root",
                detail={"AccountMFAEnabled": mfa_enabled},
            )
        )
    if access_keys_present >= 1:
        findings.append(
            finding(
                check="iam.root_account_posture",
                severity="CRITICAL",
                title="root account has active access keys",
                resource="root",
                detail={"AccountAccessKeysPresent": access_keys_present},
            )
        )
    return report("iam.root_account_posture", findings, scanned=1)


def register(mcp):
    for func in (audit_stale_access_keys, audit_users_without_mfa, audit_root_account_posture):
        mcp.tool(annotations=READ_ONLY)(func)
