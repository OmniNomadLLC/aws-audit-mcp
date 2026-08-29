"""Account-level security summary.

Read-only: uses only sts.GetCallerIdentity, iam.GetAccountSummary and
s3control.GetPublicAccessBlock. Standalone by design; it does not import
other tool modules.
"""

from botocore.exceptions import ClientError

from aws_audit_mcp.common import aws_client, finding, report

CHECK = "account.security_summary"


def account_security_summary() -> dict:
    """Cheap posture snapshot of the audited AWS account.

    Collects:
    - the account id (sts.GetCallerIdentity); this identifies the audited
      account and is returned in the summary
    - iam.GetAccountSummary counters: Users, AccountMFAEnabled,
      AccountAccessKeysPresent
    - the account-level S3 public access block (s3control.GetPublicAccessBlock)

    Findings:
    - HIGH when the root account has no MFA (AccountMFAEnabled != 1)
    - MEDIUM when the account-level S3 public access block is missing or any
      of its four flags is disabled

    Returns:
        Report envelope: {check, ok, findings[], scanned, summary}. `scanned`
        is 1 (one account). `summary` holds the collected numbers and
        account_id. Each finding has {check, severity, title, resource,
        detail} with severity one of LOW/MEDIUM/HIGH/CRITICAL.
    """
    sts = aws_client("sts")
    account_id = sts.get_caller_identity()["Account"]

    iam = aws_client("iam")
    iam_summary = iam.get_account_summary()["SummaryMap"]

    findings = []

    s3control = aws_client("s3control")
    pab = None
    try:
        pab = s3control.get_public_access_block(AccountId=account_id)[
            "PublicAccessBlockConfiguration"
        ]
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            raise
    pab_flags = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    if pab is None or not all(pab.get(flag) for flag in pab_flags):
        findings.append(
            finding(
                check=CHECK,
                severity="MEDIUM",
                title="account-level S3 public access block missing or weakened",
                resource="account",
                detail={"PublicAccessBlockConfiguration": pab},
            )
        )

    root_mfa = iam_summary.get("AccountMFAEnabled", 0)
    if root_mfa != 1:
        findings.append(
            finding(
                check=CHECK,
                severity="HIGH",
                title="root account has no MFA",
                resource="account",
                detail={"AccountMFAEnabled": root_mfa},
            )
        )

    summary = {
        "account_id": account_id,
        "Users": iam_summary.get("Users"),
        "AccountMFAEnabled": root_mfa,
        "AccountAccessKeysPresent": iam_summary.get("AccountAccessKeysPresent"),
        "PublicAccessBlockConfiguration": pab,
    }
    return report(CHECK, findings, scanned=1, summary=summary)


def register(mcp):
    from aws_audit_mcp.common import READ_ONLY

    mcp.tool(annotations=READ_ONLY)(account_security_summary)
