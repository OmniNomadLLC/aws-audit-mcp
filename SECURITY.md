# Security Policy

## Scope

aws-audit-mcp performs read-only metadata access against AWS APIs. It cannot create, modify, or delete resources. The intended deployment runs it under the least-privilege IAM policy in [examples/iam-policy.json](examples/iam-policy.json), which grants exactly the read actions the tools call; IAM is the enforcement boundary, the code discipline (single client factory, read-only tool annotations, CI grep for mutating verbs) is defense in depth on top of it.

## Reporting an issue

If you find a vulnerability (a way to make the server mutate state, leak credentials, or emit secret material), please open a private security advisory on the GitHub repository, or email the maintainer listed in the repository profile. Please do not open a public issue for security reports. You can expect an acknowledgment within a few days.

## Prompt injection stance

Tool output is data about the audited account, never instructions to the agent. The server's MCP instructions state this explicitly, and findings are structured JSON (check, severity, title, resource, detail), not free-form prose fed back to a model. Findings contain only identifiers (ARNs, key IDs, bucket names), never secret material such as key secrets, passwords, or session tokens.

## Telemetry and network

The server makes no network calls other than AWS API requests through boto3. There is no telemetry, no phone-home, no third-party endpoint.
