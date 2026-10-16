# AWS Security Audit (46 controls) — prototype v0.1.0

A Python / boto3 CLI for the **46 supplied AWS infrastructure security checklist items**. It retains their Japanese titles, criteria, risk and priorities **as provided**, and distinguishes evidence-based PASS/FAIL from `MANUAL_REVIEW`, `UNKNOWN` and `NOT_APPLICABLE`.

> **Status: offline-tested prototype.** Not yet verified against an AWS account. Do not treat it as a compliance certification or as proof that a role has no write capability. Review code before running it, especially when installed from Git.

## Prerequisites

- `uv`, AWS CLI v2 with `aws login`, and Git + SSH authorization to the GitHub repository.
- An IAM user with the `SignInLocalDevelopmentAccess` permission (or IAM Identity Center) and `sts:AssumeRole` permission for a designated role.
- The target IAM role must trust the authenticated principal and have sufficient read permission (for example, AWS managed `ReadOnlyAccess`).
- **The script does not create a role, edit IAM policies or change any AWS resources.**

## Run from the GitHub repository

```bash
# Authenticate once with your AWS identity (only the source profile sees these credentials):
aws login --profile audit-source

# Once released at a fixed SHA/tag, invoke the tool (replace OWNER/REPO/SHA):
uvx --from 'git+ssh://git@github.com/yohi/aws-security-audit.git@COMMIT_SHA' \
  aws-security-audit setup \
  --source-profile audit-source \
  --role-arn arn:aws:iam::123456789012:role/SecurityAuditReadOnlyRole \
  --regions all

uvx --from 'git+ssh://git@github.com/yohi/aws-security-audit.git@COMMIT_SHA' \
  aws-security-audit doctor

uvx --from 'git+ssh://git@github.com/yohi/aws-security-audit.git@COMMIT_SHA' \
  aws-security-audit scan --out ./reports --fail-on-findings
```

The tool can also be invoked with all settings via CLI flags, without persisting local configuration:

```bash
uvx --from 'git+ssh://git@github.com/yohi/aws-security-audit.git@COMMIT_SHA' \
  aws-security-audit scan \
  --source-profile audit-source \
  --role-arn arn:aws:iam::123456789012:role/SecurityAuditReadOnlyRole \
  --regions ap-northeast-1 \
  --out ./reports
```

Use `--regions all` for full regional coverage; with a subset the report documents its partial coverage. `--ap-tag Role=application` can supplement AP-server identification but route-table validation remains manual.

## Authentication: least privilege

1. The application loads credentials from the named **aws login** or **SSO** source profile.
2. It calls `sts:AssumeRole` with a mandatory **AWS managed ReadOnlyAccess managed session policy**, limited to a 3600-second session. It **does not** use STS `GetSessionToken`.
3. A **new boto3.Session** is constructed using only the STS credentials returned by AssumeRole.
4. It invokes `GetCallerIdentity` with those credentials and checks the account + assumed-role name before scanning. If any of these steps fail, the scan does not run.
5. API checks use list/get/describe control-plane read operations only. SDK configuration, response messages and exception contents are not written verbatim. Tokens and secrets are not added to reports.
6. Audit session credentials are **in memory only** and do **not** auto-refresh. For scans lasting nearly an hour, the tool marks remaining checks unknown and should be re-run (it never silently reverts to source credentials).

**Limitations:** ReadOnlyAccess can include data-read permissions. AWS IAM resource-based policies can also grant rights directly to assumed-role sessions that are not constrained as expected by identity/session policy intersections. For a strict no-write guarantee, use a dedicated *read-only IAM role*, an explicit-Deny permission boundary or other independently reviewed IAM controls; don't claim that a session policy alone proves an isolated no-write principal. The uvx process shares access to the host user's AWS profile files; it is not an OS sandbox.

## Output

One JSON file (machine readable, including regional findings), CSV and XLSX (46-item summary + regional evidence + execution metadata), with private `0600` file permissions on Unix. Report content never includes secrets. Output files have unique UTC timestamps and are not overwritten.

Statuses:
- `PASS` — sufficient evidence for the implemented subset of the stated criterion.
- `FAIL` — actual violation detected.
- `UNKNOWN` — unable to inspect, permissions insufficient, API error, or scanner exception.
- `MANUAL_REVIEW` — configuration alone does not establish the full item; human or external evidence required.
- `NOT_APPLICABLE` — target resources absent or item not applicable.

**Conservative implementation:** not all 46 items are auto-gradable. For example, detailed DB privileges, customer escalation, recovery drills and data access restrictions need non-AWS or operational evidence. Some automated checks deliberately return `MANUAL_REVIEW` when only a subset was checked. `PASS` never implies that any untested criteria or AWS accounts were compliant.

## Developer usage

```bash
uv sync --extra dev
uv run pytest -q
uv run aws-security-audit version
```

## Cost and access notes

The tool never changes AWS resources or enables charged services. AWS API calls and existing AWS logging/storage could still incur charges per your account's pricing. Multi-region scanning may be slow; use explicit regions for an initial smoke test. The generated report may reveal resource names; handle it as sensitive security information.

## Security disclaimer

A fixed Git commit SHA is recommended for reproducibility. `uvx --from git+ssh` does not automatically honor the repository's `uv.lock` as a package consumer; dependency constraints need deliberate release management. Validate a release's source and dependencies before use.
