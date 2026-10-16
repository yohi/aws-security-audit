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

Use `--regions all` for full regional coverage; with a subset the report withholds any account-wide PASS, recording the scanned-region result separately. `--ap-tag Role=application` can supplement AP-server identification but route-table validation remains manual.

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

The `判定` field represents account-wide compliance, while `対象地域判定` represents only scanned regions. With partial region coverage a regional PASS becomes account-wide UNKNOWN; the metadata includes `region_coverage_full`.

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

## Independent review PR #1 F-001–005 limited fixes

- F-001: CloudTrail S3 delivery error and latest successful delivery are inspected. Data selectors without proven target coverage remain MANUAL_REVIEW (no automatic PASS).
- F-002: Flow Logs require ACTIVE + ALL + DeliverLogsStatus SUCCESS for positive coverage. FAILED cannot count as delivered; absent/pending delivery is UNKNOWN.
- F-003: Security Hub READY requires enumeration of individual standard controls; controls enabled do not alone prove a check was executed.
- F-004: partial regions preserve regional findings but prevent account-wide PASS, including CSV/XLSX/JSON summaries.
- F-005: zero AP tag matches while active EC2 instances exist returns MANUAL_REVIEW instead of NOT_APPLICABLE.
- Static regression tests do not replace actual AWS integration or independent proof of effective IAM write restrictions.

## STS-001 security review correction

The SDK's **active** credential provider is verified before STS. Profiles with `login_session` but overridden by static shared credentials, environment credentials or other providers are rejected, without reading or logging secret values.

`doctor` distinguishes `IDENTITY_VERIFIED`, `REGION_VERIFIED` and `READ_API_VERIFIED` for sampled IAM, S3, EC2, CloudTrail and RDS operations. Its success does **not** establish all 46 permissions or no-write authorization. It always reports `EFFECTIVE_NO_WRITE=NOT_PROVEN`. `policy-evidence --out ./reports` compares GetPolicy → GetPolicyVersion → GetPolicy, requiring matching policy identity/default version and IsDefaultVersion=True. It saves the full Boto3-returned policy document, normalized JSON, SHA-256 and observation timestamps to a new private (0600) JSON file; stdout reports only digest and path. Detectable version changes abort without persisting evidence. This is a NON-ATOMIC observational snapshot, not proof of IAM No-Write permissions. No AWS policy is edited.

See [STS-001 No-Write verification contract](docs/STS001_NO_WRITE_CONTRACT.md). Runtime direct packages are version-pinned; transitive artifact hashes and `uvx git+ssh` consumer reproducibility remain open. AWS integration: NOT TESTED; IAM effective No-Write: NOT PROVEN; production approval: NOT GRANTED.

## STS2-004 — dependency reproducibility (review candidate)

The previously generated CI artifact lockfile for Python 3.12 and Python 3.13 had **identical bytes and SHA-256**, independently recomputed from both archived `uv.lock` files:

```text
9a6335dc59dc7c4260fa1d2e337de0b9bddfcc4de51ff8335772354d0b6663d0  uv.lock
```

The resulting `uv.lock` is now **committed** with its checksum in `docs/uv-lock.sha256`. CI checks this exact checksum before and after `uv lock --check`, installs with `uv sync --locked --extra dev`, and runs tests with `uv run --locked`. These controls detect unreviewed lock edits and stale lock metadata in CI, but not all risks from the index, tools, build backends or compromised endpoint hosts.

**Convenience execution (unchanged):**

```bash
uvx --from 'git+ssh://git@github.com/yohi/aws-security-audit.git@VERIFIED_COMMIT_SHA' aws-security-audit version
```

This remains *unlocked from the consumer's perspective*: `uvx --from git+ssh` **does not enforce the source repository's uv.lock**, and uv's `--require-hashes` mode does not accept Git dependencies. Never claim STS2-004 fully passed for this convenience path.

**Stronger consumer install path (requires Git checkout):**

```bash
git clone git@github.com:yohi/aws-security-audit.git
cd aws-security-audit
git checkout --detach VERIFIED_COMMIT_SHA
test "$(git rev-parse HEAD)" = "VERIFIED_COMMIT_SHA"
sha256sum -c docs/uv-lock.sha256
uv sync --locked --no-dev --no-editable
uv run --locked --no-sync aws-security-audit version
# After separately completing IAM approvals and STS verification:
# uv run --locked --no-sync aws-security-audit doctor --source-profile audit-source --role-arn arn:aws:iam::123456789012:role/EXISTING_AUDIT_ROLE --regions ap-northeast-1
```

Use a **reviewed, signed-off commit SHA** rather than a moving branch or tag. An actual independent user-side run, platform/architecture evaluation, build-tool pin/hash review and dependency artifact verification remain necessary before closing STS2-004. Neither installation path is an OS sandbox: the process can access host AWS login credentials.

## Investigation-only one-command workflow (Draft PR #4)

For read-only research without AWS remediation, run:

```bash
uv run --locked --no-sync aws-security-audit assess \
  --source-profile default \
  --role-arn arn:aws:iam::168975706502:role/scs2-stg-ecs-tasks-role \
  --regions all \
  --llm export \
  --out ./reports
```

This runs the existing 46 checks and supplemental inspection for #5 (dangerous security-group ingress with ENI attachment) and #19 (unencrypted EBS with EC2/ASG context and default encryption state). The original judgments are **never silently changed** based on LLM speculation.

`--llm export` creates a **local, aggregate, redacted Markdown packet** for manual review; it does not call an LLM or send evidence anywhere. Use `--llm off` to skip packet creation. The local JSON investigation report includes resource IDs and is protected by 0600 permissions on POSIX.

This is **investigation only**: no AWS IAM, networking, EBS, EC2, logging, or Security Hub configuration changes; no automated remediation; no active probing. Any claim of effective IAM No-Write remains **NOT PROVEN**, regardless of session policy. The full operating contract and limitations are in [docs/INVESTIGATION_ONLY.md](docs/INVESTIGATION_ONLY.md).

