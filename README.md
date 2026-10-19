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

`--llm export` creates a **single JSON evidence attachment** (`aws_web_review_*.json`) and **a separate Markdown prompt** (`aws_web_prompt_*.md`) for manual browser use in ChatGPT Web or Gemini Web. The operator pastes the prompt and attaches the JSON file; the program **never calls an LLM or transmits evidence**. The JSON contains all 46 original outcomes and findings plus #5/#19 deep investigation. Use `--llm off` to skip Web handoff. Local investigation and Web-review JSON may contain sensitive AWS resource IDs or names; inspect before manual external upload. All output uses 0600 file permissions on POSIX.

This is **investigation only**: no AWS IAM, networking, EBS, EC2, logging, or Security Hub configuration changes; no automated remediation; no active probing. Any claim of effective IAM No-Write remains **NOT PROVEN**, regardless of session policy. The full operating contract and limitations are in [docs/INVESTIGATION_ONLY.md](docs/INVESTIGATION_ONLY.md).

## Evidence-traceable progress reporting (offline)

`assess` now records its existing read-only collection outcomes in a passive
capture side-channel and exports one shared evidence ledger
(`evidence_ledger`) and criterion-aware review model (`control_review`) to
every format: additive audit columns in the classic JSON/CSV/XLSX report,
the same model embedded in `aws_web_review_*.json`, and a
`aws_evidence_progress_<stamp>.{json,md,csv,xlsx}` set plus a per-set
integrity manifest. Scanner verdicts (`判定`) are never rewritten and
business four-state labels only come from a submitted classification
candidate; unresolved evidence requests are deduplicated by kind, scope and
requirement key. Request IDs appear in additive audit columns; full request
details are included in progress and Web exports.

The offline `report-progress` command rebuilds the same progress report
from saved local files only — a previous `aws_web_review` bundle plus an
optional classification candidate — with no AWS session, no credentials and
no network access:

```bash
uv run --locked --no-sync aws-security-audit report-progress \
  --bundle ./reports/aws_web_review_20261019.json \
  --classification ./reports/labels/classification-candidate.json \
  --out ./reports/progress
```

Optional `--r24` and `--mcp-summary` supplements are also processed offline;
both require `--account`.

Exit code follows the review model, not the certification state:
`0` = exported, `outstanding_evidence_requests` empty; `2` = exported but
unresolved evidence requests remain (real bundles keep by-construction
Owner/criterion questions, so they normally exit `2`);
`1` = invalid input or export failure.
No AWS or LLM connection is used. Flags, exit semantics, schemas, field
meanings, legacy limits, file relationships and source-digest limits (integrity,
not provenance) are documented in
[docs/evidence-traceable-reporting.md](docs/evidence-traceable-reporting.md).

## Resource identity and product-scoped investigation (draft PR)

`assess` also exports a **resource inventory** as JSON and CSV, and adds a fourth `リソース台帳` sheet to the original XLSX. The consolidated audit JSON and web review attachment include the inventory. Identity columns include service, type, region, `name` (AWS `Name` tag where available), resource ID, ARN, selected identity tags, attribution evidence, and service-specific non-secret attributes. Inventory covers EC2 instances, EBS volumes, security groups, VPCs, subnets, RDS instances/clusters, ELBv2, CloudWatch log groups, S3 buckets, IAM users/roles and CloudFront distributions. **It does not cover every AWS service or every associated resource.** Missing tags, unsupported ownership metadata, and collection errors remain explicit coverage gaps.

Examples:

```bash
# Entire account: unchanged 46-control scanner plus new identity inventory
uv run --locked --no-sync aws-security-audit assess \\
  --source-profile default \\
  --role-arn arn:aws:iam::123456789012:role/aws-security-audit-readonly \\
  --regions all --llm export --out ./reports/account

# One product (Name/ID prefix such as scs2-*, or Product/Project/Application/Service tag exact value)
uv run --locked --no-sync aws-security-audit assess \\
  --source-profile default \\
  --role-arn arn:aws:iam::123456789012:role/aws-security-audit-readonly \\
  --regions ap-northeast-1 --product scs2 --llm export --out ./reports/scs2

# Prefer explicit tag ownership (supported identity tag keys only)
uv run --locked --no-sync aws-security-audit assess \\
  --source-profile default \\
  --role-arn arn:aws:iam::123456789012:role/aws-security-audit-readonly \\
  --regions ap-northeast-1 --product scs2 --product-tag Project=scs2 \\
  --llm export --out ./reports/scs2-tagged
```

**Product scope is conservative, not a full 46-control certification.** The existing account-wide checks are not blindly inherited. Product controls retain MANUAL_REVIEW/UNKNOWN unless an explicitly attributable resource has a deterministic negative observation (including #2, #5, #16, #19, #20, #22 and #23). Positive observations do not automatically certify PASS for an entire product.

**Practical evidence view (R4):** The tool also emits a resource-by-resource `control_observations` matrix, independent from the final control verdict. It verifies selected configuration properties where concrete evidence exists:
- `PROPERTY_OK`: that resource's particular configuration property matches the narrow rule. **Not a product-wide PASS**.
- `PROPERTY_FAIL`: that resource's particular configuration property fails the narrow rule. Review context and attribution before relying on a product finding.
- `PROPERTY_UNKNOWN`: missing, conflicting or permission-limited source data.
- `CONTEXT_ONLY`: useful observed metadata insufficient for a property-level verdict.

The terminal shows counts of controls with property evidence and OK/FAIL/uncertain property observations. The 46-item CSV/Excel summary includes these counts beside original verdicts, the product XLSX adds a 5th `属性別検証結果` worksheet (name/ID/ARN, proof and limits), and JSON/Web files include complete structured `control_observations.rows` and `by_control`. Account-scope XLSX retains its original 4-sheet layout.

Examples: S3 bucket default encryption `AES256` is `PROPERTY_OK` for default encryption configuration only; a selected unencrypted EBS volume is `PROPERTY_FAIL`; a TLS policy without a verified AWS protocol response is `PROPERTY_UNKNOWN`. These must not be mistaken for full applicability, shared-service compliance, data-plane security or region-wide completeness.

Shared VPC/SG/volume relationships remain RELATED and may be shared. Untagged/unmatched resources can be omitted; collection errors and incomplete attribution prevent blanket PASS. The audit remains investigation-only; it does not mutate AWS resources or automatically upload evidence to LLMs.
