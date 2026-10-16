# Validation status — 2026-10-16

- Checklist: IDs 1–46 exist, original Japanese criteria retained, no risk/priority normalization.
- Authenticating as a source profile via `aws login` and calling explicit `STS AssumeRole` with the `ReadOnlyAccess` managed session policy is implemented and mock-tested.
- API adapter rejects AWS operation names outside `get_*`, `list_*`, `describe_*`, or the special STS `assume_role` bootstrap path.
- Output: JSON, UTF-8 BOM CSV, ZIP-container OOXML XLSX. XLSX re-imported successfully through spreadsheet validation tooling.
- PR #1 limited revision: 29 local offline tests passed in the preparation environment; AWS SDK integration: NOT TESTED.
- Package build: not independently verified in this offline environment, because hatchling was not cached (CI job will validate when online).
- The 46 controls are **not all automatically auditable**. Where evidence is insufficient, status is `MANUAL_REVIEW` or `UNKNOWN` rather than inferred `PASS`.
- The role session lasts 3600 seconds; sessions are not auto-refreshed in this initial release.
- The `ReadOnlyAccess` session policy reduces permissions but should not be treated as proof of absolute no-write capability if resource-based policies grant permissions directly to a role session. Independent IAM review of the existing role is necessary.
- The audit may read or enumerate private resource metadata; reports are saved with 0600 file mode on POSIX.

## Direct automated checks (subject to actual AWS API access)

17 S3 default encryption, 18 S3 public access block, 19 EBS/snapshot encryption, 20 RDS storage/snapshot encryption, 22 S3 Versioning or Object Lock, 23 RDS deletion protection, 24 CloudTrail multiregion with management/data event selectors and delivery evidence (manual closure needed), 25 CloudTrail file validation setting, 27 VPC Flow Logs with delivery SUCCESS, 32 GuardDuty, 33 Security Hub active standards plus control status (manual closure needed).

## Partial automated evidence, with manual review required to prove all criteria

1, 2, 5, 6, 8, 9, 10, 11, 12, 14, 29, 31, 38.

## Primarily manual / non-AWS evidence needed

3, 4, 7, 13, 15, 16, 21, 26, 28, 30, 34, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 46.

## PR #1 review F-001–005 limited correction

All five findings accepted. Added offline regressions for failed/missing CloudTrail delivery, limited Data selectors, Flow Logs failed/unknown/successful delivery and per-subnet coverage, Security Hub READY/all-disabled, partial region summary, unmatched AP tag, AssumeRole failure and STS expiry. No AWS account was accessed; effective read-only IAM authorization is NOT PROVEN and remains a separate gate.

## STS-001 review response, 2026-10-16

- STS2-001: credential-source `get_credentials().method` checked before STS; login/SSO only.
- STS2-002: doctor separately reports identity, region discovery, sampled API reads; never claims No-Write.
- STS2-003: scope, explicit Deny review requirement, resource-policy exceptions, simulation limitations, version invalidation documented.
- STS2-004: direct dependency pins and read-only policy version + canonical SHA-256 evidence; transitive uvx hash assurance still OPEN.
- STS2-005: offline regression tests for static source mixing, account/role mismatches, invalid region, AssumeRole failure and doctor failure.
- AWS environment and effective IAM authorization **NOT PROVEN**.

## STS3-NEW-001 targeted correction (PR #3)

- Require GetPolicy before and after GetPolicyVersion with stable policy ARN, PolicyId, DefaultVersionId and IsDefaultVersion=True at the intermediate read; mismatch = EvidenceUnavailable (Fail Closed, no persisted evidence).
- Save original Boto3-returned document and normalized document, deterministic canonical JSON SHA-256 and timestamps in private 0600 evidence; preserve non-atomic / potential ABA limitation.
- Add positive and negative mocks for original-document retention, version mismatch, default flag False/missing, PolicyId drift and failure to persist. The CI result for the new fixed HEAD is separate from the earlier 48-test CI.
- Warn that resource-based policy exceptions mean STS session policy intersection is not universal No-Write proof. STS2-004 transitive/uvx reproducibility remains OPEN; IAM effective No-Write NOT PROVEN, AWS live NOT TESTED.

## STS2-004 CI-resolved lock comparison

- Obtained the Python 3.12 and 3.13 dependency-lock artifacts from [Actions #38853564217](https://github.com/yohi/aws-security-audit/actions/runs/38853564217). Both have identical `uv.lock` content and the independently computed SHA-256 `9a6335dc59dc7c4260fa1d2e337de0b9bddfcc4de51ff8335772354d0b6663d0`.
- Commit this lock as `uv.lock` with `docs/uv-lock.sha256`, and CI now checks content checksum and `uv lock --check` before `uv sync --locked --extra dev`.
- This improves reproducibility for checked-out, locked project environments. It **does not** make regular `uvx + git+ssh` installations hash-locked. Consumer verification on supported OS/architecture and secure build dependency pinning remain OPEN.
- No AWS real-environment authorization checks were performed. IAM effective No-Write NOT PROVEN, Issue #2 OPEN, PR #3 Draft.
