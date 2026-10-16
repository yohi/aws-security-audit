# Validation status — 2026-10-16

- Checklist: IDs 1–46 exist, original Japanese criteria retained, no risk/priority normalization.
- Authenticating as a source profile via `aws login` and calling explicit `STS AssumeRole` with the `ReadOnlyAccess` managed session policy is implemented and mock-tested.
- API adapter rejects AWS operation names outside `get_*`, `list_*`, `describe_*`, or the special STS `assume_role` bootstrap path.
- Output: JSON, UTF-8 BOM CSV, ZIP-container OOXML XLSX. XLSX re-imported successfully through spreadsheet validation tooling.
- Local unit tests: 11 passed; AWS SDK connection integration: NOT TESTED; Git repository publication: NOT DONE.
- Package build: not independently verified in this offline environment, because hatchling was not cached (CI job will validate when online).
- The 46 controls are **not all automatically auditable**. Where evidence is insufficient, status is `MANUAL_REVIEW` or `UNKNOWN` rather than inferred `PASS`.
- The role session lasts 3600 seconds; sessions are not auto-refreshed in this initial release.
- The `ReadOnlyAccess` session policy reduces permissions but should not be treated as proof of absolute no-write capability if resource-based policies grant permissions directly to a role session. Independent IAM review of the existing role is necessary.
- The audit may read or enumerate private resource metadata; reports are saved with 0600 file mode on POSIX.

## Direct automated checks (subject to actual AWS API access)

17 S3 default encryption, 18 S3 public access block, 19 EBS/snapshot encryption, 20 RDS storage/snapshot encryption, 22 S3 Versioning or Object Lock, 23 RDS deletion protection, 24 CloudTrail multiregion with management/data event selectors, 25 CloudTrail file validation setting, 27 VPC Flow Logs, 32 GuardDuty, 33 Security Hub and active standards.

## Partial automated evidence, with manual review required to prove all criteria

1, 2, 5, 6, 8, 9, 10, 11, 12, 14, 29, 31, 38.

## Primarily manual / non-AWS evidence needed

3, 4, 7, 13, 15, 16, 21, 26, 28, 30, 34, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 46.
