# R24 — bounded offline-first evidence collector (PRE-EXECUTION)

Parent [Issue #8](https://github.com/yohi/aws-security-audit/issues/8). Base:
merged R23 `master` `cedf9061853238049e9b30eebf88a5e85ba09ebc`.
This PR implements **operator-side read-only code and synthetic tests only**.
It does **not** authorize executing that code against AWS and does not modify
the default `assess`, `doctor`, `scan`, report formats, classification
rules or normative Japanese checklist.

## Why a separate command?

`scripts/r24_targeted_read_only.py` is not called by normal scans or the
offline LLM. It defaults to **preview-only** without initializing boto3/ST​S
or reading credentials. Actual AWS reads require a future separate human
decision, a dated scope manifest and the literal
`--execute-approved-read` opt-in. A textual Owner reference inside a
manifest **does not constitute independent approval evidence**.

The operator must first confirm product ownership of target assets and the
account and region where they exist. Unknown applicability is a **blocker**,
not permission to scan all regions or all resources.

## Supported narrow evidence

| Control | AWS read-only operations | Scope and excluded assertions |
| --- | --- | --- |
| #8 | Shield `DescribeSubscription`, filtered `ListProtections` | Explicit approved edge ARNs only; results are not product-wide Shield compliance |
| #24 | CloudTrail `GetTrailStatus`, `GetEventSelectors` | Explicit trail and bucket ARNs; compare possible bucket-selector match with no definitive effective coverage claim |
| #27 | EC2 `DescribeFlowLogs` filtered by ENI `resource-id` | No repeat VPC/subnet flow-log inventory; does not prove end-to-end logging |
| #33 | Security Hub `DescribeHub`, `GetEnabledStandards` | Only requested region, no finding-detail export; any access failure remains `UNVERIFIED`, not evidence Hub disabled |
| #39 | Inspector2 `ListCoverage` filtered by instance ID, ECR `DescribeImages` by repository and immutable digest | Coverage, scan timestamp/summary only; no unscoped findings or all-repository scans |
| #40 | **No AWS API** | Product repo/CI dependency-scan evidence must be provided separately as a non-AWS export |

For Shield the AWS global endpoint is `us-east-1`, but protected
resource ARN targets still have to match the explicit account; it must
not be confused with enabling a second assessment region.

## Fail-closed manifest contract

Schema `aws-ros-r24-targeted-read-v1`; required fields `account`
(12-digit account), `region` (one region), `product=ros`,
`scope_confirmation` (operator-recorded `owner_ref`,
`confirmed_at_utc` UTC) and all seven `targets` keys:

- `shield_resource_arns` (up to 20 exact account-matching ARNs)
- `cloudtrail_trail_arns` (up to 8 selected-region trail ARNs)
- `cloudtrail_s3_bucket_arns` (up to 20 exact bucket ARNs, provided **together** with trails)
- `flow_log_eni_ids` (up to 50 exact ENI IDs)
- `securityhub` (boolean; false by default in operator-authored manifest)
- `inspector_ec2_instance_ids` (up to 50 exact instance IDs)
- `ecr_images` (up to 20 precise repository + `sha256:...` digest pairs)

The CLI does not generate an automatically approved manifest; it refuses
an empty target map, unknown fields, duplicate IDs, missing Owner record,
cross-account/cross-region trail, unscoped wildcards and tags-only resource
identification. Source-profile credentials must pass existing STS
`AuditContext` provider checks. No IAM role creation or policy update.

## Offline-first operator preflight (no AWS connection)

Save a **separately Owner-confirmed** JSON manifest in a private location
under `/var/tmp`. Run preview only:

```bash
cd /var/tmp/aws-security-audit-r24
uv sync --locked --extra dev --no-editable
uv run --locked --no-sync pytest -q
uv run --locked --no-sync python scripts/r24_targeted_read_only.py \
  --manifest /var/tmp/ros-r24-approved-scope.json
```

**Do not append** `--execute-approved-read` until separate Owner
authorization of the exact target list and any runtime security/STS risks
has occurred. At that later gate the operator also supplies a login/SSO
profile, existing role ARN, private output path and manual explicit opt-in.
Output files use exclusive creation and mode 0600; no overwrite, network
uploads, AWS write operations or arbitrary API names.

Every attempted SDK read is routed through the existing allowlisted
`core.api_call` / `core.paged` and STS-expiration guard. API access
errors yield `UNVERIFIED`, never PASS, OFF or N/A.

## Unproven / stop conditions

- `EFFECTIVE_NO_WRITE=NOT_PROVEN`. Resource-based policies may bypass
  implicit session-policy denial; no universal write denial is established.
- Source-to-runtime independent cryptographic attestation is NOT_PROVEN.
- Absence of any Shield protection or scan result is not global absence
  without Owner-confirmed product scope and relevant AWS account.
- Trail predicate approximations do not prove ROS data events are delivered
  or cover every S3 object. Security Hub standards observed are **not**
  verified per-control compliance.
- Old 2026-10-18 baseline: 46 controls, 3 provisional negative
  classifications, 43 evidence-pending controls; 13 root requests (5 AWS,
  1 non-AWS, 7 Owner). This implementation closes **zero** requests until
  actual read evidence is collected, validated, and later Owner-adopted.
- A future runtime test in all relevant regions, scope reconciliation,
  operator output hashes, offline LLM validation and independent security
  review are independent gates.

CI tests are synthetic and never contact AWS. No automatic CodeRabbit,
AWS connection, PR merge or Issue #8 closure is part of this PR.
