# Issue #8 R15 — Selected S3 Bucket Access Evidence (limited candidate)

Base: merged PR #11, `master` commit
`e5c08e18d2b0086f6d38bdd664fa082e9f1763b2`.

## Purpose

Add read-only **configuration evidence only** for control #18 (S3 bucket
access) without changing any of the 46 formal compliance verdict rules.
The R14 product-scoped baseline remains: 46 verdicts (FAIL #16/#19/#22,
43 MANUAL_REVIEW), 48 selected resources, and 67 property observations.
Those historic outputs predate this proposal and are not R15 evidence.

## Data boundary

Only in **product** mode, only buckets selected as `DIRECT` after existing
attribution are queried. `RELATED` and `UNCLASSIFIED` buckets receive
no new policy/ownership read. Account mode is unchanged.

| API | Source | Exported bounded fields |
| --- | --- | --- |
| `s3:GetBucketPolicyStatus` | directly selected bucket | `bucket_policy_is_public` (bool or null), `bucket_policy_status_lookup` |
| `s3:GetBucketOwnershipControls` | directly selected bucket | `bucket_object_ownership` (three allowlisted AWS modes or null), `bucket_ownership_lookup` |

The scanner does **not** call `GetBucketPolicy` or `GetBucketAcl` and does
not retain raw policies, principals, ACL grants, statement conditions,
freeform response metadata, or service-specific private fields.
Each new operation calls the existing session-expiration guard and
uses the read-only `api_call` adapter; no AWS write API is added.

## Evidence classification

- Valid `PolicyStatus.IsPublic` must be a real boolean; valid ownership
  must contain exactly one known `ObjectOwnership` rule. Else return
  `UNVERIFIED_SCHEMA` and one selected-resource collection error.
- `NoSuchBucketPolicy` means `NO_BUCKET_POLICY`, not an effective
  public-access proof. `OwnershipControlsNotFoundError` means
  `NOT_CONFIGURED`, not an assertion about safe ACL behavior.
- Other read errors are `UNVERIFIED_READ_ERROR`, with bounded errors.
- Both properties become **CONTEXT_ONLY** if verified and
  **PROPERTY_UNKNOWN** otherwise; neither creates a product PASS or FAIL.
  New selected-bucket errors appear in the #18 collection-error count.
- Account-level and AWS Organizations S3 Block Public Access, access
  points, object grants, effective identity permissions, and the possibility
  of unintended public data access are **NOT_PROVEN**.

## Regression / acceptance gates

1. Offline fixtures: direct vs unrelated bucket, account mode unchanged,
   valid config with embedded secret metadata, malformed successful
   responses, explicit absence, AccessDenied, bounded export,
   attribution-constrained #18 error count and no change to 46 verdicts.
2. Python 3.12 and 3.13 CI green on fixed HEAD. Treat CI as **offline-only**.
3. Independent static security review and Human Owner's approval of any
   optional read-only AWS smoke run, separate from code review and merge.
   Do **not** trigger CodeRabbit without explicit prior permission.
4. A single human-authorized `ros` read-only smoke run is recommended only
   if the Owner wants to accept R15 real-account evidence. Preserve R14
   artifacts and use a new output directory; compare #18 and export formats.
   AWS effective No-Write and runtime HEAD attestation remain NOT_PROVEN
   absent separate evidence.
5. Keep Issue #8 OPEN; this does not close control coverage gaps or imply
   complete product audit coverage.

Primary AWS references:
- https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy_status.html
- https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_ownership_controls.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
