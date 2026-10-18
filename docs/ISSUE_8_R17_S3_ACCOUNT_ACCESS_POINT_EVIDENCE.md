# Issue #8 R17 — Account BPA and selected-bucket Access Point context (#18)

Fixed base: PR #13 merge `749269ae2a07da0c3a3fde114ea51dbab85357c4`.

## Scope

R17 is **read-only** product-audit evidence collection. Neither ownership of
account-level security settings by ROS nor effective public reachability is
established. Original 46 control verdict algorithms are unchanged.

In `--product ros` mode, **only when at least one S3 bucket is classified
DIRECT**:

- `s3control:GetPublicAccessBlock`, `AccountId` fixed to the verified STS
  account, once. The four allowlisted booleans are stored separately as
  `shared_s3_account_access_evidence` with `SHARED_UNATTRIBUTED` provenance.
  The returned effective account settings may inherit organization rules,
  but **the policy source, org enforcement and policy history are not proven**.
  A missing configuration/denied read is UNKNOWN, not a product failure.
- For each DIRECT bucket only, `s3:GetBucketLocation` to derive the
  correct regional S3Control endpoint; then a bucket-filtered
  `s3control:ListAccessPoints` (explicit, bounded pagination); then
  `s3control:GetAccessPoint` for each returned AP. Verify each AP identity
  matches the requested bucket and name. Persist only the AP name,
  `Internet`/ `VPC` network-origin label and the four PublicAccessBlock
  booleans, when schema-verified. Never export raw AP policies, grants,
  principals, ACLs, unspecified response metadata or credential values.
- Collection errors are bounded and tied to either the selected bucket or
  the STS account. Malformed success, denied reads, duplicate AP identities,
  pagination cycles and bucket-region failure remain UNKNOWN.
- Account-wide (`--product` absent) scans receive **no new S3Control calls**.

`control_observations` exposes #18 account BPA as a **SHARED_UNATTRIBUTED**
`CONTEXT_ONLY` / `PROPERTY_UNKNOWN` row. Each selected bucket gains one
per-bucket AP listing/detail context row. Successful configuration reads are
**CONTEXT_ONLY**, not PROPERTY_OK or formal PASS. The existing bucket-level
BPA, PolicyStatus and Object Ownership rows remain separate.

### Coverage boundaries

- `ListAccessPoints` with the selected bucket name is **not** a global
  inventory of all bucket access paths. MRAPs, directory buckets, S3 on
  Outposts, AWS Organizations policy provenance, other accounts' resources,
  cross-account ACL/policy grants, endpoint permissions, and actual reachability
  remain **NOT_PROVEN**.
- No owner-approved effective public access policy, permission evaluation or
  object-level inspection is attempted.
- Account BPA flags are shared-account context even when both selected ROS
  buckets are private; no account setting may be silently promoted to ROS PASS.
- IAM/STSes session policy is not an effective No-Write proof.

AWS source references:

- https://docs.aws.amazon.com/boto3/latest/reference/services/s3control/client/get_public_access_block.html
- https://docs.aws.amazon.com/cli/latest/reference/s3control/list-access-points.html
- https://docs.aws.amazon.com/botocore/latest/reference/services/s3control/client/get_access_point.html

## Required review and execution gates

- [ ] CI passes Python 3.12 and Python 3.13 with offline regression fixtures.
- [ ] Separate independent review of bucket/account scoping, S3Control
  permissions, pagination, AP identity checks, safe output data, error logic.
- [ ] Owner local fixed-HEAD ROS AWS read-only run in a **new** R17 report
  directory, followed by checking all seven exports and two provenance sidecars
  against the last R16 run and independently verifying #18 new observations.
- [ ] Re-implement and **re-run AWS** on any changed code HEAD. Do not claim
  validated R17 AWS runtime from CI alone.
- [ ] Separate Owner merge decision; Issue #8 remains open.

**Do not trigger CodeRabbit** without explicit owner permission.
