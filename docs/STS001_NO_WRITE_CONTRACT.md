# STS-001 — Effective No-Write Verification Contract

**State: NOT PROVEN / Independent IAM Review Required.** This is an acceptance contract, not a production approval or AWS live-test result. The original 46-item security checklist remains unchanged.

## Credential trust boundary

The `aws login` / SSO **source credential provider** must actually be botocore `login` or `sso`; a matching profile setting alone is insufficient. Auditing uses a separate STS AssumeRole session limited by the AWS-managed `ReadOnlyAccess` managed session policy. The source credential files remain accessible to other code running under the same local OS user: `uvx` is **not** an isolation sandbox. An IAM No-Write claim for one scoped session cannot prove that malicious code cannot access host credentials.

## Required scope declaration

Before **EFFECTIVE_NO_WRITE_PROVEN** may be declared, independently approve a time-stamped scope ledger with: AWS account ID(s), partition, region(s), global services, all audited resource ARNs, the role ARN **and immutable RoleId**, source principal, role session name, complete reviewed SDK-to-IAM action mapping, forbidden write-action universe, evaluation context and condition keys, reviewed code commit and exact dependency artifacts.

Initial relevant AWS services include EC2/VPC, IAM, S3/S3Control, RDS, CloudTrail, CloudFront, ELBv2, GuardDuty, Security Hub, SSM, WAFv2, Shield and CloudWatch Logs. This initial list is NOT a certified service/action inventory.

## Gate C: Identity and resource-based policies

Capture and review role trust policy, attached managed/inline role policies, permission boundary, applicable SCP/RCP, STS session policy, account and cross-account resource-based policies for all declared resources, their versions and original documents and SHA-256 digests. Explicitly check grants directly to `arn:aws:sts::...:assumed-role/.../session` and wildcard principals with an `aws:PrincipalArn` condition.

**Session policy implicit denials do not necessarily block permissions granted directly to session principals in resource policies.** A broad No-Write assurance requires a separately reviewed **explicit Deny** construction that excludes write operations across all relevant IAM/resource authorization paths, and an exhaustively reviewed exception list of audited reads. A finite list of tested writes only establishes a finite scope; it cannot establish universal No-Write. This CLI never changes IAM/resource policies.

## Gate D: Supporting policy simulations

For each relevant resource/context and declared forbidden action, record `iam:SimulatePrincipalPolicy` inputs, output decisions and unsupported coverage. Initial examples: `s3:PutObject`, `s3:DeleteObject`, `s3:PutBucketPolicy`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:TerminateInstances`, `iam:CreateRole`, `iam:AttachRolePolicy`, `rds:DeleteDBInstance`, `cloudtrail:StopLogging`, `logs:DeleteLogGroup`. **Never** make a real write API call, even as a denial test. AWS IAM simulation does not completely model role-based resource policies; a simulation DENY is not standalone proof.

## Gate E: Read-only live evidence

An authorized operator may run `aws login`, then the pinned Git SHA's `doctor` command. The doctor output separately identifies `IDENTITY_VERIFIED` (STS caller), `REGION_VERIFIED` (enabled regions under scoped credentials) and `READ_API_VERIFIED` (IAM/S3/EC2/CloudTrail/RDS **sample** operations). `EFFECTIVE_NO_WRITE=NOT_PROVEN` remains even if these succeed. Verify full 46-check API permissions separately. No AWS live access was performed in the static revision.

The optional `policy-evidence` subcommand calls only `iam:GetPolicy` and `iam:GetPolicyVersion` using scoped credentials. It emits the real `ReadOnlyAccess` default policy version and a SHA-256 of sorted, compact canonical JSON. The original AWS-returned policy document and collection time must also be preserved to independently verify this digest. AWS-managed policies evolve; a documented `v190` is not evidence of the live version.

## Gate G: Revision invalidation and signoff

Invalidate prior proof after any policy/version/trust/RoleId/resource policy/SCP/RCP change, region or resource expansion, code/dependency digest change, or change in authorization assumptions. Unknown scope or incomplete evidence = **NOT PROVEN**.

The independent security reviewer and human Owner must approve the evidence before Issue #2 closure. Production acceptance and AWS audit smoke tests remain separate.

## STS2-004 distribution reproducibility

Exact direct boto3/hatchling versions mitigate unbounded top-level dependency drift but **do not** pin every transitive dependency wheel hash. Even with source commit pinning, `uvx --from git+ssh://...@COMMIT` does not automatically honor the repository `uv.lock`. CI may publish a version/hash-bearing dependency lock artifact as evidence; a reproducible release needs an independently verified hash-locked consumer installation. **STS2-004 is not fully closed until that path is proven.**

Primary sources: [AWS IAM evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html), [Boto3 credential chain](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html), [IAM simulation limits](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html), [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).
