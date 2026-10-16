# Product-scoped security audit: observed evidence and remaining boundaries

Status: **Draft / investigation-only / no AWS writes** (2026-10-16 JST). Related: [PR #6](https://github.com/yohi/aws-security-audit/pull/6).

## Triggering observation

An offline product-scope evidence review (2026-10-16) exposed a **#19 FAIL** with confirmed unencrypted attached volumes, and a **potentially incorrect product-scoped #23 FAIL** because Aurora member instances reported `DeletionProtection=false` while their corresponding Aurora clusters reported `DeletionProtection=true`. The 46-control product report originally had 44 MANUAL_REVIEW and 0 PASS. The observation is a point-in-time sample, **not proof of product-wide or account-wide compliance**.

Do not use this repository to change those AWS resource settings. This work changes only offline report schema and allowed read-only calls.

## Implemented limited evidence improvements

1. **#23 Aurora deletion semantics**: evaluate `DeletionProtection` for Aurora DB **clusters**, not their member DB instances. For standalone DB instances, evaluate the instance-level flag. Preserve the Aurora instance flag separately as availability evidence, without treating it as a cluster/data-volume protection failure. The resulting product finding stays MANUAL_REVIEW when no negative cluster/standalone instance state is found; do not auto-upgrade to PASS.
2. **S3 identity/security metadata**: collect bucket encryption configuration algorithms, bucket Public Access Block, versioning status, and Object Lock enabled indication. As of January 2023 AWS applies SSE-S3 automatically for new S3 object writes even when an explicit configuration is absent. An absent encryption config or unexamined legacy objects must not be converted into FAIL/PASS without additional evidence.
3. **ALB metadata**: collect listener port/protocol/SSL policy, available WAFv2 WebACL reference, access-logging enabled/bucket/prefix and security-group attachments. Absence of a direct ALB WebACL does not disprove CloudFront protection; a TLS listener does not establish end-to-end TLS or every listener setting.
4. **Network metadata**: collect VPC Flow Log ID, configuration status, delivery status (per VPC). This does not prove subnet or ENI coverage, successful downstream log retention, or product-exclusive VPC ownership.
5. **Snapshot inventory**: add owned EBS snapshots and RDS instance/cluster snapshots with source IDs, encryption flags, and selected non-secret attributes. Include only directly matching snapshots or snapshots with an explicit reference to a selected volume/DB. Volume source IDs can be missing, recycled or irrelevant; the resulting set cannot prove complete historical backups.
6. **Attribution graph**: annotate tagged/Name-direct resources as DIRECT; only explicit EC2/ALB/RDS/SG/volume/snapshot/VPC parent-child or attachment relations qualify as RELATED. VPC, subnet and security groups can be shared. RELATED is **never proof of exclusive ownership**. Unrelated resources are not marked product scoped simply because they share a VPC.
7. **Missing tags and calls**: record per-resource failures for S3/ELB/RDS/CloudFront tag lookups. Record allowed additional read API failures as `collection_errors`. `NoSuchTagSet` on S3 is a known empty-tag case, distinct from `AccessDenied`. Collection failures mean UNKNOWN coverage, not an untagged/absent resource.
8. **Product deep evidence**: include partial product-oriented #5/#19 metadata in `supplemental_investigation.deep_evidence`; unlike account-mode investigations it does not establish complete SG egress/ENI/internet reachability or snapshot coverage. Other applicable control observations are attached without automatically changing MANUAL_REVIEW to PASS.

Sources:
- [AWS Aurora DB cluster deletion protection and instance deletion](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_DeleteCluster.html)
- [Amazon S3 default encryption FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html)
- [S3 GetBucketTagging: NoSuchTagSet](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_tagging.html)
- [ELBv2 DescribeLoadBalancerAttributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeLoadBalancerAttributes.html)
- [EC2 DescribeSnapshots](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshots.html)

## RDS storage encryption: #20 snapshot field correction

The original draft `_add_rds` read `Encrypted` from every RDS snapshot. This is not a response field for `DescribeDBClusterSnapshots`, which returns `StorageEncrypted`. This silently produced `encrypted=null` for every cluster snapshot and left the resource evidence unverified, even when AWS returned a usable field.

For the updated implementation:

- `DBSnapshots`: read `Encrypted` and `StorageEncryptionType`.
- `DBClusterSnapshots`: read `StorageEncrypted` and `StorageEncryptionType`.
- `DBInstances` and `DBClusters`: interpret `StorageEncrypted` consistently with `StorageEncryptionType` so AWS-owned-key encryption is not incorrectly reported as plaintext.
- If `StorageEncryptionType=sse-rds`, effective `encrypted=true` even when the legacy flag is false. `sse-kms` also means encryption is present (unless the legacy flag conflicts, then UNKNOWN). `none` with no conflicting true flag means `encrypted=false`.
- If the encryption type is missing and the legacy flag is false, `encrypted=null` with `encryption_state=UNVERIFIED_ENCRYPTION_TYPE`, **not FAIL**. If type and flag conflict, preserve `CONFLICTING_EVIDENCE` and do not assert PASS/FAIL from that record. Unknown type values are also unverifiable. A positive legacy flag without a type is retained as encrypted evidence.
- Preserve `encryption_flag_field`, `encryption_flag`, `storage_encryption_type`, `encryption_state` and effective `encrypted` in resource JSON/CSV/XLSX/Web handoff. Product control #20 asserts FAIL only where effective encrypted is explicitly false; no resource alone proves a complete product PASS.
- Old JSON reports that recorded only `encrypted=null` lack the underlying API fields and **cannot be fixed retrospectively**. An authorized read-only rerun with the updated code is required to collect the lost metadata.

Official API references: [DB cluster snapshot](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBClusterSnapshot.html), [DB snapshot API](https://docs.aws.amazon.com/boto3/latest/reference/services/rds/client/describe_db_snapshots.html), and [DB cluster response](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBCluster.html).

## Residual gaps (explicitly NOT closed)

| Category | Remaining necessary evidence | Why retained as MANUAL_REVIEW/UNKNOWN |
| --- | --- | --- |
| #1 public address / #2 RDS placement | Role-identification, effective routes, all EC2/EKS/ECS workloads and DBs | Public IPv4/SFTP alone is not proof of improper AP placement; RDS public flag alone is not a network path proof |
| #5 SG minimal authorization | Egress rules, SG referencing, ENI, routes, and reachability | Selected permission count is not complete path evidence |
| #6/#16/#29 WAF/TLS/logging | CloudFront distribution routing, upstream/downstream TLS policies, logging destinations and delivery | Partial configuration is not an end-to-end security guarantee |
| #11 and shared IAM identity | Role attachment, inline policies, policies boundaries, SCP/RCP/resource policies, actual workload associations | Role names/ARNs do not show effective rights |
| #17/#18/#22 S3 security | Account-level BPA, bucket policy/ACL, historical objects, lifecycle/object locks and permission paths | Bucket-level metadata only |
| #19/#20 snapshots | Backup-plan ownership, RDS shared/manual backups, historical VolumeId, restore/immutability and KMS policy | Snapshot linkage is partial |
| #24–#27 logging | Organization-level CloudTrail, data event selectors, status/delivery, log retention, subnet/ENI Flow Logs | Product tagging does not establish shared central logging |
| #28/#31/#32/#33/#34–#39 | Engine audit, actual log delivery, account threat-detection/notification and patch/scan coverage | Pure resource inventory cannot prove the control |
| #40–#46 policy/process | Approved documentation, repo pipelines, escalation trees, human evidence | Not inferable from AWS read-only API |

PR #6 has been merged. Subsequent product-scope extensions are separately reviewed in Draft PR #7; any real AWS inspection must use the existing AssumeRole + ReadOnlyAccess session and must not perform configuration changes. A complete 46-control product PASS is **not** established by the incremental evidence changes.

## Acceptance conditions

- No AWS write API, STS source-credential fallback, active probing, or automatic Web upload.
- Validate 46 unique control IDs and preservation of source statuses.
- Aurora protected cluster + unprotected instances ⇒ not FAIL solely due to instance flags; unprotected Aurora cluster / unprotected independent RDS instance ⇒ FAIL.
- Read errors for an individual tag or supplemental operation appear in the output rather than being silently assumed absent.
- A shared VPC is RELATED, never proof of exclusive product ownership; unrelated other VPC resources remain outside the selected set.
- #5/#19 supplemental product evidence clearly identifies PARTIAL_OBSERVED.
- CI tests for Python 3.12/3.13 pass; AWS real-world API coverage and STS expiration behavior remain unverified until separately tested.


## R4 next phase after PR #6 merge — bounded negative findings

Draft PR #7 implements read-only additions without changing the original control definitions:

- **#16**: `elbv2:DescribeSSLPolicies` fetches the exact protocol list of each observed HTTPS/TLS listener policy, rather than inferring enabled protocols from an SSL policy name. The product control reports a negative finding **only** for directly selected ALB HTTPS listeners where the API confirms `TLSv1`, `TLSv1.1`, or weaker protocols. Named policy without successful API response stays MANUAL_REVIEW; CloudFront/other paths, internal TLS, backend protocols remain unverified. The full TLS 1.2+ contract is not certified even when all observed protocols are modern.
- **#22**: report a negative observation only for directly selected S3 buckets where `get_bucket_versioning` explicitly yields Disabled and `get_object_lock_configuration` specifically signals `ObjectLockConfigurationNotFoundError`. AccessDenied, unknown config, or Suspended is not promoted to FAIL/PASS.
- **#5**: retain sanitized ingress/egress SG rule details (port/protocol/CIDR/referenced group/prefix list), not arbitrary rule descriptions. Rule presence is observational, not a proof of network reachability or least privilege.
- **#27**: record subnet-level as well as VPC-level flow logs; ENI-level and delivery log content remain outside this increment.
- **Security and scope**: no new AWS write operation, probe, AWS resource mutation, IAM permission grant, source-credential fallback or automatic LLM transfer.

These rule-based FAIL observations do **not** replace the complete 46-control audit. See [Issue #8](https://github.com/yohi/aws-security-audit/issues/8) for staged coverage of effective IAM permissions, shared account services, CloudTrail, WAF, app/logging paths, restoration evidence and human process controls.

AWS primary references:
- [ELBv2 DescribeSSLPolicies](https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_DescribeSSLPolicies.html)
- [ALB SSL policies](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html)
- [S3 versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
