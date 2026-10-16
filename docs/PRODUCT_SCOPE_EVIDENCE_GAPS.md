# Product-scoped security audit: observed evidence and remaining boundaries

Status: **Draft / investigation-only / no AWS writes** (2026-10-16 JST). Related: [PR #6](https://github.com/yohi/aws-security-audit/pull/6).

## Triggering observation

A real offline ROS evidence review from account `456720798575` (Tokyo region, 2026-10-16) showed **#19 FAIL** (3 unencrypted 30-GiB EBS volumes), and an **incorrect product-scoped #23 FAIL** because four Aurora member instances reported `DeletionProtection=false` even though both corresponding Aurora clusters reported `DeletionProtection=true`. The 46-control product report originally had 44 MANUAL_REVIEW and 0 PASS. The observation is a point-in-time sample, **not proof of product-wide or account-wide compliance**.

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

A subsequent independent static review and authorized real AWS smoke test are required before merging PR #6; any real AWS inspection must use the existing AssumeRole + ReadOnlyAccess session and should not perform configuration changes. A complete 46-control product PASS is **not** an acceptance criterion for this incremental change.

## Acceptance conditions

- No AWS write API, STS source-credential fallback, active probing, or automatic Web upload.
- Validate 46 unique control IDs and preservation of source statuses.
- Aurora protected cluster + unprotected instances ⇒ not FAIL solely due to instance flags; unprotected Aurora cluster / unprotected independent RDS instance ⇒ FAIL.
- Read errors for an individual tag or supplemental operation appear in the output rather than being silently assumed absent.
- A shared VPC is RELATED, never proof of exclusive product ownership; unrelated other VPC resources remain outside the selected set.
- #5/#19 supplemental product evidence clearly identifies PARTIAL_OBSERVED.
- CI tests for Python 3.12/3.13 pass; AWS real-world API coverage and STS expiration behavior remain unverified until separately tested.
