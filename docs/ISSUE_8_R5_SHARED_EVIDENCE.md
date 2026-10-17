# Issue #8 — R5 Evidence Expansion Contract

**Parent:** [Issue #8](https://github.com/yohi/aws-security-audit/issues/8)  
**Baseline:** merged PR #7, master `b6df84a2b6ac8b25ee2c856eefb06f1dd3416cff`  
**Candidate:** Draft PR #9, `feat/issue-8-shared-security-evidence-r5`  
**Scope:** local tool logic and offline tests. This PR does not authorize AWS environment modification or formal adoption.

## What is newly observed

| Control | Read-only APIs | Captured evidence | Unsupported inference |
| --- | --- | --- | --- |
| #1 AP private placement | Existing EC2 `DescribeInstances` | Instance public-IP flag, subnet, state as `CONTEXT_ONLY` | Instance is AP, public IP means AP exposure, subnet routing, full PASS |
| #5 SG least privilege | Existing EC2 `DescribeSecurityGroups` | Structured inbound/outbound rules, any-world CIDRs/ports, all-protocol egress count | Reachability, necessity, full FAIL/PASS based on port number alone |
| #14 SSM/bastion | Existing EC2 `DescribeInstances` | Instance subnet, SG associations as `CONTEXT_ONLY` | SSM/SSH operational access has been verified |
| #24 CloudTrail | `DescribeTrails(includeShadowTrails=True)`, `GetTrailStatus`, `GetEventSelectors` | Per-region trail ARN, multi-region, org flag, logging status, delivery-error presence and event selector categories/types | Complete audit/event/data logging, cross-account org/CloudTrail Lake, delivery completeness or ROS coverage |
| #25 log integrity | CloudTrail `DescribeTrails`, `GetTrailStatus` | Configured log-file validation, digest delivery-error flag and logging status | Continuous delivered immutable integrity evidence |
| #32 GuardDuty | `ListDetectors`, `GetDetector` | Detector IDs, enabled status, feature flags in requested region | All-region/account delegated administration, effective ROS detection coverage |
| #33 Security Hub | `DescribeHub`, `GetEnabledStandards` | Hub presence and standards subscriptions/states | CIS controls actually running/compliant; cross-region/product aggregation |

The shared AWS control records are stored at
`resource_inventory.shared_control_evidence` (schema `aws-shared-security-evidence-v1`). For product-only auditing, the resource-property matrix includes `SHARED_UNATTRIBUTED` / `SHARED_CONTEXT_ONLY` records for #24/#25/#32/#33. They are **never silently added to the directly matched ROS inventory**, and never imply ROS-level PASS. A successful zero-item listing is a *limited negative observation* of that API/region, not proof of service-wide absence. If the API fails, `PROPERTY_UNKNOWN` is retained and `resource_inventory.collection_errors` captures the error.

The original 46 control verdicts are unchanged except previously explicitly justified product negative rules. The new shared-control data does not generate new product FAIL or PASS. The CLI remains read-only and the `EFFECTIVE_NO_WRITE` caveat stays `NOT_PROVEN`.

## R4 QA closure scope

- **R4-QA-001:** Web prompt and evidence caveats distinguish verified #16/#22 negative findings from partial #5/#19/SG evidence.
- **R4-QA-002:** SG inbound/outbound *configuration* rules now included in #5 deep evidence; ENI/routing/operational necessity remains unverified.
- **R4-QA-003:** Existing EC2 instance information is presented as context for #1 and #14 rather than `NO_RESOURCE_EVIDENCE`. It is not role-classified as AP/bastion.
- **R4-QA-004:** Worldwide ingress including TCP/8000 and unrestricted all-protocol outbound rules are explicitly surfaced for review. No automatic FAIL without tested significance to the business/role and network topology.

## Proof boundary and CI

Offline fixture tests cover successful authorized API responses, AWS permissions failures and partial collection, source-aligned CloudTrail fields, GuardDuty/Hub statuses, explicit shared provenance, no remote data-event payload persistence, product-only collection, account-scope output preservation and conservative status behavior. CI on Python 3.12/3.13 must pass at the fixed review HEAD.

**Not yet proven:** the existing audit IAM role can read each additional regional API; comprehensive CloudTrail delivery health; CloudTrail Lake and delegated administrator coverage; effective IAM No-Write; real-region runtime and STS lifetime; organization-approved scope and inherited protection of ROS. Runtime verification must remain independently authorized and read-only.

## Remainder of Issue #8

This PR is a **partial implementation**, not Issue #8 closure. It does not cover:

- Network route/ENI/role attribution, CloudFront origin-to-ALB/WAF/Shield chain, full S3 bucket/account public enforcement.
- IAM principal/role and attached policy boundaries, actual DB/application-level secrets and access patterns.
- Application/audit log pipelines, ENI FlowLog delivery, CloudWatch alert routing, Inspector/ECR/SSM agent/patch scan coverage.
- Restore tests, dependency CI scans, personal data access reviews or human security-process documentation.
- Cross-region proof, complete resource inventory, formal product-control mapping, or any full 46-item product PASS guarantee.

Full roadmap: [Issue #8](https://github.com/yohi/aws-security-audit/issues/8). 
Official API documentation: [CloudTrail](https://docs.aws.amazon.com/boto3/latest/reference/services/cloudtrail/client/get_event_selectors.html), [GuardDuty](https://docs.aws.amazon.com/boto3/latest/reference/services/guardduty/client/get_detector.html), [Security Hub](https://docs.aws.amazon.com/boto3/latest/reference/services/securityhub/client/get_enabled_standards.html).
