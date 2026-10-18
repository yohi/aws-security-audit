# R23 — Six machine-evidence gaps: acquisition gate review

Issue #8 remains OPEN. Baseline is merged master at `9204740c8428966a6bb306d69b802da3c881e128`; the original 2026-10-18 ROS Web evidence is held privately by the operator. This PR adds an evidence-only acquisition plan, **not** AWS collection code, new permissions, a final classification or an authorization to run.

## Evidence already obtained and remaining questions

| Control | Evidence reuse | Next question | Channel |
| --- | --- | --- | --- |
| #8 Shield | Selected product edge inventory | Shield Advanced subscription and which approved endpoints are protected | Operator-approved read-only AWS export after scope confirmation |
| #24 CloudTrail | Multi-region and logging enabled; event categories observed | Actual product S3 object-selector coverage and relevant delivery errors | Operator-approved targeted read-only export |
| #27 Flow Logs | VPC/subnet settings were observed | ENI-level coverage for approved product network inventory | Operator-approved targeted read-only export |
| #33 Security Hub | `describe_hub` returned `InvalidAccessException` | Authorized independent confirmation of hub, standards and checks; **error cause remains unknown** | Approved export / error triage |
| #39 Inspector/ECR | Partial product resource inventory | Product-owned AMI/image mapping and dated scan configuration/results | Confirm image ownership, then approved AWS export |
| #40 Dependency scans | AWS evidence does not contain CI dependency reports | Product repository/branch ownership, scan configuration and dated runs | Non-AWS machine export |

No machine request is verified as fulfilled by existing evidence alone. Do not repeat already-observed basic CloudTrail or VPC/subnet configuration calls. Five AWS-local-read-only request containers and one non-AWS-export container remain requested, not executed.

## Scope/authority gates

1. Preserve the 46 original checklist controls and 4-label business status contract; there are 3 **provisional** negative classifications and 43 evidence-pending controls.
2. Reuse existing evidence before new reads. Owner must confirm product scope, applicable regions, network/image ownership, shared account controls and repository mapping, reusing the existing 7 Owner request containers.
3. No AWS acquisition is authorized by this document. Any additional AWS collector API must have a narrowly reviewed implementation plan, explicit operator authorization, and independent read-only verification.
4. Security Hub errors may not be classified as a disabled service or IAM root-cause proof. Object-event enablement does not itself prove product bucket coverage.
5. Original logs and customer resource identifiers must remain in operator-private evidence storage; no secrets, automatic uploads or LLM connection to AWS.
6. `EFFECTIVE_NO_WRITE=NOT_PROVEN`; source-to-runtime independent attestation, product attribution coverage, semantic compliance, human work reduction and Owner classification adoption remain unproven.

## Acceptance and follow-up

- [x] Offline read-first assessment for six request groups
- [x] Distinguish source facts from missing evidence and Owner prerequisites
- [ ] Independent review of the proposed acquisition scope
- [ ] Owner authorization **before** any additional AWS run or collector expansion
- [ ] Separate PR for scoped collector code after authorization; preserve original report formats
- [ ] Actual export and 46-row classification replay, with source hashes and validation exit

This documentation PR closes **no** missing-evidence request and makes **no** determination that new AWS reads must be run.
