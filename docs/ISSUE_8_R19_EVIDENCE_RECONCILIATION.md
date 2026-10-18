# Issue #8 / R19 — Read-only evidence reconciliation / manual-work reduction

Base: [merged PR #15](https://github.com/yohi/aws-security-audit/pull/15), merge commit
`d692a4a7bd59cc72a4b27780d56c84c351239d54`.

## Problem / bounded scope

R18 external LLM classifications passed cardinality and evidence-ID checks but
**failed semantic review**. The LLM called already-observed S3 account BPA and
per-bucket classic Access Point reads "unverified", demanded object history and
restore drills as prerequisites for other original control criteria, and copied
every reference ID instead of citing what supported the conclusion.

R19 does **not** extend AWS access or amend the 46 original Japanese criteria.

## New additive offline reconciliation contract

`decision_support.plans[].evidence_reconciliation` is derived from existing,
typed `control_observations.rows` only; no AWS calls, invented resources,
remediation or inferred compliance. The field is present for all 46 controls
and explicitly specialized for #17, #18, #20 and #23:

- #17: observed directly attributed bucket *default encryption*, distinguish
  from unrequired proof of historical object encryption.
- #18: observed direct bucket BPA all four flags true, regional bucket-scoped
  classic Access Point `LIST_VERIFIED` with no listed APs and account-wide
  S3Control `NOT_CONFIGURED` as a **successful negative configuration
  observation** (not access denied or unattempted). Interpretation of
  account-vs-bucket BPA requirement, other public paths and organization
  policy provenance remain **open**, not accidentally certified.
- #20: observed per-resource KMS-encrypted RDS/cluster/snapshots as facts.
  Backups/snapshots still need *scope completeness*; restore drills are #45,
  not mandatory #20 encryption proof.
- #23: observed Aurora cluster `DeletionProtection=True`. Member instance
  deletion and resulting availability are **separate** from the original
  RDS deletion-protection criterion.

A verified property is **not** a product-wide final PASS. The facts each
carry the exact `observation:<No>:<index>` source reference. The offline
validator recomputes them from the original evidence and rejects
tampered `evidence_reconciliation`.

The generated LLM prompt requires evaluating `verified_facts` before making
any missing-evidence request, using only the original 46 criteria, and citing
only refs actually used. `preferred_evidence_request` is explicitly a
*static candidate hint*, not an actual missing-evidence field.

The validator emits an advisory `citation_quality_warnings` if an LLM
cites all available refs when more than two exist; warning is not a failure
or semantic approval. LLM business labels remain advisory; technically
observed `FAIL` does not prove that no remediation is underway.

## Offline test contract

- Synthetic fixtures reproduce the exact relevant typed AWS observations:
  2 S3 default-encryption OK, 2 bucket BPA OK, 2 classic AP lists verified
  empty, account BPA NOT_CONFIGURED, 4 RDS instances/2 clusters/10 snapshots
  encrypted, 2 Aurora clusters deletion-protected.
- Wrong product attribution, schema, API error, contradictory encryption and
  member-instance-only evidence must not generate false verified facts.
- The validator checks calculated reconciliation equals the raw observation
  registry; fake/tampered summaries fail.
- Preserve 46 controls, 4 business labels + null pending, original
  account/region engine statuses and existing upload protection.
- Python 3.12/3.13 CI and real-source R18 offline comparison are required.
- **Owner-local actual read-only AWS R19 execution** must be performed at
  fixed HEAD. Verify seven original reports, provenance JSON, SHA256SUMS
  and Web contract against R18. If code changes, repeat at new HEAD.
- Actual ChatGPT/Gemini **without AWS connection** must classify the R19
  bundle, validate submitted JSON using the built CLI and measure actual
  residual human-check requests. Do not claim semantic PASS merely from a
  successful structural validator.
- Independent code/security review, explicit Owner merge authorization and
  Issue #8 closure remain separate. CodeRabbit not invoked without approval.

No AWS writes, credentials for LLM, live AWS calls from the LLM, automatic
upload, app changes, checklist modifications or project-wide PASS promotion.
