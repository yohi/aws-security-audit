# R20 / Issue #8 — Shared scope and bounded cross-control evidence reuse

Fixed baseline: merged PR #16, commit `b35279b0b4e841f555afa102781d40f852e00b21`.

## Goal and security boundary

Make **one human product-scope inquiry** reusable for #2/#17/#20/#23,
reconcile observed #5 unrestricted security-group egress, and reuse #20
automated RDS snapshot observations as **limited positive evidence** for #45.
Do **not** claim full four-state coverage, auto-approve assets/regions, auto-call
AWS from the LLM, or certify a restore drill.

## Changes (all generated offline from existing AWS snapshot)

1. `decision_support.shared_scope_contract`: one request ID
   `scope:product-resource-and-region-coverage`, reusable by #2, #17, #20,
   #23. Carries selected region(s), inventory DIRECT/RELATED/unassigned
   counts, product and attribution-limit indicators. **owner_approval=PENDING**
   and **scope_coverage_proven=false**, regardless of heuristic tags. The
   request is shared to suppress redundant Owner interviews, not equivalent
   to a signed scope register. Plan rows contain the identical
   `shared_scope_requirement_ids`. This contract cannot become APPROVED
   without an explicit independently supplied Owner record.
2. `evidence_reconciliation` for #5 includes each DIRECT SG with
   a typed observed all-protocol public egress rule count >0. R19 live bundle
   held seven such SGs; exact count/relevance must be retested in R20.
   Whether an egress rule is *unnecessary* is a distinct business approval.
   Do not infer #5 automatic FAIL, or omit the outbound criterion.
3. `decision_support.cross_control_evidence.references`: allowlist from #20
   observation to **#45 only** when the same inventory resource is DIRECT
   `db-cluster-snapshot`, `snapshot_type=automated`, and the #20
   per-resource observation explicitly says encrypted/ENCRYPTED/sse-kms.
   These are snapshot-presence refs; not complete backup coverage, assured
   schedule, live restore/test results, or #45 PASS. Validator accepts cited
   `observation:20:index` refs for #45 only, and rejects cross-control
   borrowing from other business controls.
4. New offline result validation recomputes all shared-scope and cross-control
   indices directly from the original bundle's inventory/observations.
   Spoofed Owner APPROVED, invented backup refs or incorrect control
   reassignments fail. Original 46 scanner findings and final four-state
   validation semantics are not altered.
5. Generated Web LLM prompt explicitly requires all three behaviors above,
   plus one Owner policy interpretation for #18 account- vs bucket-BPA
   requirement. LLM cannot query AWS or other live connectors.

## Non-goals / unresolved gates

- Owner must still approve actual ROS scope/region and the applicability of
  shared account controls. A provisional `PENDING` register is not a real
  signature, and the selected product inventory is not exhaustive.
- 46 checklists must still be classified as
  `対応済み/未対応/対応中/対象外` or null + EVIDENCE_PENDING.
- R19's 3 provisional `未対応` and 43 pending counts are not a
  promise that R20 will resolve a fixed number.
- Local CLI structure/ref validation is not LLM semantic proof, nor
  authority to deploy AWS changes.
- Formal source/security independent review and Owner merge decision remain
  distinct. Do not trigger CodeRabbit without Owner authorization.

## Verification protocol

- [ ] Full 3.12/3.13 CI on fixed HEAD, preserving R19 regressions plus
      #5 egress false positives, scope tampering, and allowed/forbidden
      cross-control refs.
- [ ] Owner-local fixed-HEAD ROS read-only actual AWS scan; new non-overwriting
      report directory and original seven outputs + provenance/hash sidecars.
      Source bytes, SHA-256 and base AWS facts must be checked independently.
- [ ] External AWS-disconnected ChatGPT/Gemini classification from R20
      Web JSON + generated R20 prompt; save 46-row result, run
      `validate-classification` offline and review semantic accuracy and
      **number of distinct Owner requests** (not merely pending count).
- [ ] Independently adjudicate whether new shared scope question reduced
      redundant human requests *without suppressing necessary uncertainty*.
      Explicit Owner policy decision for #18 remains pending unless documented.

No additional AWS API reads, policy changes, AWS write, automatic upload,
secret disclosure, PR merge or check-list wording changes are authorized by
this change.
