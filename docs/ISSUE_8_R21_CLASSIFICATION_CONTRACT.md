# R21: strict 46-row classification v2, deduplicated evidence requests and claim citations

Parent: [Issue #8](https://github.com/yohi/aws-security-audit/issues/8).
Baseline: merged PR #17 commit `671e0becbc6fc62870a4634099e07e25ca526b20`.

## Why this change is needed

The real R20 LLM report had 46 rows but emitted a *nested*
`summary.classifications` object rejected by the preexisting local
`validate-classification` CLI. It also separately asked for the same
ROS product/region-scope Owner confirmation in #2/#17/#20/#23; cited
bucket BPA observations as support for an Access Point list zero claim
without listing its actual source references, and frequently repeated
the original checklist text as a generic evidence request.

The R20 collector has **not** been extended and this is not an
approval to contact AWS from the classifying LLM.

## R21 generated output contract

- Adds `decision_support.output_contract.schema=
  aws-security-classification-output-contract-v2` to the
  offline Web handoff. Generated classification prompt requires
  `aws-security-offline-classification-v2` and **flat**
  `summary.finalized_count`, `pending_count`, and each of the four
  Japanese business-label counts; nested `summary.classifications`
  is explicitly prohibited.
- A single root `evidence_requests[]` contains unique, actionable,
  pending requests: id, acquisition_channel, status,
  applies_to_controls and requested_artifact. Channels:
  `AWS_LOCAL_READ_ONLY` (human operator's local read-only collector,
  **not the LLM**), `NON_AWS_MACHINE_EXPORT` (human uploads
  offline exports) and `OWNER_CONFIRMATION`. All entries remain
  `REQUESTED_NOT_FULFILLED` until actual evidence arrives.
- Each pending control includes one or more
  `missing_evidence_request_ids`. The validator verifies
  bidirectional root/row references. An Owner scope request with
  id `scope:product-resource-and-region-coverage` **must be a
  single entry** covering all still-pending controls from
  #2/#17/#20/#23. Its text must exactly match the R20 generated
  `shared_scope_contract.single_owner_question`, and approval
  remains PENDING. No four separate interviews or fake signoff.
- Root `summary` counts `distinct_evidence_request_count`,
  `owner_confirmation_request_count` and
  `machine_acquisition_request_count`, checked against the actual
  unique root list. A batch is **not** one universally sufficient
  Owner approval; the count represents unique evidence-request
  actions, not a measure of completed evidence or security outcomes.
- Each control's `evidence_claims[]` lists individual claims and
  source `evidence_refs[]`, with optional `verified_fact_code`
  bound to an actual, recomputed R19/R20 typed fact. Every
  `controls[].evidence_refs` ID must belong to some claim.
  Typed fact codes must point to the exact source observation(s)
  and same control. For #18, citing *zero classic Access Points*
  should include `DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY` fact and
  its source observations, not only bucket BPA flags.
- Retains original engine verdicts, 46 original criteria, region/
  attribution warnings, original Web input format and no automatic
  upload. External input/LLM text remains untrusted.

The original `aws-security-offline-classification-v1` can still be
read/structurally validated with an explicit
`r21_request_schema_check=NOT_PERFORMED_LEGACY_V1` response. **It
is not R21 conformance.** The R21 prompt emits **only v2**;
for a verifiable R21 workflow, use the v2 output contract.

## Important remaining limitations

- Structural validator can catch forged or cross-control evidence ID
  references, unsupported typed fact codes, output shape, and owner-
  request duplicate/incorrect counts. It **cannot** establish whether
  the LLM's words are semantically justified, assess a scope signoff,
  or prove that the requested material is adequate.
- Natural-language, claim-to-observation omissions can be alerted for
  #5 SG egress and #18 classic Access Points only. This advisory
  warning is not a comprehensive semantic classifier or proof of
  a final business label. Owner review is still necessary.
- A negative AWS setting #16/#19/#22 is a real configuration result,
  but `未対応` vs `対応中` requires actual remediation-progress
  evidence. Never infer none exists merely because it was not uploaded.
- Prior R20 counts **3 provisional failures / 43 pending** do not
  prove R21 reduced Owner work; actual unique request metrics require
  a R21 LLM rerun and review. Do not count all machine acquisition
  requests as mandatory human policy attestations.

## Acceptance / gates

- [ ] Fixed HEAD full GitHub Actions Python 3.12/3.13 CI, including
  malformed nested counts, cross-control typed references,
  duplicate/split scope request, fake Owner signoff and mismatch
  of distinct Owner/machine request counts.
- [ ] No-API R20 replay: read operator-submitted frozen Web JSON
  with new R21 code and prompt, obtain actual 46-row v2 LLM output,
  save it as a standalone JSON and execute the real local
  `validate-classification --bundle ... --result ...`. Expect
  exit code 2 if still pending. Count root requests separately
  from 46 per-row statuses.
- [ ] As the source code creating the offline handoff changes,
  **Human Owner new fixed-HEAD AWS read-only** `assess` run is
  required by the established project gate: 7 original report
  files + run provenance + SHA256SUMS, independent compare with
  R20 original AWS observations. Fresh run need not add AWS API
  calls or privileges.
- [ ] Independent fixed-head code/security review including
  applicability limits, generated prompt/LLM factual claims,
  and privacy protection. Separate Owner PR merge approval.
- [ ] Keep Issue #8 OPEN until real 46/46 evidenced final business
  labels and documented Owner adoption; DO NOT trigger CodeRabbit
  without express Owner consent.

No automatic AWS access by the classifying LLM, credentials, AWS
writes, automatic upload, production deployment or automatic merge.
