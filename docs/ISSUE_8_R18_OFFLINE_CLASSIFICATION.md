# R18 — Offline 46-control four-state LLM classification, minimize manual checks

Base: merged PR #14, `c84c4da533bd80e387af7f9ea130b9633730e5bb`.
Parent: [Issue #8](https://github.com/yohi/aws-security-audit/issues/8).

## Goal and boundaries

The operator-controlled CLI collects read-only AWS evidence and writes
local artifacts. **The ChatGPT/Gemini classifier must never connect to AWS**
by CLI, API, MCP, connector, plugin or credential. The human operator inspects
reports and manually uploads the sanitized evidence bundle. A separate
offline validation CLI likewise never calls AWS.

The final business status is one of `対応済み`, `未対応`, `対応中`,
`対象外`. A missing source **never** means "未対応" or "対応中".
`EVIDENCE_PENDING` is a workflow blocker with a null classification,
not a fifth business label. A result that still has pending rows is an
honest *incomplete* outcome, not a false claim of 46/46 success.
Existing scanner PASS/FAIL/MANUAL_REVIEW/UNKNOWN and properties are retained
as independent source fields and never replaced.

## Manual-work minimization (not automated correctness claims)

The 46-item `decision_support.plans` contains an explicit, criterion-oriented
evidence acquisition **candidate** for every control:

- `AWS_READ_ONLY_CANDIDATE`: pursue verified configuration/API evidence
  collected into the offline package; owner/manual adjudication may still
  be necessary if scope/operational exceptions are not resolved
- `AWS_PLUS_OWNER_SCOPE`: automate machine-observable facts first, request
  **only narrowly identified** product role, company policy or actual
  operational applicability from humans
- `NON_AWS_EXPORT_CANDIDATE`: seek read-only DB/CI/repository
  machine-generated exports that the operator can attach manually
- `OWNER_DOCUMENTATION`: inherently organizational runbooks, escalation
  contacts or security responsibilities, which an AWS API cannot prove

Candidate count: 15 AWS-read-only, 24 AWS+Owner scope, 3 non-AWS
machine exports, 4 Owner documentation. Thus **42/46 should seek
machine-readable evidence first**, not 42 guaranteed automated decisions.
Thirty controls can have a criterion-level human-context dependency;
their *unresolved* questions are grouped into **four conditional request
batches** (product/network scope; identities/data; logs/monitoring governance;
incident/recovery ownership). Evidence already available suppresses repeat
questions; each batch can be answered with existing redacted documents rather
than interviewing one person per checklist line.

Each row records a preferred evidence request, whether Owner context is
intrinsic, the existing observation count and stable per-control
`finding:<No>:<index>`/`observation:<No>:<index>` references.
These are **routing hints**, not determinations that evidence is sufficient.
Do not claim there are only four required human checks because four controls
are routed OWNER_DOCUMENTATION; many mixed-source controls also require
explicit role/policy applicability.

New prompt asks the LLM to **reuse existing evidence first**, batch missing
human questions, separate missing AWS data from missing Owner-only facts,
and return exactly 46 structured rows. No live querying or remediation.
A validator checks that labels/null states, 46 IDs, referenced evidence and
summary counts are consistent. It **cannot validate factual truth** or
Owner adoption by reading JSON alone.

## R18 scope implemented

- Additive fields in legacy `aws_web_review_*.json`:
  `classification_intent`, `decision_support`,
  `supplemental_evidence=[]`. Existing v1 original fields unchanged.
- `aws_web_prompt_*.md` now contains the R18 four-state offline
  classification prompt. Historical investigation-only prompt remains
  accessible in Python as `WEB_REVIEW_PROMPT`.
- Offline-only `aws-security-audit validate-classification --bundle
  PATH --result PATH` consumes human-saved LLM JSON. Code path is handled
  **before any AWS context creation**. Exit 0: 46 rows structurally
  classified (Owner semantic review still required); exit 2: pending rows;
  exit 1: malformed input/citation/summary. It never prints raw input data.
- Optional operator-added `supplemental_evidence` records must have
  `id`, nonblank `source`, nonblank `collected_at`, and explicit
  `control_numbers` limited to No.1–46; such metadata
  cannot on its own prove a document was inspected or its contents are true.
  Supporting documents must be **actually attached and reviewed** by LLM.
- No new collector AWS API, AWS policy, IAM, deployment changes.
  No automatic LLM upload. **This does not claim 46/46 classification
  completion or reduction in actual Owner checks until measured against
  completed evidence.**

## Example output contract

Each item in the LLM-produced `controls` array:

```json
{
  "number": 1,
  "final_classification": null,
  "resolution_state": "EVIDENCE_PENDING",
  "evidence_refs": ["finding:1:0"],
  "rationale": "AP role inventory not owner-confirmed",
  "missing_evidence": ["Owner-approved app server role mapping"]
}
```

Output root: `schema="aws-security-offline-classification-v1"` and
`summary={finalized_count, pending_count, 対応済み, 未対応, 対応中, 対象外}`.
No omitted/repeated No; no manufactured/cross-control citations.
Advisory final labels are not Owner approval.

## Verification and rollout gates

- [ ] Fixed-HEAD Python 3.12 and 3.13 CI, including all 46 fixtures and no-AWS CLI test.
- [ ] Run collector against actual ROS AWS with Human Owner's existing
  read-only STS flow **at R18 HEAD**, fresh output path, installed source-byte
  verification, and sidecar hashes. This tests emitted new evidence-plan
  fields. Since no new AWS API is called by R18, no authorization extensions
  are implied.
- [ ] Check the **original seven report files** plus provenance and
  SHA256SUMS against fixed R17 output. Confirm 46 rules and original status
  counts preserved, expected changes restricted to bundle
  decision support/prompt.
- [ ] Paste R18 prompt and bundle into an AWS-disconnected LLM, validate
  machine-produced 46-row JSON with the offline CLI. Record actual
  `pending_count` and grouped, specific outstanding evidence requests.
  Do not mark 46/46 as achieved merely because a synthetic test passes.
- [ ] Security/code review of source attribution, data exposure,
  prompt-injection defenses and structural-vs-semantic validation.
- [ ] Separate Human Owner merge decision. Issue #8 remains OPEN.
  CodeRabbit must not be triggered without explicit human permission.
