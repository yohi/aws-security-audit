# Evidence-Traceable Reporting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Explain, for each of the original 46 controls, the observed facts,
their collection and applicability limits, and the evidence still needed for
an offline, evidence-supported business classification.

**Architecture:** Add a versioned evidence ledger and an offline review model
to the existing R25 reporting flow. Preserve existing scanner verdicts and
classification contracts; render JSON, CSV, XLSX, Markdown and Web handoff
from shared projections instead of independently deriving conclusions.

**Tech Stack:** Python >=3.12, existing boto3 1.43.18, stdlib dataclasses,
enum, contextvars, JSON, hashlib and XML/ZIP; pytest 9.0.2 and ruff 0.14.11.
No new runtime dependency or lockfile change.

**Spec:** [Proposed reporting contract](#proposed-reporting-contract) in this
document is the single review draft derived from the preceding user discussion.
Existing constraints remain owned by
[R25](../../ISSUE_8_R25_EVIDENCE_FIRST_REPORTING.md),
[investigation-only contract](../../INVESTIGATION_ONLY.md), and the immutable
[`CHECKS`](../../../src/aws_security_audit/catalog.py).

**Status:** DRAFT; design decisions below require user review before execution.
This document does not authorize implementation, AWS execution, commits,
CodeRabbitCLI, PR merges or Issue closure.

## Global Constraints

- Preserve No.1–46, exact order, titles, criteria, severity and purpose.
- Preserve `PASS|FAIL|UNKNOWN|MANUAL_REVIEW|NOT_APPLICABLE` scanner values.
- Preserve `対応済み` / `未対応` / `対応中` / `対象外` business labels and the
  existing `FINALIZED|EVIDENCE_PENDING` classification contract.
- Pending evidence is not a fifth business label or a count of human tasks.
- Report generation and LLM classification are offline: no AWS clients,
  credentials, connectors, automatic uploads or network activity.
- Instrument existing read operations only; no additional AWS discovery,
  write APIs, IAM changes, probes, scan launches or notification tests.
- Preserve STS fail-closed behavior and `effective_no_write=NOT_PROVEN`.
- Partial observations, empty filtered searches and hashes never prove full
  product compliance, ownership, execution attestation or effective No-Write.
- Retain existing exclusive 0600 output creation and directory behavior.
- Use synthetic fixtures, not private ROS account IDs, ARNs, IPs or outputs.
- Keep new modules below 250 nonblank, noncomment lines; extract only the
  responsibilities this plan introduces from oversized existing modules.
- Python 3.12 and 3.13 are the existing CI targets. Use locked project commands.
- The existing `.gitignore` change is user work; do not stage or overwrite it.
- Commit checkpoints below are conditional on a separate explicit user commit
  instruction. Otherwise retain the corresponding logical changes uncommitted.

## Review Focus

1. A page succeeds before a denied/expired/cyclic continuation: preserve partial
   collection and never emit verified absence (Tasks 2 and 4).
2. An older bundle lacks timestamps, call records or ownership coverage: display
   unknown provenance instead of assigning the report-generation time (Task 3).
3. A resource name or evidence sentence resembles instructions or spreadsheet
   formulas: preserve it as inert data without secret leakage (Tasks 1 and 7).
4. Conflicting account/bucket or cluster/member observations: show their separate
   scopes without silently selecting a favorable conclusion (Task 5).
5. Supplementary evidence has a different execution/account/region or a forged
   reference: retain source separation and reject mismatches (Tasks 3 and 6).

## Proposed Reporting Contract

### Scope and compatibility

This is one end-to-end reporting change with two delivery milestones:
collection/provenance (Tasks 1–4), then review/export (Tasks 5–8).
Adding new service coverage, changing ownership heuristics, proving effective
reachability, and redefining control criteria are separate future work.

Existing R25 already separates business and scanner states, checks optional
supplements, and reuses #20 snapshot evidence for #45. Reuse that behavior;
do not introduce a second classifier or replace its source-reference rules.

Preserve existing filenames, columns, sheet names, verdict values and source
reference identifiers. Add `evidence_ledger` and `control_review` fields.
Existing files remain readable without these additions. Invalid new extensions
fail validation rather than being silently ignored.

### Evidence ledger v1

`schema = aws-security-evidence-ledger-v1`. Define typed, JSON-serializable
dataclasses and an explicit parser at file-input boundaries.

- `EvidenceLedger`: `schema`, `executions`, `calls`, `facts`, `scope_checks`.
- `Execution`: `id`, `source_kind`, `account`, `regions`, `product`,
  `started_at`, `finished_at`, `source_digest`, `attestation`.
- `CallRecord`: `id`, `execution_id`, `service`, `operation`, `region`,
  `safe_selector`, `started_at`, `finished_at`, `collection_state`,
  `error_code`, `page_count`, `pagination_complete`, `returned_count`.
- `EvidenceFact`: `id`, `execution_id`, `call_refs`, `source_ref`, `number`,
  `resource_key`, `field_path`, `field_present`, `value`, `interpretation`,
  `scope_limit`, `observed_at`, `provenance_level`.
- `ScopeCheck`: `id`, `execution_id`, `service`, `selector_basis`,
  `call_refs`, `selected_resource_keys`, `candidate_resource_keys`,
  `coverage_state`, `limitations`.
- `JsonValue`: recursive JSON scalars, lists and string-keyed dictionaries.
  Unknown values are `null`, never implicit false/zero/empty strings.
- Collection states: `OBSERVED`, `VERIFIED_EMPTY`, `NOT_CONFIGURED`,
  `ACCESS_DENIED`, `FAILED`, `PARTIAL`, `NOT_ATTEMPTED`, `LEGACY_UNKNOWN`.
- Coverage states: `VERIFIED_FOR_SELECTOR`, `PARTIAL`, `UNKNOWN`.
  Selector completeness never implies product-wide attribution completeness.
- Provenance levels: `COLLECTOR_PROJECTED`, `LEGACY_SOURCE`,
  `OPERATOR_CURATED`, `ASSISTANT_CURATED`.

IDs have a kind prefix plus SHA-256 of canonical JSON (sorted keys, compact
separators, UTF-8). Execution identity includes a UUID generated once per run;
record identity includes execution and logical call/fact identity. Regenerating
reports from an unchanged bundle preserves IDs; separate runs never merge.
For historical input without an execution UUID, use the artifact SHA-256 as
the execution identity and mark it `LEGACY_SOURCE`, rather than minting a new
run or claiming that two historical artifacts came from the same execution.
`source_digest` hashes the input artifact bytes and is not execution attestation.
`attestation` remains `NOT_PROVEN`.

Do not store raw SDK responses or generic request dictionaries. Keep current
allowlisted attribute projections and identity fields. `safe_selector` allows
resource IDs/ARNs, region, product selector, tag keys and names, result key and
named filter values used by current collectors; unknown fields are omitted with
a limitation. Never retain credentials, tokens, secret values, task environment
values, log bodies, arbitrary descriptions, endpoint credentials or exception
messages. Facts must point to actual source fields; narrative text alone is not
machine verification.

An empty list is `VERIFIED_EMPTY` only when the selected list operation
completed every page. API-specific not-configured codes are interpreted only
with an explicit service/operation allowlist. For example, S3 versioning
success without `Status` is an observed absent field with its documented
interpretation; `NoSuchPublicAccessBlockConfiguration` is a known unset
configuration. Access denial is never mapped to either case.

### Legacy and supplementary inputs

Older bundles are projected without AWS access. Reuse existing source IDs and
observation values, but leave absent call timing and pagination metadata unknown.
Do not manufacture raw API provenance from the observation's prose.

R24 and MCP inputs retain their original source and execution. Curated MCP
facts remain curated, even if they include an API name. Validate explicit
expected account, product and regional compatibility using existing checks;
global/account context must be explicitly scoped, not automatically applied.
An old MCP summary lacking observation time stays undated. Conflicting
observations remain visible with both references; no last-write-wins merge.

### Control review v1

`schema = aws-security-control-review-v1`. Exactly 46 ordered rows contain:
original catalog fields, original scanner account/regional status, `fact_refs`,
`scope_refs`, `criterion_checks`, `evidence_state`, `gaps`, `request_ids`,
existing provisional classification state/label and Owner-adoption state.

`evidence_state` is `NO_EVIDENCE`, `PARTIAL`, `CONFLICTING` or
`SUPPORTED_FOR_DECLARED_SCOPE`. The last requires explicit structured evidence
of coverage and all applicable criterion components, not observation counts.
This milestone never grants it from a legacy/curated source alone. It is an
evidence-sufficiency statement, not a business verdict.

`CriterionCheck` has `id`, `component`, `state`, `fact_refs`, `scope_refs`,
`limitation`; `state` is `OBSERVED_MATCH`, `OBSERVED_MISMATCH`, `UNRESOLVED`
or `CONFLICTING`. Specialized checks extend existing reconciliation for
controls #5/#17/#18/#20/#23/#45; others expose unresolved criterion
coverage instead of pretending to implement new graders.

Gap kinds: `COLLECTION`, `ATTRIBUTION`, `CRITERION_INTERPRETATION`,
`MACHINE_EVIDENCE`, `OWNER_CONTEXT`, `REMEDIATION_STATUS`, `OWNER_DOCUMENT`.
Every gap has a stable key, affected scope, controls, supporting refs and
required evidence description. An observed mismatch cannot alone resolve
`未対応` versus `対応中`.

Requests group gaps by `(kind, scope, requirement_key)`, not by free-text
similarity. Only new validated evidence satisfying the same requirement and
scope may remove a machine gap. Owner-supplied prose or an arbitrary LLM claim
does not mark a gap resolved. Reuse existing shared-scope requests and
snapshot cross-control refs. Keep uncovered machine questions separate from
questions inherently requiring an Owner document.

This milestone generates requests but adds no Owner-response ingestion
protocol. Owner approval/document gaps remain visible until supplied through
an existing validated contract; an unspecified answer is not an approval.

### Deliverables and verification boundary

JSON is authoritative. Existing audit CSV/XLSX summaries receive additive
review columns and fact refs. The existing observation/resource tables remain.
Progress exports add a 46-row CSV and XLSX with `46項目レビュー`, `証拠索引`,
`取得状態`, `対象範囲`, `追加確認` sheets; Markdown is their human summary.
Web handoff embeds the same ledger and review model, without auto-upload.
New progress files share the existing generated progress basename with
`.csv` and `.xlsx` extensions. Audit summary additions are `証拠充足状態`,
`証拠参照ID`, `対象範囲参照ID`, `未確定理由`, and `追加確認ID`.
The private manifest uses the same invocation basename plus `.manifest.json`.

Each export set includes an exclusive private manifest of relative filenames,
SHA-256 bytes and input digests; the manifest excludes itself. Generate and
validate models before writing files. On failure, remove only files created
by that invocation, leave prior files untouched and return failure. No atomic
multi-file filesystem transaction or source-to-execution attestation is claimed.

## File Structure and Responsibilities

- New `src/aws_security_audit/evidence_types.py`: typed ledger and review data.
- New `src/aws_security_audit/evidence_ledger.py`: parsers, IDs and validation.
- New `src/aws_security_audit/read_capture.py`: bounded metadata-only recording.
- Modify `core.py`: structured sanitized errors and optional read capture.
- New `src/aws_security_audit/evidence_adapters.py`: old/R24/MCP projection.
- New `src/aws_security_audit/scope_coverage.py`: offline selection diagnostics.
- Modify `resource_scope.py`: attach diagnostics without changing selection.
- New `src/aws_security_audit/control_review.py`: 46-row offline review model.
- New `src/aws_security_audit/evidence_requests.py`: residual evidence requests.
- New `src/aws_security_audit/review_export.py`: shared review table projection.
- New `src/aws_security_audit/report_manifest.py`: checksums and failure cleanup.
- Modify `report.py`, `evidence_progress_report.py`, `web_handoff.py`, `cli.py`:
  integrate additive fields and route all consumers to the shared model.
- New focused tests below, using `tests/conftest.py` for synthetic fixtures.
- New `docs/evidence-traceable-reporting.md`: final operator-facing contract.

## Execution Preconditions

- Review this draft's contracts and scope before implementation.
- Use the worktree skill at execution time; preserve existing user changes.
- Test with fake clients only. No live AWS validation is part of this plan.
- Load relevant Python/TDD skills at execution time. Use the existing environment
  and inspect any available devcontainer before choosing execution commands.
- After each task, inspect the targeted diff. Commit only if separately requested;
  stage exact files and use Japanese Conventional Commits.

## Implementation Tasks

### Task 1: Versioned types, source IDs and strict parsing

**Files:** Create `evidence_types.py`, `evidence_ledger.py` under
`src/aws_security_audit/`; add `tests/test_evidence_ledger.py` and synthetic
ledger/review factories in `tests/conftest.py`.

**Interfaces:** Produce the dataclasses listed in the contract, including
`ControlReview(schema, rows, requests)`, `ControlReviewRow` with exactly the
fields in Control review v1, `EvidenceGap(id, kind, scope_key, requirement_key,`
`controls, evidence_refs, required_evidence, acquisition_route)`, and
`ReviewTables` as defined in Task 7. Define Task 6's `EvidenceRequest` here,
plus
`parse_ledger(data: object) -> EvidenceLedger`,
`ledger_to_json(ledger: EvidenceLedger) -> dict[str, JsonValue]`, and
`evidence_id(kind: str, identity: JsonValue) -> str`.
Parsing rejects invalid enums/types, duplicate IDs and dangling references.
`ControlReviewRow` fields are `number`, `category`, `title`, `criterion`,
`severity`, `purpose`, `scanner_status`, `scanner_regional_status`, `fact_refs`,
`scope_refs`, `criterion_checks`, `evidence_state`, `gaps`, `request_ids`,
`business_resolution_state`, `business_label_provisional`,
`owner_adoption_verified`. Preserve the existing `NOT_EVALUATED` state when
classification is absent; keep adoption false unless an existing independently
validated adoption contract proves otherwise.

- [ ] Write `test_ledger_round_trip_and_stable_ids`: round trip equals input;
  repeated canonical identity produces the same ID; another execution differs.
  Parameterize malformed input, duplicate/dangling refs, invalid UTC timestamps,
  unsupported schema and credential-like unknown fields: each raises `ValueError`.

  ```python
  def test_ledger_round_trip_and_stable_ids(ledger_json):
      parsed = parse_ledger(ledger_json)
      assert ledger_to_json(parsed) == ledger_json
      assert evidence_id("fact", {"a": 1, "b": 2}) == evidence_id(
          "fact", {"b": 2, "a": 1}
      )
  ```

- [ ] Run `uv run --locked pytest tests/test_evidence_ledger.py -q`;
  expect failure because the new modules do not yet exist.
- [ ] Implement the interfaces, field validation and deterministic serialization.
  No dynamic evaluation, arbitrary object serialization or raw response fields.
- [ ] Rerun that command; expect all new tests PASS.
- [ ] Review diff; conditional commit: `feat(evidence): 証拠台帳の型と参照検証を追加`.

### Task 2: Capture outcomes of existing reads without altering reads

**Files:** Create `src/aws_security_audit/read_capture.py`; modify
`src/aws_security_audit/core.py:21-22,57-102`; add `tests/test_read_capture.py`.

**Interfaces:** Consume Task 1. Produce
`capture_reads(execution: Execution) -> ContextManager[ReadCapture]` and
`ReadCapture.snapshot() -> tuple[CallRecord, ...]`.
Add optional `service`, `operation`, `code`, `collection_state` attributes to
`EvidenceUnavailable` while preserving existing message-only construction.
`api_call`/`paged` keep their public signatures and returned data.

- [ ] Write fake-client tests: invocation arguments/counts equal the baseline;
  one logical paged call records all pages; a denied second page is `PARTIAL`
  with `pagination_complete=False`; zero completed rows is `VERIFIED_EMPTY`.
  Test token cycles, expired session failures, S3 API-specific unset codes,
  successful missing fields, nested contexts and context cleanup after errors.
  Assert sentinel credentials/SDK messages never occur in serialized records.
- [ ] Run `uv run --locked pytest tests/test_read_capture.py -q`; expect FAIL.
- [ ] Implement ContextVar-scoped capture, structured errors and sanitized
  selector allowlisting. Instrument native paginator iteration and manual token
  traversal; do not add retries, API calls, authentication capture or permissions.
- [ ] Rerun the new tests and existing core/auth tests discovered in `tests/`;
  expect PASS with unchanged operation traces and fail-closed behavior.
- [ ] Review diff; conditional commit: `feat(evidence): 既存参照APIの取得状態を記録`.

### Task 3: Adapt existing facts and supplementary provenance

**Files:** Create `src/aws_security_audit/evidence_adapters.py`; modify
`evidence_progress_report.py:58-110`; add `tests/test_evidence_adapters.py`.

**Interfaces:** Consume Tasks 1–2. Produce
`build_ledger(bundle: dict, *, r24: dict | None = None,`
`mcp_summary: dict | None = None,`
`expected_account: str | None = None) -> EvidenceLedger`.
The existing bundle is a legacy boundary; parse projected data into Task 1 types.
Existing supplement validators run before projection.

- [ ] Write tests for a legacy bundle: observation values and old source refs
  survive, while absent observed time/call records stay unknown. Current
  captured calls join facts only on verified service/operation/scope/resource
  matches; ambiguous joins have no invented call ref. Parameterize R24/MCP
  sources, mismatched account/region/product, conflicting facts, missing dates
  and altered input bytes. Assert source levels/digests never upgrade trust.
- [ ] Run `uv run --locked pytest tests/test_evidence_adapters.py -q`; expect FAIL.
- [ ] Implement explicit existing-field projections and source-artifact identity.
  Do not parse prose into settings, reset dates, or reindex old citation IDs.
- [ ] Rerun new tests and `tests/test_evidence_progress_report.py`; expect PASS.
- [ ] Review diff; conditional commit: `feat(evidence): 既存証拠と補足証拠の来歴を保持`.

### Task 4: Record selection and coverage limits

**Files:** Create `src/aws_security_audit/scope_coverage.py`; modify
`resource_scope.py:534-642,644-740`; add `tests/test_scope_coverage.py` and
targeted cases in `tests/test_resource_scope.py`.

**Interfaces:** Consume Tasks 1–3. Produce
`build_scope_checks(resources: list[dict], selected: list[dict], scope: dict,`
`calls: tuple[CallRecord, ...]) -> tuple[ScopeCheck, ...]`.
Retain `attribute_resources()`'s return shape and selected set; append diagnostics
to inventory rather than promoting candidates.

- [ ] Write synthetic tests for a nonprefix `Product=ros` resource, `roslyn`
  exclusion, a related volume, shared VPC and an untagged `dh-ros-*` candidate.
  Assert candidates never enter the selected set automatically. Test failed tag
  reads, partial pagination and a zero name-filtered alarm search: all retain
  the selector limitation and do not prove product absence/completeness.
- [ ] Run `uv run --locked pytest tests/test_scope_coverage.py`
  `tests/test_resource_scope.py -q` as one command;
  expect new cases FAIL.
- [ ] Implement diagnostics from existing returned inventory and call records.
  Candidate name tokens are only hints; do not expose unrelated full inventory
  in the Web bundle or initiate additional tag/relationship reads.
- [ ] Rerun that command; expect PASS and unchanged original selections/verdicts.
- [ ] Review diff; conditional commit: `feat(report): 対象選定と検索範囲の制約を記録`.

### Task 5: Build one criterion-aware review model

**Files:** Create `src/aws_security_audit/control_review.py`; modify
`evidence_reconciliation.py:62-158`, `evidence_progress_report.py:113-255`;
add `tests/test_control_review.py`.

**Interfaces:** Consume Tasks 1–4 and existing `reconcile_control()` /
`build_cross_control_evidence()` results. Produce
`build_control_review(bundle: dict, ledger: EvidenceLedger,`
`classification: dict | None = None) -> ControlReview`.
`ControlReview` and `CriterionCheck` are Task 1 types. Validate classification
with the existing strict validator before reading its provisional labels.

- [ ] Write `test_review_preserves_order_criteria_and_scanner_statuses`: assert
  exactly No.1–46 and all original catalog fields/statuses, no adopted labels.
  Add #5 allow-all egress needing necessity context; #17 default encryption not
  historical objects; #18 account/bucket policy ambiguity; #20 snapshot
  encryption not a restore drill; #23 Aurora cluster/member distinction;
  #45 snapshot reuse without restore success. Parameterize conflicting and
  incomplete observations: neither becomes `SUPPORTED_FOR_DECLARED_SCOPE`.

  ```python
  def test_review_preserves_order_criteria_and_scanner_statuses(review_inputs):
      bundle, ledger = review_inputs
      result = build_control_review(bundle, ledger)
      assert [row.number for row in result.rows] == list(range(1, 47))
      assert [row.criterion for row in result.rows] == [
          check.criterion for check in CHECKS
      ]
      assert not any(row.owner_adoption_verified for row in result.rows)
  ```

- [ ] Run `uv run --locked pytest tests/test_control_review.py -q`; expect FAIL.
- [ ] Implement typed review projections and criterion components. Specialized
  components are exactly those above; other controls retain unresolved criterion
  coverage. New evidence never rewrites original scanner or business states.
- [ ] Rerun new tests plus existing reconciliation/progress tests; expect PASS.
- [ ] Review diff; conditional commit: `feat(report): 基準別の証拠充足と未確定理由を表示`.

### Task 6: Deduplicate only genuinely missing evidence requests

**Files:** Create `src/aws_security_audit/evidence_requests.py`; modify
`offline_classification.py` decision-support builder and
`evidence_progress_report.py:174-247`; add `tests/test_evidence_requests.py`.

**Interfaces:** Consume `ControlReview`. Produce
`build_evidence_requests(review: ControlReview) -> tuple[EvidenceRequest, ...]`.
Task 1 defines `EvidenceRequest(id, kind, scope_key, requirement_key, controls,
evidence_refs, required_evidence, acquisition_route)` and typed gap fields.
Add requests to the review, not the existing R21 classification schema.

- [ ] Write tests: one missing product-scope requirement serves #17/#20/#23;
  #20 snapshot context is reused for #45 but the restore-drill request remains;
  a configuration mismatch without remediation evidence retains a status
  question. A newly observed machine setting removes only the corresponding
  machine gap, not scope/Owner questions. Reject fabricated refs; evidence
  from another scope and free text cannot resolve a gap. Repeated builds keep
  IDs and ordering identical.
- [ ] Run `uv run --locked pytest tests/test_evidence_requests.py -q`; expect FAIL.
- [ ] Implement exact-key grouping and retain existing shared-scope IDs and
  cross-control refs. Machine-acquisition hints remain hints, never executed
  tasks or mandatory extra prerequisites outside the original criterion.
- [ ] Rerun new tests and existing classification/shared-scope tests; expect PASS.
- [ ] Review diff; conditional commit: `feat(report): 残る証拠要求を範囲別に集約`.

### Task 7: Render consistent private exports and manifests

**Files:** Create `review_export.py`, `report_manifest.py` under
`src/aws_security_audit/`; modify `report.py:28-75,115-201`,
`evidence_progress_report.py:264-339`, `web_handoff.py:11-111`;
add `tests/test_review_export.py`, `tests/test_report_manifest.py`.

**Interfaces:** Consume Tasks 1–6. Produce
`review_tables(review: ControlReview, ledger: EvidenceLedger) -> ReviewTables`,
`build_manifest(files: Mapping[str, bytes],`
`input_digests: Mapping[str, str]) -> bytes`, and
`write_export_set(out_dir: Path, files: Mapping[str, bytes])`
`-> tuple[Path, ...]`.
`ReviewTables` holds the five named sheets' headers/rows as JSON scalar cells.
Reuse `_private_bytes`, `_safe_spreadsheet` and current XML escaping.

- [ ] Write round-trip tests parsing CSV with `csv` and XLSX with stdlib XML/ZIP:
  all 46 rows and fact/request refs equal JSON projections. Test zero evidence,
  Japanese labels, formula prefixes, XML characters, multiline/oversized cells
  and explicit truncation pointers. Markdown exposes failed/partial/undated
  evidence and distinguishes no optional supplement from no machine evidence.
  Test byte-level hashes, relative filenames, preexisting-file collisions,
  failure cleanup and 0600 permissions; previous outputs remain unchanged.
- [ ] Run `uv run --locked pytest tests/test_review_export.py`
  `tests/test_report_manifest.py -q` as one command;
  expect FAIL.
- [ ] Implement shared projections, additive existing columns and new progress
  CSV/XLSX sheets. Generate XLSX content types/relationships from the table
  list rather than adding more hardcoded sheet counts. The manifest includes
  all final payload bytes, excluding itself. Validate all refs before writing.
- [ ] Rerun new tests and existing report/Web/progress tests; expect PASS.
- [ ] Review diff; conditional commit: `feat(report): 各形式の証拠参照と整合性を統一`.

### Task 8: Integrate offline/live paths and verify the whole workflow

**Files:** Modify `src/aws_security_audit/cli.py:308-334,342-438` and
`README.md` documentation routing; create `docs/evidence-traceable-reporting.md`
and `tests/test_reporting_workflow.py`.

**Interfaces:** Preserve the existing `assess` flags and exit codes. Add a new
offline `report-progress` command with required `--bundle PATH` (a local
`aws_web_review` JSON evidence bundle), optional `--classification PATH` (a
local classification JSON result), and `--out DIR` (default `reports`). It
reconstructs review data solely from these local files and writes the progress
JSON/CSV/XLSX exports and Markdown summary; it must not initialize AWS sessions,
load AWS credentials or make network calls. Return exit code `0` when export
succeeds with no unresolved requests, `2` when export succeeds but unresolved
requests remain, and `1` for invalid input or export failure. `assess` wraps
only existing collection in `capture_reads()`, attaches the ledger, builds one
review model and passes it to every exporter. Register `report-progress` in
`cli.py`'s parser and dispatch it in `main()` before `prepare()` so the offline
contract is enforced. Use optional keyword arguments when extending existing
export functions.

- [ ] Write parser/dispatch tests for `report-progress` flags and exit codes,
  including successful complete and unresolved exports, invalid local input,
  and export failure. Add a fake-context `assess --llm off` end-to-end test:
  expected old and new outputs exist and AWS operation sequence is unchanged.
  Repeat with `--llm export`: Web ledger/review equal the report's source model.
  Run `report-progress` with boto3 session creation and network calls patched
  to raise; require exit `0` for a valid complete legacy bundle, exit `2` for
  valid output with unresolved requests, and exit `1` for forged evidence.
  Assert no SDK call, source rewrite, or business-label upgrade.
- [ ] Run `uv run --locked pytest tests/test_reporting_workflow.py -q`; expect FAIL.
- [ ] Implement `report-progress` parser registration and `main()` dispatch
  before AWS preparation; integrate both offline `report-progress` and live
  `assess` paths. Document the command flags, exit codes, schema, field meanings,
  legacy limits, file relationships and a single offline example using relative
  private paths.
  Document partial failure and source-digest limits, not source attestation.
- [ ] Run `uv run --locked pytest -q`,
  `uv run --locked ruff check` on changed Python paths,
  `uv build`, `sha256sum --check docs/uv-lock.sha256`, and Markdown lint on
  changed Markdown. Expect all commands exit 0; use the existing CI Python
  3.12/3.13 matrix for cross-version verification. Fix only introduced failures.
- [ ] Inspect generated synthetic XLSX/Markdown for readable Japanese text,
  visible limits and working JSON pointers. Follow applicable visual-QA skill
  at execution time; do not upload private artifacts or launch live scans.
- [ ] Review diff; conditional commit: `feat(report): 証拠追跡レポートを既存CLIに統合`.

## Acceptance and Handoff

- Every original control is present with unchanged normative text and statuses.
- A reader can trace a claim to an actual source, applicable resource and
  collection outcome, or see exactly which provenance is unavailable.
- Failed/partial/unattempted searches are never presented as safe configuration
  or verified product-wide absence.
- Each remaining request names its evidence, scope and affected controls;
  evidence reuse does not prove an unrelated criterion.
- All output formats agree on references, statuses and pending reasons.
- Offline reporting needs neither AWS access nor an LLM connection.
- No private evidence, credentials, machine-specific paths or user edits enter
  committed changes. No AWS mutation or production-completion claim occurs.

Self-review mapping: evidence fields/states (Tasks 1–3), attribution (Task 4),
criterion/sufficiency/business separation (Task 5), residual questions (Task 6),
format parity/protection/hashes (Task 7), full CLI compatibility/offline proof
(Task 8). All five Review Focus conditions have named tests in their owner task.

Recommended execution after user review: **Subagent-driven**, because the
capture/adapter/model/export interfaces span eight independently reviewable
tasks and a silent scope or error-state mistake could mislead an audit reader.
The reviewer checks contracts and synthetic outputs, never live account state.
