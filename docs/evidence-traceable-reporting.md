# Evidence-traceable reporting contract

This page documents the evidence-first progress reporting added around the
existing 46-control audit CLI: the offline `report-progress` command, the
shared evidence ledger / control review model that `assess` now exports, and
the limits that keep every export honest. It is descriptive documentation of
the implemented contract, not an approval to run audits against production,
and it never claims an AWS mutation or a compliance certification.

All file names in this document are relative private paths; every export is
written with `0600` permissions on POSIX.

## Scope and invariants

- Original 46-control scanner verdicts (`判定`) are preserved verbatim. No
  export rewrites, upgrades or uplifts them, and business four-state labels
  are applied only when a submitted classification candidate explicitly
  contains them (`business_label_provisional`).
- `EFFECTIVE_NO_WRITE=NOT_PROVEN` and semantic-compliance-everywhere false:
  no output in this feature proves authorization, ownership, product-wide
  compliance or otherwise.
- Machine evidence is per-resource, partial and scope-limited: an observed
  `PROPERTY_OK` on one resource is not an account-wide or product-wide PASS.
- Failed, partial, access-denied and unattempted collections stay visible as
  not-observed; absence of data is never rendered as safe configuration.
- All formats (JSON, CSV, XLSX, Markdown, Web attachment) render the same
  references, statuses and pending reasons from one shared model.

## `report-progress` (offline)

Rebuilds the progress report from saved local files only. It runs after
collection, never calls AWS, never initializes a boto3 session, never loads
AWS credentials and never touches the network; it requires neither an AWS
connection nor an LLM connection.

Flags:

- `--bundle PATH` (required): local `aws_web_review` JSON evidence bundle
  (`schema: aws-security-audit-web-review-v1`) produced by a previous
  `assess` run.
- `--classification PATH`: local R21 offline classification JSON candidate
  (v1 or v2 schema, matching the bundle's `decision_support` contract).
  Optional.
- `--r24 PATH`: optional saved R24 operator-read targeted-evidence JSON;
  requires `--account`.
- `--mcp-summary PATH`: optional operator/assistant-curated MCP read-only
  summary JSON; requires `--account`.
- `--account VALUE`: expected account bound to supplemental R24/MCP
  evidence.
- `--out DIR`: private output directory, default `reports`; existing files
  are never overwritten.

Exit codes:

- `0` — export succeeded and `outstanding_evidence_requests` is empty:
  the review model has no unresolved evidence requests left.
- `2` — export succeeded, but unresolved requests remain:
  `outstanding_evidence_requests` is non-empty. This is request-based,
  not classification-based: pending `EVIDENCE_PENDING` rows in a submitted
  classification are reported data (`summary.evidence_pending_controls`),
  never the exit condition — pending evidence is not a fifth business
  label nor a count of human tasks. In this milestone every valid
  46-control bundle carries by-construction requests (Owner/criterion
  questions for `#5`/`#18`/`#45` and the shared
  `#2/#17/#20/#23` `product-resource-and-region-coverage` question) even
  when all machine gaps are satisfied, so a successful export normally
  exits `2`; exit `0` requires an empty request set.
- `1` — invalid local input (missing/garbled files, forged or inconsistent
  bundle, rejected classification) or export failure. Nothing is left
  partially written: reference validation happens before any file is
  created, and a failed write removes only the files created by that
  invocation.

Additional optional supplement flags (R24 / MCP summary) work offline as
well; they must be consistent with the bundle product/region and, when
supplied, with `--account`.

## What `assess` exports now

`assess` keeps all existing flags and exit codes. Its behavior additions:

1. Existing collection (the 46-control scan for account scope, or the
   product inventory + observations for product scope, plus `#5/#19`
   investigation) runs inside a passive `capture_reads()` side-channel. No
   additional AWS API call is added; each logical read call is projected into
   a metadata-only `CallRecord` (service, operation, region, safe selector,
   timing, collection state, paging state). Selectors never include
   credential/token-like data.
2. The recorded calls join the evidence ledger (`evidence_ledger`), keeping
   walk named in the ledger can never silently become `verified absence`.
3. One criterion-aware review model (`control_review`, exactly 46 rows) is
   built from the same bundle + ledger and passed to every exporter:
   - `aws_security_audit_*.json/csv/xlsx` gain additive audit columns
     (`証拠充足状態`, `証拠参照ID`, `対象範囲参照ID`, `未確定理由`,
     `追加確認ID`); scanner verdict columns are untouched.
   - `aws_web_review_*.json` embeds the same `evidence_ledger` and
     `control_review` projections additively, so a Web consumer sees
     identical references and statuses. `--llm` only controls whether the
     Web handoff files are written; `aws_web_prompt_*.md` is still a local
     copy/paste prompt and no LLM API is called.
   - `aws_evidence_progress_<stamp>.json/md/csv/xlsx` and
     `aws_evidence_progress_<stamp>.manifest.json` are the same progress set
     the offline command writes (JSON + MD originally; the CSV, XLSX and
     manifest are new).

## Schemas and field meanings

Identifiers are deterministic: `kind prefix + SHA-256 of canonical identity
JSON` (for example `fact:...`, `call:...`, `scope:...`, `check:...`,
`gap:...`, `request:...`).
Live execution identity includes a UUID generated once per run; derived record
IDs remain stable within that execution, while separate runs do not merge.

### `aws-security-evidence-ledger-v1` (`evidence_ledger`)

- `executions[]`: `id`, `source_kind` (e.g. `legacy_bundle_v1`,
  `live_capture_v1`), `account`, `regions`, optional `product`,
  `started_at/finished_at` (may be absent), `source_digest`, and
  `attestation` (always `NOT_PROVEN`).
- `calls[]`: one executed read (`collection_state` among `OBSERVED`,
  `VERIFIED_EMPTY`, `NOT_CONFIGURED`, `ACCESS_DENIED`, `FAILED`, `PARTIAL`,
  `NOT_ATTEMPTED`, `LEGACY_UNKNOWN`), `error_code` (symbolic only),
  `page_count`, `pagination_complete`, `returned_count`. Pagination is
  metadata only: one logical walk is one record.
- `facts[]`: one observed source field (`number` 1–46, `field_path`,
  `field_present`, strict-JSON `value`, `interpretation`, `scope_limit`,
  optional `observed_at`, `provenance_level`, `source_ref`, `call_refs`).
  `provenance_level` is `COLLECTOR_PROJECTED` (projected by this tool),
  `LEGACY_SOURCE` (reused bundle data without fresh capture), or
  `OPERATOR_CURATED` / `ASSISTANT_CURATED` (explicit supplemental summaries;
  curated material can never auto-satisfy a machine criterion).
- `scope_checks[]`: selector/account-scope diagnostics and collection-coverage
  limits from captured calls. They distinguish selected resource keys from
  unclassified name/ID candidates, and include `selector_basis`, `call_refs`,
  `coverage_state` (`VERIFIED_FOR_SELECTOR` / `PARTIAL` / `UNKNOWN`) and
  `limitations`. Candidate keys are hints, not attribution; failed, partial or
  filtered-empty calls never prove complete coverage. The inventory scope also
  carries `scope_candidate_resource_keys` for consistency checking; those keys
  still do not establish ownership or completeness.

### `aws-security-control-review-v1` (`control_review`)

- 46 `rows[]` with the normative criterion, `scanner_status` verbatim,
  regional scanner statuses, `evidence_state`
  (`NO_EVIDENCE` / `PARTIAL` / `CONFLICTING` / `SUPPORTED_FOR_DECLARED_SCOPE`
  — the last requires collector-projected evidence inside the declared
  scope), criterion `checks[]` (`OBSERVED_MATCH` / `OBSERVED_MISMATCH` /
  `UNRESOLVED` / `CONFLICTING` per component), `gaps[]`, and
  `request_ids[]`.
- `business_resolution_state` / `business_label_provisional` mirror only a
  submitted classification draft; without one they are `NOT_EVALUATED` and
  null, and `owner_adoption_verified` stays `false`.
- `requests[]`: the residual evidence requests deduplicated by the exact
  key `(kind, scope_key, requirement_key)`. `kind` is one of
  `COLLECTION`, `ATTRIBUTION`, `CRITERION_INTERPRETATION`, `MACHINE_EVIDENCE`,
  `OWNER_CONTEXT`, `REMEDIATION_STATUS`, `OWNER_DOCUMENT`; `scope_key`
  separates account-scope from product-scope requests so evidence reuse can
  never resolve an unrelated criterion. Each request names affected controls,
  the required evidence and an acquisition route that is a hint, never an
  executed task.

### `aws-security-evidence-progress-v1` (progress JSON)

Per control: `scanner_status`, `machine_evidence_level`
(`SCOPED_NEGATIVE_OBSERVATION`, `PARTIAL_POSITIVE_OBSERVATION`,
`CROSS_CONTROL_MACHINE_CONTEXT`, `MACHINE_CONTEXT_OR_UNKNOWN`,
`NO_PROPERTY_OBSERVATION`), `property_observation_counts`
(ok/fail/unknown/context), `source_observation_refs` (JSON pointers into the
bundle's `resource_inventory.control_observations.rows[]`), the
`acquisition_route` plan (e.g. `AWS_READ_ONLY_CANDIDATE`,
`AWS_PLUS_OWNER_SCOPE`, `NON_AWS_EXPORT_CANDIDATE`,
`OWNER_DOCUMENTATION`), and the classification draft linkage as above.

### Review tables and manifest

- `aws-security-review-tables-v1`: one projection into five sheets
  (`46項目レビュー`, `証拠索引`, `取得状態`, `対象範囲`, `追加確認`).
  The CSV is the 46-row review sheet; the XLSX holds all five sheets.
  JSON stays authoritative: long values are truncated in cells with an
  explicit pointer to the JSON export.
- `aws-security-export-manifest-v1`: SHA-256 and byte size for every payload
  file of one export set (the manifest excludes itself), plus the input
  artifact digests described below.

## File relationships

```text
assess (live)
  collection --capture_reads--> calls ┐
  bundle─────┐                        ├─> evidence_ledger ─┐
             └─> control_review ─────┴────────────────────┤
                 ├── aws_security_audit_*.{json,csv,xlsx}  (additive columns)
                 ├── aws_evidence_progress_<stamp>.{json,md,csv,xlsx}
                 │     + aws_evidence_progress_<stamp>.manifest.json
                 └── aws_web_review_*.json (+ aws_web_prompt_*.md when --llm export)

report-progress (offline)
  saved bundle (+optional classification/R24/MCP)
    └─> same evidence_ledger / control_review ─> same progress set
```

The Web attachment's `evidence_ledger` and `control_review` are byte-equal
JSON projections of what the progress report used as its source model.

## Offline example

```bash
# Rebuild the progress report for a previously saved evidence bundle and
# the LLM's classification candidate; no AWS access, no LLM connection.
uv run --locked --no-sync aws-security-audit report-progress \
  --bundle './reports/aws_web_review_20261019.json' \
  --classification './reports/labels/classification-candidate.json' \
  --out './reports/progress'
```

Expected stdout prints the progress summary counts and each written file
path. The exit code reflects the review model's
`outstanding_evidence_requests` (non-empty → `2` for any real bundle in
this milestone, since the by-construction Owner/criterion questions are
always listed); a pending classification is only reported data, so
operators should process the request list itself rather than hunt for
exit `0`.

## Limitations

- **Legacy projection limits.** Legacy bundle rows carry no API operation.
  Current observation rows include an `api` field when the producing operation
  is known; a call joins only when service, operation, region, and resource or
  ARN selector match unambiguously. Rows without operation metadata use the
  legacy service/region/resource match, and ambiguous rows remain unjoined.
  Legacy facts have no `observed_at`; their provenance is explicitly
  `LEGACY_SOURCE`, never collector-grade.
- **Partial failure.** If any export fails, the command exits `1`, leaves
  the previous outputs untouched and removes only the incomplete files from
  that invocation. Validation (schema, references, model/JSON equality)
  runs before the output directory is created.
- **Source-digest limits.** The manifest hashes the exact exported payload
  bytes. `execution.source_digest` hashes the UTF-8 bytes of the input artifact's
  canonical JSON representation (sorted keys and compact separators), so JSON
  whitespace and key order do not change it. These hashes do not attest that any
  collection, approval or claim is true, and the ledger `attestation` stays
  `NOT_PROVEN` everywhere.
- Embedded `evidence_ledger` and `control_review` extensions are structurally
  parsed and checked against the base bundle's digest and source observations.
  Bundles are unsigned local files, so these checks detect inconsistency, not
  authenticity; treat their contents as untrusted evidence. Embedded call
  records are unsigned metadata too: operation/selector matching checks
  consistency, not that the API request actually occurred.
- **Exit-code semantics.** `report-progress` exit `0` means "exported,
  `outstanding_evidence_requests` empty"; exit `2` means the export
  succeeded but unresolved evidence requests remain (a repeat-work
  marker, not an error). Classification pending rows are reported inside
  the payloads on both paths and are never the exit condition.
- **Integrity hashes are not provenance**, and Markdown/CSV/XLSX summaries
  must not be treated as substitutes for the authoritative JSON.
