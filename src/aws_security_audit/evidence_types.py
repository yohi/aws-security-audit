"""Versioned evidence ledger and control review types (v1).

Typed, JSON-serializable stdlib dataclasses shared by every evidence and
reporting task. The types hold only allowlisted projections: unknown values
are None (JSON null), never implicit false/zero/empty strings, and no
credential, token or raw SDK response field exists here. Sequences are
tuples and enums replace free strings; evidence_ledger.parse_ledger is the
strict file-input boundary that validates enums, types, UTC timestamps,
IDs, duplicates and references, and evidence_ledger.ledger_to_json
projects records back to plain JSON types.

Schemas: aws-security-evidence-ledger-v1 (parse target) and
aws-security-control-review-v1 (offline review). Region/account context is
always explicit; nothing is automatically attributed to a product.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import math
from typing import TypeAlias

LEDGER_SCHEMA = 'aws-security-evidence-ledger-v1'
REVIEW_SCHEMA = 'aws-security-control-review-v1'

# Execution attestation is structurally fixed; source_digest hashes input
# artifact bytes and is not provenance of effective no-write or ownership.
NOT_PROVEN = 'NOT_PROVEN'


class CollectionState(Enum):
    """Result of an attempted data collection against the real source."""

    OBSERVED = 'OBSERVED'
    VERIFIED_EMPTY = 'VERIFIED_EMPTY'
    NOT_CONFIGURED = 'NOT_CONFIGURED'
    ACCESS_DENIED = 'ACCESS_DENIED'
    FAILED = 'FAILED'
    PARTIAL = 'PARTIAL'
    NOT_ATTEMPTED = 'NOT_ATTEMPTED'
    LEGACY_UNKNOWN = 'LEGACY_UNKNOWN'


class CoverageState(Enum):
    """Selector coverage; never implies product-wide attribution."""

    VERIFIED_FOR_SELECTOR = 'VERIFIED_FOR_SELECTOR'
    PARTIAL = 'PARTIAL'
    UNKNOWN = 'UNKNOWN'


class ProvenanceLevel(Enum):
    """How the observed projection came to exist in the report flow."""

    COLLECTOR_PROJECTED = 'COLLECTOR_PROJECTED'
    LEGACY_SOURCE = 'LEGACY_SOURCE'
    OPERATOR_CURATED = 'OPERATOR_CURATED'
    ASSISTANT_CURATED = 'ASSISTANT_CURATED'


class ScannerStatus(Enum):
    """Original scanner verdicts are preserved verbatim, never regressed."""

    PASS = 'PASS'
    FAIL = 'FAIL'
    UNKNOWN = 'UNKNOWN'
    MANUAL_REVIEW = 'MANUAL_REVIEW'
    NOT_APPLICABLE = 'NOT_APPLICABLE'


class EvidenceState(Enum):
    """Machine-evidence sufficiency; not a business or compliance verdict."""

    NO_EVIDENCE = 'NO_EVIDENCE'
    PARTIAL = 'PARTIAL'
    CONFLICTING = 'CONFLICTING'
    SUPPORTED_FOR_DECLARED_SCOPE = 'SUPPORTED_FOR_DECLARED_SCOPE'


class CriterionState(Enum):
    """Per-criterion-component observation against the stated criterion."""

    OBSERVED_MATCH = 'OBSERVED_MATCH'
    OBSERVED_MISMATCH = 'OBSERVED_MISMATCH'
    UNRESOLVED = 'UNRESOLVED'
    CONFLICTING = 'CONFLICTING'


class GapKind(Enum):
    """Why evidence is still missing; drives request grouping by exact key."""

    COLLECTION = 'COLLECTION'
    ATTRIBUTION = 'ATTRIBUTION'
    CRITERION_INTERPRETATION = 'CRITERION_INTERPRETATION'
    MACHINE_EVIDENCE = 'MACHINE_EVIDENCE'
    OWNER_CONTEXT = 'OWNER_CONTEXT'
    REMEDIATION_STATUS = 'REMEDIATION_STATUS'
    OWNER_DOCUMENT = 'OWNER_DOCUMENT'


class BusinessResolutionState(Enum):
    """Existing classification contract states, unchanged by evidence work."""

    FINALIZED = 'FINALIZED'
    EVIDENCE_PENDING = 'EVIDENCE_PENDING'
    NOT_EVALUATED = 'NOT_EVALUATED'


# Normative four-label set; equals offline_classification.FINAL_LABELS.
BUSINESS_LABELS = frozenset({'対応済み', '未対応', '対応中', '対象外'})

# The five named review sheets rendered by the review export task.
SHEET_NAMES = (
    '46項目レビュー',
    '証拠索引',
    '取得状態',
    '対象範囲',
    '追加確認',
)

JsonValue: TypeAlias = (
    str | int | float | bool | None
    | list['JsonValue'] | dict[str, 'JsonValue']
)
JsonObject: TypeAlias = dict[str, JsonValue]


def strict_json_value(value: object, name: str, what: str) -> JsonValue:
    """Reject non-JSON values: sets, non-string keys, NaN/inf and similar."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        raise ValueError(f'{what}.{name}: non-finite number is not JSON')
    if isinstance(value, list):
        return [strict_json_value(item, name, what) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key: strict_json_value(child, name, what)
                for key, child in value.items()}
    raise ValueError(f'{what}.{name}: value is not strict JSON')


@dataclass(frozen=True)
class Execution:
    """One logical scan run; identity includes a once-per-run UUID input."""

    id: str
    source_kind: str
    account: str
    regions: tuple[str, ...]
    product: str | None
    started_at: str | None
    finished_at: str | None
    source_digest: str | None
    attestation: str


@dataclass(frozen=True)
class CallRecord:
    """Metadata-only projection of one logical API call and its pages."""

    id: str
    execution_id: str
    service: str
    operation: str
    region: str | None
    safe_selector: dict[str, JsonValue]
    started_at: str | None
    finished_at: str | None
    collection_state: CollectionState
    error_code: str | None
    page_count: int | None
    pagination_complete: bool | None
    returned_count: int | None


@dataclass(frozen=True)
class EvidenceFact:
    """One observed source field with interpreted meaning and limits."""

    id: str
    execution_id: str
    call_refs: tuple[str, ...]
    source_ref: str
    number: int
    resource_key: str | None
    field_path: str
    field_present: bool
    value: JsonValue
    interpretation: str
    scope_limit: str
    observed_at: str | None
    provenance_level: ProvenanceLevel


@dataclass(frozen=True)
class ScopeCheck:
    """What the selector searched, what matched and what stayed unknown."""

    id: str
    execution_id: str
    service: str
    selector_basis: str
    call_refs: tuple[str, ...]
    selected_resource_keys: tuple[str, ...]
    candidate_resource_keys: tuple[str, ...]
    coverage_state: CoverageState
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceLedger:
    """Root ledger; parse_ledger is the strict boundary for this shape."""

    schema: str
    executions: tuple[Execution, ...]
    calls: tuple[CallRecord, ...]
    facts: tuple[EvidenceFact, ...]
    scope_checks: tuple[ScopeCheck, ...]


@dataclass(frozen=True)
class CriterionCheck:
    """One component of a control's stated criterion under reconciliation."""

    id: str
    component: str
    state: CriterionState
    fact_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]
    limitation: str | None


@dataclass(frozen=True)
class EvidenceGap:
    """A stable remaining question: kind plus scope plus requirement key."""

    id: str
    kind: GapKind
    scope_key: str
    requirement_key: str
    controls: tuple[int, ...]
    evidence_refs: tuple[str, ...]
    required_evidence: str
    acquisition_route: str


@dataclass(frozen=True)
class EvidenceRequest:
    """Deduplicated outstanding evidence request keyed exactly like gaps."""

    id: str
    kind: GapKind
    scope_key: str
    requirement_key: str
    controls: tuple[int, ...]
    evidence_refs: tuple[str, ...]
    required_evidence: str
    acquisition_route: str


@dataclass(frozen=True)
class ControlReviewRow:
    """One of the 46 controls with catalog text plus evidence projections."""

    number: int
    category: str
    title: str
    criterion: str
    severity: str
    purpose: str
    scanner_status: ScannerStatus
    scanner_regional_status: dict[str, ScannerStatus]
    fact_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]
    criterion_checks: tuple[CriterionCheck, ...]
    evidence_state: EvidenceState
    gaps: tuple[EvidenceGap, ...]
    request_ids: tuple[str, ...]
    business_resolution_state: BusinessResolutionState
    business_label_provisional: str | None
    owner_adoption_verified: bool


@dataclass(frozen=True)
class ControlReview:
    """46 ordered rows plus deduplicated outstanding evidence requests."""

    schema: str
    rows: tuple[ControlReviewRow, ...]
    requests: tuple[EvidenceRequest, ...]


@dataclass(frozen=True)
class ReviewTable:
    """One named sheet: headers plus rows of JSON scalar cells."""

    headers: tuple[str, ...]
    rows: tuple[tuple[JsonValue, ...], ...]


@dataclass(frozen=True)
class ReviewTables:
    """All export tables keyed by their sheet names in SHEET_NAMES."""

    schema: str
    tables: dict[str, ReviewTable]
