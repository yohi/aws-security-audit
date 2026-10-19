from __future__ import annotations

from enum import Enum
from typing import TypeVar

from .evidence_types import (
    BusinessResolutionState,
    ControlReview,
    ControlReviewRow,
    CriterionCheck,
    CriterionState,
    EvidenceGap,
    EvidenceRequest,
    EvidenceState,
    GapKind,
    JsonValue,
    REVIEW_SCHEMA,
    ScannerStatus,
)

_Enum = TypeVar('_Enum', bound=Enum)


def _fields(value: JsonValue, expected: set[str]) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError('Control review object has invalid fields')
    return value


def _text(value: JsonValue, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f'Control review field {name} must be a string')
    return value


def _nullable_text(value: JsonValue, name: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f'Control review field {name} must be a string or null')
    return value


def _boolean(value: JsonValue, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f'Control review field {name} must be a boolean')
    return value


def _integer(value: JsonValue, name: str) -> int:
    if type(value) is not int:
        raise ValueError(f'Control review field {name} must be an integer')
    return value


def _enum(enum_type: type[_Enum], value: JsonValue, name: str) -> _Enum:
    raw = _text(value, name)
    try:
        return enum_type(raw)
    except ValueError as exc:
        raise ValueError(f'Control review field {name} has an invalid value') from exc


def _text_tuple(value: JsonValue, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f'Control review field {name} must be an array')
    return tuple(_text(item, name) for item in value)


def _integer_tuple(value: JsonValue, name: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ValueError(f'Control review field {name} must be an array')
    return tuple(_integer(item, name) for item in value)


def _enum_map(
    enum_type: type[_Enum], value: JsonValue, name: str,
) -> dict[str, _Enum]:
    if not isinstance(value, dict):
        raise ValueError(f'Control review field {name} must be an object')
    return {
        _text(key, name): _enum(enum_type, item, name)
        for key, item in value.items()
    }


def _parse_criterion_check(value: JsonValue) -> CriterionCheck:
    row = _fields(value, {
        'id', 'component', 'state', 'fact_refs', 'scope_refs', 'limitation',
    })
    return CriterionCheck(
        id=_text(row['id'], 'id'),
        component=_text(row['component'], 'component'),
        state=_enum(CriterionState, row['state'], 'state'),
        fact_refs=_text_tuple(row['fact_refs'], 'fact_refs'),
        scope_refs=_text_tuple(row['scope_refs'], 'scope_refs'),
        limitation=_nullable_text(row['limitation'], 'limitation'),
    )


def _parse_gap(value: JsonValue) -> EvidenceGap:
    row = _fields(value, {
        'id', 'kind', 'scope_key', 'requirement_key', 'controls',
        'evidence_refs', 'required_evidence', 'acquisition_route',
    })
    return EvidenceGap(
        id=_text(row['id'], 'id'),
        kind=_enum(GapKind, row['kind'], 'kind'),
        scope_key=_text(row['scope_key'], 'scope_key'),
        requirement_key=_text(row['requirement_key'], 'requirement_key'),
        controls=_integer_tuple(row['controls'], 'controls'),
        evidence_refs=_text_tuple(row['evidence_refs'], 'evidence_refs'),
        required_evidence=_text(row['required_evidence'], 'required_evidence'),
        acquisition_route=_text(row['acquisition_route'], 'acquisition_route'),
    )


def _parse_request(value: JsonValue) -> EvidenceRequest:
    row = _fields(value, {
        'id', 'kind', 'scope_key', 'requirement_key', 'controls',
        'evidence_refs', 'required_evidence', 'acquisition_route',
    })
    return EvidenceRequest(
        id=_text(row['id'], 'id'),
        kind=_enum(GapKind, row['kind'], 'kind'),
        scope_key=_text(row['scope_key'], 'scope_key'),
        requirement_key=_text(row['requirement_key'], 'requirement_key'),
        controls=_integer_tuple(row['controls'], 'controls'),
        evidence_refs=_text_tuple(row['evidence_refs'], 'evidence_refs'),
        required_evidence=_text(row['required_evidence'], 'required_evidence'),
        acquisition_route=_text(row['acquisition_route'], 'acquisition_route'),
    )


def _parse_row(value: JsonValue) -> ControlReviewRow:
    row = _fields(value, {
        'number', 'category', 'title', 'criterion', 'severity', 'purpose',
        'scanner_status', 'scanner_regional_status', 'fact_refs', 'scope_refs',
        'criterion_checks', 'evidence_state', 'gaps', 'request_ids',
        'business_resolution_state', 'business_label_provisional',
        'owner_adoption_verified',
    })
    checks = row['criterion_checks']
    gaps = row['gaps']
    if not isinstance(checks, list) or not isinstance(gaps, list):
        raise ValueError('Control review checks and gaps must be arrays')
    return ControlReviewRow(
        number=_integer(row['number'], 'number'),
        category=_text(row['category'], 'category'),
        title=_text(row['title'], 'title'),
        criterion=_text(row['criterion'], 'criterion'),
        severity=_text(row['severity'], 'severity'),
        purpose=_text(row['purpose'], 'purpose'),
        scanner_status=_enum(ScannerStatus, row['scanner_status'], 'scanner_status'),
        scanner_regional_status=_enum_map(
            ScannerStatus, row['scanner_regional_status'], 'scanner_regional_status'),
        fact_refs=_text_tuple(row['fact_refs'], 'fact_refs'),
        scope_refs=_text_tuple(row['scope_refs'], 'scope_refs'),
        criterion_checks=tuple(_parse_criterion_check(item) for item in checks),
        evidence_state=_enum(EvidenceState, row['evidence_state'], 'evidence_state'),
        gaps=tuple(_parse_gap(item) for item in gaps),
        request_ids=_text_tuple(row['request_ids'], 'request_ids'),
        business_resolution_state=_enum(
            BusinessResolutionState, row['business_resolution_state'],
            'business_resolution_state'),
        business_label_provisional=_nullable_text(
            row['business_label_provisional'], 'business_label_provisional'),
        owner_adoption_verified=_boolean(
            row['owner_adoption_verified'], 'owner_adoption_verified'),
    )


def parse_control_review(value: JsonValue) -> ControlReview:
    """Parse the exact v1 schema and reject malformed field types."""
    row = _fields(value, {'schema', 'rows', 'requests'})
    if _text(row['schema'], 'schema') != REVIEW_SCHEMA:
        raise ValueError('Invalid control review schema')
    raw_rows, raw_requests = row['rows'], row['requests']
    if not isinstance(raw_rows, list) or not isinstance(raw_requests, list):
        raise ValueError('Control review rows and requests must be arrays')
    rows = tuple(_parse_row(item) for item in raw_rows)
    if tuple(item.number for item in rows) != tuple(range(1, 47)):
        raise ValueError('Control review must contain the ordered 46 controls')
    return ControlReview(
        schema=REVIEW_SCHEMA,
        rows=rows,
        requests=tuple(_parse_request(item) for item in raw_requests),
    )
