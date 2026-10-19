"""Residual evidence request deduplication over the control review model.

Consumes a criterion-aware ControlReview whose rows still carry unresolved
EvidenceGap questions and returns deduplicated EvidenceRequest records
grouped by the exact key (kind, scope_key, requirement_key). Grouping is
never by free-text similarity: the same question asked once for several
controls becomes one request, and evidence observed under another scope
key can never resolve or absorb a different scope's gap. Only validated
observations satisfying the same scope may remove a machine gap
(is_observation_fact gates suppression in the review builder).

Requests belong to the review model only; they are never part of the R21
classification schema or validation contract. Acquisition routes stay
hints, never executed tasks or additional prerequisites beyond the
original criterion: a merged cross-control request's route/text states a
shared hint, not a per-control prerequisite. When merged gaps disagree on
descriptive texts, the lexicographically smallest hint is retained so
repeated builds stay byte-identical.
"""
from __future__ import annotations

from dataclasses import asdict, replace

from .evidence_ledger import _plain as _plain_json, evidence_id
from .evidence_types import (REVIEW_SCHEMA, ControlReview, ControlReviewRow,
                             EvidenceFact, EvidenceGap, EvidenceRequest,
                             GapKind, JsonValue, ProvenanceLevel)
from .offline_classification import ROUTES


def _reachable_refs(rows: tuple[ControlReviewRow, ...]) -> set[str]:
    refs = set()
    for row in rows:
        refs.update(row.fact_refs)
        refs.update(row.scope_refs)
        for check in row.criterion_checks:
            refs.update(check.fact_refs)
            refs.update(check.scope_refs)
    return refs


def is_observation_fact(fact: EvidenceFact) -> bool:
    """True only for a validated observation able to close machine gaps.

    Provenance must be collector-projected, legacy or operator-curated: an
    assistant-curated MCP row stays an arbitrary LLM claim. R24 and MCP
    supplements additionally need an observed/verified underlying state;
    NOT_REQUESTED, UNVERIFIED (or absent fields) never count as a machine
    observation for the control's original criterion.
    """
    projected = (ProvenanceLevel.COLLECTOR_PROJECTED,
                 ProvenanceLevel.LEGACY_SOURCE,
                 ProvenanceLevel.OPERATOR_CURATED)
    if not fact.field_present or fact.provenance_level not in projected:
        return False
    state = fact.value.get('state') if isinstance(fact.value, dict) else None
    ref = fact.source_ref
    if isinstance(ref, str) and ref.startswith('r24_targeted_evidence.'):
        return state in ('OBSERVED', 'OBSERVED_PARTIAL', 'VERIFIED')
    if isinstance(ref, str) and ref.startswith('mcp_summary.records'):
        return state == 'OBSERVED'
    return True


def _validate_gap(gap: EvidenceGap, number: int, allowed: set[str]) -> None:
    if not isinstance(gap, EvidenceGap):
        raise ValueError('review row gaps: expected an EvidenceGap record')
    if gap.controls != (number,):
        raise ValueError(
            f"gap {gap.id!r}: forged control attribution for #{number}")
    if not isinstance(gap.scope_key, str) or not gap.scope_key.strip():
        raise ValueError(f"gap {gap.id!r}: scope_key must be a nonempty str")
    if not isinstance(gap.requirement_key, str) or not gap.requirement_key.strip():
        raise ValueError(
            f"gap {gap.id!r}: requirement_key must be a nonempty str")
    if not isinstance(gap.kind, GapKind):
        raise ValueError(f"gap {gap.id!r}: unknown gap kind")
    if gap.acquisition_route not in ROUTES:
        raise ValueError(f"gap {gap.id!r}: unknown acquisition route")
    if not isinstance(gap.required_evidence, str) or not gap.required_evidence.strip():
        raise ValueError(
            f"gap {gap.id!r}: required_evidence must be a nonempty str")
    if len(set(gap.evidence_refs)) != len(gap.evidence_refs):
        raise ValueError(f"gap {gap.id!r}: duplicated evidence reference")
    fabricated = [ref for ref in gap.evidence_refs if ref not in allowed]
    if fabricated:
        raise ValueError(
            f"gap {gap.id!r}: fabricated evidence reference {fabricated[0]!r}")


def build_evidence_requests(review: ControlReview) -> tuple[EvidenceRequest, ...]:
    """Deduplicate all outstanding gaps into exact-key grouped requests."""
    if not isinstance(review, ControlReview):
        raise ValueError('build_evidence_requests expects a ControlReview')
    if review.schema != REVIEW_SCHEMA:
        raise ValueError(f'Unsupported control review schema {review.schema!r}')
    allowed = _reachable_refs(review.rows)
    groups: dict[tuple[str, str, str], dict[str, object]] = {}
    seen_gap_ids: set[str] = set()
    for row in review.rows:
        for gap in row.gaps:
            _validate_gap(gap, row.number, allowed)
            if gap.id in seen_gap_ids:
                raise ValueError(f'gap {gap.id!r}: duplicated across rows')
            seen_gap_ids.add(gap.id)
            key = (gap.kind.value, gap.scope_key, gap.requirement_key)
            entry = groups.setdefault(
                key, {'controls': set(), 'refs': [], 'routes': [],
                      'required': []})
            entry['controls'].add(row.number)
            for ref in gap.evidence_refs:
                if ref not in entry['refs']:
                    entry['refs'].append(ref)
            if gap.acquisition_route not in entry['routes']:
                entry['routes'].append(gap.acquisition_route)
            if gap.required_evidence not in entry['required']:
                entry['required'].append(gap.required_evidence)
    return tuple(
        EvidenceRequest(
            id=evidence_id('request', {'kind': kind, 'scope': scope,
                                       'requirement': requirement}),
            kind=GapKind(kind), scope_key=scope, requirement_key=requirement,
            controls=tuple(sorted(groups[key]['controls'])),
            evidence_refs=tuple(groups[key]['refs']),
            required_evidence=min(groups[key]['required']),
            acquisition_route=min(groups[key]['routes']),
        )
        for key in sorted(groups, key=lambda item: (item[1], item[0], item[2]))
        for kind, scope, requirement in (key,)
    )


def with_evidence_requests(review: ControlReview) -> ControlReview:
    """Return a new review whose rows and requests carry request IDs.

    build_control_review leaves requests empty; the review-model wiring
    for the progress report attaches them here without rewriting gaps.
    """
    requests = build_evidence_requests(review)
    ids_per_row: dict[int, list[str]] = {}
    for request in requests:
        for number in request.controls:
            ids_per_row.setdefault(number, []).append(request.id)
    rows = tuple(
        replace(row, request_ids=tuple(ids_per_row.get(row.number, [])))
        for row in review.rows
    )
    return replace(review, rows=rows, requests=requests)


def request_to_json(request: EvidenceRequest) -> dict[str, JsonValue]:
    """Project one typed request back to plain JSON values."""
    if not isinstance(request, EvidenceRequest):
        raise ValueError('request_to_json expects an EvidenceRequest')
    return _plain_json(asdict(request))
