from __future__ import annotations

from .control_review import build_control_review, control_review_to_json
from .control_review_parser import parse_control_review
from .evidence_requests import with_evidence_requests
from .evidence_types import ControlReview, EvidenceLedger, JsonObject


def review_for_bundle(
    bundle: JsonObject, ledger: EvidenceLedger,
    classification: JsonObject | None,
    *, base_ledger: EvidenceLedger | None = None,
    supplements_supplied: bool = False,
) -> ControlReview:
    """Parse and cross-check an embedded review, or project a fresh review."""
    embedded = bundle.get('control_review')
    if embedded is not None:
        review = parse_control_review(embedded)
        validation_ledger = base_ledger or ledger
        expected = with_evidence_requests(
            build_control_review(bundle, validation_ledger, None))
        if control_review_to_json(review) != control_review_to_json(expected):
            raise ValueError('Embedded control_review does not match the bundle')
        if classification is None and not supplements_supplied:
            return review
    return with_evidence_requests(
        build_control_review(bundle, ledger, classification))
