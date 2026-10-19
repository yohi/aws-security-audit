from __future__ import annotations

from .control_review import build_control_review, control_review_to_json
from .control_review_parser import parse_control_review
from .evidence_requests import with_evidence_requests
from .evidence_types import ControlReview, EvidenceLedger, JsonObject


def review_for_bundle(
    bundle: JsonObject, ledger: EvidenceLedger,
    classification: JsonObject | None,
) -> ControlReview:
    """Parse and cross-check an embedded review, or project a fresh review."""
    embedded = bundle.get('control_review')
    if embedded is not None:
        review = parse_control_review(embedded)
        expected = with_evidence_requests(build_control_review(bundle, ledger, None))
        if control_review_to_json(review) != control_review_to_json(expected):
            raise ValueError('Embedded control_review does not match the bundle')
        if classification is None:
            return review
    return with_evidence_requests(
        build_control_review(bundle, ledger, classification))
