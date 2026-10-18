"""Versioned R21 offline output contract: one request registry and bound proof claims.

This validator proves only structural consistency and source-ID integrity.
It does not evaluate natural-language factual accuracy, Owner approval or
live AWS status. No AWS credentials, HTTP or automatic uploads are used.
"""
from __future__ import annotations

import re
from collections import Counter

REQUEST_CHANNELS = frozenset({
    'AWS_LOCAL_READ_ONLY', 'NON_AWS_MACHINE_EXPORT', 'OWNER_CONFIRMATION',
})
REQUEST_ID_PATTERN = re.compile(r'[a-z][a-z0-9:._-]{2,95}\Z')
SHARED_SCOPE_ID = 'scope:product-resource-and-region-coverage'
SHARED_SCOPE_CONTROLS = frozenset((2, 17, 20, 23))

_OUTPUT_CONTRACT = {
    'schema': 'aws-security-classification-output-contract-v2',
    'classification_schema': 'aws-security-offline-classification-v1',
    'label_count_location': 'summary.<one_of_the_four_Japanese_labels>',
    'nested_classifications_counts_allowed': False,
    'requires': [
        'root_evidence_requests', 'per_row_missing_evidence_request_ids',
        'per_row_evidence_claims', 'claim_evidence_binding',
        'distinct_action_count_summary',
    ],
    'request_channels': sorted(REQUEST_CHANNELS),
    'shared_scope_request_id': SHARED_SCOPE_ID,
    'semantic_verification': 'NOT_PROVEN_BY_STRUCTURAL_VALIDATION',
}


def output_contract() -> dict:
    return dict(_OUTPUT_CONTRACT)


def validate_r21_result(bundle: dict, result: dict) -> dict:
    """Validate R21-only fields; invoke after legacy 46-row/source checks.

    Root requests are *not* accepted as evidence of actual compliance.
    One shared ROS scope request must cover all still-pending scope controls.
    """
    support = bundle['decision_support']
    if support.get('output_contract') != output_contract():
        raise ValueError('R21 output contract altered or omitted')
    summary = result.get('summary')
    if not isinstance(summary, dict) or 'classifications' in summary:
        raise ValueError('Business counts must be direct summary fields')
    rows = result['controls']
    pending = {r['number'] for r in rows if r['resolution_state'] == 'EVIDENCE_PENDING'}
    requests = result.get('evidence_requests')
    if not isinstance(requests, list):
        raise ValueError('R21 root evidence_requests must be a list')
    by_id = {}
    normalized_text = set()
    counts = Counter()
    for req in requests:
        if not isinstance(req, dict):
            raise ValueError('Invalid request object')
        rid = req.get('id')
        channel = req.get('acquisition_channel')
        controls = req.get('applies_to_controls')
        artifact = req.get('requested_artifact')
        if (not isinstance(rid, str) or not REQUEST_ID_PATTERN.fullmatch(rid)
                or rid in by_id or channel not in REQUEST_CHANNELS
                or not isinstance(controls, list) or not controls
                or any(type(n) is not int for n in controls)
                or controls != sorted(set(controls))
                or not set(controls) <= pending
                or not isinstance(artifact, str) or len(artifact.strip()) < 12
                or req.get('status') != 'REQUESTED_NOT_FULFILLED'):
            raise ValueError('Invalid or duplicate evidence request / scope')
        canonical = ' '.join(artifact.split()).casefold()
        if canonical in normalized_text:
            raise ValueError('Duplicate actionable evidence request text')
        normalized_text.add(canonical)
        by_id[rid] = req
        counts[channel] += 1

    if 'evidence_requests' not in result or not requests and pending:
        raise ValueError('Pending controls need actionable deduplicated requests')

    for row in rows:
        number = row['number']
        used = row.get('missing_evidence_request_ids')
        claims = row.get('evidence_claims')
        if (not isinstance(used, list) or len(used) != len(set(
                x for x in used if isinstance(x, str)))
                or any(not isinstance(x, str) for x in used)
                or not isinstance(claims, list)):
            raise ValueError(f'R21 #{number} request/claim arrays missing or invalid')
        expected = {rid for rid, req in by_id.items()
                    if number in req['applies_to_controls']}
        if set(used) != expected:
            raise ValueError(f'R21 #{number} request binding mismatches root request index')
        if (number in pending and not used
                or number not in pending and used):
            raise ValueError(f'R21 #{number} incorrect pending request linkage')
        source_refs = set(row['evidence_refs'])
        claim_refs = set()
        used_fact_codes = set()
        facts = support['plans'][number - 1]['evidence_reconciliation']['verified_facts']
        for claim in claims:
            if not isinstance(claim, dict):
                raise ValueError(f'R21 #{number} invalid claim')
            refs = claim.get('evidence_refs')
            if (not isinstance(claim.get('claim'), str)
                    or not claim['claim'].strip()
                    or not isinstance(refs, list) or not refs
                    or len(refs) != len(set(x for x in refs if isinstance(x, str)))
                    or any(not isinstance(x, str) for x in refs)
                    or not set(refs) <= source_refs):
                raise ValueError(f'R21 #{number} unsupported claim reference')
            fact_code = claim.get('verified_fact_code')
            if fact_code is not None:
                if not isinstance(fact_code, str) or not any(
                    fact['code'] == fact_code and set(fact['evidence_refs']) == set(refs)
                    for fact in facts
                ):
                    raise ValueError(f'R21 #{number} claim fact code/ref mismatch')
                used_fact_codes.add(fact_code)
            claim_refs.update(refs)
        if claim_refs != source_refs:
            raise ValueError(f'R21 #{number} unbound or unclaimed evidence refs')
        # Advisory fact-code coverage, not machine semantic proof:
        # the model may omit known facts; such omissions must be human-reviewed.
        if number == 5 and facts and 'DIRECT_SG_ALLOW_ALL_EGRESS_OBSERVED' not in used_fact_codes:
            counts['review_missing_egress_fact_code'] += 1
        if number == 18 and facts and 'DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY' not in used_fact_codes:
            counts['review_missing_ap_fact_code'] += 1

    scope_pending = SHARED_SCOPE_CONTROLS & pending
    if scope_pending:
        scope = by_id.get(SHARED_SCOPE_ID)
        if (scope is None or scope['acquisition_channel'] != 'OWNER_CONFIRMATION'
                or not scope_pending <= set(scope['applies_to_controls'])
                or scope['requested_artifact'] !=
                    support['shared_scope_contract']['single_owner_question']):
            raise ValueError('Shared scope Owner request must be declared exactly once')
    elif SHARED_SCOPE_ID in by_id:
        raise ValueError('No scope confirmation needed for already finalized controls')
    if (summary.get('distinct_evidence_request_count') != len(requests)
            or summary.get('owner_confirmation_request_count') != counts['OWNER_CONFIRMATION']
            or summary.get('machine_acquisition_request_count') != (
                counts['AWS_LOCAL_READ_ONLY'] + counts['NON_AWS_MACHINE_EXPORT'])):
        raise ValueError('Distinct evidence request totals inconsistent')
    return {
        'r21_request_schema_check': 'PASS',
        'distinct_evidence_request_count': len(requests),
        'owner_confirmation_request_count': counts['OWNER_CONFIRMATION'],
        'machine_acquisition_request_count': (
            counts['AWS_LOCAL_READ_ONLY'] + counts['NON_AWS_MACHINE_EXPORT']),
        'semantic_compliance_verified': False,
        'claim_quality_warnings': [
            label for label, key in (
                ('#5:EGRESS_FACT_OMITTED', 'review_missing_egress_fact_code'),
                ('#18:ACCESS_POINT_FACT_OMITTED', 'review_missing_ap_fact_code'))
            if counts[key]
        ],
        'status': 'STRUCTURE_ONLY_OWNER_REVIEW_REQUIRED',
    }
