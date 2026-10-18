"""R21 strict offline output schema and deduplicated owner requests."""
from __future__ import annotations

import copy

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.offline_classification import (
    build_decision_support, validate_classification_result,
)


def _inputs():
    controls = [{
        'number': c.number,
        'findings': [{'region': 'ap-northeast-1',
                      'status': 'MANUAL_REVIEW',
                      'evidence': ['Synthetic finding']}],
    } for c in CHECKS]
    observations = [
        {
            'number': 18, 'property': 'S3 selected bucket access point listing/detail configuration',
            'property_result': 'CONTEXT_ONLY', 'attribution': 'DIRECT',
            'resource_type': 'bucket', 'resource_id': 'dummy-bucket',
            'observed_value': {'lookup': 'LIST_VERIFIED', 'access_points': []},
        },
        {
            'number': 5, 'property': 'public ingress and all-protocol public egress',
            'property_result': 'CONTEXT_ONLY', 'attribution': 'DIRECT',
            'resource_type': 'security-group', 'resource_id': 'dummy-sg',
            'observed_value': {'all_protocol_public_egress_rule_count': 1},
        },
    ]
    inv = {
        'scope': {'product': 'ros', 'mode': 'product',
                  'direct': 2, 'related': 0, 'unassigned': 15,
                  'attribution_complete': False},
        'regions_requested': ['ap-northeast-1'],
        'resources': [],
        'control_observations': {'rows': observations},
    }
    bundle = {
        'controls': controls,
        'resource_inventory': inv,
        'decision_support': build_decision_support(controls, inv, r21_contract=True),
        'supplemental_evidence': [],
    }
    scope = bundle['decision_support']['shared_scope_contract']
    scope_nums = scope['reused_by_controls']
    rest_nums = [n for n in range(1, 47) if n not in scope_nums and n != 16]
    requests = [
        {
            'id': scope['id'],
            'acquisition_channel': 'OWNER_CONFIRMATION',
            'status': 'REQUESTED_NOT_FULFILLED',
            'applies_to_controls': scope_nums,
            'requested_artifact': scope['single_owner_question'],
        },
        {
            'id': 'aws-local-evidence-collection',
            'acquisition_channel': 'AWS_LOCAL_READ_ONLY',
            'status': 'REQUESTED_NOT_FULFILLED',
            'applies_to_controls': rest_nums,
            'requested_artifact': (
                'Synthetic fixture only: operator exports the individual, '
                'criterion-specific read-only configuration records.'
            ),
        },
    ]
    rows = []
    for n in range(1, 47):
        req = [] if n == 16 else [
            scope['id'] if n in scope_nums else 'aws-local-evidence-collection']
        rows.append({
            'number': n,
            'final_classification': '未対応' if n == 16 else None,
            'resolution_state': 'FINALIZED' if n == 16 else 'EVIDENCE_PENDING',
            'evidence_refs': [],
            'evidence_claims': [],
            'rationale': 'Synthetic observed failure' if n == 16 else 'Insufficient product scope',
            'missing_evidence': [] if n == 16 else ['Synthetic missing evidence'],
            'missing_evidence_request_ids': req,
        })
    rows[15]['evidence_refs'] = ['finding:16:0']
    rows[15]['evidence_claims'] = [{
        'claim': 'Synthetic finding is sourced',
        'evidence_refs': ['finding:16:0'],
    }]
    # Check typed reconciliation against exact, source-owned observation refs.
    rows[17]['evidence_refs'] = ['observation:18:0']
    rows[17]['evidence_claims'] = [{
        'claim': 'Observed empty classic AP list for selected bucket',
        'evidence_refs': ['observation:18:0'],
        'verified_fact_code': 'DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY',
    }]
    rows[4]['evidence_refs'] = ['observation:5:1']
    rows[4]['evidence_claims'] = [{
        'claim': 'Observed a permissive outbound rule but not its business necessity',
        'evidence_refs': ['observation:5:1'],
        'verified_fact_code': 'DIRECT_SG_ALLOW_ALL_EGRESS_OBSERVED',
    }]
    result = {
        'schema': 'aws-security-offline-classification-v2',
        'summary': {
            'finalized_count': 1, 'pending_count': 45,
            '対応済み': 0, '未対応': 1, '対応中': 0, '対象外': 0,
            'distinct_evidence_request_count': 2,
            'owner_confirmation_request_count': 1,
            'machine_acquisition_request_count': 1,
        },
        'evidence_requests': requests,
        'controls': rows,
    }
    return bundle, result


def test_r21_full_v2_46_rows_deduplicates_one_owner_scope_request():
    bundle, result = _inputs()
    check = validate_classification_result(bundle, result)
    assert check['structure_and_reference_check'] == 'PASS'
    assert check['result_contract'] == 'aws-security-offline-classification-v2'
    assert check['pending_count'] == 45
    assert check['r21']['r21_request_schema_check'] == 'PASS'
    assert check['r21']['owner_confirmation_request_count'] == 1
    assert check['r21']['machine_acquisition_request_count'] == 1
    assert check['r21']['claim_quality_warnings'] == []
    assert check['owner_adoption_verified'] is False
    assert check['semantic_compliance_verified'] is False


@pytest.mark.parametrize('fault', (
    'nested_counts', 'missing_counts', 'wrong_request_count',
    'duplicate_id', 'duplicate_text', 'forged_owner_approval',
    'missing_shared_scope', 'split_shared_scope', 'wrong_acquisition_type',
    'missing_row_request', 'invalid_root_scope',
    'finalized_has_request', 'cross_control_request',
    'request_scope_order', 'filled_request_without_real_proof',
    'unbound_evidence', 'forged_fact_code', 'forged_fact_ref',
    'unrecognized_claim_ref', 'missing_requests_array',
))
def test_r21_fail_closed_on_schema_provenance_request_contract(fault):
    bundle, result = _inputs()
    scope = result['evidence_requests'][0]
    aws = result['evidence_requests'][1]
    if fault == 'nested_counts':
        result['summary']['classifications'] = {'未対応': 1}
    elif fault == 'missing_counts':
        result['summary'].pop('未対応')
    elif fault == 'wrong_request_count':
        result['summary']['owner_confirmation_request_count'] = 2
    elif fault == 'duplicate_id':
        aws['id'] = scope['id']
    elif fault == 'duplicate_text':
        aws['requested_artifact'] = scope['requested_artifact']
    elif fault == 'forged_owner_approval':
        bundle['decision_support']['shared_scope_contract']['owner_approval'] = 'APPROVED'
    elif fault == 'missing_shared_scope':
        scope['id'] = 'owner-other-scope'
        for row in result['controls']:
            row['missing_evidence_request_ids'] = [
                'owner-other-scope' if v.startswith('scope:') else v
                for v in row['missing_evidence_request_ids']
            ]
    elif fault == 'split_shared_scope':
        scope['applies_to_controls'] = [2, 17]
        aws['applies_to_controls'] = sorted(set(aws['applies_to_controls'] + [20, 23]))
        result['controls'][19]['missing_evidence_request_ids'] = [aws['id']]
        result['controls'][22]['missing_evidence_request_ids'] = [aws['id']]
    elif fault == 'wrong_acquisition_type':
        scope['acquisition_channel'] = 'AWS_LOCAL_READ_ONLY'
    elif fault == 'missing_row_request':
        result['controls'][1]['missing_evidence_request_ids'] = []
    elif fault == 'invalid_root_scope':
        aws['applies_to_controls'] = aws['applies_to_controls'] + [16]
    elif fault == 'finalized_has_request':
        result['controls'][15]['missing_evidence_request_ids'] = [aws['id']]
    elif fault == 'cross_control_request':
        aws['applies_to_controls'].remove(5)
    elif fault == 'request_scope_order':
        aws['applies_to_controls'] = list(reversed(aws['applies_to_controls']))
    elif fault == 'filled_request_without_real_proof':
        scope['status'] = 'APPROVED'
    elif fault == 'unbound_evidence':
        result['controls'][17]['evidence_claims'] = []
    elif fault == 'forged_fact_code':
        result['controls'][17]['evidence_claims'][0]['verified_fact_code'] = 'MADE_UP'
    elif fault == 'forged_fact_ref':
        result['controls'][17]['evidence_claims'][0]['evidence_refs'] = [
            'finding:18:0']
        result['controls'][17]['evidence_refs'].append('finding:18:0')
    elif fault == 'unrecognized_claim_ref':
        result['controls'][17]['evidence_claims'][0]['evidence_refs'] = [
            'observation:18:999']
    elif fault == 'missing_requests_array':
        result.pop('evidence_requests')
    with pytest.raises(ValueError):
        validate_classification_result(bundle, result)


def test_legacy_v1_is_explicitly_not_r21_conformance():
    bundle, result = _inputs()
    result['schema'] = 'aws-security-offline-classification-v1'
    result.pop('evidence_requests')
    for row in result['controls']:
        row.pop('evidence_claims')
        row.pop('missing_evidence_request_ids')
    check = validate_classification_result(bundle, result)
    assert check['r21']['r21_request_schema_check'] == 'NOT_PERFORMED_LEGACY_V1'
    assert check['semantic_compliance_verified'] is False


def test_reconciliation_fact_codes_belong_to_same_control():
    bundle, result = _inputs()
    result['controls'][4]['evidence_claims'][0]['verified_fact_code'] = (
        'DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY')
    with pytest.raises(ValueError, match='fact code'):
        validate_classification_result(bundle, result)
