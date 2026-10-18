"""Fail-closed regression for the historical R21 14→13 request repair.

No AWS identifiers, secrets or original operator reports are stored here.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from aws_security_audit.offline_classification import (
    HUMAN_CONTEXT_BATCHES, build_decision_support, validate_classification_result,
)
from aws_security_audit.r21_llm_request_correction import (
    correct_r21_semantic_requests,
)
from test_classification_contract import _inputs


def _observation(number: int, prop: str, value: dict, *, attribution='SHARED_UNATTRIBUTED',
                 state='CONTEXT_ONLY', kind='service') -> dict:
    return {
        'number': number, 'property': prop,
        'property_result': state, 'attribution': attribution,
        'resource_type': kind, 'resource_id': f'synthetic-{number}-{prop[:8]}',
        'observed_value': value,
    }


def _source_bundle_and_llm_response():
    bundle, result = _inputs()
    obs = bundle['resource_inventory']['control_observations']['rows']
    for i in range(2):
        obs.append(_observation(
            18, 'bucket_public_access_block',
            dict.fromkeys(('BlockPublicAcls', 'IgnorePublicAcls',
                           'BlockPublicPolicy', 'RestrictPublicBuckets'), True),
            attribution='DIRECT', state='PROPERTY_OK', kind='bucket'))
        if i == 1:
            obs.append(_observation(
                18, 'S3 selected bucket access point listing/detail configuration',
                {'lookup': 'LIST_VERIFIED', 'access_points': []},
                attribution='DIRECT', kind='bucket'))
    obs.append(_observation(
        18, 'S3 account-level Block Public Access context',
        {'lookup': 'NOT_CONFIGURED', 'public_access_block': None},
        state='PROPERTY_UNKNOWN'))
    obs.append(_observation(
        24, 'Regional CloudTrail trail configuration',
        {'multi_region': True, 'is_logging': True, 'log_status': 'VERIFIED',
         'selectors': {'basic_data_event_types': ['AWS::S3::Object']}}))
    obs.append(_observation(
        25, 'Regional CloudTrail trail configuration',
        {'log_file_validation_enabled': True, 'log_status': 'VERIFIED'}))
    obs.append(_observation(
        32, 'GuardDuty regional detector summary',
        {'state': 'LIST_VERIFIED', 'detectors': [{'status': 'ENABLED'}]}))
    obs.append(_observation(
        33, 'Security Hub regional standards summary',
        {'state': 'UNVERIFIED'}, state='PROPERTY_UNKNOWN'))
    bundle['decision_support'] = build_decision_support(
        bundle['controls'], bundle['resource_inventory'], r21_contract=True)

    # Three advisory business findings, not three independently Owner-approved decisions.
    for n in (19, 22):
        row = result['controls'][n - 1]
        row.update({
            'resolution_state': 'FINALIZED', 'final_classification': '未対応',
            'evidence_refs': [f'finding:{n}:0'],
            'evidence_claims': [{
                'claim': 'Synthetic negative finding, provisional business label',
                'evidence_refs': [f'finding:{n}:0'],
            }],
            'missing_evidence': [], 'missing_evidence_request_ids': [],
        })
    result['summary'].update({
        'finalized_count': 3, 'pending_count': 43, '未対応': 3})

    # R21 historical LLM: 5 Owner request containers and 9 machine ones.
    scope = deepcopy(result['evidence_requests'][0])
    reqs = [scope]
    pending = {r['number'] for r in result['controls']
               if r['resolution_state'] == 'EVIDENCE_PENDING'}
    for batch_id, control_numbers, question in HUMAN_CONTEXT_BATCHES:
        controls = sorted(set(control_numbers) & pending)
        request_id = 'batch:' + batch_id.replace('_', '-')
        reqs.append({
            'id': request_id, 'acquisition_channel': 'OWNER_CONFIRMATION',
            'status': 'REQUESTED_NOT_FULFILLED',
            'applies_to_controls': controls, 'requested_artifact': question,
        })
    special = {
        8: 'request:control-8-shield-subscription',
        18: 'request:control-18-s3-bpa-interpretation',
        24: 'request:control-24-cloudtrail-selectors',
        25: 'request:control-25-cloudtrail-validation',
        27: 'request:control-27-vpc-flow-logs',
        32: 'request:control-32-guardduty-status',
        33: 'request:control-33-securityhub-findings',
        39: 'request:control-39-inspector-ecr-scans',
        40: 'request:control-40-app-dependency-scans',
    }
    for n, rid in special.items():
        reqs.append({
            'id': rid,
            'acquisition_channel': (
                'NON_AWS_MACHINE_EXPORT' if n == 40 else 'AWS_LOCAL_READ_ONLY'),
            'status': 'REQUESTED_NOT_FULFILLED',
            'applies_to_controls': [n],
            'requested_artifact': (
                f'Export operator-held, read-only R21 machine configuration '
                f'evidence for original criterion {n}, with source provenance.'
            ),
        })
    for row in result['controls']:
        row['missing_evidence_request_ids'] = [
            req['id'] for req in reqs if row['number'] in req['applies_to_controls']]
    result['evidence_requests'] = reqs
    result['summary'].update({
        'distinct_evidence_request_count': 14,
        'owner_confirmation_request_count': 5,
        'machine_acquisition_request_count': 9,
    })
    assert validate_classification_result(bundle, result)['structure_and_reference_check'] == 'PASS'
    return bundle, result


def test_corrects_only_semantic_request_targets_and_retains_source():
    bundle, original = _source_bundle_and_llm_response()
    snapshot_bundle, snapshot_original = deepcopy(bundle), deepcopy(original)
    changed, report = correct_r21_semantic_requests(bundle, original)
    assert bundle == snapshot_bundle
    assert original == snapshot_original
    assert report['original_result_unchanged'] is True
    assert report['root_requests_after'] == 13
    assert report['owner_containers'] == 7
    assert report['aws_local_read_containers'] == 5
    assert report['non_aws_export_containers'] == 1
    assert report['observed_human_actions'] == 'NOT_MEASURED'
    assert report['semantic_compliance_verified'] is False
    assert report['expected_cli_exit_code'] == 2

    by_id = {req['id']: req for req in changed['evidence_requests']}
    assert by_id['request:control-18-s3-bpa-interpretation'][
        'acquisition_channel'] == 'OWNER_CONFIRMATION'
    assert 'request:control-25-cloudtrail-validation' not in by_id
    assert 'request:control-32-guardduty-status' not in by_id
    assert by_id['request:shared-account-service-applicability'][
        'applies_to_controls'] == [24, 25, 32]
    assert changed['controls'][23]['missing_evidence_request_ids'] == [
        'request:control-24-cloudtrail-ros-data-coverage',
        'request:shared-account-service-applicability']
    assert changed['controls'][24]['missing_evidence_request_ids'] == [
        'request:shared-account-service-applicability']
    assert changed['controls'][31]['missing_evidence_request_ids'] == [
        'request:shared-account-service-applicability']
    assert all(original['controls'][n - 1]['final_classification'] ==
               changed['controls'][n - 1]['final_classification']
               for n in range(1, 47))
    assert all(original['controls'][n - 1]['evidence_refs'] ==
               changed['controls'][n - 1]['evidence_refs']
               for n in range(1, 47))
    assert validate_classification_result(bundle, changed)['r21'][
        'r21_request_schema_check'] == 'PASS'


@pytest.mark.parametrize('mutation', (
    'already_corrected', 'unexpected_count', 'changed_scope', 'bad_bpa',
    'bad_trail_validation', 'bad_guardduty', 'wrong_request_channel',
    'unexpected_finalized_label', 'wrong_web_version',
))
def test_refuses_source_or_input_drift(mutation):
    bundle, original = _source_bundle_and_llm_response()
    if mutation == 'already_corrected':
        original, _ = correct_r21_semantic_requests(bundle, original)
    elif mutation == 'unexpected_count':
        original['evidence_requests'].pop()
    elif mutation == 'changed_scope':
        bundle['resource_inventory']['scope']['attribution_complete'] = True
        bundle['decision_support'] = build_decision_support(
            bundle['controls'], bundle['resource_inventory'], r21_contract=True)
    elif mutation == 'bad_bpa':
        obs = bundle['resource_inventory']['control_observations']['rows']
        next(x for x in obs if x['property'] ==
             'S3 account-level Block Public Access context')[
                 'observed_value']['lookup'] = 'API_ERROR'
        bundle['decision_support'] = build_decision_support(
            bundle['controls'], bundle['resource_inventory'], r21_contract=True)
    elif mutation == 'bad_trail_validation':
        obs = bundle['resource_inventory']['control_observations']['rows']
        next(x for x in obs if x['number'] == 25)[
            'observed_value']['log_file_validation_enabled'] = False
    elif mutation == 'bad_guardduty':
        obs = bundle['resource_inventory']['control_observations']['rows']
        next(x for x in obs if x['number'] == 32)[
            'observed_value']['detectors'][0]['status'] = 'DISABLED'
    elif mutation == 'wrong_request_channel':
        original['evidence_requests'][6]['acquisition_channel'] = 'OWNER_CONFIRMATION'
    elif mutation == 'unexpected_finalized_label':
        original['controls'][15]['final_classification'] = '対応中'
        original['summary']['未対応'] = 2
        original['summary']['対応中'] = 1
    elif mutation == 'wrong_web_version':
        bundle['decision_support'].pop('output_contract')
    with pytest.raises((ValueError, KeyError)):
        correct_r21_semantic_requests(bundle, original)
