"""R19 failure regression: reconcile observed facts and keep criteria narrow."""
from __future__ import annotations

import copy

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.evidence_reconciliation import reconcile_control
from aws_security_audit.offline_classification import (
    build_decision_support, validate_classification_result,
)


def row(number, prop, state, value, typ, ident='sample', attrib='DIRECT'):
    return {
        'number': number, 'property': prop, 'property_result': state,
        'observed_value': value, 'resource_type': typ,
        'resource_id': ident, 'attribution': attrib,
    }


def _observations():
    true_flags = {key: True for key in
                  ('BlockPublicAcls', 'IgnorePublicAcls',
                   'BlockPublicPolicy', 'RestrictPublicBuckets')}
    rows = [
        row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
            ['AES256'], 'bucket', 'ros-data'),
        row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
            ['AES256'], 'bucket', 'ros-logs'),
        row(18, 'bucket_public_access_block', 'PROPERTY_OK',
            true_flags, 'bucket', 'ros-data'),
        row(18, 'S3 selected bucket access point listing/detail configuration',
            'CONTEXT_ONLY', {
                'lookup': 'LIST_VERIFIED', 'access_points': [],
                'bucket_region': 'ap-northeast-1'
            }, 'bucket', 'ros-data'),
        row(18, 'bucket_public_access_block', 'PROPERTY_OK',
            true_flags, 'bucket', 'ros-logs'),
        row(18, 'S3 selected bucket access point listing/detail configuration',
            'CONTEXT_ONLY', {
                'lookup': 'LIST_VERIFIED', 'access_points': [],
                'bucket_region': 'ap-northeast-1'
            }, 'bucket', 'ros-logs'),
        row(18, 'S3 account-level Block Public Access context',
            'PROPERTY_UNKNOWN',
            {'lookup': 'NOT_CONFIGURED', 'public_access_block': None},
            'shared-s3-account-control', 'account-public-access-block',
            'SHARED_UNATTRIBUTED'),
    ]
    for i in range(4):
        rows.append(row(20, 'effective storage encryption', 'PROPERTY_OK',
                        {'encrypted': True, 'encryption_state': 'ENCRYPTED',
                         'storage_encryption_type': 'sse-kms'},
                        'db-instance', f'instance-{i}'))
    for i in range(2):
        rows.append(row(20, 'effective storage encryption', 'PROPERTY_OK',
                        {'encrypted': True, 'encryption_state': 'ENCRYPTED',
                         'storage_encryption_type': 'sse-kms'},
                        'db-cluster', f'cluster-{i}'))
        rows.append(row(23, 'DeletionProtection', 'PROPERTY_OK',
                        True, 'db-cluster', f'cluster-{i}'))
    for i in range(10):
        rows.append(row(20, 'effective storage encryption', 'PROPERTY_OK',
                        {'encrypted': True, 'encryption_state': 'ENCRYPTED',
                         'storage_encryption_type': 'sse-kms'},
                        'db-cluster-snapshot', f'snapshot-{i}'))
    return rows


def test_r19_reconciles_existing_actual_shape_without_inventing_a_final_pass():
    rows = _observations()
    recon = {n: reconcile_control(n, rows) for n in (17, 18, 20, 23)}
    assert [len(recon[n]['verified_facts']) for n in (17, 18, 20, 23)] == [
        2, 5, 16, 2]
    codes = [f['code'] for f in recon[18]['verified_facts']]
    assert codes.count('DIRECT_BUCKET_BPA_FOUR_FLAGS_ENABLED') == 2
    assert codes.count('DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY') == 2
    assert codes.count('ACCOUNT_BPA_CONFIGURATION_ABSENT') == 1
    assert 'NOT_CONFIGURED' in recon[18]['verified_facts'][-1]['observed_fact']
    assert 'GetPublicAccessBlock' in recon[18]['verified_facts'][-1]['observed_fact']
    assert recon[17]['not_required_by_original_criterion']
    assert 'Restore drills' in recon[20]['not_required_by_original_criterion'][0]
    assert 'member instance' in recon[23]['not_required_by_original_criterion'][0]
    assert all('product' in recon[n]['caveat'] for n in recon)
    assert reconcile_control(41, rows)['status'] == 'NOT_SPECIALIZED'


def test_r19_rejects_schema_shifts_and_false_positive_observations():
    rows = _observations()
    wrong = [
        row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
            ['AES256'], 'bucket', 'shared', 'RELATED'),
        row(18, 'bucket_public_access_block', 'PROPERTY_UNKNOWN',
            {k: True for k in ('BlockPublicAcls', 'IgnorePublicAcls',
                               'BlockPublicPolicy', 'RestrictPublicBuckets')},
            'bucket', 'read-error'),
        row(18, 'S3 selected bucket access point listing/detail configuration',
            'CONTEXT_ONLY', {'lookup': 'UNVERIFIED_LIST', 'access_points': []},
            'bucket', 'denied'),
        row(18, 'S3 account-level Block Public Access context',
            'PROPERTY_UNKNOWN', {'lookup': 'UNVERIFIED_READ_ERROR',
                                 'public_access_block': None},
            'shared-s3-account-control', 'account-public-access-block',
            'SHARED_UNATTRIBUTED'),
        row(20, 'effective storage encryption', 'PROPERTY_OK',
            {'encrypted': False, 'encryption_state': 'ENCRYPTED',
             'storage_encryption_type': 'sse-kms'},
            'db-instance', 'contradictory'),
        row(23, 'DeletionProtection', 'PROPERTY_OK',
            True, 'db-instance', 'member-instance'),
    ]
    for n in (17, 18, 20, 23):
        assert reconcile_control(n, wrong)['verified_facts'] == []


def test_r19_reconciliation_attached_to_all_46_plans_and_validator_rejects_forgery():
    rows = _observations()
    controls = [{
        'number': c.number, 'findings': [
            {'region': 'ap-northeast-1',
             'status': 'MANUAL_REVIEW', 'evidence': []}]
    } for c in CHECKS]
    inventory = {'control_observations': {'rows': rows}}
    support = build_decision_support(controls, inventory)
    bundle = {
        'controls': controls, 'resource_inventory': inventory,
        'decision_support': support, 'supplemental_evidence': [],
    }
    result = {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': p['number'], 'final_classification': None,
            'resolution_state': 'EVIDENCE_PENDING',
            'rationale': 'Insufficient product-wide scope information',
            'missing_evidence': ['Need complete product attribution'],
            'evidence_refs': [],
        } for p in support['plans']],
        'summary': {'finalized_count': 0, 'pending_count': 46},
    }
    assert len(support['plans']) == 46
    assert support['plans'][17]['evidence_reconciliation']['verified_facts']
    assert validate_classification_result(bundle, result)['pending_count'] == 46

    poisoned = copy.deepcopy(bundle)
    poisoned['decision_support']['plans'][17]['evidence_reconciliation'][
        'verified_facts'][0]['observed_fact'] = 'Falsified account BPA settings'
    with pytest.raises(ValueError, match='reconciliation'):
        validate_classification_result(poisoned, result)


def test_r19_citation_all_sources_is_warning_not_false_semantic_pass():
    rows = _observations()
    controls = [{'number': c.number, 'findings': [{'status': 'MANUAL_REVIEW'}]}
                for c in CHECKS]
    inventory = {'control_observations': {'rows': rows}}
    support = build_decision_support(controls, inventory)
    result = {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': p['number'], 'final_classification': None,
            'resolution_state': 'EVIDENCE_PENDING',
            'rationale': 'Needs further proof', 'missing_evidence': ['Owner scope'],
            'evidence_refs': [x['id'] for x in p['evidence_refs']],
        } for p in support['plans']],
        'summary': {'finalized_count': 0, 'pending_count': 46},
    }
    verified = validate_classification_result({
        'controls': controls, 'resource_inventory': inventory,
        'decision_support': support, 'supplemental_evidence': [],
    }, result)
    assert verified['structure_and_reference_check'] == 'PASS'
    assert verified['semantic_compliance_verified'] is False
    assert {w['number'] for w in verified['citation_quality_warnings']} == {17, 18, 20}
