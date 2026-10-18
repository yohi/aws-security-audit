"""R20 regression: current SG egress, one scope request, bounded backup proof."""
from __future__ import annotations

import copy

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.evidence_reconciliation import reconcile_control
from aws_security_audit.offline_classification import (
    build_decision_support, validate_classification_result,
)
from aws_security_audit.shared_evidence import (
    build_cross_control_evidence, build_shared_scope_contract,
)


def _fixtures():
    obs = []
    for n in range(7):
        obs.append({
            'number': 5, 'property': 'public ingress and all-protocol public egress',
            'property_result': 'CONTEXT_ONLY', 'attribution': 'DIRECT',
            'resource_type': 'security-group', 'resource_id': f'sg-{n}',
            'observed_value': {'all_protocol_public_egress_rule_count': 1,
                               'public_ingress': []},
        })
    resources = []
    for n in range(10):
        rid = f'rds:snap-{n}'
        resources.append({
            'resource_id': rid, 'resource_type': 'db-cluster-snapshot',
            'attribution': 'DIRECT',
            'attributes': {'snapshot_type': 'automated',
                           'storage_encryption_type': 'sse-kms'},
        })
        obs.append({
            'number': 20, 'property': 'effective storage encryption',
            'property_result': 'PROPERTY_OK', 'attribution': 'DIRECT',
            'resource_type': 'db-cluster-snapshot', 'resource_id': rid,
            'observed_value': {'encrypted': True,
                               'encryption_state': 'ENCRYPTED',
                               'storage_encryption_type': 'sse-kms'},
        })
    return {'scope': {
        'product': 'ros', 'mode': 'product', 'direct': 43, 'related': 5,
        'unassigned': 656, 'attribution_complete': False,
    }, 'regions_requested': ['ap-northeast-1'],
        'resources': resources, 'control_observations': {'rows': obs},
        'limitations': ['Heuristic product attribution, incomplete scope']}


def _bundle(inv):
    controls = [{'number': c.number, 'findings': [{'region': 'ap-northeast-1',
                'status': 'MANUAL_REVIEW'}]} for c in CHECKS]
    support = build_decision_support(controls, inv)
    return {
        'controls': controls, 'resource_inventory': inv,
        'decision_support': support, 'supplemental_evidence': [],
    }


def _pending(bundle):
    return {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': n, 'resolution_state': 'EVIDENCE_PENDING',
            'final_classification': None, 'rationale': 'Scope incomplete',
            'evidence_refs': [], 'missing_evidence': ['Explicit scope signoff'],
        } for n in range(1, 47)],
        'summary': {'finalized_count': 0, 'pending_count': 46},
    }


def test_direct_sg_egress_captured_as_observed_not_automatically_unneeded():
    facts = reconcile_control(5, _fixtures()['control_observations']['rows'])
    assert len(facts['verified_facts']) == 7
    assert all(f['code'] == 'DIRECT_SG_ALLOW_ALL_EGRESS_OBSERVED'
               for f in facts['verified_facts'])
    assert all('business necessity not proven' in f['observed_fact']
               for f in facts['verified_facts'])
    bad = [
        {'number': 5, 'property': 'public ingress and all-protocol public egress',
         'property_result': 'PROPERTY_FAIL', 'attribution': 'DIRECT',
         'resource_type': 'security-group', 'resource_id': 'spoof',
         'observed_value': {'all_protocol_public_egress_rule_count': 1}},
        {'number': 5, 'property': 'public ingress and all-protocol public egress',
         'property_result': 'CONTEXT_ONLY', 'attribution': 'RELATED',
         'resource_type': 'security-group', 'resource_id': 'related',
         'observed_value': {'all_protocol_public_egress_rule_count': 1}},
        {'number': 5, 'property': 'public ingress and all-protocol public egress',
         'property_result': 'CONTEXT_ONLY', 'attribution': 'DIRECT',
         'resource_type': 'security-group', 'resource_id': 'bad-type',
         'observed_value': {'all_protocol_public_egress_rule_count': '1'}},
    ]
    assert reconcile_control(5, bad)['verified_facts'] == []


def test_product_scope_has_one_owner_request_but_zero_fake_approvals():
    s = build_shared_scope_contract(_fixtures())
    assert s['owner_approval'] == 'PENDING'
    assert s['scope_coverage_proven'] is False
    assert s['reused_by_controls'] == [2, 17, 20, 23]
    assert s['observed_scope']['unassigned'] == 656
    bundle = _bundle(_fixtures())
    sid = s['id']
    for n in (2, 17, 20, 23):
        assert bundle['decision_support']['plans'][n-1]['shared_scope_requirement_ids'] == [sid]
    assert bundle['decision_support']['plans'][44]['shared_scope_requirement_ids'] == []
    assert validate_classification_result(bundle, _pending(bundle))['pending_count'] == 46


def test_cross_control_only_verified_automated_snapshot_exists_no_restore_proof():
    inv = _fixtures()
    evidence = build_cross_control_evidence(inv)
    assert len(evidence['references']) == 10
    assert all(e['source_control'] == 20 and e['target_control'] == 45
               and e['id'].startswith('observation:20:')
               for e in evidence['references'])
    assert all('successful restore drill' in e['does_not_prove']
               for e in evidence['references'])
    bundle = _bundle(inv)
    assert len(bundle['decision_support']['plans'][44]['cross_control_evidence_refs']) == 10
    response = _pending(bundle)
    response['controls'][44]['evidence_refs'] = [evidence['references'][0]['id']]
    assert validate_classification_result(bundle, response)['pending_count'] == 46
    response['controls'][43]['evidence_refs'] = [evidence['references'][0]['id']]
    with pytest.raises(ValueError, match='cross-control'):
        validate_classification_result(bundle, response)

    inv2 = copy.deepcopy(inv)
    inv2['resources'][0]['attributes']['snapshot_type'] = 'manual'
    assert len(build_cross_control_evidence(inv2)['references']) == 9
    inv2['resources'][1]['attribution'] = 'RELATED'
    assert len(build_cross_control_evidence(inv2)['references']) == 8
    inv2['control_observations']['rows'][9]['observed_value']['encrypted'] = False
    assert len(build_cross_control_evidence(inv2)['references']) == 7


def test_scope_and_cross_control_indexes_are_not_implicitly_trusted():
    bundle = _bundle(_fixtures())
    response = _pending(bundle)
    tampered = copy.deepcopy(bundle)
    tampered['decision_support']['shared_scope_contract']['owner_approval'] = 'APPROVED'
    with pytest.raises(ValueError, match='scope'):
        validate_classification_result(tampered, response)
    tampered = copy.deepcopy(bundle)
    tampered['decision_support']['cross_control_evidence']['references'][0][
        'does_not_prove'] = []
    with pytest.raises(ValueError, match='scope'):
        validate_classification_result(tampered, response)
    tampered = copy.deepcopy(bundle)
    tampered['decision_support']['plans'][43]['cross_control_evidence_refs'] = [
        bundle['decision_support']['cross_control_evidence']['references'][0]]
    with pytest.raises(ValueError, match='scope or cross-control'):
        validate_classification_result(tampered, response)
