"""R22 offline evidence-quality regression: remove only provably redundant metadata.

All fixtures are synthetic; no AWS account identifiers, credentials or
real customer resources are embedded into the repository.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from aws_security_audit.offline_classification import (
    build_decision_support, validate_classification_result,
)
from aws_security_audit.r22_evidence_quality import refine_r22_citations
from test_classification_contract import _inputs


def _three_source_refs():
    bundle, original = _inputs()
    obs = bundle['resource_inventory']['control_observations']['rows']
    for k in range(2):
        obs.append({
            'number': 16, 'property': 'HTTPS listener synthetic TLS policy',
            'property_result': 'PROPERTY_FAIL' if k == 0 else 'PROPERTY_OK',
            'attribution': 'DIRECT', 'resource_type': 'load-balancer',
            'resource_id': f'synthetic-alb-{k}',
            'observed_value': {'ssl_policy': f'synthetic-ssl-policy-{k}'},
        })
    bundle['decision_support'] = build_decision_support(
        bundle['controls'], bundle['resource_inventory'], r21_contract=True)
    row = original['controls'][15]
    row['evidence_refs'] = ['finding:16:0', 'observation:16:2', 'observation:16:3']
    row['evidence_claims'] = [
        {'claim': '元監査の#16はMANUAL_REVIEWであり、最終4区分の採用や全資産網羅をそれだけでは証明しない。',
         'evidence_refs': ['finding:16:0']},
        {'claim': 'Synthetic listener zero has obsolete protocol',
         'evidence_refs': ['observation:16:2']},
        {'claim': 'Synthetic listener one has current protocol',
         'evidence_refs': ['observation:16:3']},
    ]
    assert validate_classification_result(bundle, original)[
        'citation_quality_warnings'][0]['number'] == 16
    return bundle, original


def test_prune_only_one_redundant_metadata_ref_preserving_measured_facts():
    bundle, original = _three_source_refs()
    snapshot_bundle = deepcopy(bundle)
    snapshot_original = deepcopy(original)
    changed, report = refine_r22_citations(bundle, original)

    assert bundle == snapshot_bundle
    assert original == snapshot_original
    assert report['citation_warnings_before'] == 1
    assert report['citation_warnings_after'] == 0
    assert report['boilerplate_citations_removed'] == [{
        'number': 16, 'removed_generic_ref': 'finding:16:0',
        'reason': 'EXACT_SCANNER_STATUS_BOILERPLATE_ONLY'}]
    assert changed['controls'][15]['evidence_refs'] == [
        'observation:16:2', 'observation:16:3']
    assert changed['controls'][15]['final_classification'] == '未対応'
    assert changed['controls'][15]['resolution_state'] == 'FINALIZED'
    assert changed['evidence_requests'] == original['evidence_requests']
    assert changed['summary'] == original['summary']
    assert report['status'] == 'VALIDATED_STRUCTURE_ONLY_SEMANTICS_UNPROVEN'
    assert report['owner_adoption_verified'] is False
    assert report['semantic_compliance_verified'] is False
    assert report['unchanged_pending'] == 45
    assert validate_classification_result(bundle, changed)[
        'structure_and_reference_check'] == 'PASS'


def test_non_boilerplate_finding_claim_remains_flagged_not_silently_removed():
    bundle, original = _three_source_refs()
    original['controls'][15]['evidence_claims'][0]['claim'] = (
        'A specific source finding describes a separate potentially material TLS concern'
    )
    changed, report = refine_r22_citations(bundle, original)
    assert changed == original
    assert report['citation_warnings_before'] == 1
    assert report['citation_warnings_after'] == 1
    assert report['citations_not_pruned'] == [{
        'number': 16, 'reason': 'NO_UNIQUE_EXACT_GENERIC_CLAIM'}]


def test_wrong_status_metadata_is_not_pruned():
    bundle, original = _three_source_refs()
    original['controls'][15]['evidence_claims'][0]['claim'] = (
        '元監査の#16はFAILであり、最終4区分の採用や全資産網羅をそれだけでは証明しない。'
    )
    changed, report = refine_r22_citations(bundle, original)
    assert changed == original
    assert report['citation_warnings_after'] == 1


def test_shared_finding_ref_is_not_removed_from_any_claim():
    bundle, original = _three_source_refs()
    claim = original['controls'][15]['evidence_claims'][1]
    claim['evidence_refs'].append('finding:16:0')
    changed, report = refine_r22_citations(bundle, original)
    assert changed == original
    assert report['citations_not_pruned'][0]['reason'] == 'CITATION_SHARED_OR_UNLISTED'


def test_source_observation_claim_must_remain_bound():
    bundle, original = _three_source_refs()
    original['controls'][15]['evidence_claims'][2]['evidence_refs'] = ['finding:16:0']
    # Original v2 claim binding must fail before any attempt to "fix" sources.
    with pytest.raises(ValueError):
        refine_r22_citations(bundle, original)


def test_identity_and_typed_code_claims_from_unrelated_rows_unchanged():
    bundle, original = _three_source_refs()
    changed, _ = refine_r22_citations(bundle, original)
    assert changed['controls'][4] == original['controls'][4]
    assert changed['controls'][17] == original['controls'][17]
    assert changed['controls'][44] == original['controls'][44]


def test_triage_all_machine_requests_stays_evidence_only():
    bundle, original = _three_source_refs()
    all_pending = [row['number'] for row in original['controls']
                   if row['resolution_state'] == 'EVIDENCE_PENDING']
    non_scope = [n for n in all_pending if n not in (2, 17, 20, 23)]
    keys = [
        'request:control-8-shield-subscription',
        'request:control-24-cloudtrail-ros-data-coverage',
        'request:control-27-vpc-flow-logs',
        'request:control-33-securityhub-state',
        'request:control-39-inspector-ecr-scans',
        'request:control-40-app-dependency-scans',
    ]
    parts = [non_scope[i::6] for i in range(6)]
    original['evidence_requests'] = original['evidence_requests'][:1] + [
        {
            'id': key,
            'acquisition_channel': (
                'NON_AWS_MACHINE_EXPORT' if i == 5 else 'AWS_LOCAL_READ_ONLY'
            ),
            'status': 'REQUESTED_NOT_FULFILLED',
            'applies_to_controls': part,
            'requested_artifact': f'Synthetic original source gap {i} '
                                  'operator-only evidence export.',
        }
        for i, (key, part) in enumerate(zip(keys, parts))
    ]
    for row in original['controls']:
        n = row['number']
        if n in (2, 17, 20, 23, 16):
            continue
        row['missing_evidence_request_ids'] = [
            r['id'] for r in original['evidence_requests'][1:]
            if n in r['applies_to_controls']]
    original['summary']['distinct_evidence_request_count'] = 7
    original['summary']['owner_confirmation_request_count'] = 1
    original['summary']['machine_acquisition_request_count'] = 6
    assert validate_classification_result(bundle, original)['r21'][
        'r21_request_schema_check'] == 'PASS'

    changed, report = refine_r22_citations(bundle, original)
    assert changed['evidence_requests'] == original['evidence_requests']
    assert len(report['machine_gap_triage']) == 6
    assert report['machine_request_containers'] == 6
    assert report['owner_request_containers'] == 1
    assert all(not req['fulfilled'] for req in report['machine_gap_triage'])
    assert all(req['action'] == 'OFFLINE_EVIDENCE_REVIEW_BEFORE_ANY_READ'
               for req in report['machine_gap_triage'])


def test_rejects_legacy_v1_instead_of_discarding_legacy_claims():
    bundle, original = _three_source_refs()
    original['schema'] = 'aws-security-offline-classification-v1'
    bundle['decision_support'].pop('output_contract')
    with pytest.raises(ValueError):
        refine_r22_citations(bundle, original)
