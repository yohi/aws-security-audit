"""Criterion-aware control review: evidence sufficiency never upgrades verdicts.

All rows keep their original catalog fields, scanner statuses and no adopted
labels. Synthetic fixtures only; no AWS access happens in these tests.
"""
from __future__ import annotations

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.control_review import build_control_review
from aws_security_audit.evidence_adapters import build_ledger
from aws_security_audit.evidence_progress_report import build_evidence_progress
from aws_security_audit.evidence_types import (
    REVIEW_SCHEMA,
    BusinessResolutionState,
    CriterionState,
    EvidenceState,
    ScannerStatus,
)
from aws_security_audit.offline_classification import build_decision_support

REGION = 'ap-northeast-1'
FLAGS = {key: True for key in (
    'BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy',
    'RestrictPublicBuckets')}
ENCRYPTED = {'encrypted': True, 'encryption_state': 'ENCRYPTED',
             'storage_encryption_type': 'sse-kms'}
SPECIALIZED = {5, 17, 18, 20, 23, 45}


def row(number, prop, result, value, rtype, rid, attrib='DIRECT'):
    return {'number': number, 'property': prop, 'property_result': result,
            'observed_value': value, 'resource_type': rtype,
            'resource_id': rid, 'attribution': attrib}


def synthetic_bundle(rows=(), resources=()):
    controls = [{
        'number': definition.number,
        'category': definition.category,
        'title': definition.title,
        'criterion': definition.criterion,
        'severity': definition.severity,
        'purpose': definition.purpose,
        'account_status': 'MANUAL_REVIEW',
        'regional_status': 'MANUAL_REVIEW',
        'findings': [{'region': REGION, 'status': 'MANUAL_REVIEW',
                      'detail': 'synthetic', 'evidence': []}],
    } for definition in CHECKS]
    inventory = {'control_observations': {'rows': list(rows)},
                 'resources': list(resources)}
    support = build_decision_support(controls, inventory)
    return {
        'schema': 'aws-security-audit-web-review-v1',
        'execution': {'product': 'syn', 'requested_regions': [REGION],
                      'audit_scope': 'product'},
        'controls': controls,
        'decision_support': support,
        'supplemental_evidence': [],
        'resource_inventory': inventory,
    }


def review_for(rows, resources=()):
    bundle = synthetic_bundle(rows, resources)
    return bundle, build_ledger(bundle), build_control_review(
        bundle, build_ledger(bundle))


def pending_classification(bundle):
    plans = bundle['decision_support']['plans']
    return {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': plan['number'], 'final_classification': None,
            'resolution_state': 'EVIDENCE_PENDING',
            'rationale': 'Insufficient product-wide scope information',
            'missing_evidence': ['Need complete product attribution'],
            'evidence_refs': [],
        } for plan in plans],
        'summary': {'finalized_count': 0, 'pending_count': 46},
    }


def check(row_number, review, name_part):
    return [c for c in review.rows[row_number - 1].criterion_checks
            if name_part in c.component][0]


@pytest.fixture(name='review_inputs')
def review_inputs():
    bundle = synthetic_bundle()
    return bundle, build_ledger(bundle)


def test_review_preserves_order_criteria_and_scanner_statuses(review_inputs):
    bundle, ledger = review_inputs
    result = build_control_review(bundle, ledger)
    assert result.schema == REVIEW_SCHEMA
    assert [row.number for row in result.rows] == list(range(1, 47))
    assert [row.criterion for row in result.rows] == [
        check_.criterion for check_ in CHECKS]
    assert [row.category for row in result.rows] == [
        check_.category for check_ in CHECKS]
    assert [row.title for row in result.rows] == [
        check_.title for check_ in CHECKS]
    assert [row.severity for row in result.rows] == [
        check_.severity for check_ in CHECKS]
    assert [row.purpose for row in result.rows] == [
        check_.purpose for check_ in CHECKS]
    assert all(row.scanner_status is ScannerStatus.MANUAL_REVIEW
               for row in result.rows)
    assert all(row.scanner_regional_status
               == {REGION: ScannerStatus.MANUAL_REVIEW}
               for row in result.rows)
    assert not any(row.owner_adoption_verified for row in result.rows)
    assert all(row.business_label_provisional is None for row in result.rows)
    assert all(row.business_resolution_state
               is BusinessResolutionState.NOT_EVALUATED
               for row in result.rows)
    assert all(row.fact_refs == () for row in result.rows)
    assert result.requests == ()
    for row in result.rows:
        if not SPECIALIZED & {row.number}:
            assert len(row.criterion_checks) == 1
            assert row.criterion_checks[0].state is CriterionState.UNRESOLVED
            assert row.criterion_checks[0].limitation


def test_no5_allow_all_egress_needs_necessity_context():
    rows = [row(5, 'public ingress and all-protocol public egress',
                'CONTEXT_ONLY', {'all_protocol_public_egress_rule_count': 1},
                'security-group', 'sg-1')]
    bundle, ledger, review = review_for(rows)
    row5 = review.rows[4]
    egress = check(5, review, 'outbound')
    assert egress.state is CriterionState.UNRESOLVED
    assert egress.limitation
    assert 'necessity' in egress.limitation or 'needed' in egress.limitation
    ids = {fact.id for fact in ledger.facts}
    assert egress.fact_refs and set(egress.fact_refs) <= ids
    assert row5.evidence_state is EvidenceState.PARTIAL
    assert row5.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE


def test_no17_default_encryption_not_historical_objects():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data'),
            row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-logs')]
    bundle, ledger, review = review_for(rows)
    row17 = review.rows[16]
    match = check(17, review, 'default encryption')
    assert match.state is CriterionState.OBSERVED_MATCH
    assert match.fact_refs
    assert not any('historical' in c.component for c in row17.criterion_checks)
    assert check(17, review, 'coverage').state is CriterionState.UNRESOLVED
    assert row17.evidence_state is EvidenceState.PARTIAL
    assert row17.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE


def test_no18_account_bucket_policy_ambiguity():
    rows = [
        row(18, 'bucket_public_access_block', 'PROPERTY_OK', FLAGS, 'bucket',
            'syn-data'),
        row(18, 'bucket_public_access_block', 'PROPERTY_OK', FLAGS, 'bucket',
            'syn-logs'),
        row(18, 'S3 selected bucket access point listing/detail configuration',
            'CONTEXT_ONLY', {'lookup': 'LIST_VERIFIED', 'access_points': []},
            'bucket', 'syn-data'),
        row(18, 'S3 account-level Block Public Access context',
            'PROPERTY_UNKNOWN',
            {'lookup': 'NOT_CONFIGURED', 'public_access_block': None},
            'shared-s3-account-control', 'account-public-access-block',
            'SHARED_UNATTRIBUTED'),
    ]
    bundle, ledger, review = review_for(rows)
    row18 = review.rows[17]
    account = check(18, review, 'account-level')
    assert account.state is CriterionState.UNRESOLVED
    assert not any(c.state is CriterionState.OBSERVED_MATCH for c
                   in row18.criterion_checks if c.component == account.component)
    assert check(18, review, 'bucket BPA').state is CriterionState.OBSERVED_MATCH
    assert row18.evidence_state is EvidenceState.PARTIAL
    assert row18.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE


def test_no20_snapshot_encryption_not_a_restore_drill():
    resources = [{'resource_id': 'snap-aut', 'resource_type':
                  'db-cluster-snapshot', 'attribution': 'DIRECT',
                  'attributes': {'snapshot_type': 'automated'}}]
    rows = [row(20, 'effective storage encryption', 'PROPERTY_OK', ENCRYPTED,
                'db-cluster-snapshot', 'snap-aut')]
    bundle, ledger, review = review_for(rows, resources)
    row20 = review.rows[19]
    match = check(20, review, 'encryption')
    assert match.state is CriterionState.OBSERVED_MATCH
    limitations = ' '.join(c.limitation or '' for c in row20.criterion_checks)
    assert 'Restore drills' in limitations and '#45' in limitations
    assert not any('restore' in c.component for c in row20.criterion_checks)
    assert row20.evidence_state is EvidenceState.PARTIAL
    assert row20.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE


def test_no23_aurora_cluster_member_distinction():
    rows = [row(23, 'DeletionProtection', 'PROPERTY_OK', True, 'db-cluster',
                'cluster-1'),
            row(23, 'DeletionProtection', 'PROPERTY_OK', True, 'db-instance',
                'instance-1')]
    bundle, ledger, review = review_for(rows)
    row23 = review.rows[22]
    cluster = check(23, review, 'cluster')
    assert cluster.state is CriterionState.OBSERVED_MATCH
    member = check(23, review, 'member')
    assert member.state is CriterionState.UNRESOLVED
    member_keys = {c for c in member.fact_refs}
    cluster_keys = set(cluster.fact_refs)
    assert cluster_keys and member_keys
    assert member_keys != cluster_keys
    assert row23.evidence_state is EvidenceState.PARTIAL


def test_no45_snapshot_reuse_without_restore_success():
    resources = [{'resource_id': 'snap-aut', 'resource_type':
                  'db-cluster-snapshot', 'attribution': 'DIRECT',
                  'attributes': {'snapshot_type': 'automated'}}]
    rows = [row(20, 'effective storage encryption', 'PROPERTY_OK', ENCRYPTED,
                'db-cluster-snapshot', 'snap-aut')]
    bundle, ledger, review = review_for(rows, resources)
    row45 = review.rows[44]
    existence = check(45, review, 'existence')
    drill = check(45, review, 'restore drill')
    assert existence.state is CriterionState.UNRESOLVED
    assert drill.state is CriterionState.UNRESOLVED
    ids = {fact.id for fact in ledger.facts}
    assert existence.fact_refs and set(existence.fact_refs) <= ids
    limitations = ' '.join(c.limitation or '' for c in row45.criterion_checks)
    assert 'successful restore drill' in limitations
    assert row45.evidence_state is EvidenceState.PARTIAL
    assert row45.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE
    assert row45.owner_adoption_verified is False


@pytest.mark.parametrize(
    'rows, expected',
    [pytest.param(
        [row(17, 'default_encryption_algorithms', 'PROPERTY_OK', ['AES256'],
             'bucket', 'syn-a'),
         row(17, 'default_encryption_algorithms', 'PROPERTY_FAIL', ['AES256'],
             'bucket', 'syn-a')], EvidenceState.CONFLICTING, id='conflicting'),
     pytest.param(
         [row(17, 'default_encryption_algorithms', 'PROPERTY_OK', ['AES256'],
              'bucket', 'syn-a')], EvidenceState.PARTIAL, id='incomplete')],
)
def test_conflicting_and_incomplete_never_supported(rows, expected):
    bundle, ledger, review = review_for(rows)
    row17 = review.rows[16]
    assert row17.evidence_state is expected
    assert row17.evidence_state is not EvidenceState.SUPPORTED_FOR_DECLARED_SCOPE


def test_classification_labels_projected_but_never_adopted():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK', ['AES256'],
                'bucket', 'syn-a')]
    bundle = synthetic_bundle(rows)
    classification = pending_classification(bundle)
    review = build_control_review(bundle, build_ledger(bundle), classification)
    assert all(row.business_resolution_state
               is BusinessResolutionState.EVIDENCE_PENDING
               for row in review.rows)
    assert all(row.business_label_provisional is None for row in review.rows)
    classification['controls'][16].update(
        resolution_state='FINALIZED', final_classification='対応済み',
        evidence_refs=[ref['id'] for ref
                       in bundle['decision_support']['plans'][16]
                       ['evidence_refs']],
        missing_evidence=[])
    classification['summary'] = {'finalized_count': 1, 'pending_count': 45,
                                 '対応済み': 1, '未対応': 0, '対応中': 0,
                                 '対象外': 0}
    review = build_control_review(bundle, build_ledger(bundle), classification)
    row17 = review.rows[16]
    assert row17.business_resolution_state is BusinessResolutionState.FINALIZED
    assert row17.business_label_provisional == '対応済み'
    assert row17.owner_adoption_verified is False


def test_invalid_classification_rejected_before_label_projection(review_inputs):
    bundle, ledger = review_inputs
    with pytest.raises(ValueError):
        build_control_review(bundle, ledger, {'schema': 'forged'})


def test_progress_report_embeds_control_review(review_inputs):
    bundle, ledger = review_inputs
    progress = build_evidence_progress(bundle)
    review = progress['control_review']
    assert review['schema'] == REVIEW_SCHEMA
    assert [r['number'] for r in review['rows']] == list(range(1, 47))
    direct = build_control_review(bundle, build_ledger(bundle))
    for i, entry in enumerate(review['rows']):
        assert entry['scanner_status'] == direct.rows[i].scanner_status.value
        assert entry['evidence_state'] == direct.rows[i].evidence_state.value
        assert entry['owner_adoption_verified'] is False
