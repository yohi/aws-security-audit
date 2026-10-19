"""Residual evidence requests: exact-key deduplication of open gaps.

Requests live in the review model only and never mutate the R21
classification schema. Synthetic fixtures only; no AWS access happens
in these tests.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.control_review import build_control_review
from aws_security_audit.evidence_adapters import build_ledger
from aws_security_audit.evidence_progress_report import build_evidence_progress
from aws_security_audit.evidence_requests import (
    build_evidence_requests,
    request_to_json,
    with_evidence_requests,
)
from aws_security_audit.evidence_types import (
    GapKind,
    EvidenceRequest,
)
from aws_security_audit.evidence_ledger import evidence_id
from aws_security_audit.offline_classification import (
    FINAL_LABELS,
    build_decision_support,
)

REGION = 'ap-northeast-1'
ENCRYPTED = {'encrypted': True, 'encryption_state': 'ENCRYPTED',
             'storage_encryption_type': 'sse-kms'}
SHARED_SCOPE_CONTROLS = (2, 17, 20, 23)


def row(number, prop, result, value, rtype, rid, attrib='DIRECT'):
    return {'number': number, 'property': prop, 'property_result': result,
            'observed_value': value, 'resource_type': rtype,
            'resource_id': rid, 'attribution': attrib}


def synthetic_bundle(rows=(), resources=(), audit_scope='product'):
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
    return {
        'schema': 'aws-security-audit-web-review-v1',
        'execution': {'product': 'syn', 'requested_regions': [REGION],
                      'audit_scope': audit_scope},
        'controls': controls,
        'decision_support': build_decision_support(controls, inventory),
        'supplemental_evidence': [],
        'resource_inventory': inventory,
    }


def review_for(rows=(), resources=(), audit_scope='product', classification=None):
    bundle = synthetic_bundle(rows, resources, audit_scope)
    return bundle, build_control_review(
        bundle, build_ledger(bundle), classification)


def finalized_classification(bundle):
    plans = bundle['decision_support']['plans']
    return {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': plan['number'],
            'final_classification': '対応済み',
            'resolution_state': 'FINALIZED',
            'rationale': 'Free-text rationale alone must not resolve gaps.',
            'missing_evidence': [],
            'evidence_refs': [f"finding:{plan['number']}:0"],
        } for plan in plans],
        'summary': {'finalized_count': 46, 'pending_count': 0,
                    **{label: (46 if label == '対応済み' else 0)
                       for label in FINAL_LABELS}},
    }


def request_for(requests, kind, requirement_key, scope_key='product'):
    return [r for r in requests if r.kind is kind
            and r.requirement_key == requirement_key
            and r.scope_key == scope_key]


def test_one_missing_scope_requirement_serves_shared_controls():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data')]
    _, review = review_for(rows)
    requests = build_evidence_requests(review)
    owners = request_for(requests, GapKind.OWNER_CONTEXT,
                         'product-resource-and-region-coverage')
    assert len(owners) == 1
    owner = owners[0]
    assert owner.controls == SHARED_SCOPE_CONTROLS
    assert owner.id == evidence_id('request', {
        'kind': 'OWNER_CONTEXT', 'scope': 'product',
        'requirement': 'product-resource-and-region-coverage'})
    # One shared request, referenced (not duplicated) by every shared row.
    attached = with_evidence_requests(review)
    for number in SHARED_SCOPE_CONTROLS:
        row_entry = attached.rows[number - 1]
        assert owner.id in row_entry.request_ids
    owner_ids = [tuple(attached.rows[n - 1].request_ids).count(owner.id)
                 for n in SHARED_SCOPE_CONTROLS]
    assert owner_ids == [1, 1, 1, 1]  # referenced once per shared row


def test_snapshot_context_reused_for_45_but_restore_drill_request_remains():
    resources = [{'resource_id': 'snap-aut', 'resource_type':
                  'db-cluster-snapshot', 'attribution': 'DIRECT',
                  'attributes': {'snapshot_type': 'automated'}}]
    rows = [row(20, 'effective storage encryption', 'PROPERTY_OK', ENCRYPTED,
                'db-cluster-snapshot', 'snap-aut')]
    _, review = review_for(rows, resources)
    requests = build_evidence_requests(review)
    drills = request_for(requests, GapKind.OWNER_DOCUMENT,
                         'restore-drill-success-record')
    assert len(drills) == 1 and drills[0].controls == (45,)
    # The cross-control snapshot observation never becomes drill proof.
    assert drills[0].evidence_refs == ()
    machine = [r for r in requests if r.kind is GapKind.MACHINE_EVIDENCE
               and 45 in r.controls]
    assert machine and all('snap' not in str(r.evidence_refs)
                           for r in machine)
    attached = with_evidence_requests(review)
    assert drills[0].id in attached.rows[44].request_ids
    # The retained cross-control ref lives in the criterion check only.
    existence = [c for c in attached.rows[44].criterion_checks
                 if 'existence' in c.component][0]
    fact_ids = {fact.id for fact in build_ledger(
        synthetic_bundle(rows, resources)).facts}
    assert existence.fact_refs and set(existence.fact_refs) <= fact_ids


def test_configuration_mismatch_retains_status_question():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_FAIL',
                [], 'bucket', 'syn-data')]
    _, review = review_for(rows)
    requests = build_evidence_requests(review)
    # Plan: an observed mismatch cannot alone resolve 未対応 versus 対応中;
    # the mismatched control keeps a REMEDIATION_STATUS status question.
    mismatch = request_for(requests, GapKind.REMEDIATION_STATUS,
                           'observed-mismatch-remediation-status')
    assert len(mismatch) == 1
    assert mismatch[0].controls == (17,)
    assert mismatch[0].evidence_refs  # backed by the observed facts only
    assert 'remediation status' in mismatch[0].required_evidence
    attached = with_evidence_requests(review)
    assert mismatch[0].id in attached.rows[16].request_ids
    # Only the shared Owner scope question remains beside the status one;
    # the machine-observation gap closed because a real observation exists.
    covering_17 = [r for r in requests if 17 in r.controls]
    kinds = {r.kind for r in covering_17}
    assert kinds == {GapKind.OWNER_CONTEXT, GapKind.REMEDIATION_STATUS}
    owner = request_for(requests, GapKind.OWNER_CONTEXT,
                        'product-resource-and-region-coverage')[0]
    assert owner.controls == SHARED_SCOPE_CONTROLS
    assert 'Owner-approved' in owner.required_evidence


def test_new_machine_setting_removes_only_corresponding_machine_gap():
    _, before = review_for()
    _, after = review_for(rows=[row(17, 'default_encryption_algorithms',
                                    'PROPERTY_OK', ['AES256'], 'bucket',
                                    'syn-data')])
    before_requests = build_evidence_requests(before)
    after_requests = build_evidence_requests(after)
    for review_requests in (before_requests, after_requests):
        assert len(request_for(review_requests, GapKind.MACHINE_EVIDENCE,
                               'missing-machine-observation')) == 1
    machine_before = request_for(
        before_requests, GapKind.MACHINE_EVIDENCE,
        'missing-machine-observation')[0]
    machine_after = request_for(
        after_requests, GapKind.MACHINE_EVIDENCE,
        'missing-machine-observation')[0]
    assert 17 in machine_before.controls
    assert 17 not in machine_after.controls
    # Scope and Owner questions are never removed by one machine setting.
    before_owner = request_for(
        before_requests, GapKind.OWNER_CONTEXT,
        'product-resource-and-region-coverage')[0]
    after_owner = request_for(
        after_requests, GapKind.OWNER_CONTEXT,
        'product-resource-and-region-coverage')[0]
    assert before_owner.controls == after_owner.controls
    assert before_owner.id == after_owner.id


def mcp_record(number, state, source='OPERATOR_CURATED_MCP_READONLY_SUMMARY'):
    return {
        'schema': 'aws-security-mcp-observation-summary-v1',
        'account': '123456789012', 'region': REGION, 'product': 'syn',
        'source': source,
        'records': [{'number': number, 'api': 'DescribeInstances',
                     'state': state, 'fact': f'synthetic {state} reading',
                     'scope_limit': 'Synthetic single-record scope.'}],
    }


def r24_record(state):
    return {
        'schema': 'aws-ros-r24-targeted-evidence-v1',
        'product': 'syn', 'account': '123456789012', 'region': REGION,
        'control_39_inspector': {'state': state},
    }


def machine_controls(review):
    requests = build_evidence_requests(review)
    machine = request_for(requests, GapKind.MACHINE_EVIDENCE,
                          'missing-machine-observation')
    return machine[0].controls


def review_with_supplements(**supplements):
    bundle = synthetic_bundle()
    ledger = build_ledger(bundle, **supplements)
    return build_control_review(bundle, ledger)


def test_unvalidated_supplement_facts_do_not_remove_machine_gap():
    # R24 NOT_REQUESTED / UNVERIFIED are query outcomes, not observations.
    for state in ('NOT_REQUESTED', 'UNVERIFIED'):
        review = review_with_supplements(r24=r24_record(state))
        assert 39 in machine_controls(review), state
    # A genuine R24 OBSERVED_PARTIAL reading does suppress the machine gap.
    review = review_with_supplements(r24=r24_record('OBSERVED_PARTIAL'))
    assert 39 not in machine_controls(review)
    # MCP UNVERIFIED rows carry field_present=False: never suppress.
    review = review_with_supplements(mcp_summary=mcp_record(8, 'UNVERIFIED'))
    assert 8 in machine_controls(review)
    # Assistant-curated MCP OBSERVED rows are arbitrary LLM claims.
    review = review_with_supplements(mcp_summary=mcp_record(
        8, 'OBSERVED', source='ASSISTANT_CURATED_MCP_READONLY_SUMMARY'))
    assert 8 in machine_controls(review)
    # Operator-curated MCP OBSERVED rows (field_present=True) do suppress.
    review = review_with_supplements(mcp_summary=mcp_record(8, 'OBSERVED'))
    assert 8 not in machine_controls(review)
    # A direct PROPERTY_OK observation of control #2 also removes only its
    # machine gap; no observation rows means no suppression anywhere.
    review = review_with_supplements()
    assert 2 in machine_controls(review)
    bundle = synthetic_bundle(rows=[row(2, 'PubliclyAccessible',
                                        'PROPERTY_OK', False,
                                        'db-instance', 'rds-1')])
    review = build_control_review(bundle, build_ledger(bundle))
    assert 2 not in machine_controls(review)


def test_fabricated_evidence_reference_rejected():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data')]
    _, review = review_for(rows)
    tampered = [replace(gap, evidence_refs=('fact:fabricated-ref',))
                for gap in review.rows[16].gaps]
    forged_rows = (tuple(review.rows[:16])
                   + (replace(review.rows[16], gaps=tuple(tampered)),)
                   + tuple(review.rows[17:]))
    with pytest.raises(ValueError):
        build_evidence_requests(replace(review, rows=forged_rows))


@pytest.mark.parametrize('attribute,value,message', [
    ('controls', (1,), 'forged'),
    ('acquisition_route', 'AWS_MANUAL_FIX_ALL', 'route'),
    ('required_evidence', '', 'required_evidence'),
], ids=['forged-attribution', 'unknown-route', 'empty-required-text'])
def test_invalid_gap_records_rejected(attribute, value, message):
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data')]
    _, review = review_for(rows)
    gaps = tuple(replace(gap, **{attribute: value})
                 for gap in review.rows[16].gaps)
    forged = list(review.rows)
    forged[16] = replace(review.rows[16], gaps=gaps)
    with pytest.raises(ValueError, match=message):
        build_evidence_requests(replace(review, rows=tuple(forged)))


def test_evidence_from_another_scope_cannot_resolve_or_merge():
    _, product_review = review_for()
    _, account_review = review_for(audit_scope='account')
    product = build_evidence_requests(product_review)
    account = build_evidence_requests(account_review)
    product_owner = request_for(
        product, GapKind.OWNER_CONTEXT,
        'product-resource-and-region-coverage')[0]
    account_owner = [r for r in account
                     if r.requirement_key == product_owner.requirement_key
                     and r.kind is product_owner.kind]
    assert len(account_owner) == 1
    assert account_owner[0].scope_key == 'account'
    assert account_owner[0].id != product_owner.id
    assert product_owner.id not in {r.id for r in account}


def test_free_text_labels_and_rationale_cannot_resolve_gaps():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data')]
    bundle_open, review_open = review_for(rows)
    bundle = synthetic_bundle(rows)
    review_final = build_control_review(
        bundle, build_ledger(bundle), finalized_classification(bundle))
    requests_open = build_evidence_requests(review_open)
    requests_final = build_evidence_requests(review_final)
    assert requests_open and requests_final
    assert requests_final == requests_open
    assert [r.id for r in with_evidence_requests(
        review_final).requests] == [r.id for r in requests_open]


def test_repeated_builds_keep_ids_and_ordering_identical():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data'),
            row(20, 'effective storage encryption', 'PROPERTY_OK', ENCRYPTED,
                'db-cluster', 'db-1')]
    _, review = review_for(rows)
    first = build_evidence_requests(review)
    second = build_evidence_requests(review)
    assert first == second
    assert [r.id for r in first] == [r.id for r in second]
    keys = [(r.scope_key, r.kind.value, r.requirement_key) for r in first]
    assert keys == sorted(keys, key=lambda k: (k[0], k[1], k[2]))
    assert with_evidence_requests(review) == with_evidence_requests(review)


def test_request_json_projection_shape():
    requests = build_evidence_requests(review_for()[1])
    projected = [request_to_json(r) for r in requests]
    assert projected and all(isinstance(r, dict) for r in projected)
    first = projected[0]
    assert set(first) == {'id', 'kind', 'scope_key', 'requirement_key',
                          'controls', 'evidence_refs', 'required_evidence',
                          'acquisition_route'}
    assert all(isinstance(c, int) for c in first['controls'])
    assert all(isinstance(x, str) for x in first['evidence_refs'])
    assert all(isinstance(request, EvidenceRequest)
               for request in requests)


def bundles_with_counts(rows=(), resources=(), audit_scope='product'):
    bundle = synthetic_bundle(rows, resources, audit_scope)
    counts = {}
    for n in range(1, 47):
        subset = [x for x in rows if x['number'] == n]
        counts[str(n)] = {
            'ok': sum(x['property_result'] == 'PROPERTY_OK' for x in subset),
            'fail': sum(x['property_result'] == 'PROPERTY_FAIL' for x in subset),
            'unknown': sum(x['property_result'] == 'PROPERTY_UNKNOWN'
                           for x in subset),
            'context': sum(x['property_result'] == 'CONTEXT_ONLY' for x in subset),
        }
    bundle['resource_inventory']['control_observations']['by_control'] = counts
    return bundle


def test_progress_report_integrates_requests_into_review_model():
    rows = [row(17, 'default_encryption_algorithms', 'PROPERTY_OK',
                ['AES256'], 'bucket', 'syn-data')]
    report = build_evidence_progress(bundles_with_counts(rows))
    review_json = report['control_review']
    requests = review_json['requests']
    assert requests and all('id' in r and 'controls' in r for r in requests)
    summary = report['summary']
    assert summary['outstanding_evidence_request_count'] == len(requests)
    ids = {r['id']: r for r in requests}
    owner = ids[[r['id'] for r in requests
                 if r['requirement_key'] ==
                 'product-resource-and-region-coverage'
                 and r['kind'] == 'OWNER_CONTEXT'][0]]
    assert owner['controls'] == list(SHARED_SCOPE_CONTROLS)
    for entry in report['controls']:
        assert set(entry['outstanding_request_ids']) <= set(ids)
        if entry['number'] in SHARED_SCOPE_CONTROLS:
            assert owner['id'] in entry['outstanding_request_ids']
    from aws_security_audit.evidence_progress_report import render_markdown
    assert '残る証拠要求' in render_markdown(report)


def test_decision_support_declares_request_contract_without_r21_change():
    controls = [{
        'number': definition.number, 'title': definition.title,
        'criterion': definition.criterion,
        'account_status': 'MANUAL_REVIEW', 'regional_status':
        'MANUAL_REVIEW', 'findings': [],
    } for definition in CHECKS]
    support = build_decision_support(controls, {})
    contract = support['evidence_request_contract']
    assert contract['grouping_key'] == ['kind', 'scope_key',
                                        'requirement_key']
    assert contract['not_part_of_classification_schema'] is True
    assert contract['machine_acquisition_hints_are_hints'] is True
    # The R21 output contract appears only when requested and stays
    # untouched by residual request work.
    assert support.get('output_contract') is None
    assert build_decision_support(controls, {}, r21_contract=True)[
        'output_contract'] is not None
