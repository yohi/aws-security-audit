"""R18 offline-only 46-item classification and evidence acquisition tests."""
from __future__ import annotations

import json

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.cli import main
from aws_security_audit.core import Finding
from aws_security_audit.offline_classification import (
    CONTROL_EVIDENCE_PLAN, FINAL_LABELS, build_decision_support,
    validate_classification_result,
)
from aws_security_audit.web_handoff import (
    WEB_CLASSIFICATION_PROMPT, build_web_review_bundle, save_web_handoff,
)


def _bundle():
    rows = [{
        'No': item.number, 'カテゴリ': item.category,
        'チェック項目': item.title, '推奨設定・確認基準': item.criterion,
        '重要度': item.severity, '目的・対象リスク': item.purpose,
        '判定': 'MANUAL_REVIEW',
        '対象地域判定': 'MANUAL_REVIEW', '地域網羅': '一部リージョンのみ',
    } for item in CHECKS]
    findings = [Finding(n, 'MANUAL_REVIEW', 'ap-northeast-1',
                        'evidence incomplete') for n in range(1, 47)]
    inventory = {'schema': 'aws-security-resource-inventory-v1',
                 'resources': [], 'collection_errors': [],
                 'control_observations': {
                     'by_control': {'16': {'observed_resources': 1}},
                     'rows': [{
                         'number': 16, 'resource_id': 'alb-example',
                         'property_result': 'PROPERTY_FAIL',
                         'property': 'tls_protocols',
                         'observed_value': ['TLSv1.0'],
                     }],
                 }}
    return build_web_review_bundle(
        {'requested_regions': ['ap-northeast-1'], 'audit_scope': 'product',
         'product': 'ros', 'timestamp': '2026-10-18T05:44:17+00:00'},
        rows, findings, {'schema': 'test', 'regions_checked': [],
                         'deep_evidence': {}, 'limitations': []},
        resource_inventory=inventory)


def _response(bundle):
    return {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': p['number'],
            'final_classification': None,
            'resolution_state': 'EVIDENCE_PENDING',
            'evidence_refs': [],
            'rationale': 'Insufficient evidence; no label inferred',
            'missing_evidence': [p['preferred_evidence_request']],
        } for p in bundle['decision_support']['plans']],
        'summary': {'finalized_count': 0, 'pending_count': 46,
                    **{label: 0 for label in FINAL_LABELS}},
    }


def test_every_control_has_distinct_route_and_actionable_evidence_request():
    assert set(CONTROL_EVIDENCE_PLAN) == set(range(1, 47))
    bundle = _bundle()
    assert bundle['automatic_upload'] is False
    assert bundle['classification_intent'] == 'OFFLINE_46_CONTROL_FOUR_STATE_ADVISORY'
    support = bundle['decision_support']
    assert support['llm_aws_access'] == 'PROHIBITED'
    assert support['manual_checks_minimization'] == (
        'AUTO_EVIDENCE_FIRST_THEN_ONLY_BLOCKING_OWNER_INPUT')
    assert len(support['plans']) == 46
    assert sum(support['counts_by_acquisition_route'].values()) == 46
    assert [p['number'] for p in support['plans']] == list(range(1, 47))
    assert all(p['preferred_evidence_request'] for p in support['plans'])
    assert support['plans'][15]['evidence_refs'][-1]['id'] == 'observation:16:0'
    assert all(p['classification_status'] == 'NOT_EVALUATED' for p in support['plans'])
    assert support['plans'][21]['number'] == 22
    assert support['plans'][22]['number'] == 23


def test_complete_pending_contract_is_valid_but_not_finalized():
    bundle = _bundle()
    check = validate_classification_result(bundle, _response(bundle))
    assert check['structure_and_reference_check'] == 'PASS'
    assert check['semantic_compliance_verified'] is False
    assert check['pending_count'] == 46
    assert check['status'] == 'INCOMPLETE'


def test_one_evidence_linked_final_label_is_structurally_accepted_only():
    bundle = _bundle()
    response = _response(bundle)
    control = response['controls'][15]
    control.update(final_classification='未対応', resolution_state='FINALIZED',
                   evidence_refs=['observation:16:0'],
                   rationale='Observed legacy TLS in selected application listener',
                   missing_evidence=[])
    response['summary'].update(finalized_count=1, pending_count=45, 未対応=1)
    check = validate_classification_result(bundle, response)
    assert check['counts']['未対応'] == 1
    assert check['semantic_compliance_verified'] is False
    assert check['owner_adoption_verified'] is False


@pytest.mark.parametrize('failure', (
    'missing', 'duplicate', 'reorder', 'made_up_citation',
    'cross_control', 'manual_is_in_progress', 'invalid_null',
    'no_proof_final', 'bad_count', 'bad_supplemental',
))
def test_malformed_or_unsupported_classification_is_rejected(failure):
    bundle = _bundle()
    result = _response(bundle)
    row = result['controls'][0]
    if failure == 'missing':
        result['controls'].pop()
    elif failure == 'duplicate':
        result['controls'][-1]['number'] = 1
    elif failure == 'reorder':
        result['controls'] = list(reversed(result['controls']))
    elif failure == 'made_up_citation':
        row['evidence_refs'] = ['fake:1']
    elif failure == 'cross_control':
        row['evidence_refs'] = ['finding:16:0']
    elif failure == 'manual_is_in_progress':
        row['final_classification'] = '対応中'
    elif failure == 'invalid_null':
        row['resolution_state'] = 'FINALIZED'
    elif failure == 'no_proof_final':
        row['resolution_state'] = 'FINALIZED'
        row['final_classification'] = '対応済み'
        row['missing_evidence'] = []
    elif failure == 'bad_count':
        result['summary']['pending_count'] = 45
    else:
        bundle['supplemental_evidence'] = [
            {'id': 'bad id', 'source': 'private.doc', 'collected_at': 'now'}]
    with pytest.raises(ValueError):
        validate_classification_result(bundle, result)


def test_explicit_supplemental_document_reference_is_allowed_structurally():
    bundle = _bundle()
    bundle['supplemental_evidence'] = [{
        'id': 'owner-runbook-42',
        'source': 'manual-uploaded-and-reviewed-runbook.txt',
        'collected_at': '2026-10-18T05:50:00+00:00',
        'control_numbers': [42],
    }]
    result = _response(bundle)
    row = result['controls'][41]
    row.update(final_classification='対応済み', resolution_state='FINALIZED',
               evidence_refs=['supplemental:owner-runbook-42'],
               missing_evidence=[], rationale='Evidence document supports claimed procedure')
    result['summary'].update(finalized_count=1, pending_count=45, 対応済み=1)
    assert validate_classification_result(bundle, result)['finalized_count'] == 1


def test_validation_cli_never_uses_aws_session_and_returns_incomplete_exit(tmp_path, monkeypatch, capsys):
    import aws_security_audit.cli as cli

    def no_aws(*args, **kwargs):
        raise AssertionError('offline validator attempted AWS')
    monkeypatch.setattr(cli, 'prepare', no_aws)
    bundle = _bundle()
    input_file = tmp_path / 'audit.json'
    output_file = tmp_path / 'labels.json'
    input_file.write_text(json.dumps(bundle, ensure_ascii=False))
    output_file.write_text(json.dumps(_response(bundle), ensure_ascii=False))
    assert main(['validate-classification', '--bundle', str(input_file),
                 '--result', str(output_file)]) == 2
    assert json.loads(capsys.readouterr().out)['pending_count'] == 46


def test_validator_rejects_tampered_provenance_index_and_cross_scoped_document():
    bundle = _bundle()
    result = _response(bundle)
    bundle['decision_support']['plans'][0]['evidence_refs'].append({
        'id': 'finding:1:999',
        'source': 'controls[number=1].findings[999]',
        'kind': 'ENGINE_FINDING',
    })
    with pytest.raises(ValueError, match='index'):
        validate_classification_result(bundle, result)

    bundle = _bundle()
    bundle['supplemental_evidence'] = [{
        'id': 'incident-plan',
        'source': 'incident-runbook.md',
        'collected_at': '2026-10-18T06:00:00+00:00',
        'control_numbers': [42],
    }]
    result = _response(bundle)
    result['controls'][43]['evidence_refs'] = ['supplemental:incident-plan']
    with pytest.raises(ValueError, match='cross-control'):
        validate_classification_result(bundle, result)


def test_no_bool_control_id_or_final_with_missing_evidence():
    bundle = _bundle()
    result = _response(bundle)
    result['controls'][0]['number'] = True
    with pytest.raises(ValueError):
        validate_classification_result(bundle, result)
    result = _response(bundle)
    row = result['controls'][0]
    row.update(final_classification='未対応',
               resolution_state='FINALIZED',
               evidence_refs=['finding:1:0'])
    result['summary'].update(finalized_count=1, pending_count=45, 未対応=1)
    with pytest.raises(ValueError, match='blocking gaps'):
        validate_classification_result(bundle, result)


def test_web_handoff_primary_prompt_demands_offline_four_state_with_pending(tmp_path):
    bundle = _bundle()
    paths = save_web_handoff(str(tmp_path), bundle)
    assert len(paths) == 2
    prompt = paths[1].read_text()
    for term in ('対応済み', '未対応', '対応中', '対象外', 'EVIDENCE_PENDING',
                 'AWS API', 'MCP', 'UNKNOWN', 'MANUAL_REVIEW', '実行コマンドの提案・実施'):
        assert term in prompt
    assert prompt == WEB_CLASSIFICATION_PROMPT
    assert json.loads(paths[0].read_text())['decision_support']['plans'][0]['number'] == 1
