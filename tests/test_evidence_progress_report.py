"""Offline evidence progress: do not turn a scanner manual flag into 43 human tasks."""
from __future__ import annotations

import json

import pytest

from aws_security_audit import cli
from aws_security_audit.evidence_progress_report import (
    MCP_SCHEMA, PROGRESS_SCHEMA, build_evidence_progress,
    render_markdown, save_progress_report,
)
from aws_security_audit.offline_classification import CONTROL_EVIDENCE_PLAN


def source():
    controls = []
    plans = []
    for number in range(1, 47):
        route, requirement, owner = CONTROL_EVIDENCE_PLAN[number]
        controls.append({
            'number': number, 'title': f'Test #{number}',
            'criterion': 'Synthetic only',
            'account_status': ('FAIL' if number in (16, 19, 22) else 'MANUAL_REVIEW'),
            'regional_status': 'MANUAL_REVIEW',
        })
        plans.append({
            'number': number,
            'acquisition_route': route,
            'preferred_evidence_request': requirement,
            'human_context_required_by_criterion': owner,
        })
    rows = [
        {'number': 16, 'property_result': 'PROPERTY_FAIL', 'resource_id': 'alb-1',
         'property': 'tls_policy', 'attribution': 'DIRECT'},
        {'number': 19, 'property_result': 'PROPERTY_FAIL', 'resource_id': 'vol-1',
         'property': 'encrypted', 'attribution': 'RELATED'},
        {'number': 2, 'property_result': 'PROPERTY_OK', 'resource_id': 'rds-1',
         'property': 'public', 'attribution': 'DIRECT'},
        {'number': 24, 'property_result': 'CONTEXT_ONLY', 'resource_id': 'trail-1',
         'property': 'logging', 'attribution': 'SHARED_UNATTRIBUTED'},
    ]
    by = {}
    for n in range(1, 47):
        subset = [x for x in rows if x['number'] == n]
        by[str(n)] = {
            'ok': sum(x['property_result'] == 'PROPERTY_OK' for x in subset),
            'fail': sum(x['property_result'] == 'PROPERTY_FAIL' for x in subset),
            'context': sum(x['property_result'] == 'CONTEXT_ONLY' for x in subset),
            'unknown': 0,
        }
    return {
        'schema': 'aws-security-audit-web-review-v1',
        'execution': {'product': 'ros', 'requested_regions': ['ap-northeast-1'],
                      'region_coverage_full': False, 'audit_scope': 'product'},
        'controls': controls, 'decision_support': {'plans': plans},
        'resource_inventory': {'control_observations': {
            'rows': rows, 'by_control': by,
        }},
    }


def mcp():
    return {
        'schema': MCP_SCHEMA,
        'account': '123456789012',
        'region': 'ap-northeast-1',
        'product': 'ros',
        'source': 'OPERATOR_CURATED_MCP_READONLY_SUMMARY',
        'records': [
            {'number': 8, 'api': 'shield.GetSubscriptionState',
             'state': 'OBSERVED', 'fact': 'SubscriptionState=INACTIVE',
             'scope_limit': 'Account subscription, not a final Owner classification'},
        ],
    }


def test_progress_counts_not_43_manual_checks_and_keeps_fail_scopes():
    x = build_evidence_progress(source())
    assert x['schema'] == PROGRESS_SCHEMA
    counts = x['summary']
    assert counts['scanner_counts'] == {'MANUAL_REVIEW': 43, 'FAIL': 3}
    assert counts['original_attribute_observation_rows'] == 4
    assert counts['original_controls_with_property_observations'] == 4
    assert counts['controls_with_no_machine_evidence_including_supplements'] == 42
    assert counts['owner_documentation_controls'] == [42, 43, 44, 46]
    assert counts['acquisition_route_counts'] == {
        'AWS_PLUS_OWNER_SCOPE': 24, 'AWS_READ_ONLY_CANDIDATE': 15,
        'NON_AWS_EXPORT_CANDIDATE': 3, 'OWNER_DOCUMENTATION': 4,
    }
    assert counts['purely_manual_check_count'] is None
    assert x['controls'][18]['machine_evidence_level'] == 'SCOPED_NEGATIVE_OBSERVATION'
    assert x['controls'][18]['property_observation_counts']['fail'] == 1
    assert x['controls'][18]['owner_adoption_verified'] is False
    assert x['semantic_compliance_verified'] is False


def test_r24_and_mcp_evidence_increase_information_not_business_pass():
    r24 = {
        'schema': 'aws-ros-r24-targeted-evidence-v1',
        'product': 'ros', 'account': '123456789012', 'region': 'ap-northeast-1',
        'control_39_inspector': {'state': 'OBSERVED_PARTIAL'},
        'control_39_ecr': {'state': 'NOT_REQUESTED'},
    }
    x = build_evidence_progress(
        source(), r24=r24, mcp_summary=mcp(), expected_account='123456789012',
    )
    assert x['summary']['original_controls_with_property_observations'] == 4
    assert x['summary']['controls_with_some_machine_evidence_including_supplements'] == 6
    assert x['controls'][7]['mcp_summary_observations'][0]['fact'] == 'SubscriptionState=INACTIVE'
    assert x['controls'][7]['business_label_provisional'] is None
    assert x['controls'][38]['r24_evidence'] == [
        {'source': 'control_39_inspector', 'state': 'OBSERVED_PARTIAL'},
        {'source': 'control_39_ecr', 'state': 'NOT_REQUESTED'},
    ]
    assert x['owner_adoption_verified'] is False


@pytest.mark.parametrize('mutate', [
    lambda a: a.update(account='999999999999'),
    lambda a: a.update(product='other'),
    lambda a: a.update(region='us-east-1'),
    lambda a: a['records'][0].update(number=47),
    lambda a: a['records'][0].update(api='iam.DeleteUser'),
    lambda a: a['records'][0].update(api='sts.AssumeRole'),
    lambda a: a['records'][0].update(state='PASS'),
    lambda a: a['records'][0].update(fact=''),
])
def test_mcp_evidence_rejects_bad_scope_and_mutations(mutate):
    data = mcp()
    mutate(data)
    with pytest.raises(ValueError):
        build_evidence_progress(source(), mcp_summary=data, expected_account='123456789012')


def test_source_evidence_count_mismatch_fail_closed():
    data = source()
    data['resource_inventory']['control_observations']['by_control']['16']['fail'] = 5
    with pytest.raises(ValueError, match='reconcile'):
        build_evidence_progress(data)


def test_invalid_scanner_and_missing_normative_control_rejected():
    data = source()
    data['controls'][1]['account_status'] = '対応済み'
    with pytest.raises(ValueError):
        build_evidence_progress(data)
    data = source()
    data['controls'][0]['number'] = 3
    with pytest.raises(ValueError):
        build_evidence_progress(data)


def test_markdown_report_and_private_json_files(tmp_path):
    b = source()
    b['controls'][0]['title'] = 'Title | injection'
    p = build_evidence_progress(b, mcp_summary=mcp(), expected_account='123456789012')
    paths = save_progress_report(str(tmp_path), p)
    assert len(paths) == 2
    assert [x.suffix for x in paths] == ['.json', '.md']
    assert all((x.stat().st_mode & 0o777) == 0o600 for x in paths)
    assert '43 EVIDENCE_PENDING' not in paths[1].read_text()
    assert '43件を手動' not in paths[1].read_text()
    assert 'Title \\| injection' in paths[1].read_text()
    assert json.loads(paths[0].read_text())['summary']['controls'] == 46
    assert 'SubscriptionState=INACTIVE' in render_markdown(p)


def test_offline_progress_cli_never_calls_aws(monkeypatch, tmp_path, capsys):
    b = tmp_path / 'source.json'
    b.write_text(json.dumps(source()), encoding='utf-8')
    monkeypatch.setattr(cli, 'prepare', lambda *a, **k: (_ for _ in ()).throw(
        AssertionError('AWS initialization prohibited')))
    dest = tmp_path / 'progress'
    assert cli.main(['report-progress', '--bundle', str(b), '--out', str(dest)]) == 0
    assert (dest / 'aws_evidence_progress.json').exists()
    assert 'original_controls_with_property_observations' in capsys.readouterr().out


def test_classification_is_structurally_validated_before_use(monkeypatch):
    import aws_security_audit.evidence_progress_report as mod
    def invalid(*args):
        raise ValueError('invalid classification reference')
    monkeypatch.setattr(mod, 'validate_classification_result', invalid)
    with pytest.raises(ValueError, match='invalid classification'):
        build_evidence_progress(source(), classification={'controls': []})
