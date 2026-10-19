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
    # Request-based exit contract: a valid bundle keeps by-construction
    # outstanding evidence requests, so success means exit 2 (Task 8).
    assert cli.main(['report-progress', '--bundle', str(b), '--out', str(dest)]) == 2
    assert (dest / 'aws_evidence_progress.json').exists()
    assert 'original_controls_with_property_observations' in capsys.readouterr().out


def test_classification_is_structurally_validated_before_use(monkeypatch):
    import aws_security_audit.evidence_progress_report as mod
    def invalid(*args):
        raise ValueError('invalid classification reference')
    monkeypatch.setattr(mod, 'validate_classification_result', invalid)
    with pytest.raises(ValueError, match='invalid classification'):
        build_evidence_progress(source(), classification={'controls': []})


def test_assistant_curated_mcp_source_is_explicit_and_unattested():
    data = mcp()
    data['source'] = 'ASSISTANT_CURATED_MCP_READONLY_SUMMARY'
    report = build_evidence_progress(
        source(), mcp_summary=data, expected_account='123456789012',
    )
    assert report['source_validation']['mcp_summary_source'] == data['source']
    assert report['source_validation']['mcp_summary_independent_runtime_attestation'] is False


def test_unverified_r24_api_error_not_miscounted_as_machine_observation():
    r24 = {
        'schema': 'aws-ros-r24-targeted-evidence-v1',
        'product': 'ros', 'account': '123456789012', 'region': 'ap-northeast-1',
        'control_8_shield': {'state': 'UNVERIFIED'},
    }
    report = build_evidence_progress(
        source(), r24=r24, expected_account='123456789012',
    )
    assert report['summary']['controls_with_some_machine_evidence_including_supplements'] == 4
    assert report['controls'][7]['r24_evidence'][0]['state'] == 'UNVERIFIED'


def test_original_csv_excel_report_relabels_manual_as_scanner_not_human(tmp_path):
    import csv
    from zipfile import ZipFile
    from aws_security_audit.catalog import CHECKS
    from aws_security_audit.core import Finding
    from aws_security_audit.report import export_report

    obs = {'rows': [], 'by_control': {str(n): {
        'ok': (1 if n == 2 else 0),
        'fail': 0, 'unknown': 0, 'context': 0,
        'evidence_state': 'PARTIAL_RESOURCE_EVIDENCE' if n == 2
        else 'NO_RESOURCE_EVIDENCE',
    } for n in range(1, 47)}}
    findings = [Finding(c.number, 'MANUAL_REVIEW', 'ap-northeast-1', 'unknown')
                for c in CHECKS]
    output = export_report(
        str(tmp_path), findings, {'timestamp': '2026-10-18T13:00:00+00:00',
                                  'region_coverage_full': False},
        resource_inventory={'resources': [], 'control_observations': obs},
    )
    j = json.loads(next(p for p in output if p.suffix == '.json').read_text())
    assert j['summary'][1]['判定'] == 'MANUAL_REVIEW'
    assert j['summary'][1]['確認済み属性OK'] == 1
    assert j['summary'][1]['次の証拠取得経路'] == 'AWS_READ_ONLY_CANDIDATE'
    assert '手動作業件数ではない' in j['summary'][1]['判定の意味']
    assert '観測あり' in j['summary'][1]['機械観測の状態']
    assert '観測なし' in j['summary'][0]['機械観測の状態']
    with next(p for p in output if p.suffix == '.csv').open(
        encoding='utf-8-sig') as f:
        csv_rows = list(csv.DictReader(f))
    assert csv_rows[1]['次の証拠取得経路'] == 'AWS_READ_ONLY_CANDIDATE'
    with ZipFile(next(p for p in output if p.suffix == '.xlsx')) as z:
        assert 'スキャナー保留' in z.read('xl/worksheets/sheet1.xml').decode()
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in output)



def test_verified_automated_snapshot_reused_for_45_without_restore_claim():
    evidence = source()
    evidence['resource_inventory']['resources'] = [{
        'resource_id': 'snap-ros-automated',
        'resource_type': 'db-cluster-snapshot',
        'attribution': 'DIRECT',
        'attributes': {'snapshot_type': 'automated'},
    }]
    evidence['resource_inventory']['control_observations']['rows'].append({
        'number': 20,
        'property_result': 'PROPERTY_OK',
        'resource_id': 'snap-ros-automated',
        'resource_type': 'db-cluster-snapshot',
        'attribution': 'DIRECT',
        'property': 'effective storage encryption',
        'observed_value': {
            'encrypted': True,
            'encryption_state': 'ENCRYPTED',
            'storage_encryption_type': 'sse-kms',
        },
    })
    evidence['resource_inventory']['control_observations']['by_control']['20']['ok'] = 1
    report = build_evidence_progress(evidence)
    assert report['summary']['original_controls_with_property_observations'] == 5
    assert report['summary']['cross_control_machine_evidence_refs'] == 1
    assert report['summary']['controls_with_cross_control_machine_evidence'] == [45]
    assert report['summary']['controls_with_some_machine_evidence_including_supplements'] == 6
    row = report['controls'][44]
    assert row['number'] == 45
    assert row['scanner_status'] == 'MANUAL_REVIEW'
    assert row['business_resolution_state'] == 'NOT_EVALUATED'
    assert row['machine_evidence_level'] == 'CROSS_CONTROL_MACHINE_CONTEXT'
    assert row['cross_control_machine_evidence'][0]['fact_type'] == 'AUTOMATED_RDS_SNAPSHOT_EXISTS'
    assert 'successful restore drill' in row['cross_control_machine_evidence'][0]['does_not_prove']
    assert row['owner_adoption_verified'] is False


def test_embedded_control_review_is_validated_and_reused():
    from aws_security_audit.control_review import (
        build_control_review, control_review_to_json,
    )
    from aws_security_audit.evidence_adapters import build_ledger
    from aws_security_audit.evidence_ledger import ledger_to_json
    from aws_security_audit.evidence_progress_report import (
        build_evidence_progress_with_model,
    )
    from aws_security_audit.evidence_requests import with_evidence_requests

    bundle = source()
    ledger = build_ledger(bundle)
    review = with_evidence_requests(build_control_review(bundle, ledger, None))
    bundle['evidence_ledger'] = ledger_to_json(ledger)
    bundle['control_review'] = control_review_to_json(review)

    report, reused_review, reused_ledger = build_evidence_progress_with_model(bundle)

    assert reused_review == review
    assert reused_ledger == ledger
    assert report['control_review'] == bundle['control_review']


def test_embedded_control_review_is_rebuilt_when_supplement_is_supplied():
    from aws_security_audit.control_review import (
        build_control_review, control_review_to_json,
    )
    from aws_security_audit.evidence_adapters import build_ledger
    from aws_security_audit.evidence_ledger import ledger_to_json
    from aws_security_audit.evidence_progress_report import (
        build_evidence_progress_with_model,
    )
    from aws_security_audit.evidence_requests import with_evidence_requests

    bundle = source()
    ledger = build_ledger(bundle)
    review = with_evidence_requests(build_control_review(bundle, ledger, None))
    bundle['evidence_ledger'] = ledger_to_json(ledger)
    bundle['control_review'] = control_review_to_json(review)

    report, rebuilt_review, supplemented_ledger = build_evidence_progress_with_model(
        bundle, mcp_summary=mcp())

    assert rebuilt_review != review
    assert report['control_review'] == control_review_to_json(rebuilt_review)
    mcp_fact_ids = {fact.id for fact in supplemented_ledger.facts
                    if fact.source_ref.startswith('mcp_summary.records[')}
    assert mcp_fact_ids & set(rebuilt_review.rows[7].fact_refs)


def test_invalid_embedded_control_review_fails_closed():
    from aws_security_audit.evidence_progress_report import (
        build_evidence_progress_with_model,
    )

    bundle = source()
    bundle['control_review'] = {
        'schema': 'aws-security-control-review-v1',
        'rows': [],
        'requests': [],
    }
    with pytest.raises(ValueError):
        build_evidence_progress_with_model(bundle)


def test_invalid_embedded_control_review_fails_with_classification(monkeypatch):
    from aws_security_audit.control_review import build_control_review
    import aws_security_audit.control_review_input as review_input
    from aws_security_audit.evidence_adapters import build_ledger

    bundle = source()
    bundle['control_review'] = {
        'schema': 'aws-security-control-review-v1',
        'rows': [],
        'requests': [],
    }
    ledger = build_ledger(bundle)

    def without_classification(source_bundle, source_ledger, _candidate):
        return build_control_review(source_bundle, source_ledger, None)

    monkeypatch.setattr(review_input, 'build_control_review', without_classification)

    with pytest.raises(ValueError):
        review_input.review_for_bundle(bundle, ledger, {'candidate': 'present'})


def test_control_review_parser_rejects_wrong_primitive_type():
    from aws_security_audit.control_review import (
        build_control_review, control_review_to_json,
    )
    from aws_security_audit.control_review_parser import parse_control_review
    from aws_security_audit.evidence_adapters import build_ledger
    from aws_security_audit.evidence_requests import with_evidence_requests

    bundle = source()
    review = with_evidence_requests(build_control_review(
        bundle, build_ledger(bundle), None))
    malformed = control_review_to_json(review)
    malformed['rows'][0]['owner_adoption_verified'] = 'false'

    with pytest.raises(ValueError, match='owner_adoption_verified'):
        parse_control_review(malformed)
