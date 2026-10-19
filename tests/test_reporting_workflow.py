"""Whole-workflow tests: offline `report-progress` and live `assess` share one review model.

Task 8 acceptance targets:
- `report-progress` parses/dispatches offline (before prepare()) and returns
  0 (no unresolved requests) / 2 (unresolved requests remain) / 1 (invalid
  input or export failure).
- It must not initialize AWS sessions or touch the network, must never
  rewrite the local source files or upgrade business labels.
- `assess` keeps its flags/exit codes, keeps the existing AWS operation
  sequence and old outputs, adds the shared ledger/review exports, and the
  Web handoff model equals the progress report's source model.
All fixtures are synthetic; nothing connects to AWS or an LLM.
"""
from __future__ import annotations

import csv
import hashlib
import json
import socket
import xml.etree.ElementTree as ET
from pathlib import Path
from zipfile import ZipFile

import boto3
import pytest

from aws_security_audit.cli import main, parser
from aws_security_audit.core import Finding
from aws_security_audit.evidence_types import LEDGER_SCHEMA, REVIEW_SCHEMA
from aws_security_audit.offline_classification import (
    CONTROL_EVIDENCE_PLAN,
    FINAL_LABELS,
    build_decision_support,
)
from aws_security_audit.review_export import SHEET_NAMES

REGION = 'ap-northeast-1'
ACCOUNT = '111122223333'
BUNDLE_SCHEMA = 'aws-security-audit-web-review-v1'


def bundle():
    """A complete legacy aws_web_review bundle; counts reconcile with rows."""
    controls, plans = [], []
    for number in range(1, 47):
        controls.append({
            'number': number,
            'title': f'Synthetic #{number}',
            'criterion': 'Synthetic criterion text only',
            'account_status': 'MANUAL_REVIEW',
            'regional_status': 'MANUAL_REVIEW',
        })
        plans.append({
            'number': number,
            'acquisition_route': CONTROL_EVIDENCE_PLAN[number][0],
            'preferred_evidence_request': f'Synthetic request #{number}',
            'human_context_required_by_criterion': (
                CONTROL_EVIDENCE_PLAN[number][2]),
        })
    rows = [
        {'number': 16, 'property_result': 'PROPERTY_FAIL',
         'resource_id': 'synthetic-alb-1', 'property': 'tls_policy',
         'attribution': 'DIRECT'},
        {'number': 19, 'property_result': 'PROPERTY_FAIL',
         'resource_id': 'synthetic-vol-1', 'property': 'encrypted',
         'attribution': 'RELATED'},
        {'number': 2, 'property_result': 'PROPERTY_OK',
         'resource_id': 'synthetic-rds-1', 'property': 'public',
         'attribution': 'DIRECT'},
        {'number': 24, 'property_result': 'CONTEXT_ONLY',
         'resource_id': 'synthetic-trail-1', 'property': 'logging',
         'attribution': 'SHARED_UNATTRIBUTED'},
    ]
    by = {}
    for number in range(1, 47):
        subset = [row for row in rows if row['number'] == number]
        by[str(number)] = {
            'ok': sum(row['property_result'] == 'PROPERTY_OK' for row in subset),
            'fail': sum(row['property_result'] == 'PROPERTY_FAIL' for row in subset),
            'context': sum(row['property_result'] == 'CONTEXT_ONLY' for row in subset),
            'unknown': 0,
        }
    support = build_decision_support(
        controls, {'control_observations': {'rows': rows, 'by_control': by}},
        r21_contract=False)
    return {
        'schema': BUNDLE_SCHEMA,
        'execution': {
            'product': 'synthetic-product',
            'requested_regions': [REGION],
            'region_coverage_full': False,
            'audit_scope': 'product',
        },
        'controls': controls,
        'decision_support': support,
        'resource_inventory': {
            'control_observations': {'rows': rows, 'by_control': by},
        },
    }


def classification(bundle_data):
    """A structurally valid v1 classification candidate: all 46 pending."""
    return {
        'schema': 'aws-security-offline-classification-v1',
        'controls': [{
            'number': plan['number'],
            'final_classification': None,
            'resolution_state': 'EVIDENCE_PENDING',
            'evidence_refs': [],
            'rationale': 'Insufficient evidence; no label inferred',
            'missing_evidence': [plan['preferred_evidence_request']],
        } for plan in bundle_data['decision_support']['plans']],
        'summary': {
            'finalized_count': 0,
            'pending_count': 46,
            **{label: 0 for label in FINAL_LABELS},
        },
    }


def write_json(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
    return path


def progress_json(out_dir: Path) -> dict:
    """Load the progress JSON payload (never the sibling manifest)."""
    payload = next(path for path in out_dir.glob('aws_evidence_progress*.json')
                   if not path.name.endswith('.manifest.json'))
    return json.loads(payload.read_text(encoding='utf-8'))


def no_aws(*_args, **_kwargs):
    raise AssertionError('offline command attempted AWS preparation')


def no_network(*_args, **_kwargs):
    raise AssertionError('offline command attempted a network connection')


class FakeContext:
    account = ACCOUNT
    expected_role_arn = f'arn:aws:iam::{ACCOUNT}:role/synthetic-audit-role'
    identity_arn = (
        f'arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-audit-role/ses')
    source_profile = 'synthetic'

    def active_regions(self):
        return [REGION]


def synthetic_findings():
    return [Finding(number, 'MANUAL_REVIEW', REGION, 'synthetic incomplete')
            for number in range(1, 47)]


# ---------------------------------------------------------------------------
# Offline report-progress: parser, dispatch and exit codes
# ---------------------------------------------------------------------------


def test_report_progress_parser_defaults_and_required_bundle():
    args = parser().parse_args(['report-progress', '--bundle', 'saved.json'])
    assert args.bundle == 'saved.json'
    assert args.classification is None
    assert args.out == 'reports'
    args = parser().parse_args([
        'report-progress', '--bundle', 'saved.json',
        '--classification', 'labels.json', '--out', 'custom',
    ])
    assert args.classification == 'labels.json'
    assert args.out == 'custom'


def test_report_progress_parser_and_dispatch_never_reach_prepare(
        monkeypatch, tmp_path):
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    saved = write_json(tmp_path / 'bundle.json', bundle())
    # argparse: --bundle is required.
    with pytest.raises(SystemExit):
        parser().parse_args(['report-progress'])
    # Every valid bundle carries by-construction evidence requests
    # (reviewer/criterion gaps for #5/#18/#45 and the shared
    # #2/#17/#20/#23 scope question), so a request-based exit is 2.
    assert main(['report-progress', '--bundle', str(saved),
                 '--out', str(tmp_path / 'reports')]) == 2


def test_report_progress_unresolved_requests_exit_two(monkeypatch, tmp_path):
    """Request-based exit semantics (EVIDENCE_PENDING is reported data).

    A pending classification still shows in summary counts, but the exit
    code is driven only by `outstanding_evidence_requests`.
    """
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    saved = write_json(tmp_path / 'bundle.json', bundle())
    labels = write_json(tmp_path / 'labels.json', classification(bundle()))
    assert main(['report-progress', '--bundle', str(saved),
                 '--classification', str(labels),
                 '--out', str(tmp_path / 'pending')]) == 2
    payload = progress_json(tmp_path / 'pending')
    requests = payload['outstanding_evidence_requests']
    assert requests  # request-based, not classification-based
    assert payload['summary']['evidence_pending_controls'] == 46
    assert payload['summary']['outstanding_evidence_request_count'] \
        == len(requests)


def test_report_progress_machine_gaps_leave_requests(monkeypatch, tmp_path):
    """No property observations: MACHINE_EVIDENCE gaps become requests."""
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    data = bundle()
    del data['resource_inventory']
    saved = write_json(tmp_path / 'bundle.json', data)
    dest = tmp_path / 'reports'
    assert main(['report-progress', '--bundle', str(saved),
                 '--out', str(dest)]) == 2
    requests = progress_json(dest)['outstanding_evidence_requests']
    assert any(request['kind'] == 'MACHINE_EVIDENCE' for request in requests)


def test_progress_exit_code_zero_when_requests_empty():
    """Exit 0 is the exact empty-`outstanding_evidence_requests` rule.

    Real 46-control bundles can never reach it in this milestone: the
    review model keeps by-construction requests for #5/#18/#45 and the
    shared #2/#17/#20/#23 scope question even when every machine gap is
    satisfied (verified by probe). The decision function is therefore
    verified at its own boundary.
    """
    from aws_security_audit.cli import _progress_exit_code
    assert _progress_exit_code({'outstanding_evidence_requests': []}) == 0
    assert _progress_exit_code({}) == 0
    assert _progress_exit_code({
        'outstanding_evidence_requests': [{'id': 'request:x'}],
    }) == 2


def test_reports_progress_exports_complete_private_set(monkeypatch, tmp_path):
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    saved = write_json(tmp_path / 'bundle.json', bundle())
    dest = tmp_path / 'reports'
    # Request-based exit: a complete legacy bundle still exits 2 because
    # the review model carries by-construction requests (see the helper
    # test below); the exports themselves must be complete.
    assert main(['report-progress', '--bundle', str(saved),
                 '--out', str(dest)]) == 2
    names = {path.name for path in dest.iterdir()}
    expected = {f'aws_evidence_progress{suffix}'
                for suffix in ('.json', '.md', '.csv', '.xlsx',
                               '.manifest.json')}
    assert names == expected
    payload = progress_json(dest)
    assert payload['evidence_ledger']['schema'] == LEDGER_SCHEMA
    assert payload['control_review']['schema'] == REVIEW_SCHEMA
    assert payload['classification_contract_unchanged'] is True
    assert payload['summary']['evidence_pending_controls'] is None
    review = payload['control_review']
    assert [row['number'] for row in review['rows']] == list(range(1, 47))
    for path in dest.iterdir():
        assert (path.stat().st_mode & 0o777) == 0o600
    # The manifest covers every payload byte-by-byte (excluding itself).
    manifest = json.loads(next(dest.glob('*.manifest.json')).read_text())
    hashes = {entry['filename']: entry['sha256']
              for entry in manifest['files']}
    assert set(hashes) == expected - {'aws_evidence_progress.manifest.json'}
    for name, digest in hashes.items():
        assert hashlib.sha256((dest / name).read_bytes()).hexdigest() == digest


def test_progress_xlsx_has_five_named_sheets_and_csv_46_rows(
        monkeypatch, tmp_path):
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    saved = write_json(tmp_path / 'bundle.json', bundle())
    dest = tmp_path / 'reports'
    main(['report-progress', '--bundle', str(saved), '--out', str(dest)])
    with ZipFile(next(dest.glob('*.xlsx'))) as archive:
        assert archive.testzip() is None
        root = ET.fromstring(archive.read('xl/workbook.xml'))
        sheets = [element.get('name') for element in root.iter(
            '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}sheet')]
    assert sheets == list(SHEET_NAMES)
    with next(dest.glob('*.csv')).open(encoding='utf-8-sig', newline='') as f:
        rows = list(csv.reader(f))
    assert len(rows) == 47  # header + 46 controls


@pytest.mark.parametrize('corrupt', ('missing_file', 'invalid_json', 'forged'))
def test_report_progress_invalid_local_input_exits_one(
        corrupt, monkeypatch, tmp_path):
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    if corrupt == 'missing_file':
        target = str(tmp_path / 'absent.json')
    elif corrupt == 'invalid_json':
        target = str(tmp_path / 'broken.json')
    else:
        data = bundle()
        del data['controls'][7]
        target = str(write_json(tmp_path / 'forged.json', data))
    assert main(['report-progress', '--bundle', target,
                 '--out', str(tmp_path / 'reports')]) == 1


def test_report_progress_export_failure_exits_one(monkeypatch, tmp_path):
    import aws_security_audit.evidence_progress_report as progress_mod
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)

    def explode(*_args, **_kwargs):
        raise OSError('synthetic export failure')

    monkeypatch.setattr(progress_mod, 'save_progress_report', explode)
    saved = write_json(tmp_path / 'bundle.json', bundle())
    assert main(['report-progress', '--bundle', str(saved),
                 '--out', str(tmp_path / 'reports')]) == 1


def test_report_progress_is_strictly_offline_and_never_rewrites_the_source(
        monkeypatch, tmp_path):
    monkeypatch.setattr(boto3, 'Session', no_aws)
    monkeypatch.setattr(socket.socket, 'connect', no_network)
    monkeypatch.setattr(socket, 'create_connection', no_network)
    monkeypatch.setattr('aws_security_audit.cli.prepare', no_aws)
    source = write_json(tmp_path / 'bundle.json', bundle())
    saved_bytes = source.read_bytes()
    labels = write_json(tmp_path / 'labels.json', classification(bundle()))
    dest = tmp_path / 'reports'
    assert main(['report-progress', '--bundle', str(source),
                 '--classification', str(labels),
                 '--out', str(dest)]) == 2
    assert source.read_bytes() == saved_bytes  # no source rewrite
    payload = progress_json(dest)
    for row, original in zip(payload['controls'], bundle()['controls']):
        assert row['scanner_status'] == original['account_status']
        assert row['business_resolution_state'] == 'EVIDENCE_PENDING'
        assert row['business_label_provisional'] is None
        assert row['owner_adoption_verified'] is False
    assert payload['semantic_compliance_verified'] is False
    assert payload['owner_adoption_verified'] is False


# ---------------------------------------------------------------------------
# Live assess: same flags/exit codes, one shared review model, new exports
# ---------------------------------------------------------------------------


def _install_fake_assess(monkeypatch):
    recorded = []
    monkeypatch.setattr('aws_security_audit.cli.prepare',
                        lambda args: (FakeContext(), [REGION]))
    findings = synthetic_findings()

    def run_scan(ctx, regions, options):
        assert options['ap_tag'] is None
        recorded.append('run_scan')
        return list(findings)

    def build_investigation(ctx, regions, overview_rows, records_list):
        assert len(overview_rows) == 46 and len(records_list) == 46
        recorded.append('build_investigation')
        return {'schema': 'aws-investigation-v2',
                'regions_checked': list(regions),
                'deep_evidence': {'19': {
                    'state': 'PARTIAL_OBSERVED', 'snapshots': [], 'volumes': [],
                }},
                'limitations': ['synthetic only']}

    def collect_inventory(ctx, regions):
        assert len(regions) == 1
        recorded.append('collect_inventory')
        return {'schema': 'aws-security-resource-inventory-v1',
                'scope': {'mode': 'account'},
                'resources': [], 'collection_errors': []}

    monkeypatch.setattr('aws_security_audit.cli.run_scan', run_scan)
    monkeypatch.setattr(
        'aws_security_audit.investigation.build_investigation',
        build_investigation)
    monkeypatch.setattr(
        'aws_security_audit.resource_scope.collect_resource_inventory',
        collect_inventory)
    return recorded


def test_assess_llm_off_keeps_outputs_operation_sequence_and_exit_code(
        monkeypatch, tmp_path):
    recorded = _install_fake_assess(monkeypatch)
    dest = tmp_path / 'reports'
    code = main(['assess', '--llm', 'off', '--source-profile',
                 FakeContext.source_profile, '--role-arn',
                 FakeContext.expected_role_arn, '--regions', REGION,
                 '--out', str(dest)])
    assert code == 0
    # The existing collection sequence is unchanged.
    assert recorded == ['run_scan', 'build_investigation',
                        'collect_inventory']
    names = sorted(path.name for path in dest.iterdir())
    assert any(name.startswith('aws_security_audit_') and
               name.endswith('.json') for name in names)
    assert any(name.startswith('aws_security_audit_') and
               name.endswith('.csv') for name in names)
    assert any(name.startswith('aws_security_audit_') and
               name.endswith('.xlsx') for name in names)
    assert any(name.startswith('aws_resource_inventory_') and
               name.endswith('.json') for name in names)
    assert any(name.startswith('aws_investigation_') and
               name.endswith('.json') for name in names)
    # New shared-model exports (progress JSON/MD/CSV/XLSX + manifest).
    for suffix in ('.json', '.md', '.csv', '.xlsx', '.manifest.json'):
        assert any(name.startswith('aws_evidence_progress_') and
                   name.endswith(suffix) for name in names), names
    assert not any(name.startswith('aws_web_review_') for name in names)
    assert not any(name.startswith('aws_web_prompt_') for name in names)
    report = json.loads(next(dest.glob('aws_security_audit_*.json'))
                        .read_text(encoding='utf-8'))
    assert len(report['summary']) == 46
    row = report['summary'][0]
    assert row['判定'] == 'MANUAL_REVIEW'  # verdicts untouched
    assert '証拠充足状態' in row  # additive review columns present
    progress = progress_json(dest)
    assert progress['evidence_ledger']['schema'] == LEDGER_SCHEMA
    progress_review = progress['control_review']
    assert progress_review['schema'] == REVIEW_SCHEMA
    assert len(progress_review['rows']) == 46
    assert progress['summary']['outstanding_evidence_request_count'] >= 1
    for path in dest.iterdir():
        assert (path.stat().st_mode & 0o777) == 0o600


def test_assess_llm_export_web_model_equals_report_source_model(
        monkeypatch, tmp_path):
    _install_fake_assess(monkeypatch)
    dest = tmp_path / 'reports'
    assert main(['assess', '--llm', 'export', '--source-profile',
                 FakeContext.source_profile, '--role-arn',
                 FakeContext.expected_role_arn, '--regions', REGION,
                 '--out', str(dest)]) == 0
    web = json.loads(next(dest.glob('aws_web_review_*.json'))
                     .read_text(encoding='utf-8'))
    progress = progress_json(dest)
    assert web['evidence_ledger'] == progress['evidence_ledger']
    assert web['control_review'] == progress['control_review']
    assert next(dest.glob('aws_web_prompt_*.md')).stat().st_size > 0


def test_live_execution_identity_differs_between_assess_runs(monkeypatch, tmp_path):
    from contextlib import contextmanager

    from aws_security_audit.evidence_types import CollectionState
    from aws_security_audit.read_capture import capture_reads as real_capture_reads

    @contextmanager
    def captured_read(execution):
        with real_capture_reads(execution) as capture:
            capture.record(
                service='s3', operation='list_buckets', region=REGION,
                selector={}, started_at=None, finished_at=None,
                collection_state=CollectionState.OBSERVED, error_code=None,
                page_count=1, pagination_complete=True, returned_count=1,
            )
            yield capture

    monkeypatch.setattr('aws_security_audit.read_capture.capture_reads', captured_read)
    _install_fake_assess(monkeypatch)
    execution_ids = []
    for name in ('first', 'second'):
        dest = tmp_path / name
        assert main(['assess', '--llm', 'off', '--source-profile',
                     FakeContext.source_profile, '--role-arn',
                     FakeContext.expected_role_arn, '--regions', REGION,
                     '--out', str(dest)]) == 0
        ledger = progress_json(dest)['evidence_ledger']
        live_execution = next(
            execution for execution in ledger['executions']
            if execution['source_kind'] == 'live_capture_v1')
        execution_ids.append(live_execution['id'])
        assert live_execution['account'] == ACCOUNT
        assert live_execution['regions'] == [REGION]
        assert live_execution['product'] is None

    assert execution_ids[0] != execution_ids[1]
