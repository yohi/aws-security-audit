"""Shared review-export projections: CSV/XLSX round trips, Markdown, handoffs.

The shared ReviewTables model is rendered through every export path and parsed
cells are compared back to the JSON projections: all 46 rows and fact/request
references must be identical. Synthetic fixtures only; no AWS access occurs.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from dataclasses import replace
from xml.etree import ElementTree as ET

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.control_review import control_review_to_json
from aws_security_audit.evidence_ledger import ledger_to_json
from aws_security_audit.evidence_progress_report import (
    PROGRESS_SCHEMA,
    build_evidence_progress,
    render_markdown,
    save_progress_report,
    )
from aws_security_audit.web_handoff import build_web_review_bundle
from aws_security_audit.evidence_types import (
    LEDGER_SCHEMA,
    SHEET_NAMES,
    EvidenceLedger,
)
from aws_security_audit.offline_classification import CONTROL_EVIDENCE_PLAN
from aws_security_audit.report import _safe_spreadsheet
from aws_security_audit.review_export import (
    cell_text,
    review_tables,
    tables_csv,
    tables_xlsx,
    truncation_text,
)

REVIEW_SHEET = SHEET_NAMES[0]
NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
REGION = 'ap-northeast-1'
BASE = 'aws_evidence_progress'


def empty_ledger() -> EvidenceLedger:
    return EvidenceLedger(LEDGER_SCHEMA, (), (), (), ())


def wired(review_model, ledger_model, **fact_edits):
    """Point row #22 at the synthetic fact/scope and row #46 at the request."""
    fact = ledger_model.facts[0]
    if fact_edits:
        fact = replace(fact, **fact_edits)
        ledger = replace(ledger_model, facts=(fact,))
    else:
        ledger = ledger_model
    rows = list(review_model.rows)
    rows[21] = replace(rows[21], fact_refs=(fact.id,),
                       scope_refs=(ledger.scope_checks[0].id,))
    rows[45] = replace(rows[45],
                       request_ids=tuple(r.id for r in review_model.requests))
    return replace(review_model, rows=tuple(rows)), ledger


def parse_csv(payload: bytes) -> list[dict]:
    return list(csv.DictReader(io.StringIO(payload.decode('utf-8-sig'))))


def parse_xlsx(payload: bytes, index: int) -> list[list[str]]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        root = ET.fromstring(archive.read(f'xl/worksheets/sheet{index}.xml'))
    return [[cell.find(f'{NS}is/{NS}t').text or ''
             for cell in row.iter(NS + 'c')]
            for row in root.iter(NS + 'row')]


def parse_sheet_names(payload: bytes) -> list[str]:
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        workbook = ET.fromstring(archive.read('xl/workbook.xml'))
    return [sheet.get('name') for sheet in workbook.iter(NS + 'sheet')]


def expected_xlsx_row(cells) -> list[str]:
    return [_safe_spreadsheet(cell_text(c)) for c in cells]


def test_review_tables_keeps_five_sheets_and_zero_evidence(review_model):
    tables = review_tables(review_model, empty_ledger())
    assert list(tables.tables) == list(SHEET_NAMES)
    assert len(tables.tables[REVIEW_SHEET].rows) == 46
    for table in tables.tables.values():
        assert all(isinstance(head, str) for head in table.headers)
        assert all(len(cells) == len(table.headers) for cells in table.rows)
        assert all(cell is None or isinstance(cell, (str, int, float, bool))
                   for cells in table.rows for cell in cells)
    assert tables.tables['証拠索引'].rows == ()
    assert tables.tables['取得状態'].rows == ()
    assert tables.tables['対象範囲'].rows == ()
    assert len(tables.tables['追加確認'].rows) == len(review_model.requests)


def test_csv_round_trip_equals_json_projection(review_model, ledger_model):
    review, ledger = wired(review_model, ledger_model)
    tables = review_tables(review, ledger)
    parsed = parse_csv(tables_csv(tables))
    review_json = control_review_to_json(review)['rows']
    headers = tables.tables[REVIEW_SHEET].headers
    assert len(parsed) == 46
    for index, cells in enumerate(tables.tables[REVIEW_SHEET].rows):
        data = parsed[index]
        for header, cell in zip(headers, cells):
            assert data[header] == truncation_text(cell_text(cell))
        # References equal the JSON projection of the same model, value for value.
        assert json.loads(data['証拠参照ID']) == review_json[index]['fact_refs']
        assert json.loads(data['追加確認ID']) == review_json[index]['request_ids']
    assert parsed[0]['チェック項目'] == CHECKS[0].title
    assert parsed[0]['推奨設定・確認基準'] == CHECKS[0].criterion


def test_xlsx_round_trip_equals_json_projection(review_model, ledger_model):
    review, ledger = wired(review_model, ledger_model)
    tables = review_tables(review, ledger)
    payload = tables_xlsx(tables)
    assert parse_sheet_names(payload) == list(SHEET_NAMES)
    for index, table in enumerate(tables.tables.values(), 1):
        matrix = [list(table.headers)] + [list(cells) for cells in table.rows]
        assert parse_xlsx(payload, index) == [expected_xlsx_row(cells)
                                              for cells in matrix]


def test_formula_and_xml_and_multiline_cells_stay_inert(review_model, ledger_model):
    value = '=SUM(A1)\n@attached'
    text = '<script>&"quote"\n2行目'
    review, ledger = wired(review_model, ledger_model, value=value,
                           interpretation=text, observed_at=None)
    tables = review_tables(review, ledger)
    fact_row = tables.tables['証拠索引'].rows[0]
    assert fact_row[5] == value and fact_row[6] == text  # JSON stays complete
    assert fact_row[8] is None  # undated evidence stays an explicit null
    parsed = parse_xlsx(tables_xlsx(tables), 2)
    assert parsed[1][5] == _safe_spreadsheet(value)
    assert parsed[1][5].startswith("'")  # formula prefix rendered inert
    assert parsed[1][6] == _safe_spreadsheet(text)  # XML escaped, multiline kept


def test_oversized_cells_truncate_with_explicit_pointers(review_model, ledger_model):
    huge = 'ア' * 40000
    review, ledger = wired(review_model, ledger_model, interpretation=huge)
    tables = review_tables(review, ledger)
    assert tables.tables['証拠索引'].rows[0][6] == huge  # JSON keeps everything
    xlsx_cell = parse_xlsx(tables_xlsx(tables), 2)[1][6]
    assert xlsx_cell == _safe_spreadsheet(huge)
    assert 'EXCEL CELL TRUNCATED' in xlsx_cell and len(xlsx_cell) <= 32767
    csv_pointer = truncation_text(huge)
    assert 'CELL TRUNCATED' in csv_pointer
    assert 'consult' in csv_pointer and len(csv_pointer) < len(huge)


def test_review_tables_rejects_dangling_refs_and_broken_shapes(review_model,
                                                               ledger_model):
    rows = list(review_model.rows)
    dangling = replace(rows[21], fact_refs=('fact:' + '0' * 64,))
    broken = tuple(rows[:21]) + (dangling,) + tuple(rows[22:])
    with pytest.raises(ValueError, match='dangling'):
        review_tables(replace(review_model, rows=broken), ledger_model)
    with pytest.raises(ValueError, match='46 ordered'):
        review_tables(replace(review_model, rows=tuple(rows[1:])), ledger_model)
    bad_request = replace(review_model.requests[0],
                          evidence_refs=('fact:' + '0' * 64,))
    with pytest.raises(ValueError, match='dangling'):
        review_tables(replace(review_model, requests=(bad_request,)), ledger_model)
    forged = tuple(replace(row, request_ids=('request:' + '0' * 64,))
                   if row.number == 46 else row for row in rows)
    with pytest.raises(ValueError, match='dangling'):
        review_tables(replace(review_model, rows=forged), ledger_model)
    with pytest.raises(ValueError, match='ControlReview'):
        review_tables(None, ledger_model)
    with pytest.raises(ValueError, match='EvidenceLedger'):
        review_tables(review_model, {'facts': []})


MCP = {
    'schema': 'aws-security-mcp-observation-summary-v1',
    'account': '123456789012', 'region': REGION, 'product': 'syn',
    'source': 'OPERATOR_CURATED_MCP_READONLY_SUMMARY',
    'records': [{'number': 8, 'api': 'GetSubscriptionState',
                 'state': 'UNVERIFIED', 'fact': 'synthetic unverified reading',
                 'scope_limit': '合成の単一読み取り範囲。'}],
}


def progress_source():
    controls, plans = [], []
    for number in range(1, 47):
        route, requirement, owner = CONTROL_EVIDENCE_PLAN[number]
        controls.append({'number': number, 'title': f'合成 #{number}',
                         'criterion': '合成基準',
                         'account_status': 'MANUAL_REVIEW',
                         'regional_status': 'MANUAL_REVIEW'})
        plans.append({'number': number, 'acquisition_route': route,
                      'preferred_evidence_request': requirement,
                      'human_context_required_by_criterion': owner})
    rows = [{'number': 22, 'property_result': 'PROPERTY_OK',
             'resource_id': 'synthetic-bucket', 'property': 'Status',
             'attribution': 'DIRECT'}]
    by = {str(n): {'ok': 1 if n == 22 else 0, 'fail': 0,
                   'unknown': 0, 'context': 0} for n in range(1, 47)}
    return {
        'schema': 'aws-security-audit-web-review-v1',
        'execution': {'product': 'syn', 'requested_regions': [REGION],
                      'audit_scope': 'product'},
        'controls': controls, 'decision_support': {'plans': plans},
        'resource_inventory': {'control_observations': {'rows': rows,
                                                        'by_control': by}},
    }


def synthetic_call(state: str, error: str | None) -> dict:
    return {'id': f'call:{state.lower()}-synthetic', 'execution_id': 'exec:syn',
            'service': 'ec2', 'operation': 'DescribeVolumes', 'region': REGION,
            'safe_selector': [], 'started_at': None, 'finished_at': None,
            'collection_state': state, 'error_code': error, 'page_count': None,
            'pagination_complete': False if state == 'PARTIAL' else None,
            'returned_count': None}


def test_markdown_exposes_undated_failed_partial_and_supplement_gap():
    report = build_evidence_progress(progress_source())
    md = render_markdown(report)
    assert '観測時刻が記録されていない証拠: 1件' in md and '#22' in md
    assert '取得失敗・アクセス拒否の呼び出し: 0件' in md
    assert '部分取得の呼び出し: 0件' in md
    assert '基準の機械観測がない項目: 45/46' in md
    assert 'R24/MCP補足のみあり: 0件' in md

    report['evidence_ledger']['calls'] = [
        synthetic_call('FAILED', 'AccessDenied'),
        synthetic_call('PARTIAL', None),
    ]
    md = render_markdown(report)
    assert '取得失敗・アクセス拒否の呼び出し: 1件' in md
    assert '部分取得の呼び出し: 1件' in md


def test_markdown_distinguishes_supplement_only_from_machine_observation():
    report = build_evidence_progress(progress_source(), mcp_summary=MCP)
    md = render_markdown(report)
    assert 'R24/MCP補足のみあり: 1件' in md
    assert '基準の機械観測がない項目: 45/46' in md
    assert '補足は検証済みの機械観測には含まれない' in md


def test_markdown_lists_outstanding_request_details():
    md = render_markdown(build_evidence_progress(progress_source()))
    # Request rows list kind/scope/requirement and route, not free text only.
    assert 'missing-machine-observation' in md
    assert 'AWS_READ_ONLY_CANDIDATE' in md
    assert 'product-resource-and-region-coverage' in md


def _web_metadata() -> dict:
    return {'version': '0.1.0', 'timestamp': '2026-10-19T00:00:00Z',
            'requested_regions': [REGION], 'available_regions': [REGION],
            'region_coverage_full': False}


def _web_rows() -> list[dict]:
    return [{'No': c.number, 'カテゴリ': c.category, 'チェック項目': c.title,
             '推奨設定・確認基準': c.criterion, '重要度': c.severity,
             '目的・対象リスク': c.purpose, '判定': 'MANUAL_REVIEW',
             '対象地域判定': 'MANUAL_REVIEW', '地域網羅': '一部リージョンのみ'}
            for c in CHECKS]


def test_web_bundle_embeds_shared_ledger_and_review(review_model, ledger_model):
    review, ledger = wired(review_model, ledger_model)
    bundle = build_web_review_bundle(_web_metadata(), _web_rows(), [], {},
                                     ledger=ledger, review=review)
    assert bundle['evidence_ledger'] == ledger_to_json(ledger)
    assert bundle['control_review'] == control_review_to_json(review)
    json.dumps(bundle, ensure_ascii=False)  # stays uploadable JSON
    plain = build_web_review_bundle(_web_metadata(), _web_rows(), [], {})
    assert 'evidence_ledger' not in plain and 'control_review' not in plain
    with pytest.raises(ValueError):
        build_web_review_bundle(_web_metadata(), _web_rows(), [], {},
                                ledger=ledger)


def _progress_report(review, ledger) -> dict:
    controls = []
    for check in CHECKS:
        observed = check.number == 22
        controls.append({
            'number': check.number, 'title': check.title,
            'scanner_status': 'MANUAL_REVIEW',
            'property_observation_counts': {'ok': 1 if observed else 0,
                                            'fail': 0, 'unknown': 0, 'context': 0},
            'machine_evidence_level': 'PARTIAL_POSITIVE_OBSERVATION' if observed
            else 'NO_PROPERTY_OBSERVATION',
            'evidence_route_description': 'AWS読み取り候補',
            'business_resolution_state': 'NOT_EVALUATED',
            'mcp_summary_observations': [], 'r24_evidence': [],
        })
    return {
        'schema': PROGRESS_SCHEMA,
        'purpose': 'EVIDENCE_PROGRESS_NOT_FINAL_COMPLIANCE',
        'source_bundle_execution': {},
        'evidence_ledger': ledger_to_json(ledger),
        'control_review': control_review_to_json(review),
        'source_validation': {'r24_supplied': False,
                              'mcp_summary_supplied': False},
        'summary': {
            'scanner_counts': {'MANUAL_REVIEW': 46},
            'original_attribute_observation_rows': 1,
            'original_controls_with_property_observations': 1,
            'controls_with_some_machine_evidence_including_supplements': 1,
            'evidence_pending_controls': None,
            'cross_control_machine_evidence_refs': 0,
            'outstanding_evidence_request_count': len(review.requests),
            'outstanding_evidence_request_scope_keys':
                sorted({r.scope_key for r in review.requests}),
            'owner_documentation_controls': [],
        },
        'controls': controls, 'limitations': [],
    }


EXPORT_NAMES = sorted(BASE + ext for ext in
                      ('.csv', '.json', '.manifest.json', '.md', '.xlsx'))


def test_progress_save_wires_csv_xlsx_and_manifest(tmp_path, review_model,
                                                   ledger_model):
    review, ledger = wired(review_model, ledger_model)
    paths = save_progress_report(str(tmp_path), _progress_report(review, ledger),
                                 review=review, ledger=ledger)
    assert [p.name for p in paths] == EXPORT_NAMES
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in paths)
    manifest = json.loads((tmp_path / f'{BASE}.manifest.json').read_text())
    payload_names = [e['filename'] for e in manifest['files']]
    assert payload_names == [n for n in EXPORT_NAMES
                             if 'manifest' not in n]
    for entry in manifest['files']:
        assert entry['sha256'] == hashlib.sha256(
            (tmp_path / entry['filename']).read_bytes()).hexdigest()
    assert manifest['input_digests'] == {ledger.executions[0].id: 'ab' * 32}
    csv_path = next(p for p in paths if p.suffix == '.csv')
    parsed = parse_csv(csv_path.read_bytes())
    assert json.loads(parsed[21]['証拠参照ID']) == list(review.rows[21].fact_refs)


def test_progress_save_rejects_review_model_mismatch_before_writing(
        tmp_path, review_model, ledger_model):
    review, ledger = wired(review_model, ledger_model)
    tampered = dict(_progress_report(review, ledger), control_review={})
    with pytest.raises(ValueError, match='review model'):
        save_progress_report(str(tmp_path), tampered, review=review, ledger=ledger)
    assert list(tmp_path.glob('*')) == []


def test_progress_save_without_models_keeps_legacy_two_files(tmp_path):
    report = build_evidence_progress(progress_source())
    paths = save_progress_report(str(tmp_path), report)
    assert [p.suffix for p in paths] == ['.json', '.md']
