"""Shared review-table projections for JSON, CSV, XLSX, Markdown and Web.

`review_tables` is the single projection of a ControlReview plus an
EvidenceLedger into the five named sheets (`evidence_types.SHEET_NAMES`);
every other format renders exactly these scalar cells, so references and
statuses cannot diverge between formats. JSON stays authoritative: nested
values become JSON text cells, and display rendering (formula-prefixing,
XML escaping, truncation) applies only at CSV/XLSX output time.
"""
from __future__ import annotations

import csv
import json
import math
from .evidence_ledger import _plain as _plain_json
from .evidence_types import (
    REVIEW_SCHEMA, ControlReview, ControlReviewRow, EvidenceLedger,
    JsonValue, ReviewTable, ReviewTables, SHEET_NAMES,
)

TABLES_SCHEMA = 'aws-security-review-tables-v1'
TEXT_LIMIT = 31000
TRUNCATION_POINTER = '\n[CELL TRUNCATED — consult the JSON export for the complete value]'

_REVIEW_HEADERS = (
    'No', 'カテゴリ', 'チェック項目', '推奨設定・確認基準', '重要度',
    '目的・対象リスク', 'スキャナー判定', 'スキャナー地域別判定', '証拠充足状態',
    '証拠参照ID', '対象範囲参照ID', '未確定理由', '分類進捗',
    '保留ラベル（要Owner採用）', '追加確認ID',
)
_FACT_HEADERS = (
    '証拠ID', 'No', '資源キー', 'フィールド', 'フィールド有無', '観測値',
    '解釈', '範囲限界', '観測時刻', '来歴', '参照元', '取得呼び出しID',
)
_CALL_HEADERS = (
    '呼び出しID', 'サービス', '操作', 'リージョン', '取得状態', 'エラーコード',
    'ページ数', 'ページング完了', '返却件数', '開始時刻', '終了時刻', '安全セレクタ',
)
_SCOPE_HEADERS = (
    '範囲確認ID', 'サービス', '選定根拠', 'カバレッジ状態', '選択資源',
    '候補資源', '限界', '確認呼び出しID',
)
_REQUEST_HEADERS = (
    '確認要求ID', '種別', 'スコープ', '要求鍵', '対象項目',
    '必要な証拠', '取得経路', '根拠参照ID',
)


def _cell(value: object) -> JsonValue:
    """One scalar cell; lists/dicts become deterministic JSON text, null stays null."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, tuple):
        value = list(value)
    if isinstance(value, list):
        return json.dumps(_plain_json(value), ensure_ascii=False,
                          separators=(', ', ': '))
    if isinstance(value, dict):
        return json.dumps(_plain_json(value), ensure_ascii=False, sort_keys=True,
                          separators=(', ', ': '))
    raise ValueError(
        f'review table cell: value of type {type(value).__name__} is not JSON')


def cell_text(value: object) -> str:
    """Display text of one scalar cell; JSON null shows as an empty cell."""
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return value if isinstance(value, str) else str(value)


def truncation_text(text: str) -> str:
    """CSV keeps the JSON-complete cell below the Excel cell-size ceiling."""
    if len(text) > TEXT_LIMIT:
        return text[:TEXT_LIMIT] + TRUNCATION_POINTER
    return text


def open_reasons(row: ControlReviewRow) -> JsonValue:
    """Remaining explicit questions of one row (JSON text or null)."""
    keys = sorted({f'{gap.kind.value}:{gap.requirement_key}' for gap in row.gaps})
    return _cell(keys) if keys else None


def _review_row(row: ControlReviewRow) -> tuple:
    return (
        row.number, row.category, row.title, row.criterion, row.severity,
        row.purpose, row.scanner_status.value,
        _cell({region: status.value
               for region, status in row.scanner_regional_status.items()}),
        row.evidence_state.value, _cell(row.fact_refs), _cell(row.scope_refs),
        open_reasons(row), row.business_resolution_state.value,
        row.business_label_provisional, _cell(row.request_ids),
    )


def _fact_row(fact) -> tuple:
    return (fact.id, fact.number, fact.resource_key, fact.field_path,
            fact.field_present, _cell(fact.value), fact.interpretation,
            fact.scope_limit, fact.observed_at, fact.provenance_level.value,
            fact.source_ref, _cell(fact.call_refs))


def _call_row(call) -> tuple:
    return (call.id, call.service, call.operation, call.region,
            call.collection_state.value, call.error_code, call.page_count,
            call.pagination_complete, call.returned_count, call.started_at,
            call.finished_at, _cell(call.safe_selector))


def _scope_row(scope) -> tuple:
    return (scope.id, scope.service, scope.selector_basis,
            scope.coverage_state.value, _cell(scope.selected_resource_keys),
            _cell(scope.candidate_resource_keys), _cell(scope.limitations),
            _cell(scope.call_refs))


def _request_row(request) -> tuple:
    return (request.id, request.kind.value, request.scope_key,
            request.requirement_key, _cell(request.controls),
            request.required_evidence, request.acquisition_route,
            _cell(request.evidence_refs))


def _validated(review: ControlReview,
               ledger: EvidenceLedger) -> tuple[ControlReview, EvidenceLedger]:
    if not isinstance(review, ControlReview) or review.schema != REVIEW_SCHEMA:
        raise ValueError('review_tables expects a ControlReview '
                         f'with schema {REVIEW_SCHEMA}')
    if not isinstance(ledger, EvidenceLedger):
        raise ValueError('review_tables expects an EvidenceLedger')
    if [row.number for row in review.rows] != list(range(1, 47)):
        raise ValueError('review_tables expects exactly 46 ordered review rows')
    known = ({fact.id for fact in ledger.facts}
             | {scope.id for scope in ledger.scope_checks})

    def _refs(refs, label: str) -> None:
        for ref in refs:
            if ref not in known:
                raise ValueError(f'review_tables: dangling {label} reference {ref!r}')

    request_ids = {request.id for request in review.requests}
    for request in review.requests:
        _refs(request.evidence_refs, 'request evidence')
    for row in review.rows:
        _refs(row.fact_refs, 'fact')
        _refs(row.scope_refs, 'scope')
        for check in row.criterion_checks:
            _refs(check.fact_refs, 'fact')
            _refs(check.scope_refs, 'scope')
        for gap in row.gaps:
            _refs(gap.evidence_refs, 'gap evidence')
        for ref in row.request_ids:
            if ref not in request_ids:
                raise ValueError(
                    f'review_tables: dangling request reference {ref!r}')
    return review, ledger


def review_tables(review: ControlReview, ledger: EvidenceLedger) -> ReviewTables:
    review, ledger = _validated(review, ledger)
    tables = {
        SHEET_NAMES[0]: ReviewTable(
            _REVIEW_HEADERS, tuple(_review_row(row) for row in review.rows)),
        SHEET_NAMES[1]: ReviewTable(
            _FACT_HEADERS, tuple(_fact_row(f) for f in ledger.facts)),
        SHEET_NAMES[2]: ReviewTable(
            _CALL_HEADERS, tuple(_call_row(c) for c in ledger.calls)),
        SHEET_NAMES[3]: ReviewTable(
            _SCOPE_HEADERS, tuple(_scope_row(s) for s in ledger.scope_checks)),
        SHEET_NAMES[4]: ReviewTable(
            _REQUEST_HEADERS, tuple(_request_row(r) for r in review.requests)),
    }
    return ReviewTables(TABLES_SCHEMA, tables)


def _sheet_matrices(tables: ReviewTables) -> list[tuple[str, list[list[str]]]]:
    out = []
    for name in SHEET_NAMES:
        table = tables.tables[name]
        cells = ([list(table.headers)]
                 + [[truncation_text(cell_text(cell)) for cell in row]
                    for row in table.rows])
        out.append((name, cells))
    return out


def tables_csv(tables: ReviewTables) -> bytes:
    from io import StringIO
    name, matrix = _sheet_matrices(tables)[0]
    header, *rows = matrix
    if name != SHEET_NAMES[0]:
        raise ValueError('review export expects the 46-row review sheet first')
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator='\n')
    writer.writerows((header, *rows))
    return ('\ufeff' + buffer.getvalue()).encode('utf-8')


def tables_xlsx(tables: ReviewTables) -> bytes:
    """The five named sheets as a private XLSX payload via the shared builder."""
    from .report import _workbook_bytes
    matrices = _sheet_matrices(tables)
    if [name for name, _ in matrices] != list(SHEET_NAMES):
        raise ValueError('review export expects exactly the five named sheets')
    sheets = []
    for name, matrix in matrices:
        widths = [min(70, max(10, math.ceil(max(
            [8.0] + [len(row[column]) for row in matrix[:51]]) * 1.15)))
            for column in range(len(matrix[0]))]
        sheets.append((name, matrix, widths))
    return _workbook_bytes(sheets)
