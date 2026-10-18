"""Dependency-free JSON/CSV/XLSX reporters. Do not persist tokens, secrets, raw AWS SDK responses."""
from __future__ import annotations

import csv
import json
import os
from collections import Counter
from io import BytesIO
from pathlib import Path
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile

from .catalog import CHECKS
from .core import Finding, overall_status


NS = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'


def _summary_preview(value: str) -> str:
    """Only summary cells are shortened; findings JSON retains the complete evidence."""
    if len(value) > 31000:
        return value[:31000] + '\n[SUMMARY TRUNCATED — inspect findings JSON or web review for full evidence]'
    return value


def overall_rows(results: list[Finding], *, coverage_full: bool = False,
                 observations: dict | None = None) -> list[dict]:
    by_id = {c.number: [] for c in CHECKS}
    for finding in results:
        by_id[finding.number].append(finding)
    output = []
    for check in CHECKS:
        findings = by_id[check.number]
        regional_status = overall_status([f.status for f in findings]) if findings else 'UNKNOWN'
        # Scope-limited PASS is not evidence for full-account compliance.
        account_status = 'UNKNOWN' if regional_status == 'PASS' and not coverage_full else regional_status
        output.append({
            'No': check.number,
            'カテゴリ': check.category,
            'チェック項目': check.title,
            '推奨設定・確認基準': check.criterion,
            '重要度': check.severity,
            '目的・対象リスク': check.purpose,
            '判定': account_status,
            '対象地域判定': regional_status,
            '地域網羅': '全リージョン' if coverage_full else '一部リージョンのみ',
            '判定詳細': ('リージョン未網羅: アカウント全体のPASSは保留 | ' if account_status == 'UNKNOWN' and regional_status == 'PASS' else '') + (' | '.join(f'{f.scope}: {f.detail}' for f in findings) or '検査未実行'),
            '対象': ', '.join(f.scope for f in findings),
            '証拠・要確認事項': _summary_preview('\n'.join(f'{f.scope}: {e}' for f in findings for e in f.evidence)),
        })

    if observations is not None:
        from .offline_classification import CONTROL_EVIDENCE_PLAN
        for row in output:
            stats = observations.get('by_control', {}).get(str(row['No']), {})
            row['確認済み属性OK'] = stats.get('ok', 0)
            row['確認済み属性NG'] = stats.get('fail', 0)
            row['属性未確認・参考'] = stats.get('unknown', 0) + stats.get('context', 0)
            row['属性証拠カバレッジ'] = stats.get('evidence_state', 'NO_RESOURCE_EVIDENCE')
            # The scanner status is immutable; these additive columns explain
            # actual machine evidence without implying 43 human tasks or PASS.
            row['判定の意味'] = (
                'スキャナー保留（手動作業件数ではない）'
                if row['判定'] == 'MANUAL_REVIEW'
                else 'スキャナーの技術判定（Owner最終分類ではない）'
            )
            row['機械観測の状態'] = (
                '対象属性の観測あり（プロダクト全体の適合とは別）'
                if sum(stats.get(k, 0) for k in ('ok', 'fail', 'unknown', 'context'))
                else '対象属性の機械観測なし（手動作業確定ではない）'
            )
            row['次の証拠取得経路'] = CONTROL_EVIDENCE_PLAN[row['No']][0]
    return output


def _safe_spreadsheet(value: object) -> str:
    text = str(value if value is not None else '')
    # Excel cells hold at most 32,767 characters; complete data remain in JSON.
    if len(text) > 31000:
        text = text[:31000] + '\\n[EXCEL CELL TRUNCATED — consult JSON for complete evidence]'
    if text.startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
        return "'" + text
    return text


def _col(n: int) -> str:
    string = ''
    while n:
        n, mod = divmod(n - 1, 26)
        string = chr(65 + mod) + string
    return string


def _sheet_xml(matrix: list[list[str]], widths: list[float], *, filter_header: bool = True) -> bytes:
    worksheet = ET.Element('worksheet', xmlns=NS)
    views = ET.SubElement(worksheet, 'sheetViews')
    ET.SubElement(views, 'sheetView', workbookViewId='0').append(ET.Element('pane', ySplit='1', topLeftCell='A2', activePane='bottomLeft', state='frozen'))
    cols = ET.SubElement(worksheet, 'cols')
    for i, width in enumerate(widths, start=1):
        ET.SubElement(cols, 'col', min=str(i), max=str(i), width=str(width), customWidth='1')
    data = ET.SubElement(worksheet, 'sheetData')
    for r, values in enumerate(matrix, start=1):
        row = ET.SubElement(data, 'row', r=str(r))
        for c, value in enumerate(values, start=1):
            cell = ET.SubElement(row, 'c', r=f'{_col(c)}{r}', t='inlineStr', s='1' if r == 1 else '0')
            inline = ET.SubElement(cell, 'is')
            ET.SubElement(inline, 't').text = _safe_spreadsheet(value)
    if filter_header and matrix:
        ET.SubElement(worksheet, 'autoFilter', ref=f'A1:{_col(len(matrix[0]))}{len(matrix)}')
    return ET.tostring(worksheet, encoding='utf-8', xml_declaration=True)


def _excel_bytes(rows: list[dict], details: list[dict], meta: dict,
                 resources: list[dict] | None = None,
                 observations: list[dict] | None = None) -> bytes:
    wb = BytesIO()
    summary_keys = list(rows[0])
    detail_keys = ['No', 'scope', 'status', 'detail', 'evidence']
    tables = [
        ([summary_keys] + [[str(x.get(k, '')) for k in summary_keys] for x in rows], [8, 22, 32, 65, 12, 46, 19, 19, 24, 65, 32, 75, 17, 17, 18, 30, 45, 56, 30][:len(summary_keys)]),
        ([detail_keys] + [[str(d.get(k, '')) for k in detail_keys] for d in details], [8, 25, 19, 65, 78]),
        ([['項目', '値']] + [[k, str(v)] for k, v in meta.items()], [28, 100]),
    ]
    resource_keys = ['service', 'resource_type', 'region', 'name', 'resource_id', 'arn',
                     'attribution', 'attribution_evidence', 'tags', 'attributes']
    resource_lines = []
    for resource in resources or []:
        resource_lines.append([
            json.dumps(resource.get(key), ensure_ascii=False, sort_keys=True)
            if key in ('tags', 'attributes') else str(resource.get(key, ''))
            for key in resource_keys
        ])
    tables.append(([resource_keys] + resource_lines, [18, 22, 20, 42, 35, 72, 19, 48, 55, 70]))
    if observations is not None:
        obs_keys = ['number', 'control', 'property_result', 'service',
                    'resource_type', 'region', 'name', 'resource_id', 'arn',
                    'attribution', 'property', 'observed_value', 'interpretation', 'scope_limit']
        obs_lines = [[json.dumps(r.get(key), ensure_ascii=False, sort_keys=True)
                      if key == 'observed_value' else str(r.get(key, ''))
                      for key in obs_keys] for r in observations]
        tables.append(([obs_keys] + obs_lines,
                       [10, 28, 21, 16, 24, 18, 32, 32, 68, 17, 35, 70, 70, 70]))
    with ZipFile(wb, 'w', ZIP_DEFLATED) as arc:
        arc.writestr('[Content_Types].xml', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet4.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' + ('<Override PartName="/xl/worksheets/sheet5.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' if observations is not None else '') + '</Types>')
        arc.writestr('_rels/.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        arc.writestr('xl/workbook.xml', f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="{NS}" xmlns:r="{REL}"><sheets><sheet name="46項目サマリー" sheetId="1" r:id="rId1"/><sheet name="地域別証拠" sheetId="2" r:id="rId2"/><sheet name="実行メタデータ" sheetId="3" r:id="rId3"/><sheet name="リソース台帳" sheetId="4" r:id="rId4"/>{'<sheet name="属性別検証結果" sheetId="5" r:id="rId6"/>' if observations is not None else ''}</sheets></workbook>')
        arc.writestr('xl/_rels/workbook.xml.rels', '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet4.xml"/>' + ('<Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet5.xml"/>' if observations is not None else '') + '</Relationships>')
        arc.writestr('xl/styles.xml', f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="{NS}"><fonts count="2"><font><sz val="10"/><name val="Aptos"/></font><font><b/><sz val="10"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF153A59"/><bgColor indexed="64"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs></styleSheet>')
        for i, (matrix, widths) in enumerate(tables, 1):
            arc.writestr(f'xl/worksheets/sheet{i}.xml', _sheet_xml(matrix, widths))
    return wb.getvalue()


def _private_bytes(path: Path, content: bytes) -> None:
    # Exclusive write and mode 0600 on POSIX; never overwrite a previous run.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def export_report(out_dir: str, findings: list[Finding], metadata: dict, resource_inventory: dict | None = None) -> list[Path]:
    folder = Path(out_dir).expanduser().resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    observed = resource_inventory.get('control_observations') if resource_inventory else None
    rows = overall_rows(findings, coverage_full=metadata.get('region_coverage_full') is True,
                        observations=observed)
    details = [r.to_dict() for r in findings]
    for row in details:
        row['No'] = row.pop('number')
        row['evidence'] = '\n'.join(row['evidence'])
    stamp = metadata['timestamp'].replace(':', '-').replace('+', '-')
    basename = f'aws_security_audit_{stamp}'
    paths = [folder / (basename + ext) for ext in ('.json', '.csv', '.xlsx')]
    payload = {'metadata': metadata, 'summary': rows, 'findings': details}
    if resource_inventory is not None:
        payload['resource_inventory'] = resource_inventory
    if observed is not None:
        payload['control_observations'] = observed
    json_data = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode('utf-8')
    textbuf = __import__('io').StringIO()
    writer = csv.DictWriter(textbuf, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    csv_data = ('\ufeff' + textbuf.getvalue()).encode('utf-8')
    xlsx_data = _excel_bytes(
        rows, details, metadata,
        resources=resource_inventory.get('resources', []) if resource_inventory else None,
        observations=observed.get('rows', []) if observed is not None else None,
    )
    for path, content in zip(paths, (json_data, csv_data, xlsx_data)):
        _private_bytes(path, content)
    return paths
