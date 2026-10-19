"""Offline, evidence-first progress reporting for the 46-control AWS audit.

Separates scanner MANUAL_REVIEW from actual human tasks, machine evidence,
acquisition channels, and the independent four-label Owner approval gate.
Never calls AWS and never changes source classifications.
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from .evidence_adapters import (
    build_ledger,
    validate_mcp_summary,
    validate_r24_supplement,
    )
from .evidence_ledger import ledger_to_json
# The two constants below stay part of this module's public API.
from .evidence_adapters import MCP_SCHEMA, R24_FIELDS  # noqa: F401
from .offline_classification import validate_classification_result
from .report import _private_bytes
from .shared_evidence import build_cross_control_evidence
from .control_review import (SCANNER, control_review_to_json,  # noqa: F401
                             validated_head as _controls)
from .control_review_input import review_for_bundle
from .evidence_requests import request_to_json
from .report_manifest import MANIFEST_SUFFIX, build_manifest, write_export_set
from .review_export import review_tables, tables_csv, tables_xlsx
from .evidence_types import (  # noqa: F401  (used in type annotations)
    CallRecord, ControlReview, EvidenceLedger, Execution,
)

PROGRESS_SCHEMA = 'aws-security-evidence-progress-v1'
ROUTES = {
    'AWS_READ_ONLY_CANDIDATE': 'AWS読み取り候補',
    'AWS_PLUS_OWNER_SCOPE': 'AWS証拠＋Owner対象確認',
    'NON_AWS_EXPORT_CANDIDATE': 'CI/DBなどAWS外の機械証拠',
    'OWNER_DOCUMENTATION': 'Ownerの運用文書',
}


def _validate_optional_r24(bundle: dict, r24: dict | None, account: str | None):
    # Supplement validation now lives with the projection boundary so the
    # same strict checks run before projections in every consumer.
    return validate_r24_supplement(bundle, r24, account)


def _validate_mcp(bundle: dict, mcp: dict | None, account: str | None):
    return validate_mcp_summary(bundle, mcp, account)


def build_evidence_progress_with_model(
    bundle: dict,
    classification: dict | None = None,
    *,
    r24: dict | None = None,
    mcp_summary: dict | None = None,
    expected_account: str | None = None,
    calls: tuple['CallRecord', ...] | None = None,
    execution: 'Execution | None' = None,
) -> tuple[dict, 'ControlReview', 'EvidenceLedger']:
    controls, plans = _controls(bundle)
    # Strict structural/reference validation, never semantic or Owner approval.
    validation = (
        validate_classification_result(bundle, classification)
        if classification is not None else None
    )
    r24_rows = _validate_optional_r24(bundle, r24, expected_account)
    mcp_rows = _validate_mcp(bundle, mcp_summary, expected_account)
    # Projection happens behind the same validated inputs; explicit captured
    # CallRecords always stay preferred over the ambient capture context.
    supplements_supplied = r24 is not None or mcp_summary is not None
    base_ledger = build_ledger(
        bundle, expected_account=expected_account,
        calls=calls, execution=execution) if supplements_supplied else None
    ledger = build_ledger(
        bundle, r24=r24,
        mcp_summary=mcp_summary, expected_account=expected_account,
        calls=calls, execution=execution)
    inv = bundle.get('resource_inventory') or {}
    by_control = (inv.get('control_observations') or {}).get('by_control') or {}
    raw_obs = (inv.get('control_observations') or {}).get('rows') or []
    if not isinstance(by_control, dict) or not isinstance(raw_obs, list):
        raise ValueError('Invalid observed property evidence')
    # #20 encrypted automated snapshot observations may also be reused as
    # #45 backup-existence context; never as evidence of a successful restore.
    cross = build_cross_control_evidence(inv)
    cross_by_control = {}
    for ref in cross['references']:
        cross_by_control.setdefault(ref['target_control'], []).append(ref)
    # One criterion-aware review model; never rewrites scanned verdicts.
    # Residual open questions are deduplicated into review-model requests
    # (exact kind/scope/requirement keys), never into the R21 schema.
    review = review_for_bundle(
        bundle, ledger, classification, base_ledger=base_ledger,
        supplements_supplied=supplements_supplied)
    request_ids_by_number = {row.number: row.request_ids
                             for row in review.rows}
    rows = []
    for c, p in zip(controls, plans):
        n = c['number']
        counts = by_control.get(str(n)) or {}
        ok = counts.get('ok', 0)
        fail = counts.get('fail', 0)
        unknown = counts.get('unknown', 0)
        context = counts.get('context', 0)
        if any(type(k) is not int or k < 0 for k in (ok, fail, unknown, context)):
            raise ValueError('Invalid per-control observation counts')
        source_obs = [
            {'index': i, 'state': x.get('property_result'),
             'attribution': x.get('attribution'), 'property': x.get('property'),
             'resource_id': x.get('resource_id')}
            for i, x in enumerate(raw_obs)
            if isinstance(x, dict) and x.get('number') == n
        ]
        if len(source_obs) != ok + fail + unknown + context:
            raise ValueError('Source observation summary and rows do not reconcile')
        original = c['account_status']
        if fail or original == 'FAIL':
            evidence_level = 'SCOPED_NEGATIVE_OBSERVATION'
        elif ok:
            evidence_level = 'PARTIAL_POSITIVE_OBSERVATION'
        elif context or unknown:
            evidence_level = 'MACHINE_CONTEXT_OR_UNKNOWN'
        else:
            evidence_level = 'NO_PROPERTY_OBSERVATION'
        cross_for = cross_by_control.get(n, [])
        if evidence_level == 'NO_PROPERTY_OBSERVATION' and cross_for:
            evidence_level = 'CROSS_CONTROL_MACHINE_CONTEXT'
        mcp = mcp_rows.get(n, [])
        r24_for = r24_rows.get(n, [])
        draft = classification['controls'][n - 1] if classification else {}
        rows.append({
            'number': n,
            'title': c['title'],
            'criterion': c.get('criterion'),
            'scanner_status': original,
            'scanner_regional_status': c.get('regional_status'),
            'scanner_is_final_business_classification': False,
            'machine_evidence_level': evidence_level,
            'property_observation_counts': {
                'ok': ok, 'fail': fail, 'unknown': unknown, 'context': context,
            },
            'source_observation_refs': [
                'resource_inventory.control_observations.rows[' + str(x['index']) + ']'
                for x in source_obs
            ],
            'cross_control_machine_evidence': cross_for,
            'r24_evidence': r24_for,
            'mcp_summary_observations': mcp,
            'acquisition_route': p['acquisition_route'],
            'evidence_route_description': ROUTES[p['acquisition_route']],
            'missing_evidence_hint': p.get('preferred_evidence_request', ''),
            'outstanding_request_ids': tuple(
                request_ids_by_number.get(n, ())),
            'owner_context_required_by_criterion':
                p.get('human_context_required_by_criterion', False),
            'business_resolution_state': draft.get('resolution_state', 'NOT_EVALUATED'),
            'business_label_provisional': draft.get('final_classification'),
            'owner_adoption_verified': False,
        })
    measured = sum(any(row['property_observation_counts'].values()) for row in rows)
    with_new = sum(
        any(row['property_observation_counts'].values())
        or any(r.get('state') in ('OBSERVED', 'OBSERVED_PARTIAL', 'VERIFIED')
               for r in row['r24_evidence'])
        or bool(row['cross_control_machine_evidence'])
        or bool(row['mcp_summary_observations'])
        for row in rows
    )
    report = {
        'schema': PROGRESS_SCHEMA,
        'purpose': 'EVIDENCE_PROGRESS_NOT_FINAL_COMPLIANCE',
        'source_bundle_execution': bundle.get('execution', {}),
        'evidence_ledger': ledger_to_json(ledger),
        'control_review': control_review_to_json(review),
        'outstanding_evidence_requests': [
            request_to_json(request) for request in review.requests
        ],
        'classification_contract_unchanged': True,
        'semantic_compliance_verified': False,
        'owner_adoption_verified': False,
        'effective_no_write': 'NOT_PROVEN',
        'summary': {
            'controls': 46,
            'scanner_counts': dict(Counter(r['scanner_status'] for r in rows)),
            'original_attribute_observation_rows': len(raw_obs),
            'original_controls_with_property_observations': measured,
            'cross_control_machine_evidence_refs': len(cross['references']),
            'controls_with_cross_control_machine_evidence': sorted(cross_by_control),
            'controls_with_some_machine_evidence_including_supplements': with_new,
            'controls_with_no_machine_evidence_including_supplements': 46 - with_new,
            'acquisition_route_counts': dict(Counter(r['acquisition_route'] for r in rows)),
            'owner_documentation_controls': [
                r['number'] for r in rows
                if r['acquisition_route'] == 'OWNER_DOCUMENTATION'
            ],
            'evidence_pending_controls': validation['pending_count'] if validation else None,
            'structurally_finalized_draft_controls':
                validation['finalized_count'] if validation else None,
            'purely_manual_check_count': None,
            'outstanding_evidence_request_count': len(review.requests),
            'outstanding_evidence_request_scope_keys':
                sorted({r.scope_key for r in review.requests}),
        },
        'source_validation': {
            'classification_structure_and_references':
                validation['structure_and_reference_check'] if validation else 'NOT_PROVIDED',
            'r21_schema':
                validation['r21']['r21_request_schema_check'] if validation else 'NOT_PROVIDED',
            'r24_supplied': r24 is not None,
            'mcp_summary_supplied': mcp_summary is not None,
            'mcp_summary_source': mcp_summary.get('source') if mcp_summary else None,
            'mcp_summary_independent_runtime_attestation': False,
        },
        'controls': rows,
        'limitations': [
            '43 EVIDENCE_PENDING classifications do not mean 43 manual checks.',
            'Machine observations are partial and may include shared/account scope.',
        'Cross-control automated snapshots establish only existence, never a restore drill or recovery outcome.',
            'A candidate AWS acquisition route is not an executed or approved task.',
            'The Owner documentation route is a planning category, not four completed tasks.',
            'Supplemental MCP summaries are operator-curated, not raw SDK attestations.',
            'No scanner/business label is upgraded by this report.',
        ],
    }
    return report, review, ledger


def build_evidence_progress(
    bundle: dict,
    classification: dict | None = None,
    **kwargs: object,
) -> dict:
    """Historical single-dict entry point over the typed model builder."""
    report, _review, _ledger = build_evidence_progress_with_model(
        bundle, classification, **kwargs)
    return report


def _md_safe(s: object) -> str:
    return str(s if s is not None else '').replace('|', '\\|').replace('\n', ' ')


def render_markdown(report: dict) -> str:
    summary = report['summary']
    counts = summary['scanner_counts']
    lines = [
        '# AWS 46項目監査 — 証拠取得進捗レポート',
        '',
        '**この報告は最終監査判定ではありません。** '
        'スキャナーのMANUAL_REVIEWを手動作業件数として数えません。',
        '',
        '## 集計',
        '',
        '- スキャナー: FAIL ' + str(counts.get('FAIL', 0)) +
        ' / MANUAL_REVIEW ' + str(counts.get('MANUAL_REVIEW', 0)) +
        ' / UNKNOWN ' + str(counts.get('UNKNOWN', 0)),
        '- 原本属性観測: ' + str(summary['original_attribute_observation_rows']) +
        '行、該当 ' + str(summary['original_controls_with_property_observations']) + '/46項目',
        '- 追加証拠込み機械情報あり: ' +
        str(summary['controls_with_some_machine_evidence_including_supplements']) +
        '/46項目（全項目の適合を意味しない）',
        '- オフライン分類: ' + (
            str(summary['evidence_pending_controls']) + '件保留（提出された分類候補）'
            if summary['evidence_pending_controls'] is not None
            else '未評価（分類ファイル未入力）'
        ),
        '- R24補足証拠: ' + ('取込済み' if report['source_validation']['r24_supplied'] else '未取込') +
        ' / MCP補足要約: ' + ('取込済み' if report['source_validation']['mcp_summary_supplied'] else '未取込'),
        '- 対象資産の網羅性: ' + (
            '要確認（Productタグ等による限定抽出）'
            if report.get('source_bundle_execution', {}).get('product_attribution_complete') is False
            else '元監査結果を参照'
        ),
        '- #45への横断証拠: ' + str(summary.get('cross_control_machine_evidence_refs', 0)) +
        '件（スナップショット存在証拠であり復旧訓練の証明ではない）',
        '- 残る証拠要求: ' + str(summary['outstanding_evidence_request_count']) +
        '件（' + ' / '.join(summary['outstanding_evidence_request_scope_keys']) +
        ' スコープ、kind/scope/requirementの一意キーで集約。取得経路はヒントであり実行済み作業ではない）',
        '- 運用文書が主経路: ' +
        ', '.join('#' + str(x) for x in summary['owner_documentation_controls']),
        '- Owner最終採用: 未検証',
        '',
        '## 46項目の証拠・取得経路',
        '',
        '| No | 監査項目 | スキャナー | 取得済み属性 OK/NG/不明/参考 | 証拠の到達度 | 追加取得経路 | 分類進捗 | MCP情報 |',
        '|---:|---|---|---:|---|---|---|---|',
    ]
    for row in report['controls']:
        cs = row['property_observation_counts']
        line = '| ' + ' | '.join([
            str(row['number']),
            _md_safe(row['title']),
            _md_safe(row['scanner_status']),
            f"{cs['ok']}/{cs['fail']}/{cs['unknown']}/{cs['context']}",
            row['machine_evidence_level'],
            _md_safe(row['evidence_route_description']),
            row['business_resolution_state'],
            _md_safe('; '.join(
                x['api'] + ': ' + x['fact'] for x in row['mcp_summary_observations']
            )) or '-',
        ]) + ' |'
        lines.append(line)
    lines += _evidence_state_sections(report)

    lines += [
        '',
        '## 重要な境界',
        '',
        '- 属性OKはその資産・属性についての観測であり、プロダクト全体のPASSではありません。',
        '- MCP要約は報告用に再構成された資料です。実行履歴の独立検証を証明しません。',
        '- AWS接続、リソース変更、分類の正式承認はこのレポート生成では行いません。',
        '',
    ]
    return '\n'.join(lines)


def _evidence_state_sections(report: dict) -> list[str]:
    """Markdown-only summary projected from the same JSON report model.

    Undated/failed/partial evidence and the supplement-vs-machine
    observation distinction stay visible; none of this upgrades verdicts.
    """
    ledger = report.get('evidence_ledger') or {}
    calls, facts = ledger.get('calls') or [], ledger.get('facts') or []
    failed = [c for c in calls
              if c.get('collection_state') in ('FAILED', 'ACCESS_DENIED')]
    partial = [c for c in calls if c.get('collection_state') == 'PARTIAL'
               or c.get('pagination_complete') is False]
    undated = sorted({f['number'] for f in facts if f.get('observed_at') is None})
    controls = report.get('controls') or []
    no_obs = [r for r in controls
              if r.get('machine_evidence_level') == 'NO_PROPERTY_OBSERVATION']
    sup_only = [r for r in no_obs if r.get('r24_evidence') or r.get('mcp_summary_observations')]
    requests = (report.get('control_review') or {}).get('requests') or []
    labeled = ', '.join('#' + str(n) for n in undated) or 'なし'
    lines = [
        '## 証拠の取得状態',
        '',
        '- 観測時刻が記録されていない証拠: ' + str(len(undated)) + '件（' + labeled + '）。来歴レベルは記録済みで時刻のみ不明。',
        '- 取得失敗・アクセス拒否の呼び出し: ' + str(len(failed)) + '件（欠落は安全な設定ではなく未観測として扱う）',
        '- 部分取得の呼び出し: ' + str(len(partial)) + '件（失敗ページ・未完了ページング分は未観測）',
        '- 基準の機械観測がない項目: ' + str(len(no_obs)) + '/46（補足証拠の有無とは別の状態）',
        '- うちR24/MCP補足のみあり: ' + str(len(sup_only)) + '件（補足は検証済みの機械観測には含まれない）',
        '',
        '## 残る証拠要求の明細',
        '',
    ]
    if not requests:
        lines.append('- なし（未解決の証拠要求はありません）')
    for request in requests:
        lines.append(
            '- ' + request['kind'] + ' / ' + request['scope_key'] + ' / '
            + request['requirement_key'] + ' → 項目 '
            + ', '.join('#' + str(n) for n in request['controls'])
            + '（' + request['acquisition_route'] + '）')
    return lines


def save_progress_report(out_dir: str, report: dict, *, basename='aws_evidence_progress',
                         review=None, ledger=None,
                         input_digests: dict | None = None) -> list[Path]:
    """Write the JSON/Markdown report, or the full private export set.

    With a typed review plus ledger, the shared ReviewTables model also
    becomes the 46-row CSV and the five-sheet XLSX, and one manifest covers
    every payload byte (excluding itself). All refs are validated before any
    file is written.
    """
    directory = Path(out_dir).expanduser().resolve()
    payloads = [
        (basename + '.json',
         json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8')),
        (basename + '.md', render_markdown(report).encode('utf-8')),
    ]
    if (review is None) != (ledger is None):
        raise ValueError('save_progress_report: review and ledger must be'
                         ' provided together')
    if review is not None:
        from .control_review import control_review_to_json
        from .evidence_ledger import ledger_to_json
        # Fail closed if the typed model differs from the JSON being saved,
        # before the output directory is even created.
        if (control_review_to_json(review) != report.get('control_review')
                or ledger_to_json(ledger) != report.get('evidence_ledger')):
            raise ValueError('progress report does not match the supplied review model')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if review is None:
        for name, content in payloads:
            _private_bytes(directory / name, content)
        return [directory / name for name, _ in payloads]
    files = dict(payloads)
    tables = review_tables(review, ledger)
    files[basename + '.csv'] = tables_csv(tables)
    files[basename + '.xlsx'] = tables_xlsx(tables)
    digests = (dict(input_digests) if input_digests is not None else
               {execution.id: execution.source_digest
                for execution in ledger.executions if execution.source_digest})
    files[basename + MANIFEST_SUFFIX] = build_manifest(files, digests)
    return list(write_export_set(directory, files))
