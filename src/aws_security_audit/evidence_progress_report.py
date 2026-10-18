"""Offline, evidence-first progress reporting for the 46-control AWS audit.

Separates scanner MANUAL_REVIEW from actual human tasks, machine evidence,
acquisition channels, and the independent four-label Owner approval gate.
Never calls AWS and never changes source classifications.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path

from .offline_classification import CONTROL_EVIDENCE_PLAN, validate_classification_result
from .report import _private_bytes

MCP_SCHEMA = 'aws-security-mcp-observation-summary-v1'
PROGRESS_SCHEMA = 'aws-security-evidence-progress-v1'
SCANNER = {'PASS', 'FAIL', 'UNKNOWN', 'MANUAL_REVIEW', 'NOT_APPLICABLE'}
ROUTES = {
    'AWS_READ_ONLY_CANDIDATE': 'AWS読み取り候補',
    'AWS_PLUS_OWNER_SCOPE': 'AWS証拠＋Owner対象確認',
    'NON_AWS_EXPORT_CANDIDATE': 'CI/DBなどAWS外の機械証拠',
    'OWNER_DOCUMENTATION': 'Ownerの運用文書',
}
R24_FIELDS = {
    8: ('control_8_shield',),
    24: ('control_24_cloudtrail',),
    27: ('control_27_flow_logs',),
    33: ('control_33_securityhub',),
    39: ('control_39_inspector', 'control_39_ecr'),
    40: ('control_40_ci',),
}


def _controls(bundle: dict) -> tuple[list[dict], list[dict]]:
    if (not isinstance(bundle, dict)
            or bundle.get('schema') != 'aws-security-audit-web-review-v1'):
        raise ValueError('Invalid original web review evidence schema')
    controls = bundle.get('controls')
    plans = (bundle.get('decision_support') or {}).get('plans')
    if (not isinstance(controls, list) or not isinstance(plans, list)
            or len(controls) != 46 or len(plans) != 46):
        raise ValueError('Exactly 46 controls and acquisition plans are required')
    for i, (control, plan) in enumerate(zip(controls, plans), 1):
        if (not isinstance(control, dict) or type(control.get('number')) is not int
                or control['number'] != i or not isinstance(plan, dict)
                or type(plan.get('number')) is not int or plan['number'] != i
                or plan.get('acquisition_route') != CONTROL_EVIDENCE_PLAN[i][0]
                or control.get('account_status') not in SCANNER
                or not isinstance(control.get('title'), str)):
            raise ValueError('Control identity/route/status mismatch')
    return controls, plans


def _validate_optional_r24(bundle: dict, r24: dict | None, account: str | None):
    if r24 is None:
        return {}
    if (not isinstance(r24, dict)
            or r24.get('schema') != 'aws-ros-r24-targeted-evidence-v1'
            or r24.get('product') != bundle.get('execution', {}).get('product')
            or r24.get('region') not in bundle.get('execution', {}).get('requested_regions', [])
            or (account is not None and r24.get('account') != account)):
        raise ValueError('R24 product/region/account mismatch')
    return {
        number: [
            {'source': key, 'state': r24[key].get('state')}
            for key in keys
            if isinstance(r24.get(key), dict)
        ]
        for number, keys in R24_FIELDS.items()
    }


def _validate_mcp(bundle: dict, mcp: dict | None, account: str | None):
    """Only bounded attributed summaries, not raw AWS payloads or proof of execution."""
    if mcp is None:
        return {}
    if (not isinstance(mcp, dict) or set(mcp) != {
            'schema', 'account', 'region', 'product', 'source', 'records'}
            or mcp['schema'] != MCP_SCHEMA
            or mcp['source'] not in (
                'OPERATOR_CURATED_MCP_READONLY_SUMMARY',
                'ASSISTANT_CURATED_MCP_READONLY_SUMMARY',
            )
            or mcp['product'] != bundle.get('execution', {}).get('product')
            or mcp['region'] not in bundle.get('execution', {}).get('requested_regions', [])
            or not isinstance(mcp['account'], str) or len(mcp['account']) != 12
            or not mcp['account'].isdigit()
            or (account is not None and mcp['account'] != account)
            or not isinstance(mcp['records'], list) or len(mcp['records']) > 150):
        raise ValueError('Untrusted MCP summary schema/scope')
    grouped = {}
    for row in mcp['records']:
        if (not isinstance(row, dict) or set(row) != {
                'number', 'api', 'state', 'fact', 'scope_limit'}
                or type(row['number']) is not int or not 1 <= row['number'] <= 46
                or not isinstance(row['api'], str)
                or not row['api'].split('.')[-1].startswith(
                    ('Get', 'Describe', 'List', 'BatchGet'))
                or not isinstance(row['fact'], str) or not row['fact'].strip()
                or len(row['fact']) > 600
                or row['state'] not in ('OBSERVED', 'UNVERIFIED')
                or not isinstance(row['scope_limit'], str)
                or not row['scope_limit'].strip() or len(row['scope_limit']) > 400):
            raise ValueError('MCP summary row invalid or not a read-only operation')
        grouped.setdefault(row['number'], []).append(dict(row))
    return grouped


def build_evidence_progress(
    bundle: dict,
    classification: dict | None = None,
    *,
    r24: dict | None = None,
    mcp_summary: dict | None = None,
    expected_account: str | None = None,
) -> dict:
    controls, plans = _controls(bundle)
    # Strict structural/reference validation, never semantic or Owner approval.
    validation = (
        validate_classification_result(bundle, classification)
        if classification is not None else None
    )
    r24_rows = _validate_optional_r24(bundle, r24, expected_account)
    mcp_rows = _validate_mcp(bundle, mcp_summary, expected_account)
    inv = bundle.get('resource_inventory') or {}
    by_control = (inv.get('control_observations') or {}).get('by_control') or {}
    raw_obs = (inv.get('control_observations') or {}).get('rows') or []
    if not isinstance(by_control, dict) or not isinstance(raw_obs, list):
        raise ValueError('Invalid observed property evidence')
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
            'r24_evidence': r24_for,
            'mcp_summary_observations': mcp,
            'acquisition_route': p['acquisition_route'],
            'evidence_route_description': ROUTES[p['acquisition_route']],
            'missing_evidence_hint': p.get('preferred_evidence_request', ''),
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
        or bool(row['mcp_summary_observations'])
        for row in rows
    )
    return {
        'schema': PROGRESS_SCHEMA,
        'purpose': 'EVIDENCE_PROGRESS_NOT_FINAL_COMPLIANCE',
        'source_bundle_execution': bundle.get('execution', {}),
        'classification_contract_unchanged': True,
        'semantic_compliance_verified': False,
        'owner_adoption_verified': False,
        'effective_no_write': 'NOT_PROVEN',
        'summary': {
            'controls': 46,
            'scanner_counts': dict(Counter(r['scanner_status'] for r in rows)),
            'original_attribute_observation_rows': len(raw_obs),
            'original_controls_with_property_observations': measured,
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
            'A candidate AWS acquisition route is not an executed or approved task.',
            'The Owner documentation route is a planning category, not four completed tasks.',
            'Supplemental MCP summaries are operator-curated, not raw SDK attestations.',
            'No scanner/business label is upgraded by this report.',
        ],
    }


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
        '- オフライン分類保留: ' + str(summary['evidence_pending_controls']) +
        '（未提供ならNone）',
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


def save_progress_report(out_dir: str, report: dict, *, basename='aws_evidence_progress') -> list[Path]:
    directory = Path(out_dir).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = [directory / (basename + ext) for ext in ('.json', '.md')]
    _private_bytes(paths[0], json.dumps(report, ensure_ascii=False, indent=2).encode('utf-8'))
    _private_bytes(paths[1], render_markdown(report).encode('utf-8'))
    return paths
