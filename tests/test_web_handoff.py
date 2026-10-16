"""Offline validation of ChatGPT/Gemini Web attachment and copy-paste prompt."""
from __future__ import annotations

import json

from aws_security_audit.core import Finding
from aws_security_audit.web_handoff import (
    WEB_REVIEW_PROMPT, build_web_review_bundle, save_web_handoff,
)


def _row(number: int) -> dict:
    return {
        'No': number,
        'カテゴリ': 'テスト',
        'チェック項目': f'チェック{number}',
        '推奨設定・確認基準': '証拠確認',
        '重要度': '高',
        '目的・対象リスク': '可視化',
        '判定': 'UNKNOWN' if number == 5 else 'MANUAL_REVIEW',
        '対象地域判定': 'PASS' if number == 5 else 'MANUAL_REVIEW',
        '地域網羅': '一部リージョンのみ',
    }


def test_web_bundle_has_46_findings_and_preserves_uncertainty():
    rows = [_row(n) for n in range(1, 47)]
    findings = [Finding(5, 'PASS', 'ap-northeast-1',
                        'selected region passed', ['AWS id: sg-example'])]
    metadata = {
        'version': '0.1.0', 'timestamp': '2026-10-16T06:00:00Z',
        'account': '123456789012', 'role_arn': 'SENSITIVE_ROLE',
        'caller_arn': 'SENSITIVE_CALLER',
        'requested_regions': ['ap-northeast-1'],
        'available_regions': ['ap-northeast-1', 'us-east-1'],
        'region_coverage_full': False,
    }
    investigation = {
        'schema': 'aws-security-investigation-v1',
        'regions_checked': ['ap-northeast-1'],
        'deep_evidence': {
            'ap-northeast-1': {'5': {
                'state': 'OBSERVED', 'groups': [{
                    'group_id': 'sg-example', 'attached_enis': 2,
                }],
            }},
        },
        'limitations': ['No active probing'],
    }
    bundle = build_web_review_bundle(metadata, rows, findings, investigation)
    assert bundle['purpose'] == 'INVESTIGATION_ONLY'
    assert bundle['aws_remediation'] == 'STRICTLY_OUT_OF_SCOPE'
    assert bundle['automatic_upload'] is False
    assert bundle['effective_no_write'] == 'NOT_PROVEN'
    assert len(bundle['controls']) == 46
    record = bundle['controls'][4]
    assert record['account_status'] == 'UNKNOWN'
    assert record['regional_status'] == 'PASS'
    assert record['findings'][0]['evidence'] == ['AWS id: sg-example']
    assert bundle['supplemental_investigation']['deep_evidence'] == investigation['deep_evidence']
    assert 'account' not in bundle['execution']
    assert 'role_arn' not in bundle['execution']
    assert 'caller_arn' not in bundle['execution']
    assert 'SENSITIVE_ROLE' not in json.dumps(bundle)


def test_web_handoff_requires_complete_46_control_packet():
    rows = [_row(n) for n in range(1, 46)]
    try:
        build_web_review_bundle({}, rows, [], {})
    except ValueError as exc:
        assert '46' in str(exc)
    else:
        raise AssertionError('Missing controls should be rejected')


def test_handoff_files_are_local_private_and_prompt_forbid_remediation(tmp_path):
    bundle = {'schema': 'test', 'controls': [{'account_status': 'FAIL'}]}
    paths = save_web_handoff(str(tmp_path), bundle)
    assert len(paths) == 2
    assert paths[0].name.startswith('aws_web_review_')
    assert paths[1].name.startswith('aws_web_prompt_')
    assert json.loads(paths[0].read_text()) == bundle
    prompt = paths[1].read_text()
    assert 'ChatGPT' not in prompt or '改善' in prompt
    assert '改善' in prompt
    assert 'スコープ外' in prompt
    assert 'UNKNOWN' in prompt
    assert 'PASS' in prompt
    assert '実行コマンドの提案・実施' in prompt
    assert 'AWS' in WEB_REVIEW_PROMPT
    for path in paths:
        assert (path.stat().st_mode & 0o777) == 0o600
