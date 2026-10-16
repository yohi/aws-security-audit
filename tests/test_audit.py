import json
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.checks import CHECK_RUNNERS, dangerous_inbound, data_event_enabled, s3_block_all
from aws_security_audit.cli import run_scan, main
from aws_security_audit.core import AuditError, Finding, api_call, overall_status
from aws_security_audit.report import overall_rows, export_report, _safe_spreadsheet


def test_exact_46_and_runners():
    assert len(CHECKS) == 46
    assert [c.number for c in CHECKS] == list(range(1, 47))
    assert set(CHECK_RUNNERS) == set(range(1, 47))
    assert CHECKS[0].criterion.startswith('APサーバーはプライベートサブネット')
    assert CHECKS[-1].title == 'セキュリティ責任者・連絡体制の明確化'


def test_defensive_status_aggregation():
    assert overall_status(['PASS', 'UNKNOWN']) == 'UNKNOWN'
    assert overall_status(['PASS', 'FAIL']) == 'FAIL'
    assert overall_status(['PASS', 'MANUAL_REVIEW']) == 'MANUAL_REVIEW'
    assert overall_status([]) == 'NOT_APPLICABLE'


def test_no_mutating_calls_even_if_invoked_by_bug():
    client = MagicMock()
    with pytest.raises(AuditError):
        api_call(client, 'delete_bucket', Bucket='something')
    client.delete_bucket.assert_not_called()


def test_security_group_high_risk_inbound():
    assert dangerous_inbound({'IpProtocol': '-1', 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})
    assert dangerous_inbound({'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})
    assert not dangerous_inbound({'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]})


def test_s3_block_and_trail_data_selector():
    assert s3_block_all({k: True for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets')})
    assert not s3_block_all({})
    assert data_event_enabled({'AdvancedEventSelectors': [{'FieldSelectors': [{'Field': 'eventCategory', 'Equals': ['Data']}]}]})
    assert not data_event_enabled({'EventSelectors': [{'IncludeManagementEvents': True, 'DataResources': []}]})


def test_each_unfinished_check_is_manual_or_unknown_not_fake_pass():
    class CTX:
        def guard_expiration(self):
            pass
    only_manual = [3, 4, 7, 13, 15, 16, 21, 26, 28, 30, 34, 35, 36, 37, 39, 40, 41, 42, 43, 44, 45, 46]
    for number in only_manual:
        result = CHECK_RUNNERS[number](CTX(), 'ap-northeast-1', {'regions': ['ap-northeast-1']})
        assert result.status == 'MANUAL_REVIEW'


def test_check_execution_turns_api_failure_into_unknown(monkeypatch):
    class CTX:
        def guard_expiration(self):
            pass
    import aws_security_audit.cli as cli
    def fail(*_):
        raise RuntimeError('accidental secret?')
    monkeypatch.setitem(cli.CHECK_RUNNERS, 1, fail)
    # Keep short synthetic catalog
    monkeypatch.setattr(cli, 'CHECKS', [CHECKS[0]])
    findings = run_scan(CTX(), ['ap-northeast-1'], {'regions': ['ap-northeast-1']})
    assert findings[0].status == 'UNKNOWN'
    assert 'accidental secret?' not in findings[0].detail


def test_report_writes_46_rows_and_valid_spreadsheet(tmp_path):
    findings = [Finding(c.number, 'MANUAL_REVIEW', 'ap-northeast-1', 'テスト') for c in CHECKS]
    findings[0].status = 'FAIL'
    findings[0].evidence = ['=HYPERLINK("evil")']
    meta = {'timestamp': '2026-10-16T11:42:00+00:00', 'account': '123456789012', 'region_coverage_full': False}
    files = export_report(str(tmp_path), findings, meta)
    assert {p.suffix for p in files} == {'.xlsx', '.csv', '.json'}
    output = json.loads(next(p for p in files if p.suffix == '.json').read_text())
    assert len(output['summary']) == 46
    assert output['summary'][0]['判定'] == 'FAIL'
    assert output['summary'][45]['No'] == 46
    workbook = next(p for p in files if p.suffix == '.xlsx')
    with zipfile.ZipFile(workbook) as archive:
        assert archive.testzip() is None
        assert 'xl/worksheets/sheet1.xml' in archive.namelist()
        assert b'46' in archive.read('xl/worksheets/sheet1.xml')
        assert _safe_spreadsheet('=HYPERLINK("evil")').startswith("'=HYPERLINK")
    if __import__('os').name == 'posix':
        assert (workbook.stat().st_mode & 0o777) == 0o600


def test_cli_version(capsys):
    assert main(['version']) == 0
    assert capsys.readouterr().out.strip() == '0.1.0'


def test_explicit_sts_session_policy_and_identity_guard(monkeypatch):
    import boto3
    from datetime import datetime, timedelta, timezone
    from aws_security_audit.core import AuditContext

    role = 'arn:aws:iam::123456789012:role/SecurityAuditReadOnlyRole'
    source = MagicMock()
    source._session.get_scoped_config.return_value = {'login_session': 'arn:aws:iam::123456789012:user/alice'}
    source_sts = MagicMock()
    source_sts.assume_role.return_value = {'Credentials': {
        'AccessKeyId': 'ASIA_NOT_A_REAL_KEY',
        'SecretAccessKey': 'placeholder-not-a-secret',
        'SessionToken': 'not-a-token',
        'Expiration': datetime.now(timezone.utc) + timedelta(hours=1),
    }}
    source.client.return_value = source_sts

    scoped = MagicMock()
    scoped.client.return_value.get_caller_identity.return_value = {
        'Account': '123456789012',
        'Arn': 'arn:aws:sts::123456789012:assumed-role/SecurityAuditReadOnlyRole/aws-security-audit',
    }
    sessions = []
    def factory(*args, **kwargs):
        sessions.append(kwargs)
        return source if len(sessions) == 1 else scoped
    monkeypatch.setattr(boto3, 'Session', factory)
    ctx = AuditContext('audit-source', role, 'ap-northeast-1')
    assert ctx.account == '123456789012'
    source_sts.assume_role.assert_called_once()
    params = source_sts.assume_role.call_args.kwargs
    assert params['RoleArn'] == role
    assert params['PolicyArns'] == [{'arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess'}]
    assert params['DurationSeconds'] == 3600
    assert sessions[1]['aws_session_token'] == 'not-a-token'


def test_reject_static_access_keys_as_source(monkeypatch):
    import boto3
    from aws_security_audit.core import AuditContext
    source = MagicMock()
    source._session.get_scoped_config.return_value = {'region': 'ap-northeast-1'}
    monkeypatch.setattr(boto3, 'Session', lambda **kwargs: source)
    with pytest.raises(AuditError, match='static key profiles are rejected'):
        AuditContext('static-keys', 'arn:aws:iam::123456789012:role/ReadOnly', 'ap-northeast-1')
    source.client.assert_not_called()
