"""STS-001: offline authentication and IAM gate regression tests."""
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError

from aws_security_audit.core import AuditContext, AuditError, EvidenceUnavailable
from aws_security_audit import cli

ROLE = 'arn:aws:iam::123456789012:role/SecurityAuditReadOnlyRole'
REGION = 'ap-northeast-1'


def sessions(monkeypatch, method='login', config=None, identity=None):
    source = MagicMock()
    source._session.get_scoped_config.return_value = config or {'login_session': 'source-login'}
    source.get_credentials.return_value.method = method
    source.client.return_value.assume_role.return_value = {
        'Credentials': {'AccessKeyId': 'ASIA_FAKE', 'SecretAccessKey': 'DO_NOT_LOG',
                        'SessionToken': 'DUMMY_TOKEN',
                        'Expiration': datetime.now(timezone.utc) + timedelta(hours=1)}}
    scoped = MagicMock()
    scoped.client.return_value.get_caller_identity.return_value = identity or {
        'Account': '123456789012',
        'Arn': 'arn:aws:sts::123456789012:assumed-role/SecurityAuditReadOnlyRole/aws-security-audit'}
    calls = []
    def factory(**kwargs):
        calls.append(kwargs)
        return source if len(calls) == 1 else scoped
    monkeypatch.setattr(boto3, 'Session', factory)
    return source, scoped, calls


@pytest.mark.parametrize('method', ['shared-credentials-file', 'env', 'config-file', 'assume-role', 'iam-role', None])
def test_shadowed_login_rejected_before_assume_role(monkeypatch, method):
    source, _, calls = sessions(monkeypatch, method)
    with pytest.raises(AuditError, match='Credential provider'):
        AuditContext('source', ROLE, REGION)
    source.client.assert_not_called()
    assert len(calls) == 1


def test_login_is_accepted_and_scoped_session_used(monkeypatch):
    source, scoped, calls = sessions(monkeypatch)
    context = AuditContext('source', ROLE, REGION)
    assert context.account == '123456789012'
    assert len(calls) == 2
    assert calls[1]['aws_session_token'] == 'DUMMY_TOKEN'
    source.client.assert_called_once_with('sts')
    scoped.client.assert_called_once_with('sts', region_name=REGION)


@pytest.mark.parametrize('method,allowed', [('sso', True), ('login', False)])
def test_sso_provider_matches_configuration(monkeypatch, method, allowed):
    source, _, _ = sessions(monkeypatch, method, {'sso_session': 'my-sso'})
    if allowed:
        assert AuditContext('source', ROLE, REGION).account == '123456789012'
    else:
        with pytest.raises(AuditError, match='Credential provider'):
            AuditContext('source', ROLE, REGION)
        source.client.assert_not_called()


@pytest.mark.parametrize('identity', [
    {'Account': '999999999999', 'Arn': 'arn:aws:sts::999999999999:assumed-role/SecurityAuditReadOnlyRole/aws-security-audit'},
    {'Account': '123456789012', 'Arn': 'arn:aws:sts::123456789012:assumed-role/AnotherRole/aws-security-audit'},
    {'Account': '123456789012', 'Arn': 'arn:aws:iam::123456789012:role/SecurityAuditReadOnlyRole'}
])
def test_unexpected_identity_is_rejected(monkeypatch, identity):
    _, _, calls = sessions(monkeypatch, identity=identity)
    with pytest.raises(AuditError, match='Refusing to run'):
        AuditContext('source', ROLE, REGION)
    assert len(calls) == 2


def test_bad_role_arn_never_resolves_source(monkeypatch):
    factory = MagicMock(side_effect=AssertionError('AWS must not be contacted'))
    monkeypatch.setattr(boto3, 'Session', factory)
    with pytest.raises(AuditError, match='malformed'):
        AuditContext('source', 'NOT_AN_ARN', REGION)
    factory.assert_not_called()


def test_assume_role_access_denied_no_fallback_or_secrets(monkeypatch):
    source, _, calls = sessions(monkeypatch)
    source.client.return_value.assume_role.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied', 'Message': 'DO_NOT_LOG'}}, 'AssumeRole')
    with pytest.raises(EvidenceUnavailable) as err:
        AuditContext('source', ROLE, REGION)
    assert 'DO_NOT_LOG' not in str(err.value)
    assert len(calls) == 1


def test_requested_region_not_enabled_blocks_scan(monkeypatch):
    mock_ctx = MagicMock()
    mock_ctx.active_regions.return_value = [REGION]
    monkeypatch.setattr(cli, 'AuditContext', MagicMock(return_value=mock_ctx))
    monkeypatch.setattr(cli, 'local_config', lambda args: {
        'source_profile': 'source', 'role_arn': ROLE, 'regions': 'us-west-2'})
    with pytest.raises(AuditError, match='region'):
        cli.prepare(SimpleNamespace())


def test_region_discovery_denied_is_fatal(monkeypatch):
    mock_ctx = MagicMock()
    mock_ctx.active_regions.side_effect = EvidenceUnavailable('EC2 region discovery denied')
    monkeypatch.setattr(cli, 'AuditContext', MagicMock(return_value=mock_ctx))
    monkeypatch.setattr(cli, 'local_config', lambda args: {
        'source_profile': 'source', 'role_arn': ROLE, 'regions': REGION})
    with pytest.raises(EvidenceUnavailable):
        cli.prepare(SimpleNamespace())


def test_doctor_probes_only_scoped_read_apis_and_disclaims_no_write(capsys):
    mock_ctx = MagicMock()
    mock_ctx.account, mock_ctx.expected_role_arn = '123456789012', ROLE
    assert cli.doctor(mock_ctx, [REGION]) == 0
    out = capsys.readouterr().out
    assert 'IDENTITY_VERIFIED' in out
    assert 'REGION_VERIFIED' in out
    assert 'READ_API_VERIFIED sample=5' in out
    assert 'FULL_46_CHECK_PERMISSIONS=NOT_VERIFIED' in out
    assert 'EFFECTIVE_NO_WRITE=NOT_PROVEN' in out


def test_doctor_denied_read_api_cannot_claim_success(capsys):
    mock_ctx = MagicMock()
    mock_ctx.account, mock_ctx.expected_role_arn = '123456789012', ROLE
    mock_ctx.client_cached.return_value.list_account_aliases.side_effect = ClientError(
        {'Error': {'Code': 'AccessDenied', 'Message': 'DO_NOT_LOG'}}, 'ListAccountAliases')
    assert cli.doctor(mock_ctx, [REGION]) == 2
    out = capsys.readouterr().out
    assert 'READ_API_UNVERIFIED' in out
    assert 'READ_API_VERIFIED' not in out
    assert 'EFFECTIVE_NO_WRITE=NOT_PROVEN' in out
    assert 'DO_NOT_LOG' not in out


def test_readonly_policy_evidence_has_version_and_canonical_digest(tmp_path, capsys):
    import hashlib
    mock_ctx = MagicMock()
    mock_ctx.region = REGION
    iam = mock_ctx.client_cached.return_value
    document = {'Statement': [{'Effect': 'Allow', 'Action': ['s3:Get*']}], 'Version': '2012-10-17'}
    policy = {'Arn': 'arn:aws:iam::aws:policy/ReadOnlyAccess',
              'PolicyId': 'ANPAFAKEPOLICYID', 'DefaultVersionId': 'v190'}
    iam.get_policy.side_effect = [{'Policy': policy}, {'Policy': policy}]
    iam.get_policy_version.return_value = {'PolicyVersion': {
        'Document': document, 'VersionId': 'v190', 'IsDefaultVersion': True}}
    assert cli.policy_evidence(mock_ctx, out=str(tmp_path)) == 0
    output = json.loads(capsys.readouterr().out)
    evidence = json.loads(next(tmp_path.glob('readonlyaccess-policy-*.json')).read_text())
    assert output['policy_version'] == 'v190'
    canonical = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    assert output['policy_sha256_canonical_json'] == hashlib.sha256(canonical).hexdigest()
    assert evidence['policy_document_as_returned_by_boto3'] == document
    assert evidence['policy_document'] == document
    assert output['effective_no_write'] == 'NOT_PROVEN'
    assert iam.get_policy.call_count == 2
