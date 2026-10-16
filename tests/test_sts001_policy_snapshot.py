"""STS3-NEW-001: policy version time-of-check/time-of-use evidence regressions."""
import hashlib
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock
from urllib.parse import quote

import pytest

from aws_security_audit.cli import policy_evidence
from aws_security_audit.core import EvidenceUnavailable

ARN = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
POLICY_ID = 'ANPAEXAMPLEIDNOTREAL'
DOC = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': ['ec2:Describe*'], 'Resource': '*'}]}


def fake_ctx(*, before='v190', response_version='v190', is_default=True, after='v190',
             doc=DOC, first_id=POLICY_ID, last_id=POLICY_ID):
    iam = MagicMock()
    iam.get_policy.side_effect = [
        {'Policy': {'Arn': ARN, 'PolicyId': first_id, 'DefaultVersionId': before}},
        {'Policy': {'Arn': ARN, 'PolicyId': last_id, 'DefaultVersionId': after}},
    ]
    iam.get_policy_version.return_value = {'PolicyVersion': {
        'VersionId': response_version, 'IsDefaultVersion': is_default,
        'Document': doc,
    }}
    return SimpleNamespace(region='ap-northeast-1', client_cached=lambda *args: iam), iam


def test_verified_policy_snapshot_preserves_source_and_digest(tmp_path, capsys):
    # URL-encoded source string must be stored exactly as Boto3 handed it back.
    encoded = quote(json.dumps(DOC, separators=(',', ':')), safe='')
    ctx, iam = fake_ctx(doc=encoded)
    assert policy_evidence(ctx, out=str(tmp_path)) == 0
    summary = json.loads(capsys.readouterr().out.strip())
    assert summary['policy_version'] == 'v190'
    assert summary['snapshot_consistency'] == 'OBSERVED_STABLE_NON_ATOMIC'
    assert summary['effective_no_write'] == 'NOT_PROVEN'
    path = next(tmp_path.iterdir())
    result = json.loads(path.read_text(encoding='utf-8'))
    assert result['policy_document_as_returned_by_boto3'] == encoded
    assert result['policy_document'] == DOC
    assert result['default_version_before'] == result['policy_version'] == result['default_version_after'] == 'v190'
    assert result['is_default_version_at_read'] is True
    canonical = json.dumps(result['policy_document'], sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    assert hashlib.sha256(canonical).hexdigest() == result['policy_sha256_canonical_json']
    assert summary['policy_sha256_canonical_json'] == result['policy_sha256_canonical_json']
    assert result['policy_id'] == POLICY_ID
    assert result['collection_started_at_utc'] and result['verified_at_utc']
    assert iam.get_policy.call_count == 2
    assert iam.get_policy_version.call_args.kwargs == {'PolicyArn': ARN, 'VersionId': 'v190'}
    if os.name == 'posix':
        assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('overrides', [
    {'after': 'v191'},
    {'response_version': 'v189'},
    {'is_default': False},
    {'is_default': None},
    {'last_id': 'ANPA_DIFFERENT'},
    {'first_id': ''},
    {'before': 'invalid'},
    {'doc': None},
    {'doc': '{"not valid":'},
])
def test_mismatch_or_missing_metadata_rejects_without_evidence(tmp_path, capsys, overrides):
    ctx, iam = fake_ctx(**overrides)
    with pytest.raises(EvidenceUnavailable):
        policy_evidence(ctx, out=str(tmp_path))
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr().out == ''
    assert iam.get_policy.call_count <= 2


def test_failed_evidence_write_fails_closed_without_claiming_success(tmp_path, capsys):
    ctx, iam = fake_ctx()
    # An existing regular file cannot be used as an output directory.
    output_file = tmp_path / 'not-a-directory'
    output_file.write_text('sentinel')
    with pytest.raises(EvidenceUnavailable, match='persist'):
        policy_evidence(ctx, out=str(output_file))
    assert output_file.read_text() == 'sentinel'
    assert capsys.readouterr().out == ''
    assert iam.get_policy.call_count == 2
