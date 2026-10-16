"""Shared results, pagination, read-only API adapter and authentication guard."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


ROLE_PATTERN = re.compile(r"^arn:(aws(?:-cn|-us-gov)?):iam::([0-9]{12}):role/(?:[\w+=,.@-]+/)*([\w+=,.@-]+)$")
STATUSES = frozenset({'PASS', 'FAIL', 'UNKNOWN', 'MANUAL_REVIEW', 'NOT_APPLICABLE'})


class AuditError(Exception):
    """An expected failure, with secrets omitted from its message."""


class EvidenceUnavailable(AuditError):
    pass


@dataclass
class Finding:
    number: int
    status: str
    scope: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError('invalid status')

    def to_dict(self) -> dict:
        return asdict(self)


def manual(number: int, scope: str, reason: str, evidence: list[str] | None = None) -> Finding:
    return Finding(number, 'MANUAL_REVIEW', scope, reason, evidence or [])


def unknown(number: int, scope: str, reason: str) -> Finding:
    return Finding(number, 'UNKNOWN', scope, reason)


def verdict(number: int, scope: str, tested: int, failures: list[str], ok_description: str, *, evidence: list[str] | None = None) -> Finding:
    if not tested:
        return Finding(number, 'NOT_APPLICABLE', scope, '対象リソースがありません', evidence or [])
    if failures:
        return Finding(number, 'FAIL', scope, f'{len(failures)}/{tested}件で基準未達', failures[:100] + (evidence or []))
    return Finding(number, 'PASS', scope, f'{tested}件を確認: {ok_description}', evidence or [])


def api_call(client: Any, operation: str, **kwargs: Any) -> dict:
    if not operation.startswith(('get_', 'describe_', 'list_')) and operation != 'assume_role':
        raise AuditError('Mutating or unapproved AWS API operation rejected')
    """Deliberately don't print SDK exceptions: request payloads might contain sensitive info."""
    try:
        return getattr(client, operation)(**kwargs)
    except ClientError as exc:
        code = str(exc.response.get('Error', {}).get('Code', 'ClientError'))
        # Code is an AWS service-defined symbolic label, not a secret.
        safe = re.sub(r'[^A-Za-z0-9_-]', '', code)[:64]
        raise EvidenceUnavailable(f'{client.meta.service_model.service_name}.{operation}: {safe}') from None
    except BotoCoreError as exc:
        raise EvidenceUnavailable(f'{client.meta.service_model.service_name}.{operation}: {type(exc).__name__}') from None


def paged(client: Any, operation: str, result_key: str, **kwargs: Any) -> list:
    if not operation.startswith(('get_', 'describe_', 'list_')):
        raise AuditError('Mutating or unapproved AWS API operation rejected')
    try:
        if client.can_paginate(operation):
            collected = []
            for page in client.get_paginator(operation).paginate(**kwargs):
                collected.extend(page.get(result_key, []))
            return collected
    except (ClientError, BotoCoreError) as exc:
        if isinstance(exc, ClientError):
            code = re.sub(r'[^A-Za-z0-9_-]', '', exc.response.get('Error', {}).get('Code', 'ClientError'))[:64]
        else:
            code = type(exc).__name__
        raise EvidenceUnavailable(f'{client.meta.service_model.service_name}.{operation}: {code}') from None
    # Some legacy AWS APIs don't advertise boto3 paginator support; token traversal.
    output = []
    token = None
    for _ in range(10000):
        args = dict(kwargs)
        if token is not None:
            args['NextToken'] = token
        result = api_call(client, operation, **args)
        output.extend(result.get(result_key, []))
        next_token = result.get('NextToken')
        if not next_token:
            return output
        if next_token == token:
            raise EvidenceUnavailable(f'{operation}: pagination cycle')
        token = next_token
    raise EvidenceUnavailable(f'{operation}: pagination limit exceeded')


class AuditContext:
    """Use the aws-login source profile ONLY for AssumeRole; all audit clients use scoped STS keys."""

    def __init__(self, source_profile: str, expected_role_arn: str, region: str):
        match = ROLE_PATTERN.fullmatch(expected_role_arn)
        if not match:
            raise AuditError('Expected role ARN is malformed')
        self.partition, self.account, self.role_name = match.groups()
        self.expected_role_arn = expected_role_arn
        self.region = region
        self.source_profile = source_profile
        source = boto3.Session(profile_name=source_profile, region_name=region)
        source_config = source._session.get_scoped_config()
        # Don't allow a source profile that is itself an assumed role: role chaining can be surprising.
        if source_config.get('role_arn'):
            raise AuditError('Source profile must be aws login (or SSO), not an AssumeRole profile')
        if not (source_config.get('login_session') or source_config.get('sso_session') or source_config.get('sso_start_url')):
            raise AuditError('Source profile must be configured for aws login or IAM Identity Center; static key profiles are rejected')
        # A login_session config field cannot prove the active credential provider.
        # Shared keys and other credential providers can take precedence.
        # Inspect provider provenance only; do not access or log key values.
        credentials = source.get_credentials()
        method = getattr(credentials, 'method', None)
        login = bool(source_config.get('login_session'))
        sso = bool(source_config.get('sso_session') or source_config.get('sso_start_url'))
        allowed = {'login'} if login and not sso else {'sso'} if sso and not login else set()
        if method not in allowed:
            raise AuditError('Credential provider does not match declared login/SSO source; STS not attempted')
        assumed = api_call(
            source.client('sts'), 'assume_role',
            RoleArn=expected_role_arn,
            RoleSessionName='aws-security-audit',
            DurationSeconds=3600,
            PolicyArns=[{'arn': f'arn:{self.partition}:iam::aws:policy/ReadOnlyAccess'}],
        )
        cred = assumed['Credentials']
        self.expiration = cred['Expiration']
        self.session = boto3.Session(
            aws_access_key_id=cred['AccessKeyId'],
            aws_secret_access_key=cred['SecretAccessKey'],
            aws_session_token=cred['SessionToken'],
            region_name=region,
        )
        identity = api_call(self.client('sts', region), 'get_caller_identity')
        expected = f'arn:{self.partition}:sts::{self.account}:assumed-role/{self.role_name}/'
        if identity.get('Account') != self.account or not identity.get('Arn', '').startswith(expected):
            raise AuditError('Refusing to run: active credentials are not the expected assumed-role session')
        self.identity_arn = identity['Arn']
        self._cache: dict[tuple[str, str], Any] = {}
        # Discard source session reference once AssumeRole has completed.
        del source

    def guard_expiration(self) -> None:
        if (self.expiration - datetime.now(timezone.utc)).total_seconds() < 45:
            raise EvidenceUnavailable('STS scoped credentials expiring; re-run after refreshing aws login')

    def client(self, service: str, region: str | None = None) -> Any:
        return self.session.client(service, region_name=region or self.region)

    def client_cached(self, service: str, region: str | None = None) -> Any:
        key = (service, region or self.region)
        if key not in self._cache:
            self._cache[key] = self.client(*key)
        return self._cache[key]

    def active_regions(self) -> list[str]:
        regions = api_call(self.client('ec2'), 'describe_regions', AllRegions=False).get('Regions', [])
        result = sorted({entry['RegionName'] for entry in regions})
        if not result:
            raise EvidenceUnavailable('No active regions could be enumerated')
        return result


def overall_status(statuses: list[str]) -> str:
    """Partial coverage can never be a PASS."""
    if 'FAIL' in statuses:
        return 'FAIL'
    if 'UNKNOWN' in statuses:
        return 'UNKNOWN'
    if 'MANUAL_REVIEW' in statuses:
        return 'MANUAL_REVIEW'
    if 'PASS' in statuses:
        return 'PASS'
    return 'NOT_APPLICABLE'


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')
