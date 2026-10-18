"""Selected-bucket S3 account BPA and access-point configuration context.

Read-only S3Control API use. Account configuration remains SHARED_UNATTRIBUTED,
not a product compliance result. No access-point policies/ACLs/principals/ARN
payloads or unrelated bucket metadata are exported.
"""
from __future__ import annotations

import re

from .core import EvidenceUnavailable, api_call

BPA_FLAGS = ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy',
             'RestrictPublicBuckets')
REGION_PATTERN = re.compile(r'^[a-z]{2}(?:-gov)?-[a-z]+-\d+$')


def _safe_bpa(response):
    if not isinstance(response, dict):
        return None
    bpa = response.get('PublicAccessBlockConfiguration')
    if not isinstance(bpa, dict) or any(type(bpa.get(flag)) is not bool
                                        for flag in BPA_FLAGS):
        return None
    return {flag: bpa[flag] for flag in BPA_FLAGS}


def _error(errors, region, operation, reason, *, resource=None, service='s3control'):
    item = {'region': region, 'service': service, 'operation': operation,
            'reason': str(reason)[:180]}
    if resource is not None:
        item['resource'] = resource
    errors.append(item)


def _call(ctx, client, operation, **kwargs):
    ctx.guard_expiration()
    return api_call(client, operation, **kwargs)


def _account_bpa(ctx, region, errors):
    result = {'attribution': 'SHARED_UNATTRIBUTED', 'account_id': ctx.account,
              'read_region': region, 'lookup': 'UNVERIFIED',
              'public_access_block': None}
    try:
        response = _call(
            ctx, ctx.client_cached('s3control', region),
            'get_public_access_block', AccountId=ctx.account)
    except EvidenceUnavailable as exc:
        if 'NoSuchPublicAccessBlockConfiguration' in str(exc):
            result['lookup'] = 'NOT_CONFIGURED'
        else:
            result['lookup'] = 'UNVERIFIED_READ_ERROR'
            _error(errors, region, 'get_public_access_block', exc,
                   resource=ctx.account)
        return result
    flags = _safe_bpa(response)
    if flags is None:
        result['lookup'] = 'UNVERIFIED_SCHEMA'
        _error(errors, region, 'get_public_access_block',
               'Successful account BPA response failed schema validation',
               resource=ctx.account)
    else:
        result['lookup'] = 'API_VERIFIED'
        result['public_access_block'] = flags
    return result


def _bucket_region(ctx, bucket, errors):
    try:
        response = _call(ctx, ctx.client_cached('s3'),
                         'get_bucket_location', Bucket=bucket)
    except EvidenceUnavailable as exc:
        _error(errors, 'global', 'get_bucket_location', exc,
               resource=bucket, service='s3')
        return None
    if not isinstance(response, dict) or 'LocationConstraint' not in response:
        # Botocore may omit an explicit None-valued member for us-east-1.
        # The location API returns no LocationConstraint for that region.
        if not isinstance(response, dict) or response:
            _error(errors, 'global', 'get_bucket_location',
                   'Successful bucket location response schema unverified',
                   resource=bucket, service='s3')
            return None
        return 'us-east-1'
    raw = response['LocationConstraint']
    region = ('us-east-1' if raw is None else 'eu-west-1' if raw == 'EU'
              else raw)
    if not isinstance(region, str) or REGION_PATTERN.fullmatch(region) is None:
        _error(errors, 'global', 'get_bucket_location',
               'Bucket location not a supported region name',
               resource=bucket, service='s3')
        return None
    return region


def _list_bucket_access_points(ctx, region, bucket, errors):
    """Strictly page a bucket-filtered list, without recording partial success."""
    client = ctx.client_cached('s3control', region)
    points, token, visited = [], None, set()
    for _ in range(100):
        args = {'AccountId': ctx.account, 'Bucket': bucket}
        if token is not None:
            args['NextToken'] = token
        try:
            response = _call(ctx, client, 'list_access_points', **args)
        except EvidenceUnavailable as exc:
            _error(errors, region, 'list_access_points', exc, resource=bucket)
            return None
        if not isinstance(response, dict) or not isinstance(
                response.get('AccessPointList'), list):
            _error(errors, region, 'list_access_points',
                   'Successful access point listing schema unverified',
                   resource=bucket)
            return None
        for item in response['AccessPointList']:
            if (not isinstance(item, dict) or item.get('Bucket') != bucket
                    or not isinstance(item.get('Name'), str)
                    or not (3 <= len(item['Name']) <= 255)
                    or not re.fullmatch(r'[a-z0-9-]+', item['Name'])):
                _error(errors, region, 'list_access_points',
                       'Access point identity/bucket mismatch or schema unverified',
                       resource=bucket)
                return None
            points.append(item['Name'])
        next_token = response.get('NextToken')
        if next_token is None:
            return sorted(set(points)) if len(points) == len(set(points)) else None
        if (not isinstance(next_token, str) or not next_token
                or next_token in visited):
            _error(errors, region, 'list_access_points',
                   'Access point pagination invalid or repeated token',
                   resource=bucket)
            return None
        visited.add(next_token)
        token = next_token
    _error(errors, region, 'list_access_points',
           'Access point page limit reached', resource=bucket)
    return None


def _describe_point(ctx, region, bucket, name, errors):
    result = {'name': name, 'lookup': 'UNVERIFIED',
              'network_origin': None, 'public_access_block': None}
    try:
        response = _call(ctx, ctx.client_cached('s3control', region),
                         'get_access_point', AccountId=ctx.account, Name=name)
    except EvidenceUnavailable as exc:
        result['lookup'] = 'UNVERIFIED_READ_ERROR'
        _error(errors, region, 'get_access_point', exc, resource=bucket)
        return result
    if (not isinstance(response, dict) or response.get('Name') != name
            or response.get('Bucket') != bucket
            or response.get('NetworkOrigin') not in ('VPC', 'Internet')):
        result['lookup'] = 'UNVERIFIED_SCHEMA'
        _error(errors, region, 'get_access_point',
               'Access point detail identity/network schema unverified',
               resource=bucket)
        return result
    result['network_origin'] = response['NetworkOrigin']
    if 'PublicAccessBlockConfiguration' not in response:
        result['lookup'] = 'BPA_NOT_REPORTED'
        return result
    flags = _safe_bpa(response)
    if flags is None:
        result['lookup'] = 'UNVERIFIED_SCHEMA'
        _error(errors, region, 'get_access_point',
               'Access point BPA response schema unverified',
               resource=bucket)
    else:
        result['lookup'] = 'API_VERIFIED'
        result['public_access_block'] = flags
    return result


def collect_selected_s3_control_evidence(ctx, selected, errors):
    """Return shared-account BPA and set per-DIRECT-bucket access-point evidence."""
    buckets = [r for r in selected if r.get('service') == 's3'
               and r.get('resource_type') == 'bucket'
               and r.get('attribution') == 'DIRECT']
    if not buckets:
        return None
    account = getattr(ctx, 'account', None)
    if not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account):
        # Offline fake contexts without an AWS account cannot probe S3Control.
        # Real AuditContext binds the exact account from the assumed-role ARN.
        return None
    shared = _account_bpa(ctx, ctx.region, errors) if isinstance(
        getattr(ctx, 'region', None), str) else _account_bpa(
            ctx, 'ap-northeast-1', errors)
    for resource in buckets:
        name = resource['resource_id']
        attrs = resource['attributes']
        attrs['access_point_lookup'] = 'UNVERIFIED'
        attrs['access_point_evidence'] = []
        region = _bucket_region(ctx, name, errors)
        attrs['access_point_bucket_region'] = region
        if region is None:
            attrs['access_point_lookup'] = 'UNVERIFIED_BUCKET_REGION'
            continue
        names = _list_bucket_access_points(ctx, region, name, errors)
        if names is None:
            attrs['access_point_lookup'] = 'UNVERIFIED_LIST'
            continue
        entries = [_describe_point(ctx, region, name, point, errors)
                   for point in names]
        attrs['access_point_evidence'] = entries
        attrs['access_point_lookup'] = ('LIST_VERIFIED'
                                        if all(e['lookup'] == 'API_VERIFIED'
                                               for e in entries)
                                        else 'PARTIAL_DETAILS')
    return shared
