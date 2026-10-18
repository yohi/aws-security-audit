"""R17 offline fixture coverage for bounded S3Control account/AP evidence."""
from __future__ import annotations

from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.control_observations import build_product_observations
from aws_security_audit.resource_scope import (
    _record, collect_resource_inventory, product_findings,
)

REGION = 'ap-northeast-1'
ACCOUNT = '123456789012'
FLAGS = {
    'BlockPublicAcls': True,
    'IgnorePublicAcls': True,
    'BlockPublicPolicy': True,
    'RestrictPublicBuckets': True,
}


class Ctx:
    account = ACCOUNT
    region = REGION

    def __init__(self):
        self.calls = []
        self.guards = 0

    def guard_expiration(self):
        self.guards += 1

    def client_cached(self, service, region=None):
        self.calls.append((service, region))
        return (service, region)


def _setup(monkeypatch, include_direct=True):
    import aws_security_audit.resource_scope as mod

    def fake_ec2(ctx, region, out, errors):
        records = [
            _record('s3', 'bucket', 'global', 'not-ros-bucket',
                    tags=[{'Key': 'Product', 'Value': 'unrelated'}]),
        ]
        if include_direct:
            records.append(
                _record('s3', 'bucket', 'global', 'ros-bucket',
                        tags=[{'Key': 'Product', 'Value': 'ros'}]))
        out.extend(records)

    monkeypatch.setattr(mod, '_add_ec2', fake_ec2)
    for name in ('_add_rds', '_add_elb', '_add_logs', '_add_s3', '_add_iam',
                 '_add_cloudfront', '_collect_selected_s3_access_evidence'):
        monkeypatch.setattr(mod, name, lambda *args: None)
    monkeypatch.setattr(
        'aws_security_audit.shared_security_evidence.collect_shared_security_evidence',
        lambda *args: {'attribution': 'SHARED_UNATTRIBUTED', 'regions': []})
    return mod


def _bucket(inv):
    assert len(inv['resources']) == 1
    bucket = inv['resources'][0]
    assert bucket['resource_id'] == 'ros-bucket'
    assert bucket['attribution'] == 'DIRECT'
    return bucket['attributes']


def test_account_bpa_and_access_point_verified_without_raw_policies(monkeypatch):
    _setup(monkeypatch)
    seen = []
    import aws_security_audit.s3_control_access_evidence as module

    def api(client, operation, **kwargs):
        seen.append((client, operation, kwargs))
        if operation == 'get_public_access_block':
            return {'PublicAccessBlockConfiguration': dict(FLAGS), 'Secret': 'NEVER_EXPORT'}
        if operation == 'get_bucket_location':
            return {'LocationConstraint': REGION}
        if operation == 'list_access_points':
            return {'AccessPointList': [{'Bucket': 'ros-bucket',
                                        'Name': 'ros-access',
                                        'Secret': 'NEVER_EXPORT'}]}
        if operation == 'get_access_point':
            return {'Bucket': 'ros-bucket', 'Name': 'ros-access',
                    'NetworkOrigin': 'Internet',
                    'PublicAccessBlockConfiguration': dict(FLAGS),
                    'Policy': 'NEVER_EXPORT'}
        raise AssertionError(operation)

    monkeypatch.setattr(module, 'api_call', api)
    ctx = Ctx()
    inv = collect_resource_inventory(ctx, [REGION], 'ros')
    assert len(seen) == 4
    assert seen[0][1:] == ('get_public_access_block', {'AccountId': ACCOUNT})
    assert seen[1][1:] == ('get_bucket_location', {'Bucket': 'ros-bucket'})
    assert seen[2][1:] == ('list_access_points', {
        'AccountId': ACCOUNT, 'Bucket': 'ros-bucket'})
    assert seen[3][1:] == ('get_access_point', {
        'AccountId': ACCOUNT, 'Name': 'ros-access'})
    assert ctx.guards >= 4
    account = inv['shared_s3_account_access_evidence']
    assert account['lookup'] == 'API_VERIFIED'
    assert account['attribution'] == 'SHARED_UNATTRIBUTED'
    assert account['public_access_block'] == FLAGS
    attrs = _bucket(inv)
    assert attrs['access_point_lookup'] == 'LIST_VERIFIED'
    assert attrs['access_point_evidence'] == [{
        'name': 'ros-access', 'lookup': 'API_VERIFIED',
        'network_origin': 'Internet', 'public_access_block': FLAGS,
    }]
    assert inv['collection_errors'] == []
    assert 'NEVER_EXPORT' not in str(inv)
    obs = build_product_observations(inv, [REGION])
    relevant = [x for x in obs['rows'] if x['number'] == 18]
    assert len(relevant) == 2
    assert all(x['property_result'] == 'CONTEXT_ONLY' for x in relevant)
    assert any(x['attribution'] == 'SHARED_UNATTRIBUTED' for x in relevant)
    assert obs['by_control']['18']['context'] == 2
    assert obs['by_control']['18']['ok'] == obs['by_control']['18']['fail'] == 0
    assert {f.number: f.status for f in product_findings(inv, [REGION])}[18] == 'MANUAL_REVIEW'


def test_empty_listing_is_scoped_observation_not_product_pass(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module

    def api(_, operation, **kwargs):
        if operation == 'get_public_access_block':
            raise EvidenceUnavailable('s3control.get_public_access_block: NoSuchPublicAccessBlockConfiguration')
        if operation == 'get_bucket_location':
            return {'LocationConstraint': None}
        if operation == 'list_access_points':
            assert kwargs['Bucket'] == 'ros-bucket'
            return {'AccessPointList': []}
        raise AssertionError(operation)

    monkeypatch.setattr(module, 'api_call', api)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    account = inv['shared_s3_account_access_evidence']
    assert account['lookup'] == 'NOT_CONFIGURED'
    assert account['public_access_block'] is None
    assert _bucket(inv)['access_point_bucket_region'] == 'us-east-1'
    assert _bucket(inv)['access_point_lookup'] == 'LIST_VERIFIED'
    assert _bucket(inv)['access_point_evidence'] == []
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['18']['unknown'] == 1
    assert obs['by_control']['18']['context'] == 1
    assert obs['by_control']['18']['collection_error_count'] == 0
    assert obs['by_control']['18']['ok'] == 0


def test_denied_account_and_ap_listing_are_unknown_with_error_provenance(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module

    def api(_, operation, **kwargs):
        if operation == 'get_bucket_location':
            return {'LocationConstraint': REGION}
        raise EvidenceUnavailable('s3control.' + operation + ': AccessDenied')

    monkeypatch.setattr(module, 'api_call', api)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    assert inv['shared_s3_account_access_evidence']['lookup'] == 'UNVERIFIED_READ_ERROR'
    assert _bucket(inv)['access_point_lookup'] == 'UNVERIFIED_LIST'
    assert _bucket(inv)['access_point_evidence'] == []
    assert [x['operation'] for x in inv['collection_errors']] == [
        'get_public_access_block', 'list_access_points']
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['18']['unknown'] == 2
    assert obs['by_control']['18']['collection_error_count'] == 2
    assert obs['by_control']['18']['ok'] == obs['by_control']['18']['fail'] == 0


def test_wrong_bucket_identity_or_malformed_account_bpa_fails_closed(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module

    def api(_, operation, **kwargs):
        if operation == 'get_public_access_block':
            return {'PublicAccessBlockConfiguration':
                    {**FLAGS, 'BlockPublicAcls': 'true'},
                    'Sensitive': 'NEVER_EXPORT'}
        if operation == 'get_bucket_location':
            return {'LocationConstraint': REGION}
        if operation == 'list_access_points':
            return {'AccessPointList': [{'Bucket': 'unrelated',
                                        'Name': 'other-access'}]}
        raise AssertionError(operation)

    monkeypatch.setattr(module, 'api_call', api)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    assert inv['shared_s3_account_access_evidence']['lookup'] == 'UNVERIFIED_SCHEMA'
    assert _bucket(inv)['access_point_lookup'] == 'UNVERIFIED_LIST'
    assert _bucket(inv)['access_point_evidence'] == []
    assert 'NEVER_EXPORT' not in str(inv)
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['18']['unknown'] == 2
    assert obs['by_control']['18']['collection_error_count'] == 2


def test_paginated_access_points_and_partial_detail_errors(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module
    called = []

    def api(_, operation, **kwargs):
        called.append((operation, kwargs))
        if operation == 'get_public_access_block':
            return {'PublicAccessBlockConfiguration': dict(FLAGS)}
        if operation == 'get_bucket_location':
            return {'LocationConstraint': 'EU'}
        if operation == 'list_access_points':
            if 'NextToken' not in kwargs:
                return {'AccessPointList': [{'Bucket': 'ros-bucket',
                                            'Name': 'first-ap'}],
                        'NextToken': 'token-1'}
            assert kwargs['NextToken'] == 'token-1'
            return {'AccessPointList': [{'Bucket': 'ros-bucket',
                                        'Name': 'second-ap'}]}
        if operation == 'get_access_point':
            if kwargs['Name'] == 'first-ap':
                return {'Bucket': 'ros-bucket', 'Name': 'first-ap',
                        'NetworkOrigin': 'VPC',
                        'PublicAccessBlockConfiguration': dict(FLAGS)}
            return {'Bucket': 'ros-bucket', 'Name': 'second-ap',
                    'NetworkOrigin': 'Internet'}
        raise AssertionError(operation)

    monkeypatch.setattr(module, 'api_call', api)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    attrs = _bucket(inv)
    assert attrs['access_point_bucket_region'] == 'eu-west-1'
    assert attrs['access_point_lookup'] == 'PARTIAL_DETAILS'
    assert len(attrs['access_point_evidence']) == 2
    assert attrs['access_point_evidence'][1]['lookup'] == 'BPA_NOT_REPORTED'
    assert [x[1]['NextToken'] for x in called
            if x[0] == 'list_access_points' and 'NextToken' in x[1]] == ['token-1']
    assert len(inv['collection_errors']) == 0
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['18']['unknown'] == 1


def test_duplicate_access_point_or_pagination_cycle_remains_unknown(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module

    for mode in ('duplicate', 'cycle'):
        def api(_, operation, **kwargs):
            if operation == 'get_public_access_block':
                return {'PublicAccessBlockConfiguration': dict(FLAGS)}
            if operation == 'get_bucket_location':
                return {'LocationConstraint': REGION}
            if operation == 'list_access_points':
                if mode == 'duplicate':
                    return {'AccessPointList': [
                        {'Bucket': 'ros-bucket', 'Name': 'same-ap'},
                        {'Bucket': 'ros-bucket', 'Name': 'same-ap'}]}
                return {'AccessPointList': [], 'NextToken': 'cycle'}
            raise AssertionError(operation)

        monkeypatch.setattr(module, 'api_call', api)
        inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
        assert _bucket(inv)['access_point_lookup'] == 'UNVERIFIED_LIST'
        assert len(inv['collection_errors']) == 1
        assert inv['collection_errors'][0]['operation'] == 'list_access_points'
        assert build_product_observations(inv, [REGION])['by_control']['18']['unknown'] == 1


def test_account_mode_and_unrelated_resources_do_not_trigger_new_reads(monkeypatch):
    _setup(monkeypatch)
    import aws_security_audit.s3_control_access_evidence as module

    monkeypatch.setattr(module, 'api_call', lambda *args, **kwargs: (
        (_ for _ in ()).throw(AssertionError('New S3Control read unexpectedly called'))))
    inv = collect_resource_inventory(Ctx(), [REGION], None)
    assert len(inv['resources']) == 2
    assert 'shared_s3_account_access_evidence' not in inv
    assert all('access_point_lookup' not in r['attributes'] for r in inv['resources'])


def test_no_direct_s3_bucket_skips_account_and_access_point_reads(monkeypatch):
    _setup(monkeypatch, include_direct=False)
    import aws_security_audit.s3_control_access_evidence as module

    monkeypatch.setattr(module, 'api_call', lambda *args, **kwargs: (
        (_ for _ in ()).throw(AssertionError('Unselected bucket query'))))
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    assert inv['resources'] == []
    assert 'shared_s3_account_access_evidence' not in inv
    assert inv['collection_errors'] == []
