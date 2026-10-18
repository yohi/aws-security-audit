"""Issue #8 R15: selected S3 access configuration evidence, entirely offline."""
from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.control_observations import build_product_observations
from aws_security_audit.resource_scope import _record, collect_resource_inventory

REGION = 'ap-northeast-1'


class Ctx:
    def __init__(self):
        self.calls = []
        self.guards = 0

    def client_cached(self, service, region=None):
        self.calls.append(('client', service, region))
        return service

    def guard_expiration(self):
        self.guards += 1


def _setup(monkeypatch):
    import aws_security_audit.resource_scope as mod

    def fake_ec2(ctx, region, out, errors):
        out.extend([
            _record('s3', 'bucket', 'global', 'ros-private-evidence',
                    tags=[{'Key': 'Product', 'Value': 'ros'}]),
            _record('s3', 'bucket', 'global', 'irrelevant-shared-evidence',
                    tags=[{'Key': 'Product', 'Value': 'other'}]),
        ])
    monkeypatch.setattr(mod, '_add_ec2', fake_ec2)
    for name in ('_add_rds', '_add_elb', '_add_logs', '_add_s3', '_add_iam',
                 '_add_cloudfront'):
        monkeypatch.setattr(mod, name, lambda *args: None)
    monkeypatch.setattr(
        'aws_security_audit.shared_security_evidence.collect_shared_security_evidence',
        lambda *args: {'attribution': 'SHARED_UNATTRIBUTED', 'regions': []})
    return mod


def _selected(inventory):
    assert len(inventory['resources']) == 1
    bucket = inventory['resources'][0]
    assert bucket['resource_id'] == 'ros-private-evidence'
    assert bucket['attribution'] == 'DIRECT'
    return bucket['attributes']


def test_selected_s3_public_policy_and_ownership_are_context_only(monkeypatch):
    mod = _setup(monkeypatch)
    calls = []

    def api(client, operation, **kwargs):
        calls.append((client, operation, kwargs))
        if operation == 'get_bucket_policy_status':
            return {'PolicyStatus': {'IsPublic': True, 'RAW_SECRET': 'SECRET'}}
        if operation == 'get_bucket_ownership_controls':
            return {'OwnershipControls': {'Rules': [
                {'ObjectOwnership': 'BucketOwnerEnforced',
                 'RAW_PRIVATE_FIELD': 'SECRET'}]}}
        raise AssertionError('unexpected operation: ' + operation)

    monkeypatch.setattr(mod, 'api_call', api)
    ctx = Ctx()
    inventory = collect_resource_inventory(ctx, [REGION], 'ros')
    assert len(calls) == 2
    assert all(client == 's3' for client, _, _ in calls)
    assert all(kwargs == {'Bucket': 'ros-private-evidence'} for _, _, kwargs in calls)
    assert ctx.guards >= 2
    attrs = _selected(inventory)
    assert attrs['bucket_policy_is_public'] is True
    assert attrs['bucket_policy_status_lookup'] == 'API_VERIFIED'
    assert attrs['bucket_object_ownership'] == 'BucketOwnerEnforced'
    assert attrs['bucket_ownership_lookup'] == 'API_VERIFIED'
    assert inventory['collection_errors'] == []
    obs = build_product_observations(inventory, [REGION])
    rows = [row for row in obs['rows'] if row['number'] == 18]
    assert len(rows) == 2
    assert all(row['property_result'] == 'CONTEXT_ONLY' for row in rows)
    assert obs['by_control']['18']['ok'] == 0
    assert obs['by_control']['18']['fail'] == 0
    assert 'SECRET' not in str(inventory)


def test_selected_s3_malformed_success_fails_closed_and_is_counted(monkeypatch):
    mod = _setup(monkeypatch)
    calls = []

    def malformed(client, operation, **kwargs):
        calls.append(operation)
        if operation == 'get_bucket_policy_status':
            return {'PolicyStatus': {'IsPublic': 'False', 'RAW': 'SECRET'}}
        if operation == 'get_bucket_ownership_controls':
            return {'OwnershipControls': {'Rules': [
                {'ObjectOwnership': 'UNKNOWN', 'RAW': 'SECRET'}]}}
        raise AssertionError(operation)

    monkeypatch.setattr(mod, 'api_call', malformed)
    inventory = collect_resource_inventory(Ctx(), [REGION], 'ros')
    attrs = _selected(inventory)
    assert len(calls) == 2
    assert attrs['bucket_policy_is_public'] is None
    assert attrs['bucket_policy_status_lookup'] == 'UNVERIFIED_SCHEMA'
    assert attrs['bucket_object_ownership'] is None
    assert attrs['bucket_ownership_lookup'] == 'UNVERIFIED_SCHEMA'
    assert len(inventory['collection_errors']) == 2
    assert all(error['resource'] == 'ros-private-evidence'
               for error in inventory['collection_errors'])
    obs = build_product_observations(inventory, [REGION])
    assert obs['by_control']['18']['unknown'] == 2
    assert obs['by_control']['18']['collection_error_count'] == 2
    assert obs['by_control']['18']['fail'] == 0
    assert 'SECRET' not in str(inventory)


def test_selected_s3_absent_configuration_is_not_negative_public_claim(monkeypatch):
    mod = _setup(monkeypatch)

    def absent(client, operation, **kwargs):
        if operation == 'get_bucket_policy_status':
            raise EvidenceUnavailable('s3.get_bucket_policy_status: NoSuchBucketPolicy')
        if operation == 'get_bucket_ownership_controls':
            raise EvidenceUnavailable(
                's3.get_bucket_ownership_controls: OwnershipControlsNotFoundError')
        raise AssertionError(operation)

    monkeypatch.setattr(mod, 'api_call', absent)
    inventory = collect_resource_inventory(Ctx(), [REGION], 'ros')
    attrs = _selected(inventory)
    assert attrs['bucket_policy_status_lookup'] == 'NO_BUCKET_POLICY'
    assert attrs['bucket_ownership_lookup'] == 'NOT_CONFIGURED'
    assert attrs['bucket_policy_is_public'] is None
    assert attrs['bucket_object_ownership'] is None
    assert inventory['collection_errors'] == []
    obs = build_product_observations(inventory, [REGION])
    assert obs['by_control']['18']['unknown'] == 2
    assert obs['by_control']['18']['collection_error_count'] == 0
    assert obs['by_control']['18']['ok'] == obs['by_control']['18']['fail'] == 0


def test_selected_s3_access_denied_records_only_selected_bucket_errors(monkeypatch):
    mod = _setup(monkeypatch)

    def denied(client, operation, **kwargs):
        raise EvidenceUnavailable('s3.' + operation + ': AccessDenied')

    monkeypatch.setattr(mod, 'api_call', denied)
    inventory = collect_resource_inventory(Ctx(), [REGION], 'ros')
    attrs = _selected(inventory)
    assert attrs['bucket_policy_status_lookup'] == 'UNVERIFIED_READ_ERROR'
    assert attrs['bucket_ownership_lookup'] == 'UNVERIFIED_READ_ERROR'
    obs = build_product_observations(inventory, [REGION])
    assert obs['by_control']['18']['collection_error_count'] == 2
    assert obs['by_control']['18']['unknown'] == 2
    assert obs['by_control']['18']['fail'] == 0


def test_s3_access_evidence_not_queried_in_account_inventory(monkeypatch):
    mod = _setup(monkeypatch)

    def reject_new_calls(*args, **kwargs):
        raise AssertionError('new S3 operation in account inventory')

    monkeypatch.setattr(mod, 'api_call', reject_new_calls)
    inventory = collect_resource_inventory(Ctx(), [REGION], None)
    assert len(inventory['resources']) == 2
    assert all('bucket_policy_status_lookup' not in r['attributes']
               for r in inventory['resources'])
    assert inventory['collection_errors'] == []
