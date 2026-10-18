"""R24 offline-only tests: no live credentials, no AWS account access."""
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from aws_security_audit.core import AuditError, EvidenceUnavailable
from aws_security_audit import r24_targeted_evidence as r24


_ACCOUNT = '123456789012'
_REGION = 'ap-northeast-1'


def manifest():
    return {
        'schema': 'aws-ros-r24-targeted-read-v1',
        'account': _ACCOUNT,
        'region': _REGION,
        'product': 'ros',
        'scope_confirmation': {
            'owner_ref': 'ROS-OWNER-CONFIRMATION-20261018',
            'confirmed_at_utc': '2026-10-18T12:00:00Z',
        },
        'targets': {
            'shield_resource_arns': [],
            'cloudtrail_trail_arns': [],
            'cloudtrail_s3_bucket_arns': [],
            'flow_log_eni_ids': [],
            'securityhub': True,
            'inspector_ec2_instance_ids': [],
            'ecr_images': [],
        },
    }


class FakeCtx:
    account = _ACCOUNT
    region = _REGION

    def __init__(self):
        self.calls = []
        self.guards = 0

    def client_cached(self, service, region):
        self.calls.append((service, region))
        return service

    def guard_expiration(self):
        self.guards += 1


@pytest.mark.parametrize('corrupt', [
    lambda x: x.update(product='unrelated'),
    lambda x: x.update(account='123456789013'),
    lambda x: x.update(region='ap-northeast-1,us-east-1'),
    lambda x: x['scope_confirmation'].update(owner_ref=''),
    lambda x: x['scope_confirmation'].update(confirmed_at_utc='2026-10-18'),
    lambda x: x['targets'].update(securityhub='true'),
    lambda x: x['targets'].update(shield_resource_arns=['*']),
    lambda x: x['targets'].update(flow_log_eni_ids=['eni-all']),
    lambda x: x['targets'].update(inspector_ec2_instance_ids=['i-all']),
    lambda x: x['targets'].update(ecr_images=[{'repository': 'ROS', 'digest': 'latest'}]),
    lambda x: x['targets'].update(unknown_extra=True),
    lambda x: x['targets'].update(securityhub=False),
])
def test_scope_invalid_fails_before_any_client(corrupt):
    x = manifest()
    corrupt(x)
    ctx = FakeCtx()
    with pytest.raises(AuditError):
        r24.collect_r24(ctx, x)
    assert not ctx.calls
    assert ctx.guards == 0


def test_valid_target_cardinality_and_exact_account_region():
    x = manifest()
    x['targets']['shield_resource_arns'] = [
        f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/sample/abc'
    ]
    x['targets']['cloudtrail_trail_arns'] = [
        f'arn:aws:cloudtrail:{_REGION}:{_ACCOUNT}:trail/sample'
    ]
    x['targets']['cloudtrail_s3_bucket_arns'] = ['arn:aws:s3:::sample-bucket']
    x['targets']['flow_log_eni_ids'] = ['eni-0123456789abcdef0']
    x['targets']['inspector_ec2_instance_ids'] = ['i-0123456789abcdef0']
    x['targets']['ecr_images'] = [{
        'repository': 'example/repo',
        'digest': 'sha256:' + 'f' * 64,
    }]
    assert r24.validate_manifest(x) == x
    for kind, data in [
        ('shield_resource_arns', ['arn:aws:ec2:ap-northeast-1:999999999999:instance/i-test']),
        ('cloudtrail_trail_arns', [f'arn:aws:cloudtrail:us-east-1:{_ACCOUNT}:trail/t']),
        ('cloudtrail_s3_bucket_arns', ['arn:aws:s3:::sample-bucket/obj']),
        ('flow_log_eni_ids', ['eni-0123456789abcdef0'] * 2),
    ]:
        y = deepcopy(x)
        y['targets'][kind] = data
        with pytest.raises(AuditError):
            r24.validate_manifest(y)


def test_cross_scope_identity_refused_even_if_manifest_well_formed():
    x = manifest()
    ctx = FakeCtx()
    ctx.account = '999999999999'
    with pytest.raises(AuditError, match='STS role account'):
        r24.collect_r24(ctx, x)
    assert not ctx.calls


def test_sts_only_service_calls_with_unverified_securityhub(monkeypatch):
    x = manifest()
    ctx = FakeCtx()
    recorded = []

    def fake_api(client, operation, **kwargs):
        recorded.append((client, operation, kwargs))
        raise EvidenceUnavailable('securityhub.describe_hub: InvalidAccessException')

    monkeypatch.setattr(r24, 'api_call', fake_api)
    result = r24.collect_r24(ctx, x)
    assert recorded == [('securityhub', 'describe_hub', {})]
    assert result['control_33_securityhub']['state'] == 'UNVERIFIED'
    assert result['control_33_securityhub']['error_cause'] == 'NOT_PROVEN'
    assert result['control_classifications_changed'] is False
    assert result['effective_no_write'] == 'NOT_PROVEN'
    assert result['control_40_ci']['state'] == 'NON_AWS_EXPORT_REQUIRED'
    assert ctx.guards == 1


def test_cloudtrail_selector_observation_does_not_mark_coverage_proven(monkeypatch):
    seen = []
    def api(client, op, **kwargs):
        seen.append((client, op, kwargs))
        if op == 'get_event_selectors':
            return {'EventSelectors': [
                {'DataResources': [{'Type': 'AWS::S3::Object',
                                    'Values': ['arn:aws:s3:::example/']}]},
            ]}
        if op == 'get_trail_status':
            return {'IsLogging': True, 'LatestDeliveryError': '',
                    'LatestDeliveryTime': datetime(2026, 10, 18, tzinfo=timezone.utc)}
        raise AssertionError(op)
    monkeypatch.setattr(r24, 'api_call', api)
    ctx = FakeCtx()
    output = r24._trail(
        ctx, _REGION,
        [f'arn:aws:cloudtrail:{_REGION}:{_ACCOUNT}:trail/example'],
        ['arn:aws:s3:::example', 'arn:aws:s3:::example-other'])
    found = output['trails'][0]
    assert found['bucket_matches'][0]['basic_selector_maybe'] is True
    assert found['bucket_matches'][1]['basic_selector_maybe'] is False
    assert all(b['effective_coverage'] == 'NOT_PROVEN' for b in found['bucket_matches'])
    assert found['s3_delivery_error_present'] is False
    assert [x[1] for x in seen] == ['get_trail_status', 'get_event_selectors']
    assert ctx.guards == 2


def test_only_explicit_eni_ids_are_queried(monkeypatch):
    seen = []
    def fake_paged(client, op, key, **kwargs):
        seen.append((client, op, key, kwargs))
        return [{'ResourceId': 'eni-0123456789abcdef0',
                 'FlowLogId': 'fl-001', 'FlowLogStatus': 'ACTIVE'},
                {'ResourceId': 'eni-11111111111111111',
                 'FlowLogId': 'fl-OTHER'}]
    monkeypatch.setattr(r24, 'paged', fake_paged)
    ctx = FakeCtx()
    out = r24._flow(ctx, _REGION, ['eni-0123456789abcdef0'])
    assert seen == [('ec2', 'describe_flow_logs', 'FlowLogs', {
        'Filter': [{'Name': 'resource-id', 'Values': ['eni-0123456789abcdef0']}]
    })]
    assert len(out['network_interfaces']) == 1
    assert len(out['network_interfaces'][0]['flow_logs']) == 1
    assert out['network_interfaces'][0]['effective_coverage'] == 'NOT_PROVEN'


def test_shield_only_returns_requested_resource_protection(monkeypatch):
    resource = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/demo/abc'
    def api(client, op, **kwargs):
        assert client == 'shield'
        assert op == 'describe_subscription'
        return {'Subscription': {'SubscriptionLimits': []}}
    def fake_paged(client, op, key, **kwargs):
        assert op == 'list_protections'
        assert kwargs == {'InclusionFilters': {'ResourceArns': [resource]}}
        return [{'ResourceArn': resource, 'Id': 'protected-id'},
                {'ResourceArn': 'arn:aws:cloudfront::123456789012:distribution/unrelated',
                 'Id': 'other-id'}]
    monkeypatch.setattr(r24, 'api_call', api)
    monkeypatch.setattr(r24, 'paged', fake_paged)
    out = r24._shield(FakeCtx(), _REGION, [resource])
    assert out['resources'] == [{'resource_arn': resource,
                                  'protection_listed': True,
                                  'protection_id': 'protected-id'}]
    assert out['state'] == 'OBSERVED_PARTIAL'




def test_shield_two_targets_use_separate_single_arn_filters(monkeypatch):
    """Shield InclusionFilters.ResourceArns has max one element per request."""
    first = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/ros-a/aaa'
    second = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/ros-b/bbb'
    filters = []

    def api(client, op, **kwargs):
        assert (client, op, kwargs) == ('shield', 'describe_subscription', {})
        return {'Subscription': {'SubscriptionLimits': []}}

    def fake_paged(client, op, key, **kwargs):
        assert (client, op, key) == ('shield', 'list_protections', 'Protections')
        arns = kwargs['InclusionFilters']['ResourceArns']
        assert len(arns) == 1
        filters.append(arns[0])
        return ([{'ResourceArn': first, 'Id': 'first-protection'}]
                if arns[0] == first else [])

    monkeypatch.setattr(r24, 'api_call', api)
    monkeypatch.setattr(r24, 'paged', fake_paged)
    result = r24._shield(FakeCtx(), _REGION, [first, second])
    assert filters == [first, second]
    assert result['state'] == 'OBSERVED_PARTIAL'
    assert result['subscription_observed'] is True
    assert result['resources'] == [
        {'resource_arn': first, 'protection_listed': True,
         'protection_id': 'first-protection'},
        {'resource_arn': second, 'protection_listed': False,
         'protection_id': None},
    ]


def test_shield_subscription_not_found_and_partial_list_errors_stay_unknown(monkeypatch):
    first = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/ros-a/aaa'
    second = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/ros-b/bbb'

    def api(client, op, **kwargs):
        raise EvidenceUnavailable('shield.describe_subscription: ResourceNotFoundException')

    def fake_paged(client, op, key, **kwargs):
        arn = kwargs['InclusionFilters']['ResourceArns'][0]
        if arn == second:
            raise EvidenceUnavailable('shield.list_protections: ValidationException')
        return [{'ResourceArn': first, 'Id': 'one-known-protection'}]

    monkeypatch.setattr(r24, 'api_call', api)
    monkeypatch.setattr(r24, 'paged', fake_paged)
    result = r24._shield(FakeCtx(), _REGION, [first, second])
    assert result['state'] == 'UNVERIFIED'
    assert result['subscription'] == 'UNVERIFIED'
    assert result['subscription_observed'] is False
    assert result['list'] == 'UNVERIFIED'
    assert len(result['errors']) == 2
    assert result['resources'][0]['protection_listed'] is True
    assert result['resources'][1]['protection_listed'] is None
    assert result['resources'][1]['list_state'] == 'UNVERIFIED'
    assert 'error_code' in result['resources'][1]


def test_shield_single_failure_never_becomes_unprotected(monkeypatch):
    target = f'arn:aws:elasticloadbalancing:{_REGION}:{_ACCOUNT}:loadbalancer/app/ros/abc'
    monkeypatch.setattr(
        r24, 'api_call', lambda *a, **k: {'Subscription': {}},
    )
    def refuse(*args, **kwargs):
        raise EvidenceUnavailable('shield.list_protections: ValidationException')
    monkeypatch.setattr(r24, 'paged', refuse)
    result = r24._shield(FakeCtx(), _REGION, [target])
    assert result['state'] == 'UNVERIFIED'
    assert result['resources'][0]['protection_listed'] is None

def test_inspector_and_ecr_queries_are_bound_to_explicit_targets(monkeypatch):
    seen = []
    ident = 'i-0123456789abcdef0'
    digest = 'sha256:' + 'a' * 64
    def fake_paged(client, op, key, **kwargs):
        seen.append((client, op, kwargs))
        return [{'resourceId': ident, 'scanStatus': {
            'statusCode': 'ACTIVE', 'reason': 'SUCCESSFUL'}}]
    def api(client, op, **kwargs):
        seen.append((client, op, kwargs))
        return {'imageDetails': [
            {'imageDigest': digest, 'imageScanStatus': {'status': 'COMPLETE'}}
        ]}
    monkeypatch.setattr(r24, 'paged', fake_paged)
    monkeypatch.setattr(r24, 'api_call', api)
    ctx = FakeCtx()
    assert r24._inspector(ctx, _REGION, [ident])['instances'][0][
        'resources'][0]['scan_status_code'] == 'ACTIVE'
    assert r24._ecr(ctx, _REGION, [{
        'repository': 'app/example', 'digest': digest}])['images'][0][
        'images'][0]['scan_status'] == 'COMPLETE'
    assert seen[0] == ('inspector2', 'list_coverage', {
        'filterCriteria': {'resourceId': [{
            'comparison': 'EQUALS', 'value': ident}]}
    })
    assert seen[1] == ('ecr', 'describe_images', {
        'repositoryName': 'app/example', 'imageIds': [{'imageDigest': digest}]
    })


def test_standards_do_not_automatically_prove_controls(monkeypatch):
    monkeypatch.setattr(r24, 'api_call',
                        lambda client, operation, **kwargs: {'HubArn': 'arn:synthetic'})
    monkeypatch.setattr(r24, 'paged',
                        lambda client, op, key, **kwargs: [
                            {'StandardsArn': 'arn:synthetic:standard',
                             'StandardsStatus': 'READY'}])
    out = r24._securityhub(FakeCtx(), _REGION, True)
    assert out['hub_observed'] is True
    assert out['standards_state'] == 'OBSERVED'
    assert out['checks_coverage'] == 'NOT_PROVEN'


def test_source_status_not_overwritten_by_empty_source(monkeypatch):
    x = manifest()
    x['targets']['securityhub'] = False
    x['targets']['flow_log_eni_ids'] = ['eni-0123456789abcdef0']
    monkeypatch.setattr(r24, 'paged', lambda *args, **kwargs: [])
    result = r24.collect_r24(FakeCtx(), x)
    assert result['control_27_flow_logs']['state'] == 'OBSERVED_PARTIAL'
    assert result['control_27_flow_logs']['network_interfaces'][0]['flow_logs'] == []
    assert result['control_27_flow_logs']['network_interfaces'][0]['effective_coverage'] == 'NOT_PROVEN'


def test_shield_substring_account_bypass_and_cross_region_refused():
    x = manifest()
    x['targets']['shield_resource_arns'] = [
        'arn:aws:elasticloadbalancing:ap-northeast-1:999999999999:'
        'loadbalancer/app/123456789012:escaped'
    ]
    with pytest.raises(AuditError, match='approved account'):
        r24.validate_manifest(x)
    x['targets']['shield_resource_arns'] = [
        f'arn:aws:elasticloadbalancing:us-east-1:{_ACCOUNT}:loadbalancer/app/other/a'
    ]
    with pytest.raises(AuditError, match='not allowlisted'):
        r24.validate_manifest(x)


def test_operator_script_preview_never_initializes_credentials(tmp_path, monkeypatch, capsys):
    import json
    import importlib.util
    from pathlib import Path
    script_path = Path(__file__).resolve().parents[1] / 'scripts' / 'r24_targeted_read_only.py'
    spec = importlib.util.spec_from_file_location('r24_operator_script_test', script_path)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    path = tmp_path / 'scope.json'
    path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(script, 'AuditContext',
                        lambda *args: (_ for _ in ()).throw(
                            AssertionError('unexpected AWS connection')))
    assert script.main(['--manifest', str(path)]) == 0
    assert 'PREVIEW_ONLY_NO_AWS' in capsys.readouterr().out


def test_operator_script_wrong_role_account_before_sts(tmp_path, monkeypatch):
    import json
    import importlib.util
    from pathlib import Path
    script_path = Path(__file__).resolve().parents[1] / 'scripts' / 'r24_targeted_read_only.py'
    spec = importlib.util.spec_from_file_location('r24_operator_script_test', script_path)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    path = tmp_path / 'scope.json'
    path.write_text(json.dumps(manifest()))
    monkeypatch.setattr(script, 'AuditContext',
                        lambda *args: (_ for _ in ()).throw(
                            AssertionError('unexpected AWS connection')))
    with pytest.raises(SystemExit) as exc:
        script.main([
            '--manifest', str(path), '--execute-approved-read',
            '--source-profile', 'source',
            '--role-arn', 'arn:aws:iam::999999999999:role/AnotherRole',
            '--out', str(tmp_path / 'private.json'),
        ])
    assert exc.value.code == 2
    assert not (tmp_path / 'private.json').exists()
