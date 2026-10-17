"""Issue #8: offline fixtures for shared security services and negative/unknown evidence."""
from __future__ import annotations

from aws_security_audit.control_observations import (
    build_product_observations, CONTEXT_ONLY, PROPERTY_UNKNOWN,
)
from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.resource_scope import _record, product_deep_evidence


REGION = 'ap-northeast-1'


class Ctx:
    def __init__(self):
        self.actions = []
        self.guard_count = 0

    def client_cached(self, service, region):
        assert region == REGION
        return service

    def guard_expiration(self):
        self.guard_count += 1


def _success_client_api(ctx, operation, kwargs):
    if ctx == 'cloudtrail':
        if operation == 'describe_trails':
            assert kwargs == {'includeShadowTrails': True}
            return {'trailList': [{
                'TrailARN': 'arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/org-trail',
                'Name': 'org-trail', 'HomeRegion': 'ap-northeast-1',
                'IsMultiRegionTrail': True, 'IsOrganizationTrail': True,
                'LogFileValidationEnabled': True,
            }]}
        if operation == 'get_trail_status':
            return {'IsLogging': True, 'LatestDeliveryError': '',
                    'LatestDigestDeliveryError': '',
                    'LatestDeliveryTime': '2026-10-16T00:00:00Z'}
        if operation == 'get_event_selectors':
            return {'EventSelectors': [
                {'IncludeManagementEvents': True,
                 'DataResources': [{'Type': 'AWS::S3::Object',
                                    'Values': ['arn:aws:s3:::ros-data/']}]},
            ]}
    if ctx == 'guardduty' and operation == 'get_detector':
        return {'Status': 'ENABLED', 'FindingPublishingFrequency': 'FIFTEEN_MINUTES',
                'Features': [{'Name': 'S3_DATA_EVENTS', 'Status': 'ENABLED'}]}
    if ctx == 'securityhub':
        if operation == 'describe_hub':
            return {'HubArn': 'arn:aws:securityhub:ap-northeast-1:123456789012:hub/default'}
    raise AssertionError((ctx, operation))


def _success_client_paged(ctx, operation, field, kwargs):
    if ctx == 'guardduty' and operation == 'list_detectors':
        assert field == 'DetectorIds'
        return ['detector-1']
    if ctx == 'securityhub' and operation == 'get_enabled_standards':
        assert field == 'StandardsSubscriptions'
        return [{
            'StandardsArn': 'arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0',
            'StandardsSubscriptionArn': 'arn:aws:securityhub:ap-northeast-1:123456789012:subscription/abc',
            'StandardsStatus': 'READY',
        }]
    raise AssertionError((ctx, operation, field))


def test_shared_security_collection_records_explicit_shared_provenance(monkeypatch):
    import aws_security_audit.shared_security_evidence as collector
    ctx = Ctx()
    calls = []

    def api(client, op, **kwargs):
        calls.append((client, op))
        assert op.startswith(('get_', 'list_', 'describe_'))
        return _success_client_api(client, op, kwargs)

    def paged(client, op, field, **kwargs):
        calls.append((client, op))
        assert op.startswith(('get_', 'list_', 'describe_'))
        return _success_client_paged(client, op, field, kwargs)

    monkeypatch.setattr(collector, 'api_call', api)
    monkeypatch.setattr(collector, 'paged', paged)
    errors = []
    result = collector.collect_shared_security_evidence(ctx, [REGION], errors)
    assert not errors
    assert result['attribution'] == 'SHARED_UNATTRIBUTED'
    assert result['product_protection_proven'] is False
    assert ctx.guard_count == len(calls)
    block = result['regions'][0]
    trail = block['cloudtrail']['trails'][0]
    assert trail['multi_region'] is True
    assert trail['is_logging'] is True
    assert trail['selector_status'] == 'VERIFIED'
    assert trail['selectors']['basic_data_event_types'] == ['AWS::S3::Object']
    assert 'arn:aws:s3:::ros-data/' not in str(result)
    assert block['guardduty']['detectors'][0]['status'] == 'ENABLED'
    assert block['securityhub']['standards'][0]['status'] == 'READY'

    inv = {'resources': [], 'collection_errors': [], 'shared_control_evidence': result}
    evidence = build_product_observations(inv, [REGION])
    for check in (24, 25, 32, 33):
        row = evidence['by_control'][str(check)]
        assert row['evidence_state'] == 'SHARED_CONTEXT_ONLY'
        assert row['shared_context_count'] >= 1
        assert row['ok'] == 0 and row['fail'] == 0
        assert row['product_wide_pass_proven'] is False
        assert all(x['property_result'] == CONTEXT_ONLY
                   for x in evidence['rows'] if x['number'] == check)


def test_shared_security_errors_are_explicit_unknown_and_not_absence(monkeypatch):
    import aws_security_audit.shared_security_evidence as collector
    ctx = Ctx()
    def denied(*args, **kwargs):
        raise EvidenceUnavailable('CloudService.AccessDenied')
    monkeypatch.setattr(collector, 'api_call', denied)
    monkeypatch.setattr(collector, 'paged', denied)
    errors = []
    result = collector.collect_shared_security_evidence(ctx, [REGION], errors)
    assert {e['operation'] for e in errors} == {
        'describe_trails', 'list_detectors', 'describe_hub',
    }
    assert all(x['state'] == 'UNVERIFIED'
               for x in result['regions'][0].values() if isinstance(x, dict))
    obs = build_product_observations(
        {'resources': [], 'shared_control_evidence': result,
         'collection_errors': errors}, [REGION])
    for n in (24, 25, 32, 33):
        status = obs['by_control'][str(n)]
        assert status['unknown'] >= 1
        assert status['fail'] == 0
        assert status['ok'] == 0
        assert status['collection_error_count'] >= 1
        assert status['evidence_state'] == 'SHARED_EVIDENCE_UNVERIFIED'
        assert any(row['property_result'] == PROPERTY_UNKNOWN
                   for row in obs['rows'] if row['number'] == n)


def test_cloudtrail_partial_permissions_do_not_imply_delivery_or_selectors(monkeypatch):
    import aws_security_audit.shared_security_evidence as collector
    ctx = Ctx()
    def api(client, op, **kwargs):
        if op == 'describe_trails':
            return {'trailList': [{
                'TrailARN': 'arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/a',
                'Name': 'audit', 'LogFileValidationEnabled': True,
            }]}
        raise EvidenceUnavailable('CloudTrail.AccessDenied')
    monkeypatch.setattr(collector, 'api_call', api)
    monkeypatch.setattr(collector, 'paged', lambda *a, **k: [])
    errors = []
    block = collector.collect_shared_security_evidence(ctx, [REGION], errors)['regions'][0]
    trail = block['cloudtrail']['trails'][0]
    assert trail['log_file_validation_enabled'] is True
    assert trail['log_status'] == 'UNVERIFIED'
    assert trail['selector_status'] == 'UNVERIFIED'
    assert len([x for x in errors if x['service'] == 'cloudtrail']) == 2


def test_ec2_context_not_mislabeled_no_evidence_and_public_sg_review():
    inst = _record('ec2', 'instance', REGION, 'ros-sftp',
                   public_ipv4=True, subnet_id='subnet-1',
                   security_group_ids=['sg-1'])
    sg = _record('ec2', 'security-group', REGION, 'ros-alb',
                 dangerous_ingress=0,
                 ingress_rules=[{
                     'protocol': 'tcp', 'from_port': 8000, 'to_port': 8000,
                     'ipv4_cidrs': ['0.0.0.0/0'], 'ipv6_cidrs': [],
                 }],
                 egress_rules=[{
                     'protocol': '-1', 'ipv4_cidrs': ['0.0.0.0/0'],
                     'ipv6_cidrs': [],
                 }])
    inst['attribution'] = 'DIRECT'
    sg['attribution'] = 'DIRECT'
    inv = {'resources': [inst, sg], 'collection_errors': []}
    evidence = build_product_observations(inv, [REGION])
    assert evidence['by_control']['1']['context'] == 1
    assert evidence['by_control']['14']['context'] == 1
    rows = [r for r in evidence['rows'] if r['number'] == 5]
    assert any(r['observed_value']['public_ingress'][0]['from_port'] == 8000
               for r in rows if r['property'] == 'public ingress and all-protocol public egress')
    assert not any(r['property_result'] == 'PROPERTY_FAIL' for r in rows)
    packet = product_deep_evidence(inv, [REGION])
    assert packet[REGION]['5']['groups'][0]['egress_rules']
    assert 'No ingress/egress rule-by-rule payload' not in str(packet)


def test_shared_trail_success_without_guaranteed_product_association(monkeypatch):
    import aws_security_audit.shared_security_evidence as collector
    monkeypatch.setattr(collector, 'api_call', lambda *a, **k: {'trailList': []})
    monkeypatch.setattr(collector, 'paged', lambda *a, **k: [])
    result = collector.collect_shared_security_evidence(Ctx(), [REGION], [])
    obs = build_product_observations(
        {'resources': [], 'shared_control_evidence': result,
         'collection_errors': []}, [REGION])
    assert obs['by_control']['24']['context'] == 1
    assert obs['by_control']['25']['context'] == 1
    assert obs['by_control']['24']['ok'] == 0
    assert obs['by_control']['24']['fail'] == 0


def test_product_inventory_keeps_shared_evidence_unowned_and_account_mode_unchanged(monkeypatch):
    import aws_security_audit.resource_scope as scope
    class AuditCtx:
        def guard_expiration(self):
            pass

    def add_resource(ctx, region, output, errors):
        output.append(_record('ec2', 'instance', region, 'i-ros',
                              tags=[{'Key': 'Product', 'Value': 'ros'}],
                              public_ipv4=False))

    calls = {'shared': 0}
    def shared(ctx, regions, errors):
        calls['shared'] += 1
        assert regions == [REGION]
        errors.append({'region': REGION, 'service': 'securityhub',
                       'operation': 'describe_hub', 'reason': 'AccessDenied'})
        return {'regions': [], 'attribution': 'SHARED_UNATTRIBUTED',
                'product_protection_proven': False}

    monkeypatch.setattr(scope, '_add_ec2', add_resource)
    monkeypatch.setattr(scope, '_add_rds', lambda *a: None)
    monkeypatch.setattr(scope, '_add_elb', lambda *a: None)
    monkeypatch.setattr(scope, '_add_logs', lambda *a: None)
    monkeypatch.setattr(scope, '_add_s3', lambda *a: None)
    monkeypatch.setattr(scope, '_add_iam', lambda *a: None)
    monkeypatch.setattr(scope, '_add_cloudfront', lambda *a: None)
    monkeypatch.setattr(
        'aws_security_audit.shared_security_evidence.collect_shared_security_evidence', shared)

    product = scope.collect_resource_inventory(AuditCtx(), [REGION], 'ros')
    assert calls['shared'] == 1
    assert product['scope']['matched'] == 1
    assert product['scope']['collection_errors'] == 1
    assert product['resources'][0]['resource_id'] == 'i-ros'
    assert product['shared_control_evidence']['attribution'] == 'SHARED_UNATTRIBUTED'
    assert all(r['service'] != 'securityhub' for r in product['resources'])
    assert product['collection_errors'][0]['operation'] == 'describe_hub'

    account = scope.collect_resource_inventory(AuditCtx(), [REGION], None)
    assert calls['shared'] == 1
    assert 'shared_control_evidence' not in account
    assert account['collection_errors'] == []



def test_cloudtrail_delivery_time_is_utc_and_absent_errors_are_unknown():
    from datetime import datetime, timedelta, timezone
    from aws_security_audit.shared_security_evidence import (
        _string_time, _known_delivery_error,
    )
    jst = timezone(timedelta(hours=9))
    assert _string_time(datetime(2026, 10, 16, 19, 41, tzinfo=jst)) == (
        '2026-10-16T10:41:00+00:00')
    assert _string_time('2026-10-16T19:41:00+09:00') == (
        '2026-10-16T10:41:00+00:00')
    assert _string_time('invalid-date') is None
    assert _string_time(datetime(2026, 10, 16, 19, 41)) is None
    assert _known_delivery_error({}, 'LatestDeliveryError') is None
    assert _known_delivery_error({'LatestDeliveryError': None}, 'LatestDeliveryError') is None
    assert _known_delivery_error({'LatestDeliveryError': ''}, 'LatestDeliveryError') is False
    assert _known_delivery_error(
        {'LatestDeliveryError': 'AccessDenied'}, 'LatestDeliveryError') is True


def test_securityhub_unknown_does_not_advertise_verified_shared_context():
    inv = {
        'resources': [], 'collection_errors': [{
            'region': REGION, 'service': 'securityhub',
            'operation': 'describe_hub', 'reason': 'InvalidAccessException',
        }],
        'shared_control_evidence': {'regions': [{
            'region': REGION,
            'securityhub': {'state': 'UNVERIFIED', 'standards': []},
        }]}
    }
    observed = build_product_observations(inv, [REGION])
    control = observed['by_control']['33']
    assert control['evidence_state'] == 'SHARED_EVIDENCE_UNVERIFIED'
    assert control['shared_context_count'] == 1
    assert control['unknown'] == 1
    assert control['ok'] == control['fail'] == 0
