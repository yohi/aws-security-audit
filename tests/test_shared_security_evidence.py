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
