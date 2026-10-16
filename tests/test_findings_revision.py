"""Offline regression tests for PR #1 F-001 through F-005."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from aws_security_audit import checks
from aws_security_audit.core import AuditContext, EvidenceUnavailable, Finding
from aws_security_audit.cli import run_scan
from aws_security_audit.report import overall_rows, export_report

REGION = 'ap-northeast-1'
TRAIL = 'arn:aws:cloudtrail:ap-northeast-1:123456789012:trail/audit'


def _client(responses):
    client = MagicMock()
    client.can_paginate.return_value = False
    for operation, result in responses.items():
        getattr(client, operation).return_value = result
    return client


class FakeContext:
    def __init__(self, **clients):
        self.clients = clients

    def client_cached(self, service, region=None):
        return self.clients[service]


def _trail(status, selectors=None):
    return FakeContext(cloudtrail=_client({
        'describe_trails': {'trailList': [{'TrailARN': TRAIL, 'HomeRegion': REGION, 'Name': 'audit', 'IsMultiRegionTrail': True}]},
        'get_trail_status': status,
        'get_event_selectors': selectors or {
            'EventSelectors': [{'IncludeManagementEvents': True, 'DataResources': [{'Type': 'AWS::S3::Object', 'Values': ['arn:aws:s3:::example/']}]}]
        },
    }))


def test_cloudtrail_delivery_error_never_passes():
    status = {'IsLogging': True, 'LatestDeliveryTime': datetime.now(timezone.utc), 'LatestDeliveryError': 'AccessDenied'}
    finding = checks.check_24(_trail(status), REGION, {'all_account_regions': [REGION]})
    assert finding.status == 'FAIL'
    assert any('delivery error' in item for item in finding.evidence)
    assert not any('AccessDenied' in item for item in finding.evidence)


def test_cloudtrail_missing_success_time_unknown():
    finding = checks.check_24(_trail({'IsLogging': True}), REGION, {'all_account_regions': [REGION]})
    assert finding.status == 'UNKNOWN'


def test_cloudtrail_limited_data_selector_requires_review():
    finding = checks.check_24(_trail({'IsLogging': True, 'LatestDeliveryTime': datetime.now(timezone.utc)}), REGION, {'all_account_regions': [REGION]})
    assert finding.status == 'MANUAL_REVIEW'


def test_cloudtrail_without_data_event_fails():
    ctx = _trail({'IsLogging': True, 'LatestDeliveryTime': datetime.now(timezone.utc)}, {'EventSelectors': [{'IncludeManagementEvents': True, 'DataResources': []}]})
    assert checks.check_24(ctx, REGION, {'all_account_regions': [REGION]}).status == 'FAIL'


def _flow_log(delivery, resource_id='vpc-one'):
    data = {'FlowLogStatus': 'ACTIVE', 'TrafficType': 'ALL', 'ResourceId': resource_id}
    if delivery is not None:
        data['DeliverLogsStatus'] = delivery
    return data


def _vpcs(flow_logs, subnets=None):
    return FakeContext(ec2=_client({
        'describe_vpcs': {'Vpcs': [{'VpcId': 'vpc-one'}]},
        'describe_subnets': {'Subnets': subnets if subnets is not None else [{'VpcId': 'vpc-one', 'SubnetId': 'subnet-one'}]},
        'describe_flow_logs': {'FlowLogs': flow_logs},
    }))


@pytest.mark.parametrize('delivery,expected', [('FAILED', 'FAIL'), (None, 'UNKNOWN'), ('PENDING', 'UNKNOWN'), ('SUCCESS', 'PASS')])
def test_flow_delivery_status(delivery, expected):
    assert checks.check_27(_vpcs([_flow_log(delivery)]), REGION, {}).status == expected


def test_flow_partial_subnets_no_pass():
    subnets = [{'VpcId': 'vpc-one', 'SubnetId': 'subnet-one'}, {'VpcId': 'vpc-one', 'SubnetId': 'subnet-two'}]
    assert checks.check_27(_vpcs([_flow_log('SUCCESS', 'subnet-one'), _flow_log('FAILED', 'subnet-two')], subnets), REGION, {}).status == 'FAIL'


def _hub(controls):
    return FakeContext(securityhub=_client({
        'describe_hub': {'HubArn': 'arn:aws:securityhub:ap-northeast-1:123456789012:hub/default'},
        'get_enabled_standards': {'StandardsSubscriptions': [{'StandardsStatus': 'READY', 'StandardsSubscriptionArn': 'arn:aws:securityhub:ap-northeast-1:123456789012:subscription/foundational-security-best-practices/v/1.0.0'}]},
        'describe_standards_controls': {'Controls': controls},
    }))


def test_hub_ready_but_controls_all_disabled():
    assert checks.check_33(_hub([{'ControlStatus': 'DISABLED'}]), REGION, {}).status == 'FAIL'


def test_hub_enabled_controls_do_not_prove_evaluation():
    assert checks.check_33(_hub([{'ControlStatus': 'ENABLED'}]), REGION, {}).status == 'MANUAL_REVIEW'


def test_hub_missing_subscription_unknown():
    hub = _hub([])
    hub.clients['securityhub'].get_enabled_standards.return_value['StandardsSubscriptions'][0].pop('StandardsSubscriptionArn')
    assert checks.check_33(hub, REGION, {}).status == 'UNKNOWN'


def test_partial_region_account_summary_no_pass(tmp_path):
    row = overall_rows([Finding(19, 'PASS', REGION, 'encrypted')], coverage_full=False)[18]
    assert row['対象地域判定'] == 'PASS' and row['判定'] == 'UNKNOWN'
    assert row['地域網羅'] == '一部リージョンのみ'
    meta = {'timestamp': '2026-10-16T11:42:00+00:00', 'region_coverage_full': False}
    import json
    report = export_report(str(tmp_path), [Finding(19, 'PASS', REGION, 'encrypted')], meta)
    payload = json.loads(next(x for x in report if x.suffix == '.json').read_text())
    assert payload['summary'][18]['判定'] == 'UNKNOWN'
    assert payload['summary'][18]['対象地域判定'] == 'PASS'


def test_complete_region_pass_allowed():
    assert overall_rows([Finding(19, 'PASS', REGION, 'encrypted')], coverage_full=True)[18]['判定'] == 'PASS'


def test_unmatched_ap_tag_with_ec2_manual():
    ctx = FakeContext(ec2=_client({'describe_instances': {'Reservations': [{'Instances': [{'InstanceId': 'i-1', 'State': {'Name': 'running'}, 'Tags': [{'Key': 'Role', 'Value': 'db'}]}]}]}}))
    finding = checks.check_1(ctx, REGION, {'ap_tag': 'Role=app'})
    assert finding.status == 'MANUAL_REVIEW' and 'タグ' in finding.detail


def test_no_ec2_ap_not_applicable():
    ctx = FakeContext(ec2=_client({'describe_instances': {'Reservations': []}}))
    assert checks.check_1(ctx, REGION, {'ap_tag': 'Role=app'}).status == 'NOT_APPLICABLE'


def test_sts_assume_failure_blocks_scan(monkeypatch):
    import boto3
    from botocore.exceptions import ClientError
    source = MagicMock()
    source._session.get_scoped_config.return_value = {'login_session': 'example'}
    source.client.return_value.assume_role.side_effect = ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'forbidden'}}, 'AssumeRole')
    factory = MagicMock(return_value=source)
    monkeypatch.setattr(boto3, 'Session', factory)
    with pytest.raises(EvidenceUnavailable):
        AuditContext('audit-source', 'arn:aws:iam::123456789012:role/ReadOnly', REGION)
    assert factory.call_count == 1


def test_sts_expiry_no_scanner_fallback(monkeypatch):
    class Expired:
        expiration = datetime.now(timezone.utc) - timedelta(minutes=1)
        def guard_expiration(self):
            AuditContext.guard_expiration(self)
    import aws_security_audit.cli as cli
    monkeypatch.setattr(cli, 'CHECKS', [SimpleNamespace(number=19, title='test')])
    monkeypatch.setattr(cli, 'GLOBAL_CHECKS', set())
    scanner = MagicMock(return_value=Finding(19, 'PASS', REGION, 'not expected'))
    monkeypatch.setitem(cli.CHECK_RUNNERS, 19, scanner)
    assert run_scan(Expired(), [REGION], {'regions': [REGION]})[0].status == 'UNKNOWN'
    scanner.assert_not_called()
