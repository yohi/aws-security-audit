"""Offline tests: no AWS connection, modifications, or LLM calls."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from aws_security_audit.cli import parser
from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.investigation import (
    build_investigation, investigate_ebs, investigate_security_groups,
    render_llm_packet, save_investigation,
)


class StubCtx:
    def guard_expiration(self):
        return None

    def client_cached(self, service, region):
        return (service, region)


def test_assess_cli_exports_offline_by_default():
    args = parser().parse_args([
        'assess', '--source-profile', 'default',
        '--role-arn', 'arn:aws:iam::123456789012:role/ExistingRole',
        '--regions', 'ap-northeast-1',
    ])
    assert args.command == 'assess'
    assert args.llm == 'export'
    assert not args.fail_on_findings


def test_assess_cli_allows_llm_off():
    args = parser().parse_args([
        'assess', '--llm', 'off', '--regions', 'all',
    ])
    assert args.llm == 'off'


def test_sg_evidence_never_claims_reachability():
    sg = {'GroupId': 'sg-abc123', 'IpPermissions': [{
        'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
    }]}
    eni = {
        'NetworkInterfaceId': 'eni-0001',
        'InterfaceType': 'vpc_endpoint',
        'Groups': [{'GroupId': 'sg-abc123'}],
        'Association': {}, 'Ipv6Addresses': [],
    }

    def fake_paged(client, operation, result, **kwargs):
        if operation == 'describe_security_groups':
            return [sg]
        if operation == 'describe_network_interfaces':
            assert kwargs['Filters'][0]['Values'] == ['sg-abc123']
            return [eni]
        raise AssertionError('Unexpected API: ' + operation)

    with patch('aws_security_audit.investigation.paged', side_effect=fake_paged):
        out = investigate_security_groups(StubCtx(), 'ap-northeast-1')
    assert out['state'] == 'OBSERVED'
    assert out['dangerous_permission_entries'] == 1
    assert out['groups'][0]['attached_enis'] == 1
    assert out['groups'][0]['public_ipv4_enis'] == 0
    assert out['groups'][0]['eni_type_counts'] == {'vpc_endpoint': 1}
    assert out['internet_reachability'] == 'NOT_PROVEN'


def test_ebs_state_asg_root_and_default():
    volumes = [{
        'VolumeId': 'vol-1234', 'Encrypted': False, 'Size': 30,
        'State': 'in-use', 'Attachments': [{'InstanceId': 'i-test'}],
    }, {
        'VolumeId': 'vol-5678', 'Encrypted': True, 'Size': 10,
    }]
    reservations = [{
        'Instances': [{
            'InstanceId': 'i-test', 'State': {'Name': 'running'},
            'RootDeviceName': '/dev/xvda',
            'BlockDeviceMappings': [{
                'DeviceName': '/dev/xvda',
                'Ebs': {'VolumeId': 'vol-1234'},
            }],
        }],
    }]

    def fake_paged(client, operation, result, **kwargs):
        return {
            'describe_volumes': volumes,
            'describe_instances': reservations,
            'describe_auto_scaling_instances': [{'InstanceId': 'i-test'}],
        }[operation]

    with patch('aws_security_audit.investigation.paged', side_effect=fake_paged), \\
         patch('aws_security_audit.investigation.api_call',
               return_value={'EbsEncryptionByDefault': False}):
        out = investigate_ebs(StubCtx(), 'ap-northeast-1')
    assert out['unencrypted_count'] == 1
    assert out['unencrypted_capacity_gib'] == 30
    assert out['ebs_encryption_by_default'] is False
    attachment = out['volumes'][0]['attachments'][0]
    assert attachment['instance_state'] == 'running'
    assert attachment['volume_purpose'] == 'root'
    assert attachment['asg_member'] is True


def test_asg_denied_is_unknown_not_non_asg():
    volumes = [{
        'VolumeId': 'vol-1234', 'Encrypted': False, 'Size': 4,
        'Attachments': [{'InstanceId': 'i-test'}],
    }]
    reservations = [{
        'Instances': [{
            'InstanceId': 'i-test', 'State': {'Name': 'stopped'},
            'BlockDeviceMappings': [],
        }],
    }]

    def fake_paged(client, operation, result, **kwargs):
        if operation == 'describe_auto_scaling_instances':
            raise EvidenceUnavailable('AccessDenied')
        return {'describe_volumes': volumes, 'describe_instances': reservations}[operation]

    with patch('aws_security_audit.investigation.paged', side_effect=fake_paged), \\
         patch('aws_security_audit.investigation.api_call',
               return_value={'EbsEncryptionByDefault': True}):
        out = investigate_ebs(StubCtx(), 'ap-northeast-1')
    assert out['asg_inventory_error'] == 'EvidenceUnavailable'
    assert out['volumes'][0]['attachments'][0]['asg_member'] == 'UNKNOWN'


def test_private_files_and_offline_llm_packet(tmp_path: Path):
    inv = {
        'all_46_controls': [
            {'number': 5, 'title': 'SG inspection', 'account_status': 'FAIL',
             'regional_status': 'FAIL'},
        ],
        'deep_evidence': {
            'ap-northeast-1': {
                '5': {
                    'state': 'OBSERVED', 'dangerous_permission_entries': 1,
                    'groups': [{'group_id': 'sg-secret123', 'attached_enis': 1}],
                },
                '19': {
                    'state': 'OBSERVED', 'unencrypted_count': 1,
                    'unencrypted_capacity_gib': 30, 'ebs_encryption_by_default': False,
                    'volumes': [{'volume_id': 'vol-secret456', 'attachments': [{
                        'instance_state': 'running', 'asg_member': False,
                    }]}],
                },
            },
        },
    }
    paths = save_investigation(str(tmp_path), inv, llm_export=True)
    assert len(paths) == 2
    assert json.loads(paths[0].read_text()) == inv
    assert 'sg-secret123' not in paths[1].read_text()
    assert 'vol-secret456' not in paths[1].read_text()
    assert 'OUT OF SCOPE' in render_llm_packet(inv)
    for path in paths:
        assert path.stat().st_mode & 0o777 == 0o600
    assert len(save_investigation(str(tmp_path), inv, llm_export=False)) == 1
