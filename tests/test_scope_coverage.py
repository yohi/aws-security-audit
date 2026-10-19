"""Offline tests for scope selection diagnostics; no AWS connectivity."""
from __future__ import annotations

from aws_security_audit.evidence_ledger import evidence_id
from aws_security_audit.evidence_types import CallRecord, CollectionState
from aws_security_audit.resource_scope import _record, attribute_resources
from aws_security_audit.scope_coverage import (
    build_scope_checks, scope_candidate_resource_keys,
)

REGION = 'ap-northeast-1'
EXEC_ID = evidence_id('execution', {'kind': 'scope_coverage_test'})


def _key(resource) -> str:
    return f"{resource['region']}/{resource['resource_type']}/{resource['resource_id']}"


def _call(**overrides) -> CallRecord:
    values = dict(
        service='ec2', operation='list_tags_for_resource', region=REGION,
        safe_selector={}, started_at=None, finished_at=None,
        collection_state=CollectionState.OBSERVED,
        error_code=None, page_count=1, pagination_complete=True,
        returned_count=None,
    )
    values.update(overrides)
    identity = {'service': values['service'], 'operation': values['operation'],
                'state': values['collection_state'].name}
    return CallRecord(
        id=evidence_id('call', identity), execution_id=EXEC_ID, **values)


def _selected_keys(check, keys: set[str]) -> bool:
    return keys == set(check.selected_resource_keys)


def _by_basis(checks, basis):
    return [c for c in checks if c.selector_basis == basis]


def _product_resources():
    return [
        _record('ec2', 'instance', REGION, 'i-ros-prd',
                tags=[{'Key': 'Name', 'Value': 'ros-prd-api'}],
                security_group_ids=['sg-shared'], vpc_id='vpc-shared'),
        _record('ec2', 'vpc', REGION, 'vpc-shared'),
        _record('ec2', 'security-group', REGION, 'sg-shared'),
        _record('ec2', 'ebs-volume', REGION, 'vol-1',
                attached_instance_ids=['i-ros-prd']),
        _record('ec2', 'instance', REGION, 'i-roslyn'),
        _record('s3', 'bucket', 'global', 'dh-ros-assets'),
    ]


def test_nonprefix_product_tag_resource_is_selected_and_recorded():
    resources = [
        _record('ec2', 'vpc', REGION, 'vpc-1',
                tags=[{'Key': 'Product', 'Value': 'ros'}]),
        _record('s3', 'bucket', 'global', 'other-content'),
    ]
    selected, scope = attribute_resources(resources, 'ros', 'Product=ros')
    checks = build_scope_checks(resources, selected, scope, ())
    tags = [c for c in checks if c.selector_basis == 'Product=ros']
    assert len(tags) == 1
    assert _selected_keys(tags[0], {'ap-northeast-1/vpc/vpc-1'})
    assert all('other-content' not in c.selected_resource_keys
               for c in checks)
    assert scope['unassigned'] == 1


def test_roslyn_exclusion_stays_candidate_and_never_selected():
    resources = [
        _record('ec2', 'instance', REGION, 'i-ros-prd',
                tags=[{'Key': 'Name', 'Value': 'ros-prd-api'}]),
        _record('ec2', 'instance', REGION, 'i-roslyn',
                tags=[{'Key': 'Name', 'Value': 'roslyn-app'}]),
    ]
    selected, scope = attribute_resources(resources, 'ros')
    checks = build_scope_checks(resources, selected, scope, ())
    assert _selected_keys(_by_basis(checks, 'PREFIX:NameOrId')[0],
                          {'ap-northeast-1/instance/i-ros-prd'})
    hints = _by_basis(checks, 'NAME:product-token-hint')
    assert len(hints) == 1
    assert 'ap-northeast-1/instance/i-roslyn' in hints[0].candidate_resource_keys
    assert scope_candidate_resource_keys(resources, scope) == hints[0].candidate_resource_keys
    assert 'i-roslyn' not in str([c.selected_resource_keys for c in checks])


def test_related_volume_recorded_with_shared_limitation():
    resources = [
        _record('ec2', 'instance', REGION, 'i-scs2',
                tags=[{'Key': 'Name', 'Value': 'scs2-prd-api'}]),
        _record('ec2', 'ebs-volume', REGION, 'vol-123',
                attached_instance_ids=['i-scs2']),
    ]
    selected, scope = attribute_resources(resources, 'scs2')
    checks = build_scope_checks(resources, selected, scope, ())
    related = _by_basis(checks, 'TOPOLOGY:one-hop')
    assert len(related) == 1
    assert _selected_keys(related[0], {'ap-northeast-1/ebs-volume/vol-123'})
    assert 'shared' in str(related[0].limitations)
    assert 'product-wide PASS' in str(related[0].limitations)


def test_shared_vpc_is_related_not_exclusive_ownership():
    resources = [
        _record('ec2', 'instance', REGION, 'i-ros-1',
                tags=[{'Key': 'Name', 'Value': 'ros-web'}], vpc_id='vpc-sh'),
        _record('ec2', 'vpc', REGION, 'vpc-sh'),
    ]
    selected, scope = attribute_resources(resources, 'ros')
    checks = build_scope_checks(resources, selected, scope, ())
    related = _by_basis(checks, 'TOPOLOGY:one-hop')
    assert len(related) == 1
    assert 'ap-northeast-1/vpc/vpc-sh' in related[0].selected_resource_keys
    assert 'not exclusive ownership' in str(related[0].limitations)


def test_untagged_dh_ros_candidate_never_promotes_and_no_mutation():
    resources = _product_resources()
    selected, scope = attribute_resources(resources, 'ros')
    before = [r['attribution'] for r in resources]
    checks = build_scope_checks(resources, selected, scope, ())
    after = [r['attribution'] for r in resources]
    assert before == after
    assert 'dh-ros-assets' not in str([c.selected_resource_keys for c in checks])
    hints = _by_basis(checks, 'NAME:product-token-hint')
    assert 'global/bucket/dh-ros-assets' in hints[0].candidate_resource_keys
    assert 'hints only' in str(hints[0].limitations)


def test_failed_tag_read_keeps_limitation_without_absence_proof():
    resources = [
        _record('ec2', 'instance', REGION, 'i-ros-1',
                tags=[{'Key': 'Name', 'Value': 'ros-api'}]),
        _record('ec2', 'instance', REGION, 'i-deny'),
    ]
    selected, scope = attribute_resources(resources, 'ros')
    calls = (
        _call(service='ec2', operation='list_tags_for_resource',
              safe_selector={'ResourceName': 'arn:aws:ec2:...'},
              collection_state=CollectionState.ACCESS_DENIED,
              error_code='AccessDenied'),
    )
    checks = build_scope_checks(resources, selected, scope, calls)
    failed = [c for c in checks
              if 'list_tags_for_resource' in str(c.limitations)]
    assert len(failed) == 1
    assert failed[0].coverage_state.name in ('PARTIAL', 'UNKNOWN')
    assert 'absence' in str(failed[0].limitations)
    assert calls[0].id in failed[0].call_refs
    assert failed[0].execution_id == EXEC_ID


def test_partial_pagination_records_selector_limit():
    resources = [_record('ec2', 'instance', REGION, 'i-ros-1')]
    selected, scope = attribute_resources(resources, 'ros')
    calls = (
        _call(service='rds', operation='describe_db_instances',
              collection_state=CollectionState.OBSERVED, page_count=3,
              pagination_complete=False, returned_count=7),
    )
    checks = build_scope_checks(resources, selected, scope, calls)
    target = [c for c in checks
              if 'describe_db_instances' in str(c.limitations)]
    assert len(target) == 1
    assert target[0].coverage_state.name == 'PARTIAL'
    assert 'pagination' in str(target[0].limitations)
    assert 'not proven' in str(target[0].limitations)


def test_zero_name_filtered_alarm_search_is_not_absence_proof():
    resources = [_record('ec2', 'instance', REGION, 'i-ros-1')]
    selected, scope = attribute_resources(resources, 'ros')
    calls = (
        _call(service='cloudwatch', operation='list_alarms',
              safe_selector={'AlarmNamePrefix': 'ros-'}, returned_count=0),
    )
    checks = build_scope_checks(resources, selected, scope, calls)
    target = [c for c in checks
              if c.service == 'cloudwatch'
              and 'list_alarms' in str(c.limitations)]
    assert len(target) == 1
    assert 'zero does not prove absence' in str(target[0].limitations)


def test_account_mode_records_basis_and_coverage_limit():
    resources = [_record('ec2', 'instance', REGION, 'i-1')]
    selected, scope = attribute_resources(resources)
    checks = build_scope_checks(resources, selected, scope, ())
    basis = _by_basis(checks, 'account')
    assert len(basis) == 1
    assert basis[0].coverage_state.name in ('PARTIAL', 'UNKNOWN')
    assert 'not exhaustive' in str(basis[0].limitations)


def test_scope_checks_are_deterministic():
    resources = _product_resources()
    selected, scope = attribute_resources(resources, 'ros')
    assert build_scope_checks(resources, selected, scope, ()) == \
        build_scope_checks(resources, selected, scope, ())
