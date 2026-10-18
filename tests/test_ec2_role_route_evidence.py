"""R16 offline regression for selected EC2 route/SSH context only."""
from copy import deepcopy

from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.control_observations import (
    build_product_observations, CONTEXT_ONLY, PROPERTY_UNKNOWN,
)
from aws_security_audit.resource_scope import (
    _record, collect_resource_inventory, product_findings,
)

REGION = 'ap-northeast-1'
VPC = 'vpc-012345'
SSH_RULE = {
    'protocol': 'tcp', 'from_port': 22, 'to_port': 22,
    'ipv4_cidrs': ['192.0.2.5/32'], 'ipv6_cidrs': [],
    'referenced_sg_ids': ['sg-ops'], 'prefix_list_ids': [],
}


class Ctx:
    def __init__(self):
        self.guards = 0
        self.clients = []

    def guard_expiration(self):
        self.guards += 1

    def client_cached(self, service, region=None):
        self.clients.append((service, region))
        return (service, region)


def _resources():
    return [
        _record('ec2', 'instance', REGION, 'i-ros-app',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                vpc_id=VPC, subnet_id='subnet-app',
                security_group_ids=['sg-app'], public_ipv4=False, state='running'),
        _record('ec2', 'instance', REGION, 'i-ros-bastion-name-only',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                vpc_id=VPC, subnet_id='subnet-other',
                security_group_ids=['sg-app'], public_ipv4=True, state='running'),
        _record('ec2', 'instance', REGION, 'i-not-ros',
                tags=[{'Key': 'Product', 'Value': 'different'}],
                vpc_id='vpc-unrelated', subnet_id='subnet-excluded',
                security_group_ids=['sg-excluded']),
        _record('ec2', 'security-group', REGION, 'sg-app',
                ingress_rules=[deepcopy(SSH_RULE)], egress_rules=[]),
        _record('ec2', 'security-group', REGION, 'sg-excluded',
                ingress_rules=[deepcopy(SSH_RULE)], egress_rules=[]),
    ]


def _tables():
    return [
        {'VpcId': VPC, 'RouteTableId': 'rtb-app',
         'Associations': [
             {'SubnetId': 'subnet-app',
              'AssociationState': {'State': 'associated'}}],
         'Routes': [
             {'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-sensitive-id',
              'State': 'active'},
             {'DestinationCidrBlock': '10.0.0.0/16', 'GatewayId': 'local',
              'State': 'active'}]},
        {'VpcId': VPC, 'RouteTableId': 'rtb-main',
         'Associations': [
             {'Main': True, 'AssociationState': {'State': 'associated'}}],
         'Routes': [
             {'DestinationCidrBlock': '0.0.0.0/0',
              'NatGatewayId': 'nat-sensitive-id', 'State': 'blackhole'},
             {'DestinationIpv6CidrBlock': '::/0',
              'EgressOnlyInternetGatewayId': 'eigw-private',
              'State': 'active'}]},
    ]


def _setup(monkeypatch, records=None):
    import aws_security_audit.resource_scope as mod

    def ec2(ctx, region, out, errors):
        out.extend(_resources() if records is None else deepcopy(records))

    monkeypatch.setattr(mod, '_add_ec2', ec2)
    for name in ('_add_rds', '_add_elb', '_add_logs', '_add_s3', '_add_iam',
                 '_add_cloudfront'):
        monkeypatch.setattr(mod, name, lambda *args: None)
    monkeypatch.setattr(
        'aws_security_audit.shared_security_evidence.collect_shared_security_evidence',
        lambda *args: {'attribution': 'SHARED_UNATTRIBUTED', 'regions': []})
    return mod


def test_selected_subnet_explicit_beats_main_and_ssh_is_role_unknown(monkeypatch):
    _setup(monkeypatch)
    calls = []

    def route_page(client, operation, collection, **kwargs):
        calls.append((client, operation, collection, kwargs))
        return _tables()

    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                        route_page)
    ctx = Ctx()
    inv = collect_resource_inventory(ctx, [REGION], 'ros')
    assert len(calls) == 1
    assert calls[0] == (
        ('ec2', REGION), 'describe_route_tables', 'RouteTables',
        {'Filters': [{'Name': 'vpc-id', 'Values': [VPC]}]})
    assert ctx.guards >= 1
    instances = {r['resource_id']: r for r in inv['resources']
                 if r['resource_type'] == 'instance'}
    assert set(instances) == {'i-ros-app', 'i-ros-bastion-name-only'}
    app = instances['i-ros-app']['attributes']
    named_bastion = instances['i-ros-bastion-name-only']['attributes']
    assert app['subnet_route_lookup'] == 'CONFIG_OBSERVED'
    assert app['subnet_route_context'] == {
        'route_table_id': 'rtb-app', 'association': 'EXPLICIT_SUBNET',
        'default_routes': [
            {'ip_family': 'ipv4', 'route_state': 'active',
             'target_class': 'INTERNET_GATEWAY'}]}
    assert named_bastion['subnet_route_context'] == {
        'route_table_id': 'rtb-main', 'association': 'IMPLICIT_MAIN',
        'default_routes': [
            {'ip_family': 'ipv4', 'route_state': 'blackhole',
             'target_class': 'NAT_GATEWAY'},
            {'ip_family': 'ipv6', 'route_state': 'active',
             'target_class': 'EGRESS_ONLY_INTERNET_GATEWAY'}]}
    assert app['ssh_sg_lookup'] == named_bastion['ssh_sg_lookup'] == 'CONFIG_OBSERVED'
    assert app['ssh_port22_ingress_context'] == {
        'attached_sg_count': 1, 'ipv4_cidr_sources': 1,
        'ipv6_cidr_sources': 0, 'security_group_sources': 1,
        'prefix_list_sources': 0, 'world_ipv4': False,
        'world_ipv6': False, 'ssh_port22_rule_count': 1,
    }
    assert app['owner_approved_role'] == named_bastion['owner_approved_role'] == 'NOT_PROVIDED'
    assert 'sensitive-id' not in str(inv)
    assert '192.0.2.5' in str(inv)  # Existing SG inventory remains unmodified.
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['1']['context'] >= 2
    assert obs['by_control']['3']['context'] == 2
    assert obs['by_control']['1']['collection_error_count'] == 0
    assert inv['collection_errors'] == []
    findings = {f.number: f.status
                for f in product_findings(inv, [REGION])}
    assert findings[1] == findings[3] == 'MANUAL_REVIEW'


def test_denied_route_read_is_unknown_only_for_direct_instances(monkeypatch):
    _setup(monkeypatch)
    calls = []

    def denied(client, operation, collection, **kwargs):
        calls.append((client, operation))
        raise EvidenceUnavailable('ec2.describe_route_tables: AccessDenied')

    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged', denied)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    assert len(calls) == 1
    assert len(inv['collection_errors']) == 2
    assert {e['resource'] for e in inv['collection_errors']} == {
        'i-ros-app', 'i-ros-bastion-name-only'}
    assert all(e['operation'] == 'describe_route_tables'
               for e in inv['collection_errors'])
    assert all(r['attributes']['subnet_route_lookup'] == 'UNVERIFIED_READ_ERROR'
               for r in inv['resources'] if r['resource_type'] == 'instance')
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['1']['collection_error_count'] == 2
    assert obs['by_control']['1']['unknown'] == 2
    assert obs['by_control']['3']['context'] == 2
    assert obs['by_control']['3']['ok'] == obs['by_control']['3']['fail'] == 0


def test_ambiguous_and_malformed_routes_fail_closed(monkeypatch):
    _setup(monkeypatch)
    bad_cases = [
        [],
        [{'VpcId': VPC, 'RouteTableId': 'rtb-1',
          'Associations': [], 'Routes': []}],
        [{'VpcId': VPC, 'RouteTableId': 'rtb-1',
          'Associations': [{'Main': True, 'AssociationState': {'State': 'associated'}}],
          'Routes': [{'DestinationCidrBlock': '0.0.0.0/0',
                      'GatewayId': 'igw-1', 'NatGatewayId': 'nat-1',
                      'State': 'active'}]}],
        [{'VpcId': 'vpc-other', 'RouteTableId': 'rtb-1',
          'Associations': [], 'Routes': []}],
    ]
    for case in bad_cases:
        monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                            lambda *args, _case=case, **kw: _case)
        inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
        assert all(r['attributes']['subnet_route_lookup'] == 'UNVERIFIED_SCHEMA'
                   for r in inv['resources'] if r['resource_type'] == 'instance')
        assert all('subnet_route_context' not in r['attributes']
                   for r in inv['resources'] if r['resource_type'] == 'instance')
        assert len(inv['collection_errors']) == 2
        obs = build_product_observations(inv, [REGION])
        assert obs['by_control']['1']['unknown'] == 2
        assert obs['by_control']['1']['collection_error_count'] == 2
        assert obs['by_control']['1']['fail'] == 0


def test_missing_sg_or_invalid_port22_rule_does_not_certify_ssh_restriction(monkeypatch):
    _setup(monkeypatch, records=[
        _resources()[0],
        _record('ec2', 'security-group', REGION, 'sg-app',
                ingress_rules=[{'protocol': 'tcp', 'from_port': None,
                                'to_port': 22}], egress_rules=[]),
    ])
    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                        lambda *args, **kw: _tables())
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    instance = next(r for r in inv['resources']
                    if r['resource_type'] == 'instance')
    assert instance['attributes']['ssh_sg_lookup'] == 'UNVERIFIED_SG_SCHEMA'
    assert 'ssh_port22_ingress_context' not in instance['attributes']
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['3']['unknown'] == 1
    assert obs['by_control']['3']['ok'] == obs['by_control']['3']['fail'] == 0
    assert {f.number: f.status for f in product_findings(inv, [REGION])}[3] == 'MANUAL_REVIEW'


def test_missing_sg_resource_is_unknown(monkeypatch):
    _setup(monkeypatch, records=[_resources()[0]])
    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                        lambda *args, **kw: _tables())
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    attrs = inv['resources'][0]['attributes']
    assert attrs['ssh_sg_lookup'] == 'UNVERIFIED_SG_COVERAGE'
    assert 'ssh_port22_ingress_context' not in attrs
    assert build_product_observations(inv, [REGION])['by_control']['3']['unknown'] == 1


def test_account_inventory_does_not_call_new_route_api(monkeypatch):
    _setup(monkeypatch)
    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                        lambda *args, **kw: (_ for _ in ()).throw(
                            AssertionError('extra route API call from account mode')))
    inv = collect_resource_inventory(Ctx(), [REGION], None)
    assert len(inv['resources']) == 5
    assert all('subnet_route_lookup' not in r['attributes']
               for r in inv['resources'])
    assert all('ssh_sg_lookup' not in r['attributes']
               for r in inv['resources'])


def test_unrelated_vpc_not_scanned_and_no_auto_bastion_name_classification(monkeypatch):
    _setup(monkeypatch)
    calls = []
    def route_page(client, operation, collection, **kwargs):
        calls.append(kwargs['Filters'])
        return _tables()

    monkeypatch.setattr('aws_security_audit.ec2_role_route_evidence.paged',
                        route_page)
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    assert calls == [[{'Name': 'vpc-id', 'Values': [VPC]}]]
    assert all(r['attributes']['owner_approved_role'] == 'NOT_PROVIDED'
               for r in inv['resources'] if r['resource_type'] == 'instance')
