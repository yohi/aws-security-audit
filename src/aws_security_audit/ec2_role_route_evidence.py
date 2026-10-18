"""Bounded EC2 subnet-route and SSH ingress evidence for selected product instances.

Neither AWS network reachability nor EC2 application/bastion role is inferred.
No raw route targets, unrelated VPC routes or arbitrary SG metadata are exported.
"""
from __future__ import annotations

from collections import defaultdict

from .core import EvidenceUnavailable, paged


def _direct_instances(selected):
    return [r for r in selected
            if r.get('service') == 'ec2'
            and r.get('resource_type') == 'instance'
            and r.get('attribution') == 'DIRECT']


def _port22_rule(rule):
    """True/False for a known rule, None for an unclassifiable rule."""
    proto = rule.get('protocol')
    if proto == '-1':
        return True
    if proto not in ('tcp', '6'):
        return False if isinstance(proto, str) and proto else None
    low, high = rule.get('from_port'), rule.get('to_port')
    if type(low) is not int or type(high) is not int or not (0 <= low <= high <= 65535):
        return None
    return low <= 22 <= high


def _summarize_instance_ssh(instance, sg_index):
    attrs = instance['attributes']
    sg_ids = attrs.get('security_group_ids')
    if not isinstance(sg_ids, list) or not sg_ids or any(
            not isinstance(x, str) or not x for x in sg_ids):
        attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_ATTACHMENTS'
        return
    summaries = {'ipv4_cidr_sources': 0, 'ipv6_cidr_sources': 0,
                 'security_group_sources': 0, 'prefix_list_sources': 0,
                 'world_ipv4': False, 'world_ipv6': False,
                 'ssh_port22_rule_count': 0}
    for sg_id in sg_ids:
        candidates = sg_index.get((instance['region'], sg_id), [])
        if len(candidates) != 1:
            attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_COVERAGE'
            return
        rules = candidates[0].get('attributes', {}).get('ingress_rules')
        if not isinstance(rules, list):
            attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_SCHEMA'
            return
        for rule in rules:
            if not isinstance(rule, dict):
                attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_SCHEMA'
                return
            applies = _port22_rule(rule)
            if applies is None:
                attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_SCHEMA'
                return
            if not applies:
                continue
            sources = {}
            for key in ('ipv4_cidrs', 'ipv6_cidrs',
                        'referenced_sg_ids', 'prefix_list_ids'):
                values = rule.get(key)
                if not isinstance(values, list) or any(
                        not isinstance(s, str) or not s for s in values):
                    attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_SCHEMA'
                    return
                sources[key] = values
            summaries['ssh_port22_rule_count'] += 1
            summaries['ipv4_cidr_sources'] += len(sources['ipv4_cidrs'])
            summaries['ipv6_cidr_sources'] += len(sources['ipv6_cidrs'])
            summaries['security_group_sources'] += len(sources['referenced_sg_ids'])
            summaries['prefix_list_sources'] += len(sources['prefix_list_ids'])
            summaries['world_ipv4'] |= '0.0.0.0/0' in sources['ipv4_cidrs']
            summaries['world_ipv6'] |= '::/0' in sources['ipv6_cidrs']
            if not any(sources.values()):
                attrs['ssh_sg_lookup'] = 'UNVERIFIED_SG_SCHEMA'
                return
    attrs['ssh_sg_lookup'] = 'CONFIG_OBSERVED'
    attrs['ssh_port22_ingress_context'] = {
        'attached_sg_count': len(sg_ids), **summaries,
    }


def _route_target(route):
    fields = ('GatewayId', 'NatGatewayId', 'TransitGatewayId',
              'VpcPeeringConnectionId', 'NetworkInterfaceId',
              'EgressOnlyInternetGatewayId', 'VpcEndpointId',
              'CarrierGatewayId', 'LocalGatewayId', 'CoreNetworkArn',
              'InstanceId')
    specified = [(k, route[k]) for k in fields if route.get(k) is not None]
    if len(specified) != 1 or not isinstance(specified[0][1], str) or not specified[0][1]:
        return None
    key, value = specified[0]
    if key == 'GatewayId':
        return 'INTERNET_GATEWAY' if value.startswith('igw-') else 'OTHER_GATEWAY'
    return {
        'NatGatewayId': 'NAT_GATEWAY',
        'TransitGatewayId': 'TRANSIT_GATEWAY',
        'VpcPeeringConnectionId': 'VPC_PEERING',
        'NetworkInterfaceId': 'NETWORK_INTERFACE',
        'EgressOnlyInternetGatewayId': 'EGRESS_ONLY_INTERNET_GATEWAY',
        'VpcEndpointId': 'VPC_ENDPOINT',
        'CarrierGatewayId': 'CARRIER_GATEWAY',
        'LocalGatewayId': 'LOCAL_GATEWAY',
        'CoreNetworkArn': 'CORE_NETWORK',
        'InstanceId': 'EC2_INSTANCE',
    }[key]


def _route_context(tables, vpc_id, subnet_id):
    """Resolve explicit subnet association before implicit VPC main table.

    Return None on missing, duplicated, or malformed evidence: never assume a
    subnet is private just because an association or a default route was missed.
    """
    if not isinstance(tables, list) or not tables:
        return None
    explicit, main = [], []
    for table in tables:
        if (not isinstance(table, dict) or table.get('VpcId') != vpc_id
                or not isinstance(table.get('RouteTableId'), str)
                or not isinstance(table.get('Associations'), list)
                or not isinstance(table.get('Routes'), list)):
            return None
        for assoc in table['Associations']:
            if not isinstance(assoc, dict):
                return None
            state = assoc.get('AssociationState')
            if not isinstance(state, dict) or state.get('State') not in (
                    'associated', 'disassociated', 'disassociating'):
                return None
            if state['State'] != 'associated':
                continue
            if assoc.get('SubnetId') == subnet_id:
                explicit.append(table)
            if assoc.get('Main') is True:
                main.append(table)
    chosen = explicit if explicit else main
    if len(chosen) != 1:
        return None
    table = chosen[0]
    defaults = []
    for route in table['Routes']:
        if not isinstance(route, dict):
            return None
        family = ('ipv4' if route.get('DestinationCidrBlock') == '0.0.0.0/0'
                  else 'ipv6' if route.get('DestinationIpv6CidrBlock') == '::/0'
                  else None)
        if family is None:
            continue
        if route.get('State') not in ('active', 'blackhole'):
            return None
        target = _route_target(route)
        if target is None:
            return None
        defaults.append({'ip_family': family, 'route_state': route['State'],
                         'target_class': target})
    if len({x['ip_family'] for x in defaults}) != len(defaults):
        return None
    return {'route_table_id': table['RouteTableId'],
            'association': 'EXPLICIT_SUBNET' if explicit else 'IMPLICIT_MAIN',
            'default_routes': sorted(defaults, key=lambda x: x['ip_family'])}


def collect_selected_instance_network_evidence(ctx, selected, errors):
    """One DescribeRouteTables per selected VPC; no account-mode extra reads."""
    instances = _direct_instances(selected)
    if not instances:
        return
    sg_index = defaultdict(list)
    for r in selected:
        if r.get('service') == 'ec2' and r.get('resource_type') == 'security-group':
            sg_index[(r['region'], r['resource_id'])].append(r)
    grouped = defaultdict(list)
    for instance in instances:
        instance['attributes']['owner_approved_role'] = 'NOT_PROVIDED'
        _summarize_instance_ssh(instance, sg_index)
        attrs = instance['attributes']
        vpc, subnet = attrs.get('vpc_id'), attrs.get('subnet_id')
        if not isinstance(vpc, str) or not vpc or not isinstance(subnet, str) or not subnet:
            attrs['subnet_route_lookup'] = 'UNVERIFIED_INSTANCE_TOPOLOGY'
        else:
            grouped[(instance['region'], vpc)].append(instance)

    for (region, vpc), members in grouped.items():
        try:
            ctx.guard_expiration()
            routes = paged(
                ctx.client_cached('ec2', region),
                'describe_route_tables', 'RouteTables',
                Filters=[{'Name': 'vpc-id', 'Values': [vpc]}])
        except EvidenceUnavailable as exc:
            for member in members:
                member['attributes']['subnet_route_lookup'] = 'UNVERIFIED_READ_ERROR'
                errors.append({'region': region, 'service': 'ec2',
                               'operation': 'describe_route_tables',
                               'resource': member['resource_id'],
                               'reason': str(exc)[:180]})
            continue

        for member in members:
            context = _route_context(routes, vpc, member['attributes']['subnet_id'])
            if context is None:
                member['attributes']['subnet_route_lookup'] = 'UNVERIFIED_SCHEMA'
                errors.append({'region': region, 'service': 'ec2',
                               'operation': 'describe_route_tables',
                               'resource': member['resource_id'],
                               'reason': 'Missing or ambiguous selected subnet route evidence'})
            else:
                member['attributes']['subnet_route_lookup'] = 'CONFIG_OBSERVED'
                member['attributes']['subnet_route_context'] = context
