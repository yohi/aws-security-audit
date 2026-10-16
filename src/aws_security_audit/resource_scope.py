"""Read-only resource identity inventory and conservative product attribution.

This module never mutates AWS. Product reports are evidence-oriented and intentionally
do not inherit account-wide control verdicts without a resource-to-product proof.
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter
from io import StringIO
from pathlib import Path
from uuid import uuid4

from .catalog import CHECKS
from .core import EvidenceUnavailable, Finding, api_call, paged
from .report import _private_bytes

IDENTITY_TAGS = ('Name', 'Product', 'Project', 'Application', 'Service', 'Environment', 'Owner')
PRODUCT_TAGS = ('Product', 'Project', 'Application', 'Service')


def identity_tags(raw) -> dict[str, str]:
    """Capture identifying tags only; never persist arbitrary secret-bearing tags."""
    if isinstance(raw, dict):
        raw = [{'Key': k, 'Value': v} for k, v in raw.items()]
    return {t['Key']: str(t.get('Value', '')) for t in (raw or [])
            if isinstance(t, dict) and t.get('Key') in IDENTITY_TAGS}


def _record(service, kind, region, identifier, arn='', tags=None, name='', **attributes):
    tags = identity_tags(tags or [])
    return {
        'service': service, 'resource_type': kind, 'region': region,
        'resource_id': str(identifier), 'arn': str(arn or ''),
        'name': str(tags.get('Name') or name or identifier),
        'tags': tags, 'attributes': attributes,
        'attribution': 'UNCLASSIFIED', 'attribution_evidence': '',
    }


def _tagged(ctx, service, region, arn, errors, key='TagList'):
    try:
        return api_call(ctx.client_cached(service, region), 'list_tags_for_resource', ResourceName=arn).get(key, [])
    except EvidenceUnavailable as exc:
        errors.append({'region': region, 'service': service, 'operation': 'list_tags_for_resource',
                       'resource': arn, 'reason': str(exc)[:180]})
        return []  # Explicit uncertainty; never interpret failed tag lookup as untagged.


def _add_ec2(ctx, region, out, errors):
    ec2 = ctx.client_cached('ec2', region)
    for reservation in paged(ec2, 'describe_instances', 'Reservations'):
        for i in reservation.get('Instances', []):
            if i.get('State', {}).get('Name') == 'terminated':
                continue
            out.append(_record('ec2', 'instance', region, i['InstanceId'], tags=i.get('Tags'),
                               state=i.get('State', {}).get('Name'),
                               vpc_id=i.get('VpcId'), subnet_id=i.get('SubnetId'),
                               public_ipv4=bool(i.get('PublicIpAddress')),
                               security_group_ids=[g['GroupId'] for g in i.get('SecurityGroups', [])],
                               volume_ids=[m['Ebs']['VolumeId'] for m in i.get('BlockDeviceMappings', [])
                                           if m.get('Ebs', {}).get('VolumeId')]))
    for sg in paged(ec2, 'describe_security_groups', 'SecurityGroups'):
        # Count high-risk rules with the same deterministic scanner logic.
        from .checks import dangerous_inbound
        out.append(_record('ec2', 'security-group', region, sg['GroupId'], tags=sg.get('Tags'),
                           vpc_id=sg.get('VpcId'),
                           dangerous_ingress=sum(bool(dangerous_inbound(p)) for p in sg.get('IpPermissions', []))))
    for vol in paged(ec2, 'describe_volumes', 'Volumes'):
        out.append(_record('ec2', 'ebs-volume', region, vol['VolumeId'], tags=vol.get('Tags'),
                           encrypted=vol.get('Encrypted'), size_gib=vol.get('Size'),
                           attached_instance_ids=[a['InstanceId'] for a in vol.get('Attachments', [])
                                                  if a.get('InstanceId')]))
    try:
        flow_logs = paged(ec2, 'describe_flow_logs', 'FlowLogs')
    except EvidenceUnavailable as exc:
        errors.append({'region': region, 'service': 'ec2',
                       'operation': 'describe_flow_logs', 'reason': str(exc)[:180]})
        flow_logs = []
    for vpc in paged(ec2, 'describe_vpcs', 'Vpcs'):
        linked_logs = [log for log in flow_logs if log.get('ResourceId') == vpc['VpcId']]
        out.append(_record('ec2', 'vpc', region, vpc['VpcId'], tags=vpc.get('Tags'),
                           cidr_block=vpc.get('CidrBlock'),
                           flow_logs=[{'id': log.get('FlowLogId'), 'status': log.get('FlowLogStatus'),
                                       'delivery_status': log.get('DeliverLogsStatus')}
                                      for log in linked_logs]))
    for subnet in paged(ec2, 'describe_subnets', 'Subnets'):
        out.append(_record('ec2', 'subnet', region, subnet['SubnetId'], tags=subnet.get('Tags'),
                           vpc_id=subnet.get('VpcId'), cidr_block=subnet.get('CidrBlock')))
    # DescribeSnapshots exposes VolumeId only for known snapshots; an absent
    # linkage is not proof that no backup belongs to the product.
    try:
        snapshots = paged(ec2, 'describe_snapshots', 'Snapshots', OwnerIds=['self'])
        for snap in snapshots:
            out.append(_record('ec2', 'ebs-snapshot', region, snap['SnapshotId'],
                               tags=snap.get('Tags'), encrypted=snap.get('Encrypted'),
                               source_volume_id=snap.get('VolumeId'),
                               volume_size_gib=snap.get('VolumeSize')))
    except EvidenceUnavailable as exc:
        errors.append({'region': region, 'service': 'ec2',
                       'operation': 'describe_snapshots', 'reason': str(exc)[:180})


def _add_rds(ctx, region, out, errors):
    rds = ctx.client_cached('rds', region)
    for db in paged(rds, 'describe_db_instances', 'DBInstances'):
        arn = db.get('DBInstanceArn', '')
        tags = db.get('TagList')
        if tags is None and arn:
            tags = _tagged(ctx, 'rds', region, arn, errors)
        out.append(_record('rds', 'db-instance', region, db['DBInstanceIdentifier'],
                           arn=arn, tags=tags, encrypted=db.get('StorageEncrypted'),
                           publicly_accessible=db.get('PubliclyAccessible'),
                           deletion_protection=db.get('DeletionProtection'),
                           cluster_id=db.get('DBClusterIdentifier'), engine=db.get('Engine'),
                           security_group_ids=[g.get('VpcSecurityGroupId')
                                               for g in db.get('VpcSecurityGroups', [])]))
    for db in paged(rds, 'describe_db_clusters', 'DBClusters'):
        arn = db.get('DBClusterArn', '')
        tags = db.get('TagList')
        if tags is None and arn:
            tags = _tagged(ctx, 'rds', region, arn, errors)
        out.append(_record('rds', 'db-cluster', region, db['DBClusterIdentifier'],
                           arn=arn, tags=tags, encrypted=db.get('StorageEncrypted'),
                           deletion_protection=db.get('DeletionProtection'), engine=db.get('Engine'),
                           security_group_ids=[g.get('VpcSecurityGroupId')
                                               for g in db.get('VpcSecurityGroups', [])]))
    for operation, collection, kind, id_field, parent_field in (
        ('describe_db_snapshots', 'DBSnapshots', 'db-snapshot', 'DBSnapshotIdentifier', 'DBInstanceIdentifier'),
        ('describe_db_cluster_snapshots', 'DBClusterSnapshots', 'db-cluster-snapshot',
         'DBClusterSnapshotIdentifier', 'DBClusterIdentifier'),
    ):
        try:
            snapshots = paged(rds, operation, collection)
            for snap in snapshots:
                out.append(_record('rds', kind, region, snap[id_field],
                                   arn=snap.get('DBSnapshotArn', '') or snap.get('DBClusterSnapshotArn', ''),
                                   tags=snap.get('TagList'),
                                   source_db_id=snap.get(parent_field),
                                   encrypted=snap.get('Encrypted'),
                                   snapshot_type=snap.get('SnapshotType')))
        except EvidenceUnavailable as exc:
            errors.append({'region': region, 'service': 'rds',
                           'operation': operation, 'reason': str(exc)[:180]})


def _add_elb(ctx, region, out, errors):
    elb = ctx.client_cached('elbv2', region)
    lbs = paged(elb, 'describe_load_balancers', 'LoadBalancers')
    # ALB/NLB tags are not present in DescribeLoadBalancers.
    tag_map = {}
    for index in range(0, len(lbs), 20):
        batch = lbs[index:index + 20]
        if not batch:
            continue
        try:
            resp = api_call(elb, 'describe_tags', ResourceArns=[lb['LoadBalancerArn'] for lb in batch])
            for d in resp.get('TagDescriptions', []):
                tag_map[d['ResourceArn']] = d.get('Tags', [])
        except EvidenceUnavailable as exc:
            for lb in batch:
                errors.append({'region': region, 'service': 'elbv2',
                               'operation': 'describe_tags', 'resource': lb['LoadBalancerArn'],
                               'reason': str(exc)[:180]})
    for lb in lbs:
        arn = lb['LoadBalancerArn']
        observed = {}
        for operation, key, extract in (
            ('describe_listeners', 'listeners', lambda x: [
                {'protocol': y.get('Protocol'), 'port': y.get('Port'),
                 'ssl_policy': y.get('SslPolicy')}
                for y in x.get('Listeners', [])]),
            ('describe_load_balancer_attributes', 'access_logs', lambda x: {
                a.get('Key'): a.get('Value') for a in x.get('Attributes', [])
                if a.get('Key') in ('access_logs.s3.enabled',
                                    'access_logs.s3.bucket',
                                    'access_logs.s3.prefix')}),
        ):
            try:
                response = ({'Listeners': paged(elb, operation, 'Listeners', LoadBalancerArn=arn)}
                            if operation == 'describe_listeners'
                            else api_call(elb, operation, LoadBalancerArn=arn))
                observed[key] = extract(response)
            except EvidenceUnavailable as exc:
                errors.append({'region': region, 'service': 'elbv2', 'operation': operation,
                               'resource': arn, 'reason': str(exc)[:180]})
        if lb.get('Type') == 'application':
            try:
                response = api_call(ctx.client_cached('wafv2', region),
                                    'get_web_acl_for_resource', ResourceArn=arn)
                observed['waf_web_acl_arn'] = (response.get('WebACL') or {}).get('ARN')
            except EvidenceUnavailable as exc:
                # A missing WebACL is distinct from no permission to inspect it.
                observed['waf_web_acl_lookup'] = 'NOT_ASSOCIATED' if 'WAFNonexistentItemException' in str(exc) else 'UNVERIFIED'
                if observed['waf_web_acl_lookup'] == 'UNVERIFIED':
                    errors.append({'region': region, 'service': 'wafv2',
                                   'operation': 'get_web_acl_for_resource',
                                   'resource': arn, 'reason': str(exc)[:180]})
        out.append(_record('elbv2', lb.get('Type', 'load-balancer'), region,
                           lb.get('LoadBalancerName', arn), arn=arn,
                           tags=tag_map.get(arn), name=lb.get('LoadBalancerName', ''),
                           scheme=lb.get('Scheme'), dns_name=lb.get('DNSName'),
                           security_group_ids=lb.get('SecurityGroups', []),
                           vpc_id=lb.get('VpcId'), state=lb.get('State', {}).get('Code'),
                           **observed))


def _add_logs(ctx, region, out, errors):
    for g in paged(ctx.client_cached('logs', region), 'describe_log_groups', 'logGroups'):
        out.append(_record('logs', 'log-group', region, g['logGroupName'],
                           arn=g.get('arn', ''), name=g['logGroupName'],
                           retention_days=g.get('retentionInDays')))


def _add_s3(ctx, out, errors):
    s3 = ctx.client_cached('s3')
    buckets = api_call(s3, 'list_buckets').get('Buckets', [])
    for bucket in buckets:
        name = bucket['Name']
        tags = []
        try:
            tags = api_call(s3, 'get_bucket_tagging', Bucket=name).get('TagSet', [])
        except EvidenceUnavailable as exc:
            if 'NoSuchTagSet' not in str(exc):
                errors.append({'region': 'global', 'service': 's3',
                               'operation': 'get_bucket_tagging', 'resource': name,
                               'reason': str(exc)[:180]})
        observed = {}
        for operation, name_key, extract, benign_errors in (
            ('get_bucket_encryption', 'default_encryption_algorithms',
             lambda r: sorted({rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
                               for rule in r.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                               if rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')}),
             ('ServerSideEncryptionConfigurationNotFoundError',)),
            ('get_public_access_block', 'bucket_public_access_block',
             lambda r: r.get('PublicAccessBlockConfiguration'),
             ('NoSuchPublicAccessBlockConfiguration',)),
            ('get_bucket_versioning', 'versioning_status',
             lambda r: r.get('Status', 'Disabled'), ()),
            ('get_object_lock_configuration', 'object_lock_enabled',
             lambda r: r.get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled',
             ('ObjectLockConfigurationNotFoundError',)),
        ):
            try:
                observed[name_key] = extract(api_call(s3, operation, Bucket=name))
            except EvidenceUnavailable as exc:
                if any(code in str(exc) for code in benign_errors):
                    observed[name_key] = None
                else:
                    errors.append({'region': 'global', 'service': 's3',
                                   'operation': operation, 'resource': name,
                                   'reason': str(exc)[:180]})
        out.append(_record('s3', 'bucket', 'global', name, arn=f'arn:aws:s3:::{name}',
                           tags=tags, name=name, **observed))


def _add_iam(ctx, out, errors):
    iam = ctx.client_cached('iam')
    for user in paged(iam, 'list_users', 'Users'):
        out.append(_record('iam', 'user', 'global', user['UserName'],
                           arn=user.get('Arn', ''), name=user['UserName'],
                           path=user.get('Path', '')))
    for role in paged(iam, 'list_roles', 'Roles'):
        out.append(_record('iam', 'role', 'global', role['RoleName'],
                           arn=role.get('Arn', ''), name=role['RoleName'],
                           path=role.get('Path', '')))


def _add_cloudfront(ctx, out, errors):
    cf = ctx.client_cached('cloudfront', 'us-east-1')
    marker = None
    for _ in range(10000):
        args = {'Marker': marker} if marker else {}
        data = api_call(cf, 'list_distributions', **args).get('DistributionList', {})
        for d in data.get('Items', []):
            arn = d.get('ARN', '')
            tags = []
            if arn:
                try:
                    tags = api_call(cf, 'list_tags_for_resource', Resource=arn).get('Tags', {}).get('Items', [])
                except EvidenceUnavailable as exc:
                    errors.append({'region': 'global', 'service': 'cloudfront',
                                   'operation': 'list_tags_for_resource', 'resource': d['Id'],
                                   'reason': str(exc)[:180]})
            out.append(_record('cloudfront', 'distribution', 'global', d['Id'],
                               arn=arn, tags=tags, name=d.get('Comment', '') or d['Id'],
                               domain_name=d.get('DomainName'), enabled=d.get('Enabled')))
        if not data.get('IsTruncated'):
            return
        next_marker = data.get('NextMarker')
        if not next_marker or next_marker == marker:
            raise EvidenceUnavailable('cloudfront.list_distributions: pagination cycle')
        marker = next_marker
    raise EvidenceUnavailable('cloudfront.list_distributions: pagination limit')


def _prefix_match(value: str, product: str) -> bool:
    # Avoid conflating 'ros' and 'roslyn', or 'scs2' with 'scs20'.
    left, right = value.casefold(), product.casefold()
    return left == right or left.startswith(right + '-') or left.startswith(right + '_') or left.startswith(right + '/')


def _direct_match(resource, product, product_tag):
    tags = resource['tags']
    if product_tag:
        key, value = product_tag.split('=', 1)
        if tags.get(key) == value:
            return 'TAG:' + product_tag
        return None
    for key in PRODUCT_TAGS:
        if tags.get(key, '').casefold() == product.casefold():
            return 'TAG:' + key
    if _prefix_match(resource['name'], product) or _prefix_match(resource['resource_id'], product):
        return 'PREFIX:NameOrId'
    return None


def attribute_resources(resources, product=None, product_tag=None):
    if product is None:
        return resources, {'mode': 'account', 'matched': len(resources),
                           'unassigned': 0, 'related': 0}
    for resource in resources:
        match = _direct_match(resource, product, product_tag)
        if match:
            resource['attribution'] = 'DIRECT'
            resource['attribution_evidence'] = match
    # One-hop AWS topology relationships only. Do not infer a product solely
    # from membership in a shared VPC, subnet, IAM role, or security group.
    direct = [r for r in resources if r['attribution'] == 'DIRECT']
    keys = {(r['region'], r['resource_type'], r['resource_id']) for r in direct}
    attached_sg = {(r['region'], sg) for r in direct
                   for sg in r['attributes'].get('security_group_ids', []) if sg}
    referenced_vpc = {(r['region'], r['attributes']['vpc_id']) for r in direct
                      if r['attributes'].get('vpc_id')}
    referenced_subnet = {(r['region'], r['attributes']['subnet_id']) for r in direct
                         if r['attributes'].get('subnet_id')}
    for resource in resources:
        if resource['attribution'] == 'DIRECT':
            continue
        attrs = resource['attributes']
        region, kind, rid = resource['region'], resource['resource_type'], resource['resource_id']
        reason = None
        if kind == 'ebs-volume' and any(
            (region, 'instance', x) in keys for x in attrs.get('attached_instance_ids', [])):
            reason = 'Attached to directly matched EC2 instance; may be shared'
        elif kind == 'ebs-snapshot' and attrs.get('source_volume_id') and (
            (region, 'ebs-volume', attrs['source_volume_id']) in keys or
            any((region, 'ebs-volume', x['resource_id']) in keys and
                x['resource_id'] == attrs['source_volume_id'] for x in resources)):
            reason = 'Snapshot references directly matched EBS volume'
        elif kind == 'security-group' and (region, rid) in attached_sg:
            reason = 'Referenced by directly matched EC2/ALB/RDS; may be shared'
        elif kind == 'db-cluster' and any(
            x['region'] == region and x['resource_type'] == 'db-instance'
            and x['attributes'].get('cluster_id') == rid for x in direct):
            reason = 'Parent cluster of directly matched RDS instance'
        elif kind in ('db-snapshot', 'db-cluster-snapshot') and attrs.get('source_db_id'):
            target_kind = 'db-instance' if kind == 'db-snapshot' else 'db-cluster'
            if (region, target_kind, attrs['source_db_id']) in keys:
                reason = 'Snapshot references directly matched RDS resource'
        elif kind == 'vpc' and (region, rid) in referenced_vpc:
            reason = 'Referenced VPC; shared infrastructure, not exclusive ownership'
        elif kind == 'subnet' and (region, rid) in referenced_subnet:
            reason = 'Referenced EC2 subnet; may be shared'
        if reason:
            resource['attribution'] = 'RELATED'
            resource['attribution_evidence'] = reason
    # A second *one-hop* pass includes snapshots attached to RELATED volumes,
    # cluster snapshots for RELATED clusters, without recursively including
    # unrelated members of shared VPCs.
    linked = {(r['region'], r['resource_type'], r['resource_id'])
              for r in resources if r['attribution'] in ('DIRECT', 'RELATED')}
    for resource in resources:
        if resource['attribution'] != 'UNCLASSIFIED':
            continue
        attrs, region, kind = resource['attributes'], resource['region'], resource['resource_type']
        source_kind = {'ebs-snapshot': 'ebs-volume',
                       'db-snapshot': 'db-instance',
                       'db-cluster-snapshot': 'db-cluster'}.get(kind)
        source_id = attrs.get('source_volume_id' if kind == 'ebs-snapshot' else 'source_db_id')
        if source_kind and source_id and (region, source_kind, source_id) in linked:
            resource['attribution'] = 'RELATED'
            resource['attribution_evidence'] = (
                f'Snapshot references {source_kind} with DIRECT/RELATED attribution; ownership not proven'
            )
    selected = [r for r in resources if r['attribution'] != 'UNCLASSIFIED']
    return selected, {
        'mode': 'product', 'product': product, 'product_tag': product_tag,
        'matched': len(selected),
        'direct': sum(x['attribution'] == 'DIRECT' for x in selected),
        'related': sum(x['attribution'] == 'RELATED' for x in selected),
        'unassigned': len(resources) - len(selected),
        'attribution_complete': False,
        'warning': 'Tag/Name and topology attribution cannot prove product ownership. VPC, SG, snapshots and other resources can be shared.',
    }

def collect_resource_inventory(ctx, regions, product=None, product_tag=None):
    inventory = []
    errors = []
    for region in regions:
        for label, collect in (
            ('ec2', _add_ec2), ('rds', _add_rds),
            ('elbv2', _add_elb), ('logs', _add_logs),
        ):
            try:
                ctx.guard_expiration()
                collect(ctx, region, inventory, errors)
            except EvidenceUnavailable as exc:
                errors.append({'region': region, 'service': label,
                               'reason': str(exc)[:180]})
    for label, collect in (('s3', _add_s3), ('iam', _add_iam), ('cloudfront', _add_cloudfront)):
        try:
            ctx.guard_expiration()
            collect(ctx, inventory, errors)
        except EvidenceUnavailable as exc:
            errors.append({'region': 'global', 'service': label,
                           'reason': str(exc)[:180]})
    selected, scope = attribute_resources(inventory, product, product_tag)
    scope['service_counts'] = dict(Counter(r['service'] for r in selected))
    scope['collection_errors'] = len(errors)
    return {'schema': 'aws-security-resource-inventory-v1',
            'scope': scope, 'regions_requested': list(regions),
            'resources': selected, 'collection_errors': errors,
            'limitations': [
                'Not all AWS services and resource types are inventoried.',
                'Resource identity tags are a restricted allowlist, not full tag payloads.',
                'Related SG/EBS may be shared with other products.',
                'collection_errors includes per-resource tag read failures; empty tags do not establish absence of a product.',
                'Name-prefix attribution is heuristic; untagged/shared resources may be omitted.',
                'Resource inventory is not a replacement for per-control security assessment.',
            ]}


def product_findings(inventory, regions):
    """Emit conservative, product-scoped findings; keep account-level status separate.

    Aurora data protection is a DB *cluster* property. Its DB instances may be
    deleted while the cluster/volume remains protected. This is distinct from
    standalone RDS DB instances and from availability protection.
    """
    by_region = {}
    for resource in inventory['resources']:
        by_region.setdefault(resource['region'], []).append(resource)
    output = []
    for region in regions:
        region_items = by_region.get(region, [])
        global_items = by_region.get('global', [])
        relevant = region_items + (global_items if region == regions[0] else [])
        for check in CHECKS:
            status = 'MANUAL_REVIEW'
            detail = '製品単位の判定には追加の紐付け/共通基盤証拠が必要'
            evidence = []
            selected = []
            key = None
            negative = None
            if check.number == 2:
                selected, key, negative = [r for r in region_items if r['resource_type'] == 'db-instance'], 'publicly_accessible', True
            elif check.number == 5:
                selected, key, negative = [r for r in region_items if r['resource_type'] == 'security-group'], 'dangerous_ingress', None
            elif check.number == 19:
                selected, key, negative = [r for r in region_items if r['resource_type'] == 'ebs-volume'], 'encrypted', False
            elif check.number == 20:
                selected, key, negative = [r for r in region_items if r['resource_type'] in ('db-instance', 'db-cluster')], 'encrypted', False
            elif check.number == 23:
                clusters = {r['resource_id']: r for r in region_items if r['resource_type'] == 'db-cluster'}
                instances = [r for r in region_items if r['resource_type'] == 'db-instance']
                standalone = [r for r in instances if not r['attributes'].get('cluster_id')]
                selected = list(clusters.values()) + standalone
                failures = [r for r in selected if r['attributes'].get('deletion_protection') is False]
                missing_parents = [r for r in instances if
                                   r['attributes'].get('cluster_id') and
                                   r['attributes']['cluster_id'] not in clusters]
                if failures:
                    status = 'FAIL'
                    detail = f'削除保護無効なDBクラスターまたは独立RDSインスタンス: {len(failures)}件'
                    evidence = [f"{r['resource_type']} {r['name']} ({r['resource_id']}): deletion_protection=False"
                                for r in failures]
                else:
                    detail = (f'対象クラスター/独立DB {len(selected)}件で削除保護の無効状態は未検出。'
                              'データ保護とDBインスタンス削除による可用性は別基準')
                evidence += [f"Aurora cluster {r['name']} ({r['resource_id']}): deletion_protection={r['attributes'].get('deletion_protection')}"
                             for r in clusters.values()]
                evidence += [f"Aurora instance {r['name']} ({r['resource_id']}): "
                             f"parent_cluster={r['attributes']['cluster_id']}; "
                             f"instance_deletion_protection={r['attributes'].get('deletion_protection')}; "
                             "member deletion remains possible despite cluster protection"
                             for r in instances if r['attributes'].get('cluster_id')]
                if missing_parents:
                    detail += f'。親クラスターの証拠不在{len(missing_parents)}件'
                if not relevant:
                    status, detail = 'UNKNOWN', '対象リソースを特定できない。タグ/Name/収集権限/リージョンを確認'
                output.append(Finding(check.number, status, region, detail, evidence))
                continue
            if key:
                failures = [r for r in selected if
                            (r['attributes'].get(key) is negative if negative is not None
                             else bool(r['attributes'].get(key)))]
                if failures:
                    status = 'FAIL'
                    detail = f'プロダクト関連リソース{len(failures)}件で明示的な基準未達を観測（関連リソースは共有の可能性あり）'
                    evidence = [f"{r['resource_type']} {r['name']} ({r['resource_id']}): {key}={r['attributes'].get(key)}"
                                for r in failures]
                else:
                    detail = f'対象リソース{len(selected)}件。未検出はPASSの証明ではない'
            if not relevant:
                status, detail = 'UNKNOWN', '対象リソースを特定できない。タグ/Name/収集権限/リージョンを確認'
            output.append(Finding(check.number, status, region, detail, evidence))
    return output

def save_resource_inventory(out_dir, inventory):
    folder = Path(out_dir).expanduser().resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    suffix = uuid4().hex
    json_path = folder / f'aws_resource_inventory_{suffix}.json'
    csv_path = folder / f'aws_resource_inventory_{suffix}.csv'
    _private_bytes(json_path, (json.dumps(inventory, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    cols = ['service', 'resource_type', 'region', 'resource_id', 'name', 'arn',
            'attribution', 'attribution_evidence', 'tags', 'attributes']
    data = StringIO()
    writer = csv.DictWriter(data, fieldnames=cols)
    writer.writeheader()
    for resource in inventory['resources']:
        line = {k: (json.dumps(resource[k], ensure_ascii=False, sort_keys=True)
                    if k in ('tags', 'attributes') else resource.get(k, '')) for k in cols}
        # Spreadsheet formula injection is possible even via CSV import.
        for key, val in line.items():
            if isinstance(val, str) and val.startswith(('=', '+', '-', '@', '\t', '\r', '\n')):
                line[key] = "'" + val
        writer.writerow(line)
    _private_bytes(csv_path, ('\ufeff' + data.getvalue()).encode('utf-8'))
    return [json_path, csv_path]
