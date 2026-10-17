"""Product-resource evidence matrix independent from compliance verdicts.

A verified property on a selected resource is NOT proof of product-wide PASS.
All rule outputs retain resource attribution and an explicit evidence limitation.
No AWS API calls are made by this module.
"""
from __future__ import annotations

from collections import Counter

from .catalog import CHECKS


PROPERTY_OK = 'PROPERTY_OK'
PROPERTY_FAIL = 'PROPERTY_FAIL'
PROPERTY_UNKNOWN = 'PROPERTY_UNKNOWN'
CONTEXT_ONLY = 'CONTEXT_ONLY'
KINDS = (PROPERTY_OK, PROPERTY_FAIL, PROPERTY_UNKNOWN, CONTEXT_ONLY)


def build_product_observations(inventory: dict, regions: list[str]) -> dict:
    rows = []

    def add(number, resource, state, property_name, value, interpretation):
        rows.append({
            'number': number,
            'control': CHECKS[number - 1].title,
            'service': resource['service'],
            'resource_type': resource['resource_type'],
            'region': resource['region'],
            'name': resource['name'],
            'resource_id': resource['resource_id'],
            'arn': resource.get('arn', ''),
            'attribution': resource['attribution'],
            'attribution_evidence': resource.get('attribution_evidence', ''),
            'property': property_name,
            'observed_value': value,
            'property_result': state,
            'interpretation': interpretation,
            'scope_limit': 'Only this resource/property, not a complete product control PASS',
        })

    for r in inventory.get('resources', []):
        kind = r['resource_type']
        attrs = r['attributes']
        direct = r['attribution'] == 'DIRECT'

        if kind == 'instance':
            add(1, r, CONTEXT_ONLY, 'EC2 public address and subnet',
                {'public_ipv4': attrs.get('public_ipv4'),
                 'subnet_id': attrs.get('subnet_id'), 'state': attrs.get('state')},
                'EC2 role as AP/server/bastion is unverified; cannot score AP private placement')
            add(14, r, CONTEXT_ONLY, 'EC2 connectivity observation',
                {'state': attrs.get('state'),
                 'subnet_id': attrs.get('subnet_id'),
                 'security_group_ids': attrs.get('security_group_ids')},
                'SSM registration, network path, SSH necessity and actual access are not inspected')

        if kind == 'db-instance':
            value = attrs.get('publicly_accessible')
            if isinstance(value, bool):
                add(2, r, PROPERTY_FAIL if value else PROPERTY_OK,
                    'PubliclyAccessible', value,
                    'RDS public-access configuration; network reachability not proven')
            if not attrs.get('cluster_id'):
                value = attrs.get('deletion_protection')
                if isinstance(value, bool):
                    add(23, r, PROPERTY_FAIL if not value else PROPERTY_OK,
                        'DeletionProtection', value,
                        'Standalone RDS instance deletion protection')
        if kind == 'db-cluster':
            value = attrs.get('deletion_protection')
            if isinstance(value, bool):
                add(23, r, PROPERTY_FAIL if not value else PROPERTY_OK,
                    'DeletionProtection', value,
                    'DB cluster deletion protection; member availability is separate')

        if kind == 'security-group':
            public_ports = [
                {'protocol': rule.get('protocol'),
                 'from_port': rule.get('from_port'),
                 'to_port': rule.get('to_port'),
                 'ipv4_cidrs': [c for c in rule.get('ipv4_cidrs', []) if c == '0.0.0.0/0'],
                 'ipv6_cidrs': [c for c in rule.get('ipv6_cidrs', []) if c == '::/0']}
                for rule in attrs.get('ingress_rules', [])
                if '0.0.0.0/0' in rule.get('ipv4_cidrs', [])
                or '::/0' in rule.get('ipv6_cidrs', [])
            ]
            open_egress = [
                rule for rule in attrs.get('egress_rules', [])
                if (rule.get('protocol') == '-1'
                    and ('0.0.0.0/0' in rule.get('ipv4_cidrs', [])
                         or '::/0' in rule.get('ipv6_cidrs', [])))
            ]
            if 'ingress_rules' in attrs and 'egress_rules' in attrs:
                add(5, r, CONTEXT_ONLY, 'public ingress and all-protocol public egress',
                    {'public_ingress': public_ports, 'all_protocol_public_egress_rule_count': len(open_egress)},
                    'Any public ingress is reviewable, including TCP/8000; ALB 80/443 may be intentional. '
                    'No reachability, business necessity or automatic security FAIL inferred')
            count = attrs.get('dangerous_ingress')
            if type(count) is int:
                add(5, r, PROPERTY_FAIL if count > 0 else CONTEXT_ONLY,
                    'dangerous_ingress_permission_count', count,
                    'Selected inbound-rule heuristic; egress, role necessity and reachability unverified')

        if kind == 'application':
            web_acl = attrs.get('waf_web_acl_arn')
            add(6, r, CONTEXT_ONLY, 'direct_alb_waf_web_acl_arn', web_acl,
                'Direct ALB WAF association only; an upstream CloudFront WAF may exist')
            rule = attrs.get('waf_rule_summary')
            lookup = attrs.get('waf_web_acl_lookup')
            if isinstance(rule, dict) or lookup is not None:
                state = (CONTEXT_ONLY if isinstance(rule, dict) and
                         rule.get('state') == 'VERIFIED_SUMMARY' else
                         CONTEXT_ONLY if lookup == 'NOT_ASSOCIATED' else PROPERTY_UNKNOWN)
                add(6, r, state, 'ALB WAF rule configuration summary',
                    {'lookup': lookup, 'rules': rule},
                    'Rule type/action counts are WAF configuration only; no end-to-end '
                    'effective filtering or upstream WAF assurance')
            for listener in attrs.get('listeners', []):
                if listener.get('protocol') not in ('HTTPS', 'TLS'):
                    continue
                port = listener.get('port')
                if (listener.get('ssl_protocol_evidence') == 'API_VERIFIED' and
                        isinstance(listener.get('ssl_protocols'), list) and
                        listener['ssl_protocols']):
                    weak = listener.get('weak_ssl_protocols')
                    if isinstance(weak, list) and weak:
                        state = PROPERTY_FAIL
                    elif isinstance(weak, list):
                        state = PROPERTY_OK
                    else:
                        state = PROPERTY_UNKNOWN
                else:
                    state = PROPERTY_UNKNOWN
                add(16, r, state, f'HTTPS listener {port} TLS protocol set',
                    {'ssl_policy': listener.get('ssl_policy'),
                     'protocols': listener.get('ssl_protocols'),
                     'verification': listener.get('ssl_protocol_evidence')},
                    'Frontend listener protocols only; backend/internal TLS not certified')
            logs = attrs.get('access_logs', {})
            if isinstance(logs, dict) and 'access_logs.s3.enabled' in logs:
                add(29, r, CONTEXT_ONLY, 'ALB access logs configured',
                    logs['access_logs.s3.enabled'],
                    'ALB setting only; application logs and delivery not verified')

        if kind == 'distribution':
            # A CloudFront distribution can front several products, while some
            # requests may bypass it and go straight to a publicly exposed ALB.
            # A WAF ARN proves only configured association, not rules/actions
            # and never proves this product has end-to-end WAF protection.
            acl = attrs.get('web_acl_id')
            acl_state = CONTEXT_ONLY if isinstance(acl, str) else PROPERTY_UNKNOWN
            add(6, r, acl_state, 'CloudFront configured Web ACL association',
                {'web_acl_id': acl, 'origins': attrs.get('origin_domains', []),
                 'enabled': attrs.get('enabled'),
                 'source': attrs.get('web_acl_metadata_source')},
                'CloudFront WAF configuration only; rule effectiveness, ALB bypass and '
                'product route coverage not verified')
            summary = attrs.get('waf_rule_summary')
            lookup = attrs.get('waf_rule_lookup')
            if isinstance(summary, dict) or lookup is not None:
                state = (CONTEXT_ONLY if isinstance(summary, dict) and
                         summary.get('state') == 'VERIFIED_SUMMARY' else
                         CONTEXT_ONLY if lookup == 'NOT_ASSOCIATED' else PROPERTY_UNKNOWN)
                add(6, r, state, 'CloudFront WAF rule configuration summary',
                    {'lookup': lookup, 'rules': summary},
                    'Only selected CloudFront WebACLs inspected. Outer rule types/actions '
                    'do not prove complete ROS protection, traffic path or attack blocking')
            geo = attrs.get('geo_restriction_type')
            add(7, r, CONTEXT_ONLY if isinstance(geo, str) else PROPERTY_UNKNOWN,
                'CloudFront GeoRestriction configuration',
                {'restriction_type': geo,
                 'location_count': attrs.get('geo_restriction_location_count')},
                'Geo restriction is policy-dependent; WAF geographic match rules and '
                'business requirements not inspected')
            policy = attrs.get('viewer_minimum_protocol_version')
            add(16, r, CONTEXT_ONLY if isinstance(policy, str) else PROPERTY_UNKNOWN,
                'CloudFront viewer minimum protocol policy',
                {'minimum_protocol_version': policy, 'enabled': attrs.get('enabled')},
                'Security policy label is not a verified protocol-list for every TLS '
                'connection and does not supersede the ALB #16 negative finding')

        if kind == 'bucket':
            algorithms = attrs.get('default_encryption_algorithms')
            known = {'AES256', 'aws:kms', 'aws:kms:dsse'}
            if isinstance(algorithms, list) and algorithms:
                state = PROPERTY_OK if set(algorithms).issubset(known) else PROPERTY_UNKNOWN
                add(17, r, state, 'default_encryption_algorithms', algorithms,
                    'Bucket default encryption configuration, not every stored object')
            bpa = attrs.get('bucket_public_access_block')
            if isinstance(bpa, dict):
                flags = ('BlockPublicAcls', 'IgnorePublicAcls',
                         'BlockPublicPolicy', 'RestrictPublicBuckets')
                state = (PROPERTY_OK if all(bpa.get(x) is True for x in flags)
                         else CONTEXT_ONLY)
                add(18, r, state, 'bucket_public_access_block', {k: bpa.get(k) for k in flags},
                    'Bucket-level BPA only; account-level, policy and actual exposure unverified')
            versioning = attrs.get('versioning_status')
            lock = attrs.get('object_lock_enabled')
            if versioning == 'Enabled' or lock is True:
                state = PROPERTY_OK
            elif versioning == 'Disabled' and lock is False:
                state = PROPERTY_FAIL if direct else CONTEXT_ONLY
            else:
                state = PROPERTY_UNKNOWN
            add(22, r, state, 'S3 versioning or Object Lock',
                {'versioning': versioning, 'object_lock': lock},
                'Selected bucket property only; lifecycle, retention and shared control unverified')

        if kind in ('ebs-volume', 'ebs-snapshot'):
            value = attrs.get('encrypted')
            if type(value) is bool:
                add(19, r, PROPERTY_FAIL if not value else PROPERTY_OK,
                    'encrypted', value, 'Observed EBS resource encryption; backup coverage unverified')

        if kind in ('db-instance', 'db-cluster', 'db-snapshot', 'db-cluster-snapshot'):
            value = attrs.get('encrypted')
            if type(value) is bool:
                state = PROPERTY_FAIL if not value else PROPERTY_OK
            else:
                state = PROPERTY_UNKNOWN
            add(20, r, state, 'effective storage encryption',
                {'encrypted': value, 'encryption_state': attrs.get('encryption_state'),
                 'storage_encryption_type': attrs.get('storage_encryption_type')},
                'Observed RDS resource only; backup/restore scope unverified')

        if kind in ('vpc', 'subnet'):
            logs = attrs.get('flow_logs')
            if isinstance(logs, list):
                add(27, r, CONTEXT_ONLY, 'Flow Logs at resource scope', logs,
                    'VPC/subnet configuration only; ENI or upstream/shared logging may exist')


    # Region/account-level security services cannot be assigned to a product from
    # tag/name matches. Preserve them as SHARED_UNATTRIBUTED context separately.
    shared = inventory.get('shared_control_evidence') or {}
    for block in shared.get('regions', []):
        region = block['region']
        for service, numbers in (
            ('cloudtrail', (24, 25)),
            ('guardduty', (32,)),
            ('securityhub', (33,)),
        ):
            source = block.get(service) or {}
            state = source.get('state', 'UNVERIFIED')
            context = {
                'region': region,
                'service': service,
                'resource_type': 'shared-security-control',
                'name': service + ':' + region,
                'resource_id': service + ':' + region,
                'arn': '',
                'attribution': 'SHARED_UNATTRIBUTED',
                'attribution_evidence': 'Region-level account service; product ownership not established',
            }
            if service == 'cloudtrail':
                trails = source.get('trails', [])
                for number in numbers:
                    if trails:
                        for trail in trails:
                            item = dict(context, name=trail.get('name') or context['name'],
                                        resource_id=trail.get('trail_arn') or context['resource_id'],
                                        arn=trail.get('trail_arn') or '')
                            if number == 24:
                                value = {
                                    'multi_region': trail.get('multi_region'),
                                    'organization': trail.get('organization'),
                                    'log_status': trail.get('log_status'),
                                    'is_logging': trail.get('is_logging'),
                                    'has_s3_delivery_error': trail.get('has_s3_delivery_error'),
                                    'selector_status': trail.get('selector_status'),
                                    'selectors': trail.get('selectors'),
                                }
                            else:
                                value = {
                                    'log_file_validation_enabled': trail.get('log_file_validation_enabled'),
                                    'has_digest_delivery_error': trail.get('has_digest_delivery_error'),
                                    'log_status': trail.get('log_status'),
                                }
                            status = CONTEXT_ONLY if state == 'LIST_VERIFIED' else PROPERTY_UNKNOWN
                            add(number, item, status, 'Regional CloudTrail trail configuration',
                                value, 'Shared trail; delivery/selector/region coverage and product protection not certified')
                    else:
                        add(number, context, CONTEXT_ONLY if state == 'LIST_VERIFIED'
                            else PROPERTY_UNKNOWN, 'Regional CloudTrail trail listing',
                            {'state': state, 'trail_count': len(trails)},
                            'No trails returned is not proof of no CloudTrail Lake, organization or linked-region coverage')
            elif service == 'guardduty':
                detectors = source.get('detectors', [])
                add(32, context, CONTEXT_ONLY if state == 'LIST_VERIFIED'
                    else PROPERTY_UNKNOWN, 'GuardDuty regional detector summary',
                    {'state': state, 'detector_count': len(detectors),
                     'detectors': detectors},
                    'Regional detector status; features/organization configuration and ROS protection unverified')
            elif service == 'securityhub':
                add(33, context, CONTEXT_ONLY if state == 'HUB_OBSERVED'
                    else PROPERTY_UNKNOWN, 'Security Hub regional standards summary',
                    {'state': state, 'hub_arn': source.get('hub_arn'),
                     'standards_state': source.get('standards_state'),
                     'standards': source.get('standards', [])},
                    'Hub existence/standards only; CIS controls, findings and ROS linkage unverified')

    summaries = {}
    for definition in CHECKS:
        matching = [r for r in rows if r['number'] == definition.number]
        counts = Counter(r['property_result'] for r in matching)
        shared_count = sum(r['attribution'] == 'SHARED_UNATTRIBUTED' for r in matching)
        region_errors = [
            err for err in inventory.get('collection_errors', [])
            if err.get('service') in (
                {24: ('cloudtrail',), 25: ('cloudtrail',),
                 32: ('guardduty',), 33: ('securityhub',)}.get(definition.number, ()))
        ]
        summaries[str(definition.number)] = {
            'control_number': definition.number,
            'observed_resources': len(matching),
            'ok': counts[PROPERTY_OK],
            'fail': counts[PROPERTY_FAIL],
            'unknown': counts[PROPERTY_UNKNOWN],
            'context': counts[CONTEXT_ONLY],
            'evidence_state': (
                'NO_RESOURCE_EVIDENCE' if not matching
                else (
                    'SHARED_EVIDENCE_UNVERIFIED' if counts[PROPERTY_UNKNOWN] > 0
                    else 'SHARED_CONTEXT_ONLY'
                ) if shared_count == len(matching)
                else 'PARTIAL_RESOURCE_EVIDENCE'
            ),
            'shared_context_count': shared_count,
            'collection_error_count': len(region_errors),
            'product_wide_pass_proven': False,
        }
    return {
        'schema': 'aws-product-resource-observations-v1',
        'regions_checked': regions,
        'source': 'resource_inventory.attributes',
        'rows': rows,
        'by_control': summaries,
        'limitations': [
            'PROPERTY_OK means only a particular selected resource attribute meets a check, NOT product/account PASS.',
            'PROPERTY_FAIL means a negative property is observed, not necessarily the full control failed without context.',
            'CONTEXT_ONLY cannot be used as PASS or FAIL; PROPERTY_UNKNOWN is missing or conflicting evidence.',
            'Attribution is heuristic; shared, untagged and omitted resources may exist.',
            'Only a limited subset of 46 controls has attribute-level evaluations.',
            'A property observation must not overwrite the original deterministic control verdict.',
        ],
    }
