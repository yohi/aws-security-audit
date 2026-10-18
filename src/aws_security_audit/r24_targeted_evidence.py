"""R24: tightly scoped, read-only operator evidence for Issue #8.

This is NOT part of the normal assess or offline-LLM path. Manifest validity
and an explicit operator invocation are necessary, not proof of Owner approval.
Output is descriptive only; no control is classified or automatically closed.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .core import AuditError, EvidenceUnavailable, api_call, paged

_ACCOUNT = re.compile(r'\d{12}\Z')
_REGION = re.compile(r'(?:ap|us|eu|sa|ca|af|me|il|mx)-[a-z0-9-]+-\d\Z')
_ENI = re.compile(r'eni-[0-9a-f]{8,17}\Z')
_EC2 = re.compile(r'i-[0-9a-f]{8,17}\Z')
_ECR_REPO = re.compile(r'[a-z0-9]+(?:[._/-][a-z0-9]+)*\Z')
_DIGEST = re.compile(r'sha256:[a-f0-9]{64}\Z')
_ALLOWED = frozenset((
    'shield_resource_arns', 'cloudtrail_trail_arns', 'cloudtrail_s3_bucket_arns',
    'flow_log_eni_ids', 'securityhub', 'inspector_ec2_instance_ids', 'ecr_images',
))
_LIST_KEYS = _ALLOWED - {'securityhub', 'ecr_images'}
_LIMITS = {
    'shield_resource_arns': 20,
    'cloudtrail_trail_arns': 8,
    'cloudtrail_s3_bucket_arns': 20,
    'flow_log_eni_ids': 50,
    'inspector_ec2_instance_ids': 50,
    'ecr_images': 20,
}


def validate_manifest(data: dict) -> dict:
    """Fail closed on malformed, unbounded or cross-account target requests."""
    if not isinstance(data, dict) or set(data) != {
        'schema', 'account', 'region', 'product', 'scope_confirmation', 'targets',
    } or data['schema'] != 'aws-ros-r24-targeted-read-v1' or data['product'] != 'ros':
        raise AuditError('R24 requires a narrowly scoped ROS v1 manifest')
    account, region = data['account'], data['region']
    if (not isinstance(account, str) or not _ACCOUNT.fullmatch(account)
            or not isinstance(region, str) or not _REGION.fullmatch(region)):
        raise AuditError('Account and region must be explicit and valid')
    # Date and ref are fields the human operator supplies; neither is a
    # cryptographic authorization credential or independent approval proof.
    scope = data['scope_confirmation']
    if (not isinstance(scope, dict) or set(scope) != {'owner_ref', 'confirmed_at_utc'}
            or not isinstance(scope['owner_ref'], str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:_./-]{5,127}', scope['owner_ref'])
            or not isinstance(scope['confirmed_at_utc'], str)):
        raise AuditError('Dated operator/Owner scope record is required')
    try:
        dt = datetime.fromisoformat(scope['confirmed_at_utc'].replace('Z', '+00:00'))
        if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
            raise ValueError('UTC required')
    except ValueError:
        raise AuditError('Scope record requires valid UTC date') from None
    targets = data['targets']
    if not isinstance(targets, dict) or set(targets) != _ALLOWED:
        raise AuditError('Explicit seven-field R24 target map required')
    for key in _LIST_KEYS:
        values = targets[key]
        if (not isinstance(values, list) or len(values) > _LIMITS[key]
                or any(not isinstance(v, str) or len(v) > 400 for v in values)
                or len(values) != len(set(values))):
            raise AuditError(f'Invalid or duplicate target values: {key}')
    if type(targets['securityhub']) is not bool:
        raise AuditError('securityhub must be an explicit boolean')
    images = targets['ecr_images']
    if not isinstance(images, list) or len(images) > _LIMITS['ecr_images']:
        raise AuditError('Invalid ECR image list')
    seen = set()
    for image in images:
        if (not isinstance(image, dict) or set(image) != {'repository', 'digest'}
                or not isinstance(image['repository'], str)
                or len(image['repository']) > 256
                or not _ECR_REPO.fullmatch(image['repository'])
                or not isinstance(image['digest'], str)
                or not _DIGEST.fullmatch(image['digest'])):
            raise AuditError('ECR must have explicit repository and SHA256 image digest')
        pair = (image['repository'], image['digest'])
        if pair in seen:
            raise AuditError('Duplicate ECR image target')
        seen.add(pair)
    for arn in targets['shield_resource_arns']:
        # Use exact ARN components, not a substring containing the account ID
        # inside a different account's arbitrary resource suffix.
        parts = arn.split(':', 5)
        if (len(parts) != 6 or parts[0:2] != ['arn', 'aws']
                or parts[4] != account or not parts[5]):
            raise AuditError('Shield resource ARN must match the approved account')
        service, resource_region = parts[2:4]
        if (service == 'cloudfront' and resource_region == ''
                and parts[5].startswith('distribution/')):
            continue
        if (service == 'elasticloadbalancing' and resource_region == region
                and parts[5].startswith('loadbalancer/')):
            continue
        if (service == 'ec2' and resource_region == region
                and parts[5].startswith('eip-allocation/')):
            continue
        raise AuditError('Shield resource type or ARN region is not allowlisted')
    for arn in targets['cloudtrail_trail_arns']:
        if not arn.startswith(f'arn:aws:cloudtrail:{region}:{account}:trail/') or len(arn) > 400:
            raise AuditError('CloudTrail ARNs must match the approved account/region')
    for arn in targets['cloudtrail_s3_bucket_arns']:
        if not re.fullmatch(r'arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', arn):
            raise AuditError('S3 target must be a bucket ARN, not an object or wildcard')
    if (bool(targets['cloudtrail_trail_arns'])
            != bool(targets['cloudtrail_s3_bucket_arns'])):
        raise AuditError('Trail and product S3 buckets must be provided together')
    if any(not _ENI.fullmatch(x) for x in targets['flow_log_eni_ids']):
        raise AuditError('ENI targets must be exact instance network-interface IDs')
    if any(not _EC2.fullmatch(x) for x in targets['inspector_ec2_instance_ids']):
        raise AuditError('Inspector targets must be exact EC2 instance IDs')
    if not (any(targets[x] for x in _LIST_KEYS) or images or targets['securityhub']):
        raise AuditError('An empty manifest cannot initiate a scoped read')
    return data


def _safe_attempt(ctx, service, region, operation, *, paged_field=None, **kwargs):
    ctx.guard_expiration()
    client = ctx.client_cached(service, region)
    try:
        if paged_field:
            return {'state': 'OBSERVED', 'data': paged(client, operation, paged_field, **kwargs)}
        return {'state': 'OBSERVED', 'data': api_call(client, operation, **kwargs)}
    except EvidenceUnavailable as exc:
        # Already sanitized by core.api_call and core.paged.
        return {'state': 'UNVERIFIED', 'error_code': str(exc)[:160]}


def _shield(ctx, region, resource_arns):
    """AWS Shield ListProtections permits exactly one ResourceArn per filter.

    Preserve the result of each explicitly selected resource independently:
    one bad API response must not turn other resources into false negatives.
    Subscription errors remain UNVERIFIED, never INACTIVE.
    """
    if not resource_arns:
        return {'state': 'NOT_REQUESTED'}
    sub = _safe_attempt(ctx, 'shield', 'us-east-1', 'describe_subscription')
    rows = []
    list_errors = []
    for arn in resource_arns:
        result = _safe_attempt(
            ctx, 'shield', 'us-east-1', 'list_protections',
            paged_field='Protections',
            InclusionFilters={'ResourceArns': [arn]},
        )
        if result['state'] != 'OBSERVED':
            code = result.get('error_code')
            list_errors.append(code)
            rows.append({
                'resource_arn': arn, 'protection_listed': None,
                'protection_id': None, 'list_state': 'UNVERIFIED',
                'error_code': code,
            })
            continue
        actual = next(
            (r for r in result['data'] if isinstance(r, dict)
             and r.get('ResourceArn') == arn), None,
        )
        rows.append({
            'resource_arn': arn,
            'protection_listed': actual is not None,
            'protection_id': actual.get('Id') if actual else None,
        })
    sub_verified = (
        sub['state'] == 'OBSERVED'
        and isinstance(sub['data'].get('Subscription'), dict)
    )
    errors = ([sub.get('error_code')] if sub['state'] == 'UNVERIFIED'
              else []) + list_errors
    return {
        'state': ('OBSERVED_PARTIAL' if sub_verified and not list_errors
                  else 'UNVERIFIED'),
        'subscription': sub['state'],
        'subscription_observed': sub_verified,
        'list': 'OBSERVED' if not list_errors else 'UNVERIFIED',
        'errors': errors,
        'resources': rows,
        'limitation': (
            'Per-resource ListProtections observations do not establish '
            'active subscription, complete ROS/organization coverage, or '
            'Owner-adopted compliance. An API error is never a negative finding.'
        ),
    }


def _trail(ctx, region, trails, bucket_arns):
    if not trails:
        return {'state': 'NOT_REQUESTED'}
    out = []
    for arn in trails:
        status = _safe_attempt(ctx, 'cloudtrail', region, 'get_trail_status', Name=arn)
        selectors = _safe_attempt(ctx, 'cloudtrail', region, 'get_event_selectors',
                                  TrailName=arn)
        row = {'trail_arn': arn, 'status_state': status['state'],
               'selectors_state': selectors['state'], 'bucket_matches': []}
        if status['state'] == 'OBSERVED':
            data = status['data']
            row['is_logging'] = data.get('IsLogging')
            row['s3_delivery_error_present'] = (
                bool(data['LatestDeliveryError'])
                if isinstance(data.get('LatestDeliveryError'), str) else None)
            row['latest_delivery_time_utc'] = _utc(data.get('LatestDeliveryTime'))
        else:
            row['status_error'] = status.get('error_code')
        if selectors['state'] == 'OBSERVED':
            data = selectors['data']
            basic = data.get('EventSelectors') or []
            advanced = data.get('AdvancedEventSelectors') or []
            for bucket in bucket_arns:
                object_prefix = bucket + '/'
                basic_maybe = any(
                    r.get('Type') == 'AWS::S3::Object'
                    and any(isinstance(v, str) and (
                        v == object_prefix or v.startswith(object_prefix)
                        or v == 'arn:aws:s3'  # Some legacy all-S3 selectors.
                    ) for v in r.get('Values', []))
                    for sel in basic for r in sel.get('DataResources', []))
                advanced_maybe = any(
                    field.get('Field') == 'resources.ARN'
                    and any(isinstance(v, str) and (
                        v == object_prefix or v.startswith(object_prefix)
                        or object_prefix.startswith(v)
                    ) for op in ('Equals', 'StartsWith')
                        for v in field.get(op, []))
                    for sel in advanced for field in sel.get('FieldSelectors', []))
                row['bucket_matches'].append({
                    'bucket_arn': bucket,
                    'basic_selector_maybe': basic_maybe,
                    'advanced_selector_maybe': advanced_maybe,
                    'effective_coverage': 'NOT_PROVEN',
                })
        else:
            row['selectors_error'] = selectors.get('error_code')
        out.append(row)
    return {'state': 'OBSERVED_PARTIAL', 'trails': out,
            'limitation': 'Predicate/selector approximation, omissions and org trails '
                          'prevent conclusive product-wide event coverage.'}


def _utc(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _flow(ctx, region, ids):
    if not ids:
        return {'state': 'NOT_REQUESTED'}
    result = _safe_attempt(ctx, 'ec2', region, 'describe_flow_logs',
                           paged_field='FlowLogs',
                           Filter=[{'Name': 'resource-id', 'Values': ids}])
    if result['state'] != 'OBSERVED':
        return result
    matches = {i: [] for i in ids}
    for row in result['data']:
        if not isinstance(row, dict) or row.get('ResourceId') not in matches:
            continue
        matches[row['ResourceId']].append({
            'flow_log_id': row.get('FlowLogId'),
            'status': row.get('FlowLogStatus'),
            'delivery_status': row.get('DeliverLogsStatus'),
            'destination_type': row.get('LogDestinationType'),
        })
    return {'state': 'OBSERVED_PARTIAL',
            'network_interfaces': [{
                'eni_id': i, 'flow_logs': matches[i],
                'effective_coverage': 'NOT_PROVEN',
            } for i in ids],
            'limitation': 'ENI observations do not prove end-to-end flow record delivery.'}


def _securityhub(ctx, region, requested):
    if not requested:
        return {'state': 'NOT_REQUESTED'}
    hub = _safe_attempt(ctx, 'securityhub', region, 'describe_hub')
    if hub['state'] != 'OBSERVED':
        return {'state': 'UNVERIFIED', 'operation': 'describe_hub',
                'error_code': hub.get('error_code'),
                'error_cause': 'NOT_PROVEN'}
    standards = _safe_attempt(ctx, 'securityhub', region, 'get_enabled_standards',
                              paged_field='StandardsSubscriptions')
    if standards['state'] != 'OBSERVED':
        return {'state': 'OBSERVED_PARTIAL', 'hub_observed': True,
                'standards_state': 'UNVERIFIED',
                'standards_error_code': standards.get('error_code')}
    return {'state': 'OBSERVED_PARTIAL', 'hub_observed': True,
            'standards_state': 'OBSERVED',
            'standards': [{'arn': x.get('StandardsArn'), 'status': x.get('StandardsStatus')}
                          for x in standards['data'] if isinstance(x, dict)],
            'checks_coverage': 'NOT_PROVEN'}


def _inspector(ctx, region, ids):
    if not ids:
        return {'state': 'NOT_REQUESTED'}
    out = []
    for ident in ids:
        result = _safe_attempt(ctx, 'inspector2', region, 'list_coverage',
                               paged_field='coveredResources',
                               filterCriteria={'resourceId': [{
                                   'comparison': 'EQUALS', 'value': ident}]})
        row = {'instance_id': ident, 'state': result['state'],
               'scan_coverage': 'NOT_PROVEN'}
        if result['state'] == 'OBSERVED':
            # Coverage is a status, not a vulnerability report.
            row['resources'] = [{
                'resource_id': r.get('resourceId'),
                'scan_status_code': (r.get('scanStatus') or {}).get('statusCode'),
                'scan_status_reason': (r.get('scanStatus') or {}).get('reason'),
                'scan_type': r.get('scanType'),
                'last_scanned_at_utc': _utc(r.get('lastScannedAt')),
            } for r in result['data'] if r.get('resourceId') == ident]
        else:
            row['error_code'] = result.get('error_code')
        out.append(row)
    return {'state': 'OBSERVED_PARTIAL', 'instances': out,
            'limitation': 'Inspector coverage alone does not prove dated findings/remediation.'}


def _ecr(ctx, region, items):
    if not items:
        return {'state': 'NOT_REQUESTED'}
    out = []
    for image in items:
        result = _safe_attempt(ctx, 'ecr', region, 'describe_images',
                               repositoryName=image['repository'],
                               imageIds=[{'imageDigest': image['digest']}])
        row = {'repository': image['repository'], 'digest': image['digest'],
               'state': result['state'], 'findings': 'NOT_PROVEN'}
        if result['state'] == 'OBSERVED':
            row['images'] = [{
                'digest': d.get('imageDigest'),
                'scan_status': (d.get('imageScanStatus') or {}).get('status'),
                'scan_description_present': bool(
                    (d.get('imageScanStatus') or {}).get('description')),
                'finding_severity_counts': (
                    (d.get('imageScanFindingsSummary') or {}).get('findingSeverityCounts') or {}),
                'scan_completed_at_utc': _utc(
                    (d.get('imageScanFindingsSummary') or {}).get('imageScanCompletedAt')),
            } for d in result['data'].get('imageDetails', []) if
                d.get('imageDigest') == image['digest']]
        else:
            row['error_code'] = result.get('error_code')
        out.append(row)
    return {'state': 'OBSERVED_PARTIAL', 'images': out,
            'limitation': 'ECR image summary alone does not establish all Inspector findings.'}


def collect_r24(ctx, manifest: dict) -> dict:
    """Local operator-only entrypoint; no AWS operation before manifest validation."""
    manifest = validate_manifest(manifest)
    if ctx.account != manifest['account'] or ctx.region != manifest['region']:
        raise AuditError('STS role account/region differ from frozen target manifest')
    targets = manifest['targets']
    return {
        'schema': 'aws-ros-r24-targeted-evidence-v1',
        'control_classifications_changed': False,
        'owner_classification_adopted': False,
        'owner_scope_approval_independently_verified': False,
        'effective_no_write': 'NOT_PROVEN',
        'product': 'ros',
        'account': manifest['account'],
        'region': manifest['region'],
        'scope_confirmation_as_supplied': manifest['scope_confirmation'],
        'control_8_shield': _shield(ctx, manifest['region'],
                                    targets['shield_resource_arns']),
        'control_24_cloudtrail': _trail(
            ctx, manifest['region'], targets['cloudtrail_trail_arns'],
            targets['cloudtrail_s3_bucket_arns']),
        'control_27_flow_logs': _flow(ctx, manifest['region'],
                                      targets['flow_log_eni_ids']),
        'control_33_securityhub': _securityhub(
            ctx, manifest['region'], targets['securityhub']),
        'control_39_inspector': _inspector(
            ctx, manifest['region'], targets['inspector_ec2_instance_ids']),
        'control_39_ecr': _ecr(ctx, manifest['region'], targets['ecr_images']),
        'control_40_ci': {
            'state': 'NON_AWS_EXPORT_REQUIRED',
            'autonomous_aws_lookup': False,
        },
        'limitations': [
            'Standalone read-only observations only; source bundle and business labels unchanged.',
            'No source-to-runtime independent attestation or formal Owner acceptance.',
            'No proof of product completeness, approved all-regions scope or effective no-write.',
            'API denial or missing data is not proof of service disabled.',
        ],
    }
