"""Read-only shared/account-level security configuration evidence.

These settings MAY protect product resources but product inheritance is unproven.
They never become product-owned resources and never determine product PASS/FAIL.
No secrets, detailed event records, arbitrary error messages or write APIs are persisted.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .core import EvidenceUnavailable, api_call, paged


def _error(errors, region, service, operation, exc, resource=None):
    data = {'region': region, 'service': service, 'operation': operation,
            'reason': str(exc)[:180]}
    if resource is not None:
        data['resource'] = resource
    errors.append(data)


def _guard(ctx):
    if hasattr(ctx, 'guard_expiration'):
        ctx.guard_expiration()


def _call(ctx, client, operation, **kwargs):
    _guard(ctx)
    return api_call(client, operation, **kwargs)


def _paged(ctx, client, operation, field, **kwargs):
    _guard(ctx)
    return paged(client, operation, field, **kwargs)


def _string_time(value):
    """Return a verified UTC timestamp, not an unconverted local-time offset."""
    try:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if isinstance(value, datetime) and value.tzinfo is not None:
            return value.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None
    return None


def _known_delivery_error(status, field):
    """An omitted optional AWS error field is UNKNOWN, not a confirmed no-error."""
    value = status.get(field)
    return bool(value) if isinstance(value, str) else None


def _trail_selector_summary(response):
    """Selector descriptors only, not captured CloudTrail events."""
    basic = response.get('EventSelectors') or []
    advanced = response.get('AdvancedEventSelectors') or []
    return {
        'basic_selector_count': len(basic),
        'basic_management_event_enabled': any(
            x.get('IncludeManagementEvents') is True for x in basic),
        'basic_data_event_types': sorted({
            resource['Type'] for item in basic
            for resource in item.get('DataResources', [])
            if isinstance(resource.get('Type'), str)
        }),
        'advanced_selector_count': len(advanced),
        'advanced_event_categories': sorted({
            v for item in advanced for selector in item.get('FieldSelectors', [])
            if selector.get('Field') == 'eventCategory'
            for v in selector.get('Equals', []) if isinstance(v, str)
        }),
        'advanced_fields': sorted({
            selector['Field'] for item in advanced
            for selector in item.get('FieldSelectors', [])
            if isinstance(selector.get('Field'), str)
        }),
        'coverage_note': 'Selector summaries do not prove inclusion of any particular product resource.',
    }


def _cloudtrail(ctx, region, errors):
    result = {'region': region, 'service': 'cloudtrail',
              'state': 'UNVERIFIED', 'trails': []}
    client = ctx.client_cached('cloudtrail', region)
    try:
        response = _call(ctx, client, 'describe_trails', includeShadowTrails=True)
        trails = response.get('trailList')
        if not isinstance(trails, list):
            raise EvidenceUnavailable('cloudtrail.describe_trails: trailList unavailable')
    except EvidenceUnavailable as exc:
        _error(errors, region, 'cloudtrail', 'describe_trails', exc)
        return result
    result['state'] = 'LIST_VERIFIED'
    for trail in trails:
        arn = trail.get('TrailARN')
        if not arn:
            _error(errors, region, 'cloudtrail', 'describe_trails',
                   EvidenceUnavailable('trail identifier absent'))
            continue
        item = {
            'trail_arn': arn,
            'name': trail.get('Name'),
            'home_region': trail.get('HomeRegion'),
            'multi_region': trail.get('IsMultiRegionTrail'),
            'organization': trail.get('IsOrganizationTrail'),
            'log_file_validation_enabled': trail.get('LogFileValidationEnabled'),
            'log_status': 'UNVERIFIED',
            'selector_status': 'UNVERIFIED',
        }
        try:
            status = _call(ctx, client, 'get_trail_status', Name=arn)
            item.update({
                'log_status': 'VERIFIED',
                'is_logging': status.get('IsLogging'),
                'latest_delivery_time_utc': _string_time(status.get('LatestDeliveryTime')),
                'has_s3_delivery_error': _known_delivery_error(status, 'LatestDeliveryError'),
                'has_cloudwatch_delivery_error': _known_delivery_error(
                    status, 'LatestCloudWatchLogsDeliveryError'),
                'has_digest_delivery_error': _known_delivery_error(
                    status, 'LatestDigestDeliveryError'),
            })
        except EvidenceUnavailable as exc:
            _error(errors, region, 'cloudtrail', 'get_trail_status', exc, arn)
        try:
            selectors = _call(ctx, client, 'get_event_selectors', TrailName=arn)
            item['selectors'] = _trail_selector_summary(selectors)
            item['selector_status'] = 'VERIFIED'
        except EvidenceUnavailable as exc:
            _error(errors, region, 'cloudtrail', 'get_event_selectors', exc, arn)
        result['trails'].append(item)
    return result


def _guardduty(ctx, region, errors):
    result = {'region': region, 'service': 'guardduty',
              'state': 'UNVERIFIED', 'detectors': []}
    client = ctx.client_cached('guardduty', region)
    try:
        identifiers = _paged(ctx, client, 'list_detectors', 'DetectorIds')
    except EvidenceUnavailable as exc:
        _error(errors, region, 'guardduty', 'list_detectors', exc)
        return result
    result['state'] = 'LIST_VERIFIED'
    for identifier in identifiers:
        item = {'detector_id': identifier, 'status': 'UNVERIFIED'}
        try:
            detail = _call(ctx, client, 'get_detector', DetectorId=identifier)
            item.update({
                'status': detail.get('Status', 'UNKNOWN'),
                'finding_publishing_frequency': detail.get('FindingPublishingFrequency'),
                'features': [
                    {'name': feature.get('Name'), 'status': feature.get('Status')}
                    for feature in detail.get('Features', [])
                ],
            })
        except EvidenceUnavailable as exc:
            _error(errors, region, 'guardduty', 'get_detector', exc, identifier)
        result['detectors'].append(item)
    return result


def _securityhub(ctx, region, errors):
    result = {'region': region, 'service': 'securityhub',
              'state': 'UNVERIFIED', 'standards': []}
    client = ctx.client_cached('securityhub', region)
    try:
        hub = _call(ctx, client, 'describe_hub')
        arn = hub.get('HubArn')
        if not arn:
            raise EvidenceUnavailable('securityhub.describe_hub: missing HubArn')
        result['state'] = 'HUB_OBSERVED'
        result['hub_arn'] = arn
    except EvidenceUnavailable as exc:
        _error(errors, region, 'securityhub', 'describe_hub', exc)
        return result
    try:
        standards = _paged(ctx, client, 'get_enabled_standards', 'StandardsSubscriptions')
        result['standards_state'] = 'LIST_VERIFIED'
        for standard in standards:
            result['standards'].append({
                'standard_arn': standard.get('StandardsArn'),
                'subscription_arn': standard.get('StandardsSubscriptionArn'),
                'status': standard.get('StandardsStatus'),
            })
    except EvidenceUnavailable as exc:
        result['standards_state'] = 'UNVERIFIED'
        _error(errors, region, 'securityhub', 'get_enabled_standards', exc)
    return result


def collect_shared_security_evidence(ctx, regions, errors):
    """Account/regional observations kept separate from product attribution."""
    output = {
        'schema': 'aws-shared-security-evidence-v1',
        'attribution': 'SHARED_UNATTRIBUTED',
        'product_protection_proven': False,
        'regions': [],
        'limitations': [
            'Shared account/regional settings are NOT attributable to a product without explicit control mapping.',
            'CloudTrail trails do not include CloudTrail Lake event data stores or external org evidence.',
            'Trail selectors and status describe control configuration, not end-to-end log delivery completeness.',
            'A missing GuardDuty detector or Security Hub hub observed in one region is not a global absence claim.',
            'Only requested regions are probed; delegated administrator and aggregation boundaries are not resolved.',
            'API errors, including AccessDenied and unsupported-region errors, remain UNKNOWN and appear in collection_errors.',
        ],
    }
    for region in regions:
        output['regions'].append({
            'region': region,
            'cloudtrail': _cloudtrail(ctx, region, errors),
            'guardduty': _guardduty(ctx, region, errors),
            'securityhub': _securityhub(ctx, region, errors),
        })
    return output
