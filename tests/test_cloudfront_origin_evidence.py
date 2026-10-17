"""Issue #8 CloudFront/ALB/WAF attribution read-only regression tests."""
from aws_security_audit.control_observations import build_product_observations, CONTEXT_ONLY, PROPERTY_UNKNOWN
from aws_security_audit.resource_scope import (
    _add_cloudfront, _cloudfront_summary_attributes, _dns_hostname,
    _record, attribute_resources, product_findings,
)


REGION = 'ap-northeast-1'
ALB = 'ros-api-123456.ap-northeast-1.elb.amazonaws.com'
ARN = 'arn:aws:cloudfront::123456789012:distribution/EFG1'


def alb(name='ros-api', dns=ALB):
    return _record(
        'elbv2', 'application', REGION, name,
        tags=[{'Key': 'Product', 'Value': 'ros'}],
        dns_name=dns, waf_web_acl_arn=None, listeners=[],
    )


def cloudfront(identifier='EFG1', origins=None, waf=None, tags=None, **overrides):
    attrs = {
        'origin_domains': origins if origins is not None else [ALB],
        'web_acl_id': waf,
        'enabled': True,
        'geo_restriction_type': 'none',
        'geo_restriction_location_count': 0,
        'viewer_minimum_protocol_version': 'TLSv1.2_2021',
        'web_acl_metadata_source': 'cloudfront.list_distributions',
    }
    attrs.update(overrides)
    return _record('cloudfront', 'distribution', 'global', identifier,
                   arn=ARN, tags=tags or [], **attrs)


def test_exact_alb_origin_selects_untagged_cloudfront_without_claiming_ownership():
    selected, scope = attribute_resources([
        alb(), cloudfront(origins=[ALB]), cloudfront('not-related', ['elsewhere.example.net']),
    ], 'ros')
    assert scope['matched'] == 2
    assert scope['direct'] == 1
    assert scope['related'] == 1
    assert scope['unassigned'] == 1
    dist = next(r for r in selected if r['resource_type'] == 'distribution')
    assert dist['attribution'] == 'RELATED'
    assert 'may be shared' in dist['attribution_evidence']
    assert dist['attributes']['web_acl_id'] is None


def test_origin_match_is_casefold_exact_not_subdomain_prefix_or_url():
    assert _dns_hostname(ALB.upper() + '.') == ALB
    for invalid in (
        None, '', 'https://' + ALB, 'user@' + ALB,
        ALB + '/admin', 'evil.' + ALB, ALB + ':443', '*.elb.amazonaws.com',
        'api.ros-alb.elb.amazonaws.com/https',
    ):
        assert _dns_hostname(invalid) is None or _dns_hostname(invalid) != ALB
    selected, scope = attribute_resources([
        alb(), cloudfront('near-match', ['evil.' + ALB]),
        cloudfront('different-alb', [ALB + '-fake']),
    ], 'ros')
    assert len(selected) == 1
    assert scope['unassigned'] == 2


def test_direct_cloudfront_remains_direct_and_other_project_alb_not_inferred():
    selected, scope = attribute_resources([
        _record('elbv2', 'application', REGION, 'other-product-alb',
                tags=[{'Key': 'Product', 'Value': 'other'}],
                dns_name='other.elb.amazonaws.com'),
        cloudfront(tags=[{'Key': 'Product', 'Value': 'ros'}],
                   origins=['other.elb.amazonaws.com']),
    ], 'ros')
    assert {r['resource_type'] for r in selected} == {'distribution'}
    assert selected[0]['attribution'] == 'DIRECT'
    assert scope['direct'] == 1


def test_cloudfront_summary_allowlist_omits_custom_headers_and_waf_rules():
    raw = {
        'Origins': {'Quantity': 2, 'Items': [
            {'Id': 'origin1', 'DomainName': ALB,
             'CustomHeaders': {'Items': [{'HeaderName': 'X-Key', 'HeaderValue': 'SENSITIVE'}]}},
            {'Id': 'origin2', 'DomainName': ALB.upper() + '.'},
        ]},
        'WebACLId': 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/sample/abc',
        'Restrictions': {'GeoRestriction': {
            'RestrictionType': 'blacklist', 'Quantity': 2, 'Items': ['CN', 'RU'],
        }},
        'ViewerCertificate': {'MinimumProtocolVersion': 'TLSv1.2_2021',
                              'ACMCertificateArn': 'SENSITIVE-NOT-NEEDED'},
        'Status': 'Deployed', 'Comment': 'SENSITIVE-DESCRIPTION',
    }
    config = _cloudfront_summary_attributes(raw)
    assert config['origin_domains'] == [ALB]
    assert config['geo_restriction_type'] == 'blacklist'
    assert config['geo_restriction_location_count'] == 2
    assert config['web_acl_id'].startswith('arn:aws:wafv2:')
    assert config['viewer_minimum_protocol_version'] == 'TLSv1.2_2021'
    assert 'SENSITIVE' not in str(config)
    assert 'CN' not in str(config)
    assert 'RU' not in str(config)


def test_cloudfront_page_collection_reads_summary_without_extra_cloudfront_calls(monkeypatch):
    import aws_security_audit.resource_scope as scope
    class Ctx:
        def client_cached(self, service, region):
            assert (service, region) == ('cloudfront', 'us-east-1')
            return 'client'
    operations = []
    def fake_api(client, operation, **kwargs):
        operations.append((operation, kwargs))
        if operation == 'list_distributions':
            if not kwargs:
                return {'DistributionList': {
                    'IsTruncated': True, 'NextMarker': 'page-2',
                    'Items': [{
                        'Id': 'EFG1', 'ARN': ARN, 'Status': 'Deployed',
                        'DomainName': 'd111.cloudfront.net', 'Enabled': True,
                        'Origins': {'Items': [{'DomainName': ALB}]},
                        'WebACLId': 'arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/a',
                        'Restrictions': {'GeoRestriction': {'RestrictionType': 'none', 'Quantity': 0}},
                        'ViewerCertificate': {'MinimumProtocolVersion': 'TLSv1.2_2021'},
                    }],
                }}
            assert kwargs == {'Marker': 'page-2'}
            return {'DistributionList': {'IsTruncated': False, 'Items': []}}
        if operation == 'list_tags_for_resource':
            assert kwargs == {'Resource': ARN}
            return {'Tags': {'Items': []}}
        raise AssertionError(operation)
    monkeypatch.setattr(scope, 'api_call', fake_api)
    output, errors = [], []
    _add_cloudfront(Ctx(), output, errors)
    assert not errors
    assert len(output) == 1
    assert output[0]['attributes']['origin_domains'] == [ALB]
    assert output[0]['attributes']['web_acl_id'].startswith('arn:aws:wafv2:')
    assert [x[0] for x in operations] == [
        'list_distributions', 'list_tags_for_resource', 'list_distributions',
    ]


def test_cloudfront_related_waf_is_context_only_not_product_pass_fail():
    resources, _ = attribute_resources([
        alb(),
        cloudfront(waf='arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/a'),
    ], 'ros')
    obs = build_product_observations(
        {'resources': resources, 'collection_errors': []}, [REGION])
    assert obs['by_control']['6']['context'] == 2  # ALB direct, CloudFront related
    assert obs['by_control']['7']['context'] == 1
    assert obs['by_control']['16']['context'] == 1
    assert obs['by_control']['6']['ok'] == obs['by_control']['6']['fail'] == 0
    assert any(r['property'] == 'CloudFront configured Web ACL association'
               and r['attribution'] == 'RELATED' and r['property_result'] == CONTEXT_ONLY
               for r in obs['rows'])
    controls = {f.number: f for f in product_findings(
        {'resources': resources}, [REGION])}
    assert controls[6].status == 'MANUAL_REVIEW'
    assert controls[7].status == 'MANUAL_REVIEW'
    assert controls[16].status == 'MANUAL_REVIEW'


def test_unverified_cloudfront_web_acl_does_not_become_confirmed_missing():
    resources, _ = attribute_resources([
        cloudfront(tags=[{'Key': 'Product', 'Value': 'ros'}], waf=None,
                   geo_restriction_type=None, viewer_minimum_protocol_version=None)
    ], 'ros')
    obs = build_product_observations({'resources': resources}, [REGION])
    for number in (6, 7, 16):
        assert obs['by_control'][str(number)]['unknown'] == 1
        assert obs['by_control'][str(number)]['fail'] == 0
        assert obs['by_control'][str(number)]['ok'] == 0


def test_empty_cloudfront_waf_explicitly_no_cf_association_but_not_end_to_end_fail():
    resources, _ = attribute_resources([
        alb(), cloudfront(waf=''),
    ], 'ros')
    obs = build_product_observations({'resources': resources}, [REGION])
    lines = [r for r in obs['rows'] if r['number'] == 6
             and r['resource_type'] == 'distribution']
    assert len(lines) == 1
    assert lines[0]['observed_value']['web_acl_id'] == ''
    assert lines[0]['property_result'] == CONTEXT_ONLY
    assert {f.number: f for f in product_findings(
        {'resources': resources}, [REGION])}[6].status == 'MANUAL_REVIEW'
