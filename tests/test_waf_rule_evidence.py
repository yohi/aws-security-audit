"""Issue #8 R9 WAF-only bounded evidence tests; no AWS connectivity."""
from aws_security_audit.core import EvidenceUnavailable
from aws_security_audit.resource_scope import (
    _add_elb, _record, attribute_resources, collect_resource_inventory,
)
from aws_security_audit.control_observations import (
    build_product_observations, CONTEXT_ONLY, PROPERTY_UNKNOWN,
)
from aws_security_audit.waf_rule_evidence import web_acl_rule_summary

REGION = 'ap-northeast-1'
ARN = ('arn:aws:wafv2:us-east-1:123456789012:global/webacl/'
       'shared-web-acl/12345678-1234-1234-1234-123456789012')
ALB_DNS = 'ros-api-12345.ap-northeast-1.elb.amazonaws.com'


class Ctx:
    def __init__(self):
        self.guards = 0
        self.clients = []

    def guard_expiration(self):
        self.guards += 1

    def client_cached(self, service, region):
        self.clients.append((service, region))
        return (service, region)


def _web_acl():
    return {
        'ARN': ARN,
        'Name': 'SENSITIVE-NAME',
        'DefaultAction': {'Allow': {'CustomRequestHandling': {
            'InsertHeaders': [{'Name': 'X-Password', 'Value': 'SENSITIVE'}]}}},
        'Rules': [
            {'Name': 'secret-rule', 'Statement': {
                'ManagedRuleGroupStatement': {
                    'VendorName': 'AWS', 'Name': 'AWSManagedRulesCommonRuleSet',
                    'ScopeDownStatement': {'ByteMatchStatement': {
                        'SearchString': b'SENSITIVE-PAYLOAD'}}},
             'OverrideAction': {'None': {}}},
            {'Name': 'sql-injection-path', 'Statement': {
                'SqliMatchStatement': {'FieldToMatch': {'UriPath': {}},
                                       'TextTransformations': []}},
             'Action': {'Count': {}}},
        ],
        'CustomResponseBodies': {'any': {'Content': 'SENSITIVE-BODY'}},
        'TokenDomains': ['internal-private.example.com'],
    }


def test_waf_summary_is_bounded_and_never_emits_raw_rule_fields():
    result = web_acl_rule_summary(_web_acl())
    assert result['state'] == 'VERIFIED_SUMMARY'
    assert result['rule_count'] == 2
    assert result['default_action'] == 'Allow'
    assert result['statement_type_counts'] == {
        'ManagedRuleGroupStatement': 1, 'SqliMatchStatement': 1}
    assert result['explicit_rule_action_counts'] == {'Count': 1}
    assert result['rule_override_counts'] == {'None': 1}
    assert 'SENSITIVE' not in str(result)
    assert 'secret-rule' not in str(result)
    assert 'sql-injection-path' not in str(result)
    assert 'AWSManagedRulesCommonRuleSet' not in str(result)
    assert 'internal-private.example.com' not in str(result)


def test_incomplete_rule_list_or_unknown_statement_cannot_be_verified():
    assert web_acl_rule_summary(None)['state'] == 'UNVERIFIED_WEB_ACL'
    assert web_acl_rule_summary({'DefaultAction': {'Allow': {}}})['state'] == (
        'UNVERIFIED_RULE_LIST')
    assert web_acl_rule_summary({'DefaultAction': {}, 'Rules': []})['state'] == (
        'UNVERIFIED_DEFAULT_ACTION')
    result = web_acl_rule_summary({
        'DefaultAction': {'Block': {}},
        'Rules': [{'Statement': {'FutureStatement': {'Private': 'SENSITIVE'}}}],
    })
    assert result['state'] == 'PARTIAL_RULE_SUMMARY'
    assert result['unclassified_rule_count'] == 1
    assert 'SENSITIVE' not in str(result)


def _linked_cloudfront(identifier, acl=ARN, domain=ALB_DNS, tags=None):
    return _record('cloudfront', 'distribution', 'global', identifier,
                   arn=f'arn:aws:cloudfront::123456789012:distribution/{identifier}',
                   tags=tags or [], web_acl_id=acl, origin_domains=[domain],
                   enabled=True)


def _alb():
    return _record('elbv2', 'application', REGION, 'ros-alb',
                   tags=[{'Key': 'Product', 'Value': 'ros'}],
                   dns_name=ALB_DNS, waf_web_acl_arn=None)


def _prepare_collection(monkeypatch, resource_factory):
    import aws_security_audit.resource_scope as mod

    def ec2(ctx, region, output, errors):
        output.extend(resource_factory())

    monkeypatch.setattr(mod, '_add_ec2', ec2)
    for name in ('_add_rds', '_add_elb', '_add_logs', '_add_s3', '_add_iam',
                 '_add_cloudfront'):
        monkeypatch.setattr(mod, name, lambda *args: None)
    monkeypatch.setattr(
        'aws_security_audit.shared_security_evidence.collect_shared_security_evidence',
        lambda *args: {'attribution': 'SHARED_UNATTRIBUTED', 'regions': []})
    return mod


def test_web_acl_read_only_selected_cloudfront_not_29_unrelated(monkeypatch):
    resources = [
        _alb(),
        _linked_cloudfront('linked-distribution'),
        _linked_cloudfront('unrelated-1', domain='unrelated.example.com'),
        _linked_cloudfront('unrelated-2', domain='unrelated-2.example.com'),
    ]
    mod = _prepare_collection(monkeypatch, lambda: resources)
    calls = []

    def api(client, operation, **kwargs):
        calls.append((client, operation, kwargs))
        assert client == ('wafv2', 'us-east-1')
        assert operation == 'get_web_acl'
        assert kwargs == {'ARN': ARN, 'Scope': 'CLOUDFRONT'}
        return {'WebACL': _web_acl()}

    monkeypatch.setattr(mod, 'api_call', api)
    ctx = Ctx()
    inventory = collect_resource_inventory(ctx, [REGION], 'ros')
    assert len(calls) == 1
    assert inventory['scope']['matched'] == 2
    assert inventory['scope']['cloudfront_origin_linkage']['unassigned'] == 2
    linked = next(r for r in inventory['resources']
                  if r['resource_type'] == 'distribution')
    assert linked['attribution'] == 'RELATED'
    assert linked['attributes']['waf_rule_summary']['rule_count'] == 2
    assert linked['attributes']['waf_rule_lookup'] == 'VERIFIED_SUMMARY'
    assert ctx.guards >= 1
    assert 'SENSITIVE' not in str(inventory)
    obs = build_product_observations(inventory, [REGION])
    assert any(r['property'] == 'CloudFront WAF rule configuration summary'
               and r['property_result'] == CONTEXT_ONLY
               for r in obs['rows'])
    assert obs['by_control']['6']['ok'] == obs['by_control']['6']['fail'] == 0


def test_waf_read_failure_remains_unknown_and_records_error(monkeypatch):
    mod = _prepare_collection(monkeypatch, lambda: [_alb(), _linked_cloudfront('linked')])

    def denied(*args, **kwargs):
        raise EvidenceUnavailable('AccessDeniedException')
    monkeypatch.setattr(mod, 'api_call', denied)
    inventory = collect_resource_inventory(Ctx(), [REGION], 'ros')
    linked = next(r for r in inventory['resources']
                  if r['resource_type'] == 'distribution')
    assert linked['attributes']['waf_rule_lookup'] == 'UNVERIFIED_READ_ERROR'
    assert 'waf_rule_summary' not in linked['attributes']
    assert any(e.get('operation') == 'get_web_acl' for e in inventory['collection_errors'])
    obs = build_product_observations(inventory, [REGION])
    assert any(row['property_result'] == PROPERTY_UNKNOWN for row in obs['rows']
               if row['property'] == 'CloudFront WAF rule configuration summary')
    assert obs['by_control']['6']['fail'] == 0


def test_unsupported_webacl_ids_and_absence_never_trigger_reads(monkeypatch):
    resources = [_linked_cloudfront('classic', acl='4cdbeabc-cfbc-11e5-acab-004cdbeabcde',
                                    tags=[{'Key': 'Product', 'Value': 'ros'}]),
                 _linked_cloudfront('blank', acl='',
                                    tags=[{'Key': 'Product', 'Value': 'ros'}]),
                 _linked_cloudfront('unreadable', acl=None,
                                    tags=[{'Key': 'Product', 'Value': 'ros'}])]
    mod = _prepare_collection(monkeypatch, lambda: resources)
    monkeypatch.setattr(mod, 'api_call', lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError('unexpected WAF API call')))
    inv = collect_resource_inventory(Ctx(), [REGION], 'ros')
    statuses = {r['resource_id']: r['attributes']['waf_rule_lookup']
                for r in inv['resources']}
    assert statuses == {
        'classic': 'UNSUPPORTED_WEB_ACL_IDENTIFIER',
        'blank': 'NOT_ASSOCIATED',
        'unreadable': 'UNVERIFIED_ASSOCIATION',
    }
    obs = build_product_observations(inv, [REGION])
    assert obs['by_control']['6']['fail'] == 0
    assert obs['by_control']['6']['ok'] == 0


def test_account_inventory_does_not_query_cloudfront_waf(monkeypatch):
    mod = _prepare_collection(monkeypatch, lambda: [_linked_cloudfront('unselected')])
    monkeypatch.setattr(mod, 'api_call', lambda *a, **kw: (_ for _ in ()).throw(
        AssertionError('account inventory must not read new WAF APIs')))
    inv = collect_resource_inventory(Ctx(), [REGION], None)
    assert 'waf_rule_lookup' not in inv['resources'][0]['attributes']
    assert 'shared_control_evidence' not in inv
    assert 'cloudfront_origin_linkage' not in inv['scope']


def test_alb_existing_waf_response_is_summarized_without_extra_api(monkeypatch):
    import aws_security_audit.resource_scope as mod

    class LocalCtx:
        def client_cached(self, service, region):
            return service
    operations = []

    def fake_paged(client, operation, field, **kwargs):
        operations.append(operation)
        if operation == 'describe_load_balancers':
            return [{'LoadBalancerArn': 'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/ros/1',
                     'LoadBalancerName': 'ros-alb', 'Type': 'application',
                     'DNSName': ALB_DNS}]
        if operation == 'describe_listeners':
            return []
        raise AssertionError(operation)

    def fake_api(client, operation, **kwargs):
        operations.append(operation)
        if operation == 'describe_tags':
            return {'TagDescriptions': []}
        if operation == 'describe_load_balancer_attributes':
            return {'Attributes': []}
        if operation == 'get_web_acl_for_resource':
            return {'WebACL': _web_acl()}
        raise AssertionError(operation)

    monkeypatch.setattr(mod, 'paged', fake_paged)
    monkeypatch.setattr(mod, 'api_call', fake_api)
    records, errors = [], []
    _add_elb(LocalCtx(), REGION, records, errors)
    assert errors == []
    assert operations.count('get_web_acl_for_resource') == 1
    assert len(records) == 1
    assert records[0]['attributes']['waf_web_acl_lookup'] == 'API_VERIFIED'
    assert records[0]['attributes']['waf_rule_summary']['rule_count'] == 2
    assert 'SENSITIVE' not in str(records[0])


def test_rule_count_is_never_promoted_to_product_pass():
    res = _record(
        'elbv2', 'application', REGION, 'ros-alb',
        tags=[{'Key': 'Product', 'Value': 'ros'}],
        waf_web_acl_arn=ARN, waf_web_acl_lookup='API_VERIFIED',
        waf_rule_summary=web_acl_rule_summary(_web_acl()),
    )
    inventory, _ = attribute_resources([res], 'ros')
    obs = build_product_observations({'resources': inventory}, [REGION])
    assert obs['by_control']['6']['context'] >= 1
    assert obs['by_control']['6']['ok'] == obs['by_control']['6']['fail'] == 0
