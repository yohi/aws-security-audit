"""Offline tests for report resource identity and conservative product-scoped analysis."""
from __future__ import annotations

import csv
import json
from io import StringIO
from zipfile import ZipFile
from xml.etree import ElementTree as ET

from aws_security_audit.catalog import CHECKS
from aws_security_audit.cli import parser
from aws_security_audit.core import Finding
from aws_security_audit.report import export_report
from aws_security_audit.resource_scope import (
    _record, attribute_resources, identity_tags, product_findings,
    save_resource_inventory,
)
from aws_security_audit.web_handoff import build_web_review_bundle


def test_product_matching_is_prefix_bounded_and_tags_are_allowlisted():
    assert identity_tags([{'Key': 'Name', 'Value': 'scs2-prd-api'},
                          {'Key': 'SECRET_TOKEN', 'Value': 'never-persist'}]) == {
                              'Name': 'scs2-prd-api',
                          }
    resources = [
        _record('ec2', 'instance', 'ap-northeast-1', 'i-1',
                tags=[{'Key': 'Name', 'Value': 'scs2-prd-api'}]),
        _record('ec2', 'instance', 'ap-northeast-1', 'i-2',
                tags=[{'Key': 'Name', 'Value': 'scs20-prd-api'}]),
        _record('s3', 'bucket', 'global', 'media-content',
                tags=[{'Key': 'Project', 'Value': 'scs2'}]),
    ]
    selected, scope = attribute_resources(resources, product='scs2')
    assert {r['resource_id'] for r in selected} == {'i-1', 'media-content'}
    assert scope['unassigned'] == 1
    assert scope['attribution_complete'] is False


def test_exact_product_tag_only_matches_approved_tag():
    resources = [
        _record('rds', 'db-instance', 'ap-northeast-1', 'prod-db',
                tags=[{'Key': 'Project', 'Value': 'scs2'}]),
        _record('rds', 'db-instance', 'ap-northeast-1', 'scs2-test',
                tags=[{'Key': 'Project', 'Value': 'other'}]),
    ]
    selected, scope = attribute_resources(resources, 'scs2', 'Project=scs2')
    assert [r['resource_id'] for r in selected] == ['prod-db']
    assert selected[0]['attribution_evidence'] == 'TAG:Project=scs2'
    assert scope['unassigned'] == 1


def test_related_sg_and_ebs_can_be_shared_and_remain_explicit():
    region = 'ap-northeast-1'
    items = [
        _record('ec2', 'instance', region, 'i-scs2', tags=[{
            'Key': 'Name', 'Value': 'scs2-prd-api',
        }], security_group_ids=['sg-shared']),
        _record('ec2', 'security-group', region, 'sg-shared', dangerous_ingress=1),
        _record('ec2', 'ebs-volume', region, 'vol-123', attached_instance_ids=['i-scs2'],
                encrypted=False),
        _record('ec2', 'security-group', region, 'sg-other', dangerous_ingress=1),
    ]
    selected, scope = attribute_resources(items, 'scs2')
    assert {r['resource_id'] for r in selected} == {'i-scs2', 'sg-shared', 'vol-123'}
    assert scope['direct'] == 1
    assert scope['related'] == 2
    assert scope['unassigned'] == 1
    assert 'may be shared' in selected[1]['attribution_evidence']


def test_product_controls_never_inherit_account_pass_and_flag_observed_failures():
    region = 'ap-northeast-1'
    inventory = {'resources': [
        _record('ec2', 'instance', region, 'i-sc', name='scs2-api'),
        _record('ec2', 'security-group', region, 'sg-sc', dangerous_ingress=2),
        _record('ec2', 'ebs-volume', region, 'vol-sc', encrypted=False),
        _record('rds', 'db-instance', region, 'rds-sc',
                encrypted=True, publicly_accessible=False,
                deletion_protection=True),
    ]}
    findings = product_findings(inventory, [region])
    assert len(findings) == len(CHECKS) == 46
    by_no = {f.number: f for f in findings}
    assert by_no[5].status == 'FAIL'
    assert by_no[19].status == 'FAIL'
    assert by_no[20].status == 'MANUAL_REVIEW'
    assert by_no[23].status == 'MANUAL_REVIEW'
    assert by_no[1].status == 'MANUAL_REVIEW'
    assert all(f.status != 'PASS' for f in findings)


def test_empty_product_match_is_unknown_not_pass():
    findings = product_findings({'resources': []}, ['ap-northeast-1'])
    assert len(findings) == 46
    assert {f.status for f in findings} == {'UNKNOWN'}


def test_reports_write_identity_json_csv_and_xlsx_with_no_formula_execution(tmp_path):
    region = 'ap-northeast-1'
    r = _record('rds', 'db-instance', region, 'db-id', name='=HYPERLINK("example")',
                arn='arn:aws:rds:ap-northeast-1:123456789012:db:db-id',
                tags=[{'Key': 'Project', 'Value': 'scs2'}],
                encrypted=True)
    inventory = {'schema': 'aws-security-resource-inventory-v1',
                 'resources': [r], 'scope': {'mode': 'product'},
                 'collection_errors': []}
    files = save_resource_inventory(str(tmp_path), inventory)
    assert len(files) == 2
    assert json.loads(files[0].read_text())['resources'][0]['name'] == '=HYPERLINK("example")'
    with files[1].open(encoding='utf-8-sig', newline='') as f:
        item = next(csv.DictReader(f))
        assert item['name'].startswith("'=")
        assert item['resource_id'] == 'db-id'
    findings = [Finding(c.number, 'MANUAL_REVIEW', region, 'not established') for c in CHECKS]
    meta = {'timestamp': '2026-10-16T06:00:00+00:00', 'region_coverage_full': False}
    reports = export_report(str(tmp_path), findings, meta, resource_inventory=inventory)
    document = json.loads(next(p for p in reports if p.suffix == '.json').read_text())
    assert document['resource_inventory']['resources'][0]['name'].startswith('=')
    book = next(p for p in reports if p.suffix == '.xlsx')
    with ZipFile(book) as archive:
        assert archive.testzip() is None
        assert 'xl/worksheets/sheet4.xml' in archive.namelist()
        resource_sheet = archive.read('xl/worksheets/sheet4.xml').decode('utf-8')
        assert 'db-id' in resource_sheet
        assert 'HYPERLINK' in resource_sheet
        rel = ET.fromstring(archive.read('xl/_rels/workbook.xml.rels'))
        ids = [el.attrib['Id'] for el in rel]
        assert len(ids) == len(set(ids))
    for p in files + reports:
        assert (p.stat().st_mode & 0o777) == 0o600


def test_web_handoff_includes_scope_and_resource_attribution():
    rows = [{
        'No': n, 'カテゴリ': 'test', 'チェック項目': str(n),
        '推奨設定・確認基準': 'test', '重要度': '高', '目的・対象リスク': 'test',
        '判定': 'MANUAL_REVIEW', '対象地域判定': 'MANUAL_REVIEW',
        '地域網羅': '一部リージョンのみ',
    } for n in range(1, 47)]
    inventory = {'resources': [{'name': 'scs2-prd'}], 'scope': {'mode': 'product'}}
    bundle = build_web_review_bundle(
        {'audit_scope': 'product', 'product': 'scs2',
         'product_attribution_complete': False}, rows, [], {}, inventory)
    assert bundle['execution']['audit_scope'] == 'product'
    assert bundle['execution']['product_attribution_complete'] is False
    assert bundle['resource_inventory'] == inventory


def test_assess_product_parser_and_rejects_cross_scope_confusion():
    args = parser().parse_args(['assess', '--product', 'scs2',
                                '--product-tag', 'Project=scs2'])
    assert args.product == 'scs2'
    assert args.product_tag == 'Project=scs2'
    assert args.llm == 'export'


def test_product_mode_never_runs_account_wide_scanner(monkeypatch):
    import aws_security_audit.cli as cli

    class Ctx:
        account = '123456789012'
        expected_role_arn = 'arn:aws:iam::123456789012:role/audit'
        identity_arn = 'arn:aws:sts::123456789012:assumed-role/audit/test'
        source_profile = 'default'

        def active_regions(self):
            return ['ap-northeast-1']

    monkeypatch.setattr(cli, 'prepare', lambda args: (Ctx(), ['ap-northeast-1']))
    monkeypatch.setattr(cli, 'run_scan', lambda *a, **k: (_ for _ in ()).throw(
        AssertionError('Account-wide scanner must not run')))
    monkeypatch.setattr('aws_security_audit.resource_scope.collect_resource_inventory',
                        lambda *a, **kw: {'resources': [], 'scope': {'mode': 'product'},
                                         'collection_errors': []})
    monkeypatch.setattr('aws_security_audit.resource_scope.save_resource_inventory',
                        lambda *a, **kw: [])
    monkeypatch.setattr(cli, 'export_report', lambda *a, **kw: [])
    assert cli.main(['assess', '--product', 'scs2', '--llm', 'off',
                     '--role-arn', Ctx.expected_role_arn,
                     '--source-profile', 'default']) == 0


def test_all_detected_evidence_is_preserved_beyond_old_100_item_cap(tmp_path):
    from aws_security_audit.core import verdict
    from aws_security_audit.report import overall_rows
    evidence = [f'Resource-{i:03d}-' + 'a' * 300 for i in range(150)]
    finding = verdict(22, 'ap-northeast-1', 160, evidence, '')
    assert finding.status == 'FAIL'
    assert len(finding.evidence) == 150
    summaries = overall_rows([finding], coverage_full=True)
    assert '[SUMMARY TRUNCATED' in summaries[21]['証拠・要確認事項']
    meta = {'timestamp': '2026-10-16T06:00:00+00:00', 'region_coverage_full': True}
    output = export_report(str(tmp_path), [finding], meta)
    payload = json.loads(next(p for p in output if p.suffix == '.json').read_text())
    assert len(payload['findings'][0]['evidence'].splitlines()) == 150
    assert len(payload['summary'][21]['証拠・要確認事項']) < 32767
    with ZipFile(next(p for p in output if p.suffix == '.xlsx')) as book:
        assert book.testzip() is None
        details_xml = book.read('xl/worksheets/sheet2.xml').decode('utf-8')
        assert 'EXCEL CELL TRUNCATED' in details_xml


def test_aurora_cluster_deletion_protection_does_not_inherit_member_false():
    from aws_security_audit.resource_scope import product_findings
    region = 'ap-northeast-1'
    resources = [
        _record('rds', 'db-cluster', region, 'ros-cluster',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                engine='aurora-postgresql', deletion_protection=True),
        _record('rds', 'db-instance', region, 'ros-writer',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                engine='aurora-postgresql', cluster_id='ros-cluster',
                deletion_protection=False),
    ]
    selected, _ = attribute_resources(resources, 'ros')
    finding = {f.number: f for f in product_findings({'resources': selected}, [region])}[23]
    assert finding.status == 'MANUAL_REVIEW'
    assert any('Aurora cluster' in e and 'deletion_protection=True' in e
               for e in finding.evidence)
    assert any('Aurora instance' in e and 'instance_deletion_protection=False' in e
               for e in finding.evidence)
    resources[0]['attributes']['deletion_protection'] = False
    finding = {f.number: f for f in product_findings({'resources': selected}, [region])}[23]
    assert finding.status == 'FAIL'
    assert 'ros-cluster' in finding.evidence[0]


def test_standalone_rds_deletion_protection_false_is_fail():
    region = 'ap-northeast-1'
    r = _record('rds', 'db-instance', region, 'ros-standalone',
                deletion_protection=False)
    f = {e.number: e for e in product_findings({'resources': [r]}, [region])}[23]
    assert f.status == 'FAIL'


def test_related_parent_vpc_and_snapshots_without_claiming_ownership():
    region = 'ap-northeast-1'
    resources = [
        _record('ec2', 'instance', region, 'i-ros',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                vpc_id='vpc-shared', subnet_id='subnet-shared',
                security_group_ids=['sg-shared']),
        _record('ec2', 'vpc', region, 'vpc-shared', flow_logs=[]),
        _record('ec2', 'subnet', region, 'subnet-shared', vpc_id='vpc-shared'),
        _record('ec2', 'security-group', region, 'sg-shared'),
        _record('ec2', 'ebs-volume', region, 'vol-linked',
                tags=[{'Key': 'Project', 'Value': 'ros'}], encrypted=False),
        _record('ec2', 'ebs-snapshot', region, 'snap-1', source_volume_id='vol-linked',
                encrypted=False),
        _record('rds', 'db-cluster', region, 'cluster-ros',
                tags=[{'Key': 'Product', 'Value': 'ros'}], deletion_protection=True),
        _record('rds', 'db-cluster-snapshot', region, 'cluster-snap-ros',
                source_db_id='cluster-ros', encrypted=True),
        _record('ec2', 'vpc', region, 'vpc-unrelated'),
    ]
    chosen, meta = attribute_resources(resources, 'ros')
    by_id = {r['resource_id']: r for r in chosen}
    assert set(by_id) == set(r['resource_id'] for r in resources) - {'vpc-unrelated'}
    assert by_id['vpc-shared']['attribution'] == 'RELATED'
    assert 'shared infrastructure' in by_id['vpc-shared']['attribution_evidence']
    assert by_id['snap-1']['attribution'] == 'RELATED'
    assert by_id['cluster-snap-ros']['attribution'] == 'RELATED'
    assert meta['unassigned'] == 1


def test_individual_s3_tag_permission_failure_is_recorded(monkeypatch):
    import aws_security_audit.resource_scope as scope
    from aws_security_audit.core import EvidenceUnavailable
    class Ctx:
        def client_cached(self, *args):
            return object()

    def api(client, operation, **kwargs):
        if operation == 'list_buckets':
            return {'Buckets': [{'Name': 'ros-prd'}]}
        if operation == 'get_bucket_tagging':
            raise EvidenceUnavailable('s3.get_bucket_tagging: AccessDenied')
        if operation == 'get_bucket_encryption':
            return {'ServerSideEncryptionConfiguration': {'Rules': [
                {'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]}}
        if operation == 'get_public_access_block':
            return {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True}}
        if operation == 'get_bucket_versioning':
            return {'Status': 'Enabled'}
        if operation == 'get_object_lock_configuration':
            raise EvidenceUnavailable('s3.get_object_lock_configuration: ObjectLockConfigurationNotFoundError')
        raise AssertionError(operation)

    monkeypatch.setattr(scope, 'api_call', api)
    out, errors = [], []
    scope._add_s3(Ctx(), out, errors)
    assert len(out) == 1 and len(errors) == 1
    assert errors[0]['operation'] == 'get_bucket_tagging'
    assert out[0]['tags'] == {}
    assert out[0]['attributes']['default_encryption_algorithms'] == ['AES256']
    assert out[0]['attributes']['bucket_public_access_block']['BlockPublicAcls'] is True
    assert out[0]['attributes']['object_lock_enabled'] is False


def test_product_deep_evidence_and_partial_observations_do_not_claim_pass():
    from aws_security_audit.resource_scope import product_deep_evidence
    region = 'ap-northeast-1'
    resources = [
        _record('ec2', 'security-group', region, 'sg-ros',
                dangerous_ingress=0),
        _record('ec2', 'ebs-volume', region, 'vol-ros',
                encrypted=False, size_gib=30,
                attached_instance_ids=['i-ros']),
        _record('s3', 'bucket', 'global', 'ros-bucket',
                default_encryption_algorithms=['AES256'],
                versioning_status='Enabled'),
    ]
    packet = product_deep_evidence({'resources': resources}, [region])
    assert packet[region]['5']['state'] == 'PARTIAL_OBSERVED'
    assert packet[region]['19']['volumes'][0]['id'] == 'vol-ros'
    findings = {f.number: f for f in product_findings({'resources': resources}, [region])}
    assert findings[17].status == 'MANUAL_REVIEW'
    assert any('AES256' in item for item in findings[17].evidence)
    assert findings[19].status == 'FAIL'
    assert findings[22].status == 'MANUAL_REVIEW'
    assert findings[5].status == 'MANUAL_REVIEW'


def test_cluster_tag_selects_untagged_aurora_members_and_preserves_availability_evidence():
    region = 'ap-northeast-1'
    resources = [
        _record('rds', 'db-cluster', region, 'ros-data',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                deletion_protection=True),
        _record('rds', 'db-instance', region, 'db-member-1',
                cluster_id='ros-data', deletion_protection=False),
        _record('rds', 'db-instance', region, 'other-db',
                cluster_id='other-cluster', deletion_protection=False),
    ]
    selected, _ = attribute_resources(resources, 'ros')
    assert {r['resource_id'] for r in selected} == {'ros-data', 'db-member-1'}
    assert selected[1]['attribution'] == 'RELATED'
    f = {e.number: e for e in product_findings({'resources': selected}, [region])}[23]
    assert f.status == 'MANUAL_REVIEW'
    assert any('member deletion remains possible' in e for e in f.evidence)


def test_product_snapshots_are_assessed_without_fabricated_pass():
    region = 'ap-northeast-1'
    inv = {'resources': [
        _record('ec2', 'ebs-snapshot', region, 'snap-1',
                encrypted=False, source_volume_id='vol-ros'),
        _record('rds', 'db-cluster-snapshot', region, 'db-snap-1',
                encrypted=False, source_db_id='db-cluster-ros'),
    ]}
    results = {f.number: f for f in product_findings(inv, [region])}
    assert results[19].status == 'FAIL'
    assert 'snap-1' in results[19].evidence[0]
    assert results[20].status == 'FAIL'
    assert 'db-snap-1' in results[20].evidence[0]



def test_rds_snapshot_collection_reads_distinct_encryption_flags(monkeypatch):
    """Regression: DB-cluster-snapshot does not use DB-snapshot Encrypted key."""
    import aws_security_audit.resource_scope as scope

    region = 'ap-northeast-1'
    class Ctx:
        def client_cached(self, *args):
            return object()

    snapshots = {
        'describe_db_instances': [],
        'describe_db_clusters': [],
        'describe_db_snapshots': [
            {'DBSnapshotIdentifier': 'instance-kms', 'DBInstanceIdentifier': 'db',
             'Encrypted': True, 'StorageEncryptionType': 'sse-kms'},
            {'DBSnapshotIdentifier': 'instance-none', 'DBInstanceIdentifier': 'db',
             'Encrypted': False, 'StorageEncryptionType': 'none'},
            {'DBSnapshotIdentifier': 'instance-owned', 'DBInstanceIdentifier': 'db',
             'Encrypted': False, 'StorageEncryptionType': 'sse-rds'},
        ],
        'describe_db_cluster_snapshots': [
            {'DBClusterSnapshotIdentifier': 'cluster-owned', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': False, 'StorageEncryptionType': 'sse-rds',
             'Encrypted': False},
            {'DBClusterSnapshotIdentifier': 'cluster-kms', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': True, 'StorageEncryptionType': 'sse-kms'},
            {'DBClusterSnapshotIdentifier': 'cluster-none', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': False, 'StorageEncryptionType': 'none'},
            {'DBClusterSnapshotIdentifier': 'cluster-unknown', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': False},
            {'DBClusterSnapshotIdentifier': 'cluster-conflict', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': True, 'StorageEncryptionType': 'none'},
            {'DBClusterSnapshotIdentifier': 'cluster-unknown-mode', 'DBClusterIdentifier': 'cluster',
             'StorageEncrypted': False, 'StorageEncryptionType': 'new-unknown-value'},
        ],
    }

    def fake_paged(client, operation, result_key, **kwargs):
        assert operation in snapshots
        return snapshots[operation]

    monkeypatch.setattr(scope, 'paged', fake_paged)
    records, errors = [], []
    scope._add_rds(Ctx(), region, records, errors)
    assert errors == []
    assert len(records) == 9
    by_id = {r['resource_id']: r['attributes'] for r in records}
    assert by_id['instance-kms']['encrypted'] is True
    assert by_id['instance-kms']['encryption_flag_field'] == 'Encrypted'
    assert by_id['instance-none']['encrypted'] is False
    assert by_id['instance-owned']['encrypted'] is True
    assert by_id['cluster-owned']['encrypted'] is True
    assert by_id['cluster-owned']['encryption_state'] == 'ENCRYPTED'
    assert by_id['cluster-owned']['encryption_flag'] is False
    assert by_id['cluster-owned']['encryption_flag_field'] == 'StorageEncrypted'
    assert by_id['cluster-kms']['encrypted'] is True
    assert by_id['cluster-none']['encrypted'] is False
    assert by_id['cluster-unknown']['encrypted'] is None
    assert by_id['cluster-unknown']['encryption_state'] == 'UNVERIFIED_ENCRYPTION_TYPE'
    assert by_id['cluster-conflict']['encrypted'] is None
    assert by_id['cluster-conflict']['encryption_state'] == 'CONFLICTING_EVIDENCE'
    assert by_id['cluster-unknown-mode']['encrypted'] is None
    findings = {f.number: f for f in product_findings({'resources': records}, [region])}
    assert findings[20].status == 'FAIL'
    assert sum('encrypted=False' in line for line in findings[20].evidence) == 2
    assert 'instance-none' in findings[20].evidence[0]
    assert 'cluster-none' in findings[20].evidence[1]
    assert any('storage_encryption_type' in item and 'sse-rds' in item
               for item in findings[20].evidence)


def test_rds_encryption_mode_prevents_false_positive_with_missing_fields():
    from aws_security_audit.resource_scope import _rds_encryption_observation
    scenarios = [
        ({'StorageEncrypted': False, 'StorageEncryptionType': 'sse-rds'},
         True, 'ENCRYPTED'),
        ({'StorageEncrypted': True, 'StorageEncryptionType': 'sse-kms'},
         True, 'ENCRYPTED'),
        ({'StorageEncrypted': False, 'StorageEncryptionType': 'none'},
         False, 'NOT_ENCRYPTED'),
        ({'StorageEncrypted': False}, None, 'UNVERIFIED_ENCRYPTION_TYPE'),
        ({}, None, 'UNVERIFIED_ENCRYPTION_TYPE'),
        ({'StorageEncrypted': True}, True, 'ENCRYPTED_LEGACY_FLAG'),
        ({'StorageEncrypted': True, 'StorageEncryptionType': 'none'},
         None, 'CONFLICTING_EVIDENCE'),
        ({'StorageEncrypted': False, 'StorageEncryptionType': 'sse-kms'},
         None, 'CONFLICTING_EVIDENCE'),
        ({'StorageEncrypted': False, 'StorageEncryptionType': 'unrecognized'},
         None, 'UNVERIFIED_ENCRYPTION_TYPE'),
    ]
    for metadata, expected, state in scenarios:
        evidence = _rds_encryption_observation(metadata, 'StorageEncrypted')
        assert evidence['encrypted'] is expected, metadata
        assert evidence['encryption_state'] == state, metadata
        assert evidence['storage_encryption_type'] == metadata.get('StorageEncryptionType')

    assert _rds_encryption_observation(
        {'Encrypted': False, 'StorageEncryptionType': 'sse-rds'},
        'Encrypted')['encrypted'] is True


def test_rds_snapshot_uncertainty_is_not_product_fail():
    from aws_security_audit.resource_scope import _rds_encryption_observation
    region = 'ap-northeast-1'
    records = [
        _record('rds', 'db-cluster-snapshot', region, f'snap-{i}', **fields)
        for i, fields in enumerate([
            _rds_encryption_observation(
                {'StorageEncrypted': False, 'StorageEncryptionType': 'sse-rds'},
                'StorageEncrypted'),
            _rds_encryption_observation(
                {'StorageEncrypted': False},
                'StorageEncrypted'),
            _rds_encryption_observation(
                {'StorageEncrypted': True, 'StorageEncryptionType': 'none'},
                'StorageEncrypted'),
        ])
    ]
    finding = {f.number: f for f in product_findings({'resources': records}, [region])}[20]
    assert finding.status == 'MANUAL_REVIEW'
    assert not any('encrypted=False' in x for x in finding.evidence)
    assert any('UNVERIFIED_ENCRYPTION_TYPE' in x for x in finding.evidence)
    assert any('CONFLICTING_EVIDENCE' in x for x in finding.evidence)


def test_sg_rules_are_structured_identifiers_without_descriptions():
    from aws_security_audit.resource_scope import _sg_rule_evidence
    rules = [{
        'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'potential-secret'}],
        'Ipv6Ranges': [{'CidrIpv6': '::/0', 'Description': 'sensitive'}],
        'UserIdGroupPairs': [{'GroupId': 'sg-123', 'Description': 'internal note'}],
    }]
    observed = _sg_rule_evidence(rules)
    assert observed == [{
        'protocol': 'tcp', 'from_port': 443, 'to_port': 443,
        'ipv4_cidrs': ['0.0.0.0/0'], 'ipv6_cidrs': ['::/0'],
        'referenced_sg_ids': ['sg-123'], 'prefix_list_ids': [],
    }]


def test_elb_ssl_policy_probed_and_cannot_infer_pass_from_policy_name(monkeypatch):
    from aws_security_audit.core import EvidenceUnavailable
    import aws_security_audit.resource_scope as scope

    class Ctx:
        def client_cached(self, *args):
            return object()

    arn = 'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/ros-alb/abc'
    lbs = [
        {'LoadBalancerArn': arn, 'LoadBalancerName': 'ros-alb', 'Type': 'application',
         'Scheme': 'internet-facing'},
    ]
    operations = []
    def fake_paged(client, operation, result_key, **kwargs):
        operations.append(operation)
        if operation == 'describe_load_balancers':
            return lbs
        if operation == 'describe_listeners':
            return [
                {'Protocol': 'HTTPS', 'Port': 443, 'SslPolicy': 'ELBSecurityPolicy-2016-08'},
                {'Protocol': 'HTTP', 'Port': 80},
            ]
        raise AssertionError(operation)

    def fake_api(client, operation, **kwargs):
        operations.append(operation)
        if operation == 'describe_tags':
            return {'TagDescriptions': [{'ResourceArn': arn, 'Tags': [
                {'Key': 'Product', 'Value': 'ros'},
            ]}]}
        if operation == 'describe_load_balancer_attributes':
            return {'Attributes': []}
        if operation == 'describe_ssl_policies':
            assert kwargs['Names'] == ['ELBSecurityPolicy-2016-08']
            return {'SslPolicies': [{
                'Name': 'ELBSecurityPolicy-2016-08',
                'SslProtocols': ['TLSv1', 'TLSv1.1', 'TLSv1.2'],
            }]}
        if operation == 'get_web_acl_for_resource':
            return {'WebACL': None}
        raise AssertionError(operation)

    monkeypatch.setattr(scope, 'paged', fake_paged)
    monkeypatch.setattr(scope, 'api_call', fake_api)
    resources, errors = [], []
    scope._add_elb(Ctx(), 'ap-northeast-1', resources, errors)
    assert errors == []
    assert len(resources) == 1
    assert resources[0]['attributes']['listeners'][0]['weak_ssl_protocols'] == ['TLSv1', 'TLSv1.1']
    selected, _ = attribute_resources(resources, 'ros')
    finding = {f.number: f for f in product_findings({'resources': selected}, ['ap-northeast-1'])}[16]
    assert finding.status == 'FAIL'
    assert any('source=elbv2.describe_ssl_policies' in e for e in finding.evidence)
    assert 'describe_ssl_policies' in operations


def test_tls_only_known_weak_protocol_from_aws_can_raise_fail():
    region = 'ap-northeast-1'
    resources = [
        _record('elbv2', 'application', region, 'ros-api',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                listeners=[{'protocol': 'HTTPS', 'port': 443,
                            'ssl_policy': 'custom', 'ssl_protocols': ['TLSv1.2'],
                            'weak_ssl_protocols': []}]),
        _record('elbv2', 'application', region, 'ros-unknown',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                listeners=[{'protocol': 'HTTPS', 'port': 443,
                            'ssl_policy': 'unverified',
                            'weak_ssl_protocols': None}]),
        _record('elbv2', 'application', region, 'shared-other-project',
                listeners=[{'protocol': 'HTTPS', 'port': 443,
                            'ssl_policy': 'legacy', 'ssl_protocols': ['TLSv1'],
                            'weak_ssl_protocols': ['TLSv1']}]),
    ]
    chosen, _ = attribute_resources(resources, 'ros')
    assert len(chosen) == 2
    finding = {f.number: f for f in product_findings({'resources': chosen}, [region])}[16]
    assert finding.status == 'MANUAL_REVIEW'
    assert not any('source=elbv2.describe_ssl_policies' in e for e in finding.evidence)


def test_elb_ssl_policy_error_is_explicit_and_does_not_mark_fail(monkeypatch):
    from aws_security_audit.core import EvidenceUnavailable
    import aws_security_audit.resource_scope as scope
    class Ctx:
        def client_cached(self, *args):
            return object()

    arn = 'arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/app/ros-api/abc'
    def fake_paged(client, operation, result_key, **kwargs):
        if operation == 'describe_load_balancers':
            return [{'LoadBalancerArn': arn, 'LoadBalancerName': 'ros-api',
                     'Type': 'application', 'Scheme': 'internet-facing'}]
        if operation == 'describe_listeners':
            return [{'Protocol': 'HTTPS', 'Port': 443, 'SslPolicy': 'custom'}]
        raise AssertionError(operation)

    def fake_api(client, operation, **kwargs):
        if operation == 'describe_tags':
            return {'TagDescriptions': [{'ResourceArn': arn, 'Tags': [
                {'Key': 'Product', 'Value': 'ros'},
            ]}]}
        if operation == 'describe_load_balancer_attributes':
            return {'Attributes': []}
        if operation == 'describe_ssl_policies':
            raise EvidenceUnavailable('elbv2.describe_ssl_policies: AccessDenied')
        if operation == 'get_web_acl_for_resource':
            return {'WebACL': None}
        raise AssertionError(operation)

    monkeypatch.setattr(scope, 'paged', fake_paged)
    monkeypatch.setattr(scope, 'api_call', fake_api)
    records, errors = [], []
    scope._add_elb(Ctx(), 'ap-northeast-1', records, errors)
    assert len(errors) == 1
    assert errors[0]['operation'] == 'describe_ssl_policies'
    assert records[0]['attributes']['listeners'][0]['ssl_protocol_evidence'] == 'UNVERIFIED'
    chosen, _ = attribute_resources(records, 'ros')
    assert {f.number: f for f in product_findings({'resources': chosen}, ['ap-northeast-1'])}[16].status == 'MANUAL_REVIEW'


def test_versioning_and_object_lock_proof_is_bucket_scoped():
    region = 'ap-northeast-1'
    resources = [
        _record('s3', 'bucket', 'global', 'ros-logs',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                versioning_status='Disabled', object_lock_enabled=False),
        _record('s3', 'bucket', 'global', 'ros-missing-evidence',
                tags=[{'Key': 'Product', 'Value': 'ros'}],
                versioning_status='Disabled', object_lock_enabled=None),
        _record('s3', 'bucket', 'global', 'other-unprotected',
                tags=[{'Key': 'Product', 'Value': 'other'}],
                versioning_status='Disabled', object_lock_enabled=False),
    ]
    selected, _ = attribute_resources(resources, 'ros')
    finding = {f.number: f for f in product_findings({'resources': selected}, [region])}[22]
    assert finding.status == 'FAIL'
    assert len([x for x in finding.evidence if 'object_lock_enabled=False' in x]) == 1
    assert 'ros-logs' in finding.evidence[0]
    resources[0]['attributes']['object_lock_enabled'] = None
    finding = {f.number: f for f in product_findings({'resources': selected}, [region])}[22]
    assert finding.status == 'MANUAL_REVIEW'


def test_s3_bucket_object_lock_configuration_not_found_is_false_only_on_known_error(monkeypatch):
    import aws_security_audit.resource_scope as scope
    from aws_security_audit.core import EvidenceUnavailable
    class Ctx:
        def client_cached(self, *args):
            return object()
    def fake_api(client, operation, **kwargs):
        if operation == 'list_buckets':
            return {'Buckets': [{'Name': 'ros-logs'}]}
        if operation == 'get_bucket_tagging':
            return {'TagSet': [{'Key': 'Product', 'Value': 'ros'}]}
        if operation == 'get_bucket_encryption':
            return {'ServerSideEncryptionConfiguration': {'Rules': []}}
        if operation == 'get_public_access_block':
            return {'PublicAccessBlockConfiguration': {}}
        if operation == 'get_bucket_versioning':
            return {}
        if operation == 'get_object_lock_configuration':
            raise EvidenceUnavailable('s3.get_object_lock_configuration: AccessDenied')
        raise AssertionError(operation)
    monkeypatch.setattr(scope, 'api_call', fake_api)
    out, errors = [], []
    scope._add_s3(Ctx(), out, errors)
    assert len(errors) == 1
    assert 'object_lock_enabled' not in out[0]['attributes']
    finding = {f.number: f for f in product_findings({'resources': out}, ['ap-northeast-1'])}[22]
    assert finding.status == 'MANUAL_REVIEW'
