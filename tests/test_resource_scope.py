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
