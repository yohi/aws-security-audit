"""Public CLI: setup | doctor | scan | assess | policy-evidence | version."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from . import __version__
from .catalog import CHECKS
from .checks import CHECK_RUNNERS, GLOBAL_CHECKS
from .core import AuditContext, AuditError, EvidenceUnavailable, Finding, api_call, timestamp
from .report import export_report, overall_rows

CONFIG = Path.home() / '.config' / 'aws-security-audit' / 'config.json'


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog='aws-security-audit', description='AWS 46-control read-only audit via STS session policy')
    sub = p.add_subparsers(dest='command', required=True)
    setup = sub.add_parser('setup', help='Configure local defaults (never changes AWS resources)')
    setup.add_argument('--source-profile')
    setup.add_argument('--role-arn')
    setup.add_argument('--regions')
    setup.add_argument('--force', action='store_true', help='Overwrite existing local configuration')
    for name in ('doctor', 'scan', 'assess', 'policy-evidence'):
        cmd = sub.add_parser(name, help={'doctor': 'Verify identity, region and sampled AWS reads', 'scan':'Run all 46 checks', 'assess':'Investigate 46 checks and export supplemental read-only evidence', 'policy-evidence':'Fingerprint actual AWS IAM managed policy'}[name])
        cmd.add_argument('--source-profile', help='Profile authenticated by aws login / aws sso login')
        cmd.add_argument('--role-arn', help='Existing IAM role to assume with managed ReadOnlyAccess session policy')
        cmd.add_argument('--regions', help='Comma-separated regions, or all (default all)')
        if name == 'policy-evidence':
            cmd.add_argument('--out', default='reports', help='Output directory for original IAM policy evidence (0600)')
        if name in ('scan', 'assess'):
            cmd.add_argument('--ap-tag', help='Identify AP instances, e.g. Role=application')
            cmd.add_argument('--out', default='reports', help='Output directory (private 0600 files)')
            cmd.add_argument('--fail-on-findings', action='store_true', help='Exit 2 if FAIL or UNKNOWN exists')
        if name == 'assess':
            cmd.add_argument('--llm', choices=('off', 'export'), default='export',
                             help='Generate a JSON attachment and copy/paste prompt for ChatGPT/Gemini Web; no upload')
            cmd.add_argument('--product', help='Restrict audit evidence to one product using Product/Project/Application/Service tags or Name/ID prefix')
            cmd.add_argument('--product-tag', help='Explicit Key=Value selector (Product, Project, Application, Service or Name); requires --product')
    sub.add_parser('version', help='Show package version')
    return p


def read_config() -> dict:
    if not CONFIG.exists():
        return {}
    with CONFIG.open(encoding='utf-8') as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise AuditError('Invalid local config format')
    return cfg


def local_config(args: argparse.Namespace) -> dict:
    stored = read_config()
    cfg = {k: getattr(args, k, None) or stored.get(k) for k in ('source_profile', 'role_arn', 'regions')}
    cfg['regions'] = cfg['regions'] or 'all'
    if not cfg['source_profile'] or not cfg['role_arn']:
        raise AuditError('Run `aws-security-audit setup` or provide --source-profile and --role-arn')
    for field in ('source_profile', 'role_arn'):
        if any(char in cfg[field] for char in '\r\n\0'):
            raise AuditError('Invalid configuration')
    return cfg


def setup(args: argparse.Namespace) -> int:
    if CONFIG.exists() and not args.force:
        raise AuditError(f'Local config already exists: {CONFIG}. Use --force to replace it.')
    profile = args.source_profile or input('AWS login source profile [audit-source]: ').strip() or 'audit-source'
    role_arn = args.role_arn or input('IAM audit role ARN: ').strip()
    regions = args.regions or input('Regions [all]: ').strip() or 'all'
    if not profile or not role_arn or '\n' in profile or '\n' in role_arn:
        raise AuditError('Invalid profile or ARN')
    from .core import ROLE_PATTERN
    if not ROLE_PATTERN.fullmatch(role_arn):
        raise AuditError('Invalid role ARN format')
    CONFIG.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = CONFIG.with_suffix('.tmp')
    content = json.dumps({'source_profile': profile, 'role_arn': role_arn, 'regions': regions}, ensure_ascii=False, indent=2)
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        stream.write(content + '\n')
    tmp.replace(CONFIG)
    if os.name == 'posix':
        CONFIG.chmod(0o600)
    print(f'Wrote local configuration: {CONFIG} (no AWS credentials stored)')
    print('Next: aws-security-audit doctor && aws-security-audit scan')
    return 0


def prepare(args: argparse.Namespace) -> tuple[AuditContext, list[str]]:
    cfg = local_config(args)
    regions_spec = cfg['regions']
    parts = [x.strip() for x in regions_spec.split(',')]
    if not all(parts):
        raise AuditError('Invalid regions list')
    bootstrap_region = 'ap-northeast-1' if regions_spec == 'all' else parts[0]
    # STS in the requested partition; only aws commercial partition was checked in this release.
    if not cfg['role_arn'].startswith('arn:aws:'):
        raise AuditError('This release only supports the commercial AWS partition (arn:aws)')
    ctx = AuditContext(cfg['source_profile'], cfg['role_arn'], bootstrap_region)
    available_regions = ctx.active_regions()
    if regions_spec == 'all':
        regions = available_regions
    else:
        if len(parts) != len(set(parts)) or any(not r.startswith(('ap-', 'us-', 'eu-', 'sa-', 'ca-', 'af-', 'me-', 'il-', 'mx-')) for r in parts):
            raise AuditError('Invalid/duplicate region names')
        if set(parts) - set(available_regions):
            raise AuditError('Requested AWS region invalid, disabled or not verifiable; audit aborted')
        regions = parts
    return ctx, regions



def doctor(ctx: AuditContext, regions: list[str]) -> int:
    """Verify sampled reads with scoped STS credentials, not universal No-Write."""
    print(f'IDENTITY_VERIFIED account={ctx.account} role={ctx.expected_role_arn}', flush=True)
    print(f'REGION_VERIFIED count={len(regions)}', flush=True)
    probes = [('iam', regions[0], 'list_account_aliases'),
              ('s3', regions[0], 'list_buckets')]
    for region in regions:
        probes += [('ec2', region, 'describe_vpcs'),
                   ('cloudtrail', region, 'describe_trails'),
                   ('rds', region, 'describe_db_instances')]
    for service, region, action in probes:
        try:
            ctx.guard_expiration()
            api_call(ctx.client_cached(service, region), action)
        except (AuditError, BotoCoreError, ClientError) as exc:
            print(f'READ_API_UNVERIFIED service={service} action={action} '
                  f'region={region} error_type={type(exc).__name__}', flush=True)
            print('EFFECTIVE_NO_WRITE=NOT_PROVEN', flush=True)
            return 2
    print(f'READ_API_VERIFIED sample={len(probes)} scope=selected-probes-only', flush=True)
    print('FULL_46_CHECK_PERMISSIONS=NOT_VERIFIED', flush=True)
    print('EFFECTIVE_NO_WRITE=NOT_PROVEN', flush=True)
    return 0


def policy_evidence(ctx: AuditContext, out: str = 'reports') -> int:
    """Collect a checked, non-atomic ReadOnlyAccess default-version snapshot.

    This is observational evidence only; it does not prove IAM authorization
    or exclude an undetected change-and-revert between read operations.
    """
    import hashlib
    import re
    import uuid
    from urllib.parse import unquote

    arn = 'arn:aws:iam::aws:policy/ReadOnlyAccess'
    iam = ctx.client_cached('iam', ctx.region)
    started_at = timestamp()

    first = api_call(iam, 'get_policy', PolicyArn=arn).get('Policy')
    if not isinstance(first, dict):
        raise EvidenceUnavailable('ReadOnlyAccess policy metadata unavailable')
    version = first.get('DefaultVersionId')
    policy_id = first.get('PolicyId')
    if (first.get('Arn') != arn or not isinstance(policy_id, str) or
            not policy_id or not isinstance(version, str) or
            not re.fullmatch(r'v[1-9][0-9]*(?:\.[A-Za-z0-9-]+)?', version)):
        raise EvidenceUnavailable('ReadOnlyAccess initial policy identity/version not verifiable')

    version_data = api_call(
        iam, 'get_policy_version', PolicyArn=arn, VersionId=version
    ).get('PolicyVersion')
    if not isinstance(version_data, dict):
        raise EvidenceUnavailable('ReadOnlyAccess policy version metadata unavailable')
    if (version_data.get('VersionId') != version or
            version_data.get('IsDefaultVersion') is not True):
        raise EvidenceUnavailable('ReadOnlyAccess policy version is not verified as default')

    original_document = version_data.get('Document')
    try:
        document = (json.loads(unquote(original_document))
                    if isinstance(original_document, str) else original_document)
    except (ValueError, TypeError):
        raise EvidenceUnavailable('ReadOnlyAccess policy document is invalid') from None
    if not isinstance(document, dict):
        raise EvidenceUnavailable('ReadOnlyAccess policy document unavailable')

    last = api_call(iam, 'get_policy', PolicyArn=arn).get('Policy')
    if (not isinstance(last, dict) or last.get('Arn') != arn or
            last.get('PolicyId') != policy_id or
            last.get('DefaultVersionId') != version):
        raise EvidenceUnavailable('ReadOnlyAccess default policy version changed or identity is inconsistent')
    verified_at = timestamp()

    canonical = json.dumps(document, sort_keys=True, ensure_ascii=False,
                           separators=(',', ':')).encode('utf-8')
    digest = hashlib.sha256(canonical).hexdigest()
    snapshot = {
        'schema': 'sts001-iam-policy-snapshot-v1',
        'policy_arn': arn,
        'policy_id': policy_id,
        'default_version_before': version,
        'policy_version': version_data['VersionId'],
        'is_default_version_at_read': version_data['IsDefaultVersion'],
        'default_version_after': last['DefaultVersionId'],
        'collection_started_at_utc': started_at,
        'verified_at_utc': verified_at,
        'snapshot_consistency': 'OBSERVED_STABLE_NON_ATOMIC',
        'policy_document_as_returned_by_boto3': original_document,
        'policy_document': document,
        'policy_sha256_canonical_json': digest,
        'canonicalization': 'UTF-8 JSON, sort_keys=True, ensure_ascii=False, separators=(comma,colon)',
        'effective_no_write': 'NOT_PROVEN',
        'note': 'No atomicity/ABA guarantee. No-Write and live IAM rights remain unverified.',
    }
    serialized = json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                            indent=2) + '\n'
    output_dir = Path(out)
    destination = output_dir / ('readonlyaccess-policy-' + uuid.uuid4().hex + '.json')
    created = False
    try:
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(destination, flags, 0o600)
        created = True
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(serialized)
    except OSError:
        if created:
            destination.unlink(missing_ok=True)
        raise EvidenceUnavailable('Unable to persist ReadOnlyAccess policy evidence') from None

    print(json.dumps({
        'policy_arn': arn,
        'policy_version': version,
        'policy_sha256_canonical_json': digest,
        'observed_at_utc': verified_at,
        'snapshot_consistency': 'OBSERVED_STABLE_NON_ATOMIC',
        'evidence_path': str(destination),
        'effective_no_write': 'NOT_PROVEN',
    }, ensure_ascii=False, sort_keys=True), flush=True)
    return 0

def run_scan(ctx: AuditContext, regions: list[str], options: dict) -> list[Finding]:
    records: list[Finding] = []
    for item in CHECKS:
        scopes = regions[:1] if item.number in GLOBAL_CHECKS else regions
        for region in scopes:
            try:
                ctx.guard_expiration()
                record = CHECK_RUNNERS[item.number](ctx, region, options)
            except (EvidenceUnavailable, ClientError, BotoCoreError) as exc:
                if isinstance(exc, EvidenceUnavailable):
                    message = str(exc)
                elif isinstance(exc, ClientError):
                    message = f"AWS API error: {exc.response.get('Error', {}).get('Code', 'ClientError')}"
                else:
                    message = type(exc).__name__
                record = Finding(item.number, 'UNKNOWN', region, message)
            except Exception as exc:
                # No raw exceptions: boto3 might print service request bodies.
                record = Finding(item.number, 'UNKNOWN', region, f'Unexpected error: {type(exc).__name__}')
            records.append(record)
            print(f'{item.number:02d} {region:20s} {record.status:14s} {item.title}', flush=True)
    return records


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == 'version':
            print(__version__)
            return 0
        if args.command == 'setup':
            return setup(args)
        ctx, regions = prepare(args)
        print(f'Assumed role (STS): {ctx.identity_arn} | source: {ctx.source_profile}', flush=True)
        print('STS session policy: ReadOnlyAccess (role/session-policy intersection; resource-based grants may bypass implicit denial; EFFECTIVE_NO_WRITE=NOT_PROVEN)', flush=True)
        if args.command == 'doctor':
            return doctor(ctx, regions)
        if args.command == 'policy-evidence':
            return policy_evidence(ctx, out=args.out)
        options = {'regions': regions, 'all_account_regions': ctx.active_regions(), 'ap_tag': args.ap_tag}
        inventory = None
        if args.command == 'assess':
            if args.product_tag and not args.product:
                raise AuditError('--product-tag requires --product')
            if args.product_tag:
                key, sep, value = args.product_tag.partition('=')
                if not sep or key not in ('Name', 'Product', 'Project', 'Application', 'Service') or not value:
                    raise AuditError('Expected --product-tag Key=Value with an approved identity tag key')
            if args.product and (len(args.product) > 128 or
                                 any(ord(c) < 32 for c in args.product)):
                raise AuditError('Invalid product identifier')
            from .resource_scope import collect_resource_inventory, product_findings
            if args.product:
                print(f'PRODUCT SCOPE: {args.product} (conservative matching; unassigned/shared resources are not PASS)', flush=True)
                inventory = collect_resource_inventory(ctx, regions, args.product, args.product_tag)
                records = product_findings(inventory, regions)
                for item in records:
                    if item.status == 'FAIL':
                        print(f'{item.number:02d} {item.scope:20s} FAIL           product evidence only', flush=True)
            else:
                records = run_scan(ctx, regions, options)
                # Preserve the established #5/#19 deep evidence before the expanded
                # identity inventory adds extra read traffic and consumes STS lifetime.
                from .investigation import build_investigation
                investigation = build_investigation(
                    ctx, regions, overall_rows(
                        records, coverage_full=set(regions) == set(options['all_account_regions'])
                    ), records)
                inventory = collect_resource_inventory(ctx, regions)
        else:
            records = run_scan(ctx, regions, options)
        full_coverage = set(regions) == set(options['all_account_regions'])
        overview = overall_rows(records, coverage_full=full_coverage)
        counts = Counter(x['判定'] for x in overview)
        metadata = {
            'version': __version__, 'timestamp': timestamp(), 'account': ctx.account,
            'role_arn': ctx.expected_role_arn, 'caller_arn': ctx.identity_arn,
            'requested_regions': regions, 'available_regions': options['all_account_regions'],
            'region_coverage_full': full_coverage,
            'audit_scope': 'product' if args.command == 'assess' and args.product else 'account',
            'product': args.product if args.command == 'assess' else None,
            'product_selector': args.product_tag if args.command == 'assess' else None,
            'product_attribution_complete': False if args.command == 'assess' and args.product else None,
            'session_policy': 'arn:aws:iam::aws:policy/ReadOnlyAccess',
            'note': 'No AWS resources were changed; manual/unknown statuses are not PASS.',
        }
        paths = export_report(args.out, records, metadata, resource_inventory=inventory)
        if args.command == 'assess':
            from .resource_scope import save_resource_inventory
            paths.extend(save_resource_inventory(args.out, inventory))
            if args.product:
                from .resource_scope import product_deep_evidence
                investigation = {
                    'schema': 'aws-product-investigation-v2',
                    'regions_checked': regions,
                    'deep_evidence': product_deep_evidence(inventory, regions),
                    'collection_errors': inventory.get('collection_errors', []),
                    'limitations': [
                        'Account-wide 46 checks are NOT reused for product verdicts.',
                        'Only selected direct negative observations (#2/#5/#19/#20/#23) can assert FAIL.',
                        'Product #5/#19 supplemental evidence is PARTIAL and not the full account-mode examination.',
                        'No PASS is inferred when untagged/shared/unrelated resources could exist.',
                    ],
                }
                print('PRODUCT SCOPE: account-wide scanner skipped; all unproven control statuses remain MANUAL_REVIEW/UNKNOWN', flush=True)
            else:
                from .investigation import save_investigation
                paths.extend(save_investigation(args.out, investigation, llm_export=False))
            if args.llm == 'export':
                from .web_handoff import build_web_review_bundle, save_web_handoff
                bundle = build_web_review_bundle(metadata, overview, records, investigation,
                                                 resource_inventory=inventory)
                paths.extend(save_web_handoff(args.out, bundle))
                print('WEB HANDOFF: attach aws_web_review_*.json to ChatGPT/Gemini Web and paste aws_web_prompt_*.md', flush=True)
                print('SENSITIVE DATA NOTICE: inspect the attachment before uploading; it contains original finding evidence', flush=True)
                print('No file was uploaded and no LLM API was called', flush=True)
        if not full_coverage:
            print('WARNING: partial region coverage; full-account PASS is withheld', flush=True)
        print('Summary: ' + ', '.join(f'{name}={counts[name]}' for name in ('PASS', 'FAIL', 'UNKNOWN', 'MANUAL_REVIEW', 'NOT_APPLICABLE')))
        for path in paths:
            print(f'Report: {path}')
        if args.fail_on_findings and (counts['FAIL'] or counts['UNKNOWN']):
            return 2
        return 0
    except (AuditError, ProfileNotFound) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 1
    except (BotoCoreError, ClientError) as exc:
        print(f'ERROR: AWS authentication/API failed ({type(exc).__name__})', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('Cancelled', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
