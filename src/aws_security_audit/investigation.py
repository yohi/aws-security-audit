"""Supplemental investigation evidence; never make AWS changes or auto-send to LLMs."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from uuid import uuid4

from .checks import dangerous_inbound
from .core import api_call, paged, timestamp
from .report import _private_bytes


def _broad_sources(permission: dict) -> list[str]:
    sources = [
        r.get('CidrIp') for r in permission.get('IpRanges', [])
        if r.get('CidrIp') == '0.0.0.0/0'
    ]
    sources.extend(
        r.get('CidrIpv6') for r in permission.get('Ipv6Ranges', [])
        if r.get('CidrIpv6') == '::/0'
    )
    return sources


def investigate_security_groups(ctx, region: str) -> dict:
    """Collect observed use of risky SGs; do not assert internet reachability."""
    ctx.guard_expiration()
    ec2 = ctx.client_cached('ec2', region)
    groups = paged(ec2, 'describe_security_groups', 'SecurityGroups')
    flagged = []
    for sg in groups:
        rules = []
        for permission in sg.get('IpPermissions', []):
            if dangerous_inbound(permission):
                rules.append({
                    'protocol': permission.get('IpProtocol'),
                    'from_port': permission.get('FromPort'),
                    'to_port': permission.get('ToPort'),
                    'sources': _broad_sources(permission),
                })
        if rules:
            flagged.append({'group_id': sg['GroupId'], 'rules': rules})
    if not flagged:
        return {
            'state': 'OBSERVED',
            'security_groups_scanned': len(groups),
            'dangerous_permission_entries': 0,
            'groups': [],
            'internet_reachability': 'NOT_PROVEN',
        }

    ids = [g['group_id'] for g in flagged]
    eni_counts: dict[str, Counter] = {gid: Counter() for gid in ids}
    # Avoid assuming a public IP is required for all possible ingress paths.
    # Enumerate one security group at a time to keep AWS filter sizes bounded.
    for gid in ids:
        enis = paged(
            ec2, 'describe_network_interfaces', 'NetworkInterfaces',
            Filters=[{'Name': 'group-id', 'Values': [gid]}],
        )
        seen = set()
        for eni in enis:
            eni_id = eni.get('NetworkInterfaceId')
            if eni_id in seen:
                continue
            seen.add(eni_id)
            if gid not in {x.get('GroupId') for x in eni.get('Groups', [])}:
                continue
            eni_counts[gid]['attached_enis'] += 1
            eni_counts[gid]['public_ipv4_enis'] += bool(
                eni.get('Association', {}).get('PublicIp')
            )
            eni_counts[gid]['ipv6_enis'] += bool(eni.get('Ipv6Addresses'))
            kind = eni.get('InterfaceType', 'unknown')
            eni_counts[gid]['type:' + kind] += 1

    for sg in flagged:
        counts = eni_counts[sg['group_id']]
        sg['attached_enis'] = counts['attached_enis']
        sg['public_ipv4_enis'] = counts['public_ipv4_enis']
        sg['ipv6_enis'] = counts['ipv6_enis']
        sg['eni_type_counts'] = {
            key.removeprefix('type:'): val for key, val in counts.items()
            if key.startswith('type:')
        }
        sg['reachability'] = 'NOT_PROVEN'
    return {
        'state': 'OBSERVED',
        'security_groups_scanned': len(groups),
        'dangerous_permission_entries': sum(len(g['rules']) for g in flagged),
        'groups': flagged,
        'internet_reachability': 'NOT_PROVEN',
        'note': 'SG ingress and ENI attachment do not prove an internet route, NACL permission, or a live listener.',
    }


def investigate_ebs(ctx, region: str) -> dict:
    """Classify all observed unencrypted EBS volumes without changing them."""
    ctx.guard_expiration()
    ec2 = ctx.client_cached('ec2', region)
    volumes = paged(ec2, 'describe_volumes', 'Volumes')
    missing_encryption_status = sum('Encrypted' not in v for v in volumes)
    unencrypted = [v for v in volumes if v.get('Encrypted') is False]
    attached_ids = sorted({
        a['InstanceId'] for vol in unencrypted
        for a in vol.get('Attachments', []) if a.get('InstanceId')
    })
    instances = {}
    if attached_ids:
        # DescribeInstances supports pagination with Filters and avoids
        # reporting nonexistent/terminated instance IDs as success.
        reservations = paged(
            ec2, 'describe_instances', 'Reservations',
            Filters=[{'Name': 'instance-id', 'Values': attached_ids}],
        )
        instances = {
            inst['InstanceId']: inst for res in reservations
            for inst in res.get('Instances', [])
        }
    # ASG inventory is read-only. Missing permission makes the subfield UNKNOWN,
    # not a false assertion that no instances belong to an ASG.
    asg_ids = None
    asg_error = None
    try:
        asgs = paged(
            ctx.client_cached('autoscaling', region),
            'describe_auto_scaling_instances', 'AutoScalingInstances',
        )
        asg_ids = {x['InstanceId'] for x in asgs}
    except Exception as exc:
        asg_error = type(exc).__name__
    encrypted_by_default = None
    default_error = None
    try:
        response = api_call(ec2, 'get_ebs_encryption_by_default')
        value = response.get('EbsEncryptionByDefault')
        if isinstance(value, bool):
            encrypted_by_default = value
    except Exception as exc:
        default_error = type(exc).__name__

    details = []
    for vol in unencrypted:
        associations = []
        for attachment in vol.get('Attachments', []):
            iid = attachment.get('InstanceId')
            instance = instances.get(iid)
            if instance is None:
                associations.append({
                    'instance_id': iid,
                    'instance_state': 'UNKNOWN',
                    'volume_purpose': 'UNKNOWN',
                    'asg_member': 'UNKNOWN',
                })
                continue
            root_ids = {
                m.get('Ebs', {}).get('VolumeId')
                for m in instance.get('BlockDeviceMappings', [])
                if m.get('DeviceName') == instance.get('RootDeviceName')
            }
            associations.append({
                'instance_id': iid,
                'instance_state': instance.get('State', {}).get('Name', 'UNKNOWN'),
                'volume_purpose': 'root' if vol['VolumeId'] in root_ids else 'data_or_unresolved',
                'asg_member': 'UNKNOWN' if asg_ids is None else iid in asg_ids,
            })
        details.append({
            'volume_id': vol['VolumeId'],
            'size_gib': vol.get('Size'),
            'volume_state': vol.get('State', 'UNKNOWN'),
            'attachments': associations,
        })
    return {
        'state': 'OBSERVED' if not missing_encryption_status else 'PARTIAL',
        'volumes_scanned': len(volumes),
        'unencrypted_count': len(unencrypted),
        'missing_encryption_status': missing_encryption_status,
        'unencrypted_capacity_gib': sum(v.get('Size', 0) for v in unencrypted),
        'ebs_encryption_by_default': encrypted_by_default,
        'encryption_default_error': default_error,
        'asg_inventory_error': asg_error,
        'volumes': details,
        'note': 'Volume state in-use does not prove that the attached EC2 is running.',
    }


def build_investigation(ctx, regions: list[str], overall_rows: list[dict], findings: list) -> dict:
    """Preserve original 46 decisions; evidence is supplemental, never approval."""
    deep = {}
    for region in regions:
        observations = {}
        for control, collector in ((5, investigate_security_groups), (19, investigate_ebs)):
            try:
                observations[str(control)] = collector(ctx, region)
            except Exception as exc:
                # SDK exception messages may include request details. Keep only the type.
                observations[str(control)] = {
                    'state': 'UNKNOWN',
                    'error_type': type(exc).__name__,
                }
        deep[region] = observations
    return {
        'schema': 'aws-security-investigation-v1',
        'generated_at_utc': timestamp(),
        'mode': 'INVESTIGATION_ONLY',
        'aws_resource_changes': 'FORBIDDEN',
        'remediation': 'OUT_OF_SCOPE',
        'effective_no_write': 'NOT_PROVEN',
        'regions_checked': list(regions),
        'all_46_controls': [
            {
                'number': row['No'],
                'title': row['チェック項目'],
                'account_status': row['判定'],
                'regional_status': row['対象地域判定'],
                'coverage': row['地域網羅'],
                'evidence_count': sum(len(f.evidence) for f in findings if f.number == row['No']),
            }
            for row in overall_rows
        ],
        'deep_evidence': deep,
        'limitations': [
            'Observed settings do not prove internet reachability or application-level effectiveness.',
            'MANUAL_REVIEW, UNKNOWN and untested regions cannot be promoted to PASS.',
            'LLM interpretation cannot replace missing original evidence.',
            'No AWS change, IAM modification, active probing, or remediation is performed.',
        ],
    }


def render_llm_packet(investigation: dict) -> str:
    """Privacy-reduced manual handoff: no AWS names, IDs or raw responses."""
    lines = [
        '# AWS Security Investigation — evidence review packet',
        '',
        'Purpose: assess available evidence ONLY. Remediation and AWS changes are OUT OF SCOPE.',
        'Do not infer PASS from absent evidence; retain UNKNOWN / MANUAL_REVIEW.',
        'Do not request credentials or suggest executing AWS mutating operations.',
        'No external LLM API was contacted when generating this file.',
        '',
        '## 46-control outcomes',
        '',
        '| # | Control | Account | Regional |',
        '|---|---|---|---|',
    ]
    for item in investigation['all_46_controls']:
        title = str(item['title']).replace('|', '\\|').replace('\n', ' ')
        lines.append(f"| {item['number']} | {title} | {item['account_status']} | {item['regional_status']} |")
    lines += ['', '## Aggregated supplemental observations', '']
    for region, evidence in investigation['deep_evidence'].items():
        lines.append(f'### Region: {region}')
        sg = evidence.get('5', {})
        if sg.get('state') == 'OBSERVED':
            active = sum(g['attached_enis'] > 0 for g in sg['groups'])
            lines.append(
                f"- #5: {sg['dangerous_permission_entries']} dangerous ingress permission entries, "
                f"{len(sg['groups'])} affected SGs, {active} with ENI attachments; "
                'internet reachability NOT PROVEN.'
            )
        else:
            lines.append('- #5: supplemental evidence UNKNOWN.')
        ebs = evidence.get('19', {})
        if ebs.get('state') in ('OBSERVED', 'PARTIAL'):
            counts = Counter()
            for volume in ebs['volumes']:
                for attachment in volume['attachments']:
                    counts[(attachment['instance_state'], str(attachment['asg_member']))] += 1
            lines.append(
                f"- #19: {ebs['unencrypted_count']} unencrypted EBS volumes, "
                f"{ebs['unencrypted_capacity_gib']} GiB; encryption by default: "
                f"{ebs['ebs_encryption_by_default']}."
            )
            for (state, asg), count in sorted(counts.items()):
                lines.append(f'  - {state}; ASG={asg}: {count} volume attachments.')
            if ebs['state'] == 'PARTIAL' or ebs.get('asg_inventory_error') or ebs.get('encryption_default_error'):
                lines.append('  - Some EBS evidence is incomplete and must remain UNKNOWN.')
        else:
            lines.append('- #19: supplemental evidence UNKNOWN.')
        lines.append('')
    lines += [
        '## Review contract',
        '',
        'For each finding, distinguish confirmed configuration observations, potential impact,',
        'unproven reachability, unavailable evidence, and scope limitations.',
        'Do not invent evidence or treat an LLM conclusion as AWS authorization proof.',
        'Do not provide or execute remediation commands. Changes are outside scope.',
        '',
    ]
    return '\n'.join(lines)


def save_investigation(out_dir: str, investigation: dict, *, llm_export: bool) -> list[Path]:
    folder = Path(out_dir).expanduser().resolve()
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    suffix = uuid4().hex
    json_path = folder / f'aws_investigation_{suffix}.json'
    encoded = (json.dumps(investigation, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode('utf-8')
    _private_bytes(json_path, encoded)
    paths = [json_path]
    if llm_export:
        packet_path = folder / f'aws_llm_review_{suffix}.md'
        _private_bytes(packet_path, render_llm_packet(investigation).encode('utf-8'))
        paths.append(packet_path)
    return paths
