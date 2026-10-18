"""Decision-support metadata and strict offline result validation for 46 controls.

The collector may use AWS. This module never creates AWS clients, fetches URLs,
reads credentials or executes the classifying LLM. Its purpose is to minimize
human work by directing *evidence acquisition*, not to fabricate compliance.
"""
from __future__ import annotations

from collections import Counter

from .catalog import CHECKS
from .evidence_reconciliation import reconcile_control
from .shared_evidence import build_cross_control_evidence, build_shared_scope_contract

FINAL_LABELS = frozenset({'対応済み', '未対応', '対応中', '対象外'})
ROUTES = frozenset({
    'AWS_READ_ONLY_CANDIDATE', 'AWS_PLUS_OWNER_SCOPE',
    'NON_AWS_EXPORT_CANDIDATE', 'OWNER_DOCUMENTATION',
})

# Each entry contains: primary preferred acquisition channel, concrete next
# evidence to pursue, and whether human/context evidence is intrinsic to the
# stated criterion. AWS read-only candidate != currently automatable or PASS.
CONTROL_EVIDENCE_PLAN = {
    1: ('AWS_PLUS_OWNER_SCOPE', 'EC2 role-to-workload Owner mapping; all AP ENIs/public IPv4, selected subnet routes and effective ingress paths', True),
    2: ('AWS_READ_ONLY_CANDIDATE', 'Complete DB instances/clusters, network interfaces, subnet routes and PubliclyAccessible status in declared product scope', False),
    3: ('AWS_PLUS_OWNER_SCOPE', 'Owner-approved bastion IDs and authorized corporate/office CIDRs; all SSH ingress paths and SG references', True),
    4: ('AWS_PLUS_OWNER_SCOPE', 'IAM Identity Center/console sign-in source restrictions and approved corporate network policy', True),
    5: ('AWS_PLUS_OWNER_SCOPE', 'Selected ENI/SG ingress and egress with permitted business port inventory and justified public listeners', True),
    6: ('AWS_PLUS_OWNER_SCOPE', 'Complete ALB/CloudFront origin path, WAF associations, verified rule actions and applicable protection policy', True),
    7: ('AWS_PLUS_OWNER_SCOPE', 'WAF/Geo restrictions or geo-monitoring records plus region policy applicability', True),
    8: ('AWS_READ_ONLY_CANDIDATE', 'Shield Advanced subscription/protected resources and scope of externally facing endpoints', False),
    9: ('AWS_PLUS_OWNER_SCOPE', 'IAM/Identity Center identities and signed staff-to-identity mapping, including exception inventory', True),
    10: ('AWS_PLUS_OWNER_SCOPE', 'IAM/Identity Center MFA policy and effective sign-in enforcement for all console principals', True),
    11: ('AWS_PLUS_OWNER_SCOPE', 'IAM policy/role assignments, boundaries, SCP context and reviewed necessary permissions', True),
    12: ('AWS_PLUS_OWNER_SCOPE', 'IAM access-key age/last use, service-owner exceptions and verified role alternatives', True),
    13: ('NON_AWS_EXPORT_CANDIDATE', 'Read-only DB role/grant export plus app/admin user mapping and personal-access accountability', True),
    14: ('AWS_PLUS_OWNER_SCOPE', 'EC2/SSM Session Manager deployment, SSH ingress inventory and approved access architecture', True),
    15: ('NON_AWS_EXPORT_CANDIDATE', 'Data classification and read-only DB/application authorization exports for customer personal data', True),
    16: ('AWS_READ_ONLY_CANDIDATE', 'All external/internal TLS termination points with observed protocols and listener configurations', False),
    17: ('AWS_READ_ONLY_CANDIDATE', 'Complete in-scope S3 bucket list and encryption settings, accounting for default SSE-S3 semantics', False),
    18: ('AWS_READ_ONLY_CANDIDATE', 'Account and bucket BPA, bucket policy, access points and inherited org restrictions; full target scope', False),
    19: ('AWS_READ_ONLY_CANDIDATE', 'All attached EBS volumes and backups/snapshots, KMS encryption metadata and linkage', False),
    20: ('AWS_READ_ONLY_CANDIDATE', 'RDS/DB clusters, storage encryption type and automatic snapshot/backup encryption', False),
    21: ('AWS_PLUS_OWNER_SCOPE', 'Secrets Manager/SSM references linked to deployed app configuration and non-secret evidence of plaintext exposure checks', True),
    22: ('AWS_READ_ONLY_CANDIDATE', 'In-scope S3 Versioning/Object Lock and required protection policy; explicit negative observations', False),
    23: ('AWS_READ_ONLY_CANDIDATE', 'All in-scope RDS clusters/instances and deletion-protection attributes separately', False),
    24: ('AWS_READ_ONLY_CANDIDATE', 'CloudTrail multi-region/trail selectors, management/data event coverage and logging delivery status', False),
    25: ('AWS_READ_ONLY_CANDIDATE', 'CloudTrail log file validation configuration and applicable digest delivery observations', False),
    26: ('AWS_PLUS_OWNER_SCOPE', 'CloudTrail log destination S3 policy/versioning/delete protections and approved evidence retention scope', True),
    27: ('AWS_READ_ONLY_CANDIDATE', 'VPC/subnet/ENI Flow Logs coverage and delivery status for each applicable network', False),
    28: ('AWS_PLUS_OWNER_SCOPE', 'RDS parameter/audit settings plus pgAudit/plugin/runtime SQL audit evidence for selected engines', True),
    29: ('AWS_PLUS_OWNER_SCOPE', 'ALB/access log configurations and non-sensitive app/log shipping evidence with delivery verification', True),
    30: ('AWS_PLUS_OWNER_SCOPE', 'Anonymized sample of actual access logs proving source IP and geolocation attribution', True),
    31: ('AWS_PLUS_OWNER_SCOPE', 'CloudWatch/S3 retention settings and approved retention/compliance policy', True),
    32: ('AWS_READ_ONLY_CANDIDATE', 'GuardDuty detector status and protected-region/account scope', False),
    33: ('AWS_READ_ONLY_CANDIDATE', 'Security Hub status, standards subscriptions and verified active checks across intended regions', False),
    34: ('AWS_PLUS_OWNER_SCOPE', 'EventBridge/CloudWatch/SNS alarm links plus verified Slack/email notification delivery/ownership', True),
    35: ('AWS_PLUS_OWNER_SCOPE', 'SG config-change detection rule, event target and alert delivery evidence', True),
    36: ('AWS_PLUS_OWNER_SCOPE', 'IAM policy/privilege change detection rule, event target and alert delivery evidence', True),
    37: ('AWS_PLUS_OWNER_SCOPE', 'EC2/CloudWatch metric and network alarm coverage with appropriate threshold and notification route', True),
    38: ('AWS_PLUS_OWNER_SCOPE', 'SSM patch compliance/host inventory or signed OS patch export covering all in-scope hosts', True),
    39: ('AWS_READ_ONLY_CANDIDATE', 'Inspector/ECR scan configurations and scan coverage for the actual AMI/container inventory', False),
    40: ('NON_AWS_EXPORT_CANDIDATE', 'GitHub Dependabot/Snyk/CI machine-exported scan configurations and recent results', False),
    41: ('AWS_PLUS_OWNER_SCOPE', 'Dated orphan-resource inventory and evidence of recurring owner review/disposition', True),
    42: ('OWNER_DOCUMENTATION', 'Owner-provided dated incident containment runbook and evidence of publication/ownership', True),
    43: ('OWNER_DOCUMENTATION', 'Owner-provided dated documented safe infrastructure/application recovery runbook', True),
    44: ('OWNER_DOCUMENTATION', 'Approved incident communication and customer escalation contacts/procedure, redacted for LLM', True),
    45: ('AWS_PLUS_OWNER_SCOPE', 'AWS backup plan/snapshot evidence plus dated completed restore-drill records and target RTO/RPO', True),
    46: ('OWNER_DOCUMENTATION', 'Approved product security responsibility matrix and redacted out-of-hours contact coverage', True),
}
assert set(CONTROL_EVIDENCE_PLAN) == set(range(1, 47))

# One shared request can support multiple controls; only ask for the genuinely
# missing questions after reviewing automatically gathered evidence first.
HUMAN_CONTEXT_BATCHES = (
    ('product_scope_network', (1, 3, 4, 5, 6, 7, 14, 21),
     'Confirm ROS system/host roles, approved ingress sources, supported edge path '
     'and actual application secret handling; attach existing architecture approvals.'),
    ('identities_and_data', (9, 10, 11, 12, 13, 15),
     'Provide the approved personnel-to-identity, DB user and customer-data role '
     'mapping and exceptions; prefer redacted exports over individual interviews.'),
    ('logging_monitoring_governance', (26, 28, 29, 30, 31, 34, 35, 36, 37, 38, 41),
     'Provide current log/monitor/patch/retention policy and owner-approved '
     'coverage; attach machine-exported settings and alert delivery evidence.'),
    ('incident_recovery_ownership', (42, 43, 44, 45, 46),
     'Provide dated incident/recovery/customer escalation/security-owner documents '
     'and last successful restore drill; redact private contact details.'),
)
assert {n for _, ns, _ in HUMAN_CONTEXT_BATCHES for n in ns} == {
    n for n, (_, _, human) in CONTROL_EVIDENCE_PLAN.items() if human
}


def _source_refs(control: dict, observations: list[dict]) -> list[dict]:
    number = control['number']
    refs = []
    for i, finding in enumerate(control.get('findings', [])):
        # Reference source data already in controls[number].findings[i].
        if isinstance(finding, dict):
            refs.append({'id': f'finding:{number}:{i}',
                         'source': f'controls[number={number}].findings[{i}]',
                         'kind': 'ENGINE_FINDING'})
    for i, row in enumerate(observations):
        if isinstance(row, dict) and row.get('number') == number:
            refs.append({'id': f'observation:{number}:{i}',
                         'source': f'resource_inventory.control_observations.rows[{i}]',
                         'kind': 'RESOURCE_ATTRIBUTE'})
    return refs


def build_decision_support(controls: list[dict], inventory: dict) -> dict:
    """Non-decisional acquisition plan. Never maps scanner status to final label."""
    if len(controls) != 46 or {row.get('number') for row in controls} != set(range(1, 47)):
        raise ValueError('46 unique normative control IDs required')
    rows = (inventory.get('control_observations') or {}).get('rows', [])
    if not isinstance(rows, list):
        raise ValueError('Invalid observation rows')
    common_scope = build_shared_scope_contract(inventory)
    cross = build_cross_control_evidence(inventory)
    plans = []
    for control in controls:
        no = control['number']
        route, needed, owner_input = CONTROL_EVIDENCE_PLAN[no]
        refs = _source_refs(control, rows)
        props = (inventory.get('control_observations') or {}).get(
            'by_control', {}).get(str(no), {})
        count = props.get('observed_resources', 0)
        plans.append({
            'number': no,
            'acquisition_route': route,
            'preferred_evidence_request': needed,
            'human_context_required_by_criterion': owner_input,
            'evidence_refs': refs,
            'evidence_reconciliation': reconcile_control(no, rows),
            'shared_scope_requirement_ids': (
                [common_scope['id']] if no in common_scope['reused_by_controls'] else []),
            'cross_control_evidence_refs': (
                cross['references'] if no == 45 else []),
            'observed_attribute_rows': count if type(count) is int and count >= 0 else 0,
            'classification_status': 'NOT_EVALUATED',
            'readiness_caveat': 'Observed attributes do not establish 4-state classification completeness.',
        })
    return {
        'schema': 'aws-security-decision-support-v1',
        'shared_scope_contract': common_scope,
        'cross_control_evidence': cross,
        'goal': 'OFFLINE_46_CONTROL_FOUR_STATE_CLASSIFICATION',
        'final_labels': sorted(FINAL_LABELS),
        'temporary_unresolved': 'EVIDENCE_PENDING',
        'llm_aws_access': 'PROHIBITED',
        'manual_checks_minimization': 'AUTO_EVIDENCE_FIRST_THEN_ONLY_BLOCKING_OWNER_INPUT',
        'counts_by_acquisition_route': dict(Counter(p['acquisition_route'] for p in plans)),
        'machine_evidence_first': [
            p['number'] for p in plans if p['acquisition_route'] != 'OWNER_DOCUMENTATION'],
        'conditional_human_review_batches': [
            {'id': name, 'control_numbers': list(numbers),
             'request_only_if_unresolved': True, 'shared_evidence_request': question}
            for name, numbers, question in HUMAN_CONTEXT_BATCHES
        ],
        'plans': plans,
    }


def _supplemental_ids(bundle: dict) -> dict[str, set[int]]:
    result = {}
    supplied = bundle.get('supplemental_evidence', [])
    if not isinstance(supplied, list):
        raise ValueError('supplemental_evidence must be a list')
    for item in supplied:
        if (not isinstance(item, dict) or not isinstance(item.get('id'), str)
                or not item['id'] or not item['id'].isascii()
                or len(item['id']) > 96 or not all(
                    ch.isalnum() or ch in '-_.' for ch in item['id'])
                or not isinstance(item.get('source'), str) or not item['source']
                or not isinstance(item.get('collected_at'), str)
                or not item['collected_at']
                or not isinstance(item.get('control_numbers'), list)
                or not item['control_numbers']
                or any(type(n) is not int or not 1 <= n <= 46
                       for n in item['control_numbers'])
                or len(item['control_numbers']) != len(set(item['control_numbers']))):
            raise ValueError('Invalid supplemental evidence provenance/scope')
        ref = 'supplemental:' + item['id']
        if ref in result:
            raise ValueError('Duplicated supplemental evidence ID')
        result[ref] = set(item['control_numbers'])
    return result


def validate_classification_result(bundle: dict, result: dict) -> dict:
    """Reject omitted controls, fabricated citations and unsupported final labels.

    This is structural/evidence-reference validation, not a semantic check of
    whether the LLM's interpretation is factually correct or Owner-approved.
    """
    if not isinstance(bundle, dict) or not isinstance(result, dict):
        raise ValueError('Expected JSON objects')
    support = bundle.get('decision_support')
    if (not isinstance(support, dict)
            or support.get('schema') != 'aws-security-decision-support-v1'):
        raise ValueError('Versioned decision support is required')
    if result.get('schema') != 'aws-security-offline-classification-v1':
        raise ValueError('Unsupported classification schema')
    plans = support.get('plans')
    bundle_controls = bundle.get('controls')
    if (not isinstance(bundle_controls, list)
            or len(bundle_controls) != 46
            or [(p.get('number') if type(p.get('number')) is int else None)
                if isinstance(p, dict) else None
                for p in bundle_controls] != list(range(1, 47))):
        raise ValueError('Evidence bundle must contain normative 46 controls')
    if (not isinstance(plans, list) or len(plans) != 46
            or [(p.get('number') if type(p.get('number')) is int else None)
                if isinstance(p, dict) else None
                for p in plans] != list(range(1, 47))):
        raise ValueError('Decision support must contain ordered 46 plans')
    inventory = bundle.get('resource_inventory') or {}
    observations = (inventory.get('control_observations') or {}).get('rows', [])
    if not isinstance(observations, list):
        raise ValueError('Invalid evidence bundle observations')
    expected_scope = build_shared_scope_contract(inventory)
    expected_cross = build_cross_control_evidence(inventory)
    if (support.get('shared_scope_contract') != expected_scope
            or support.get('cross_control_evidence') != expected_cross):
        raise ValueError('Shared scope/cross-control index inconsistent with source bundle')
    for control, plan in zip(bundle_controls, plans):
        if plan.get('evidence_refs') != _source_refs(control, observations):
            raise ValueError('Evidence reference index inconsistent with source bundle')
        if plan.get('evidence_reconciliation') != reconcile_control(control['number'], observations):
            raise ValueError('Evidence reconciliation inconsistent with source bundle')
        n = control['number']
        expected_scope_ids = [expected_scope['id']] if n in expected_scope['reused_by_controls'] else []
        expected_cross_refs = expected_cross['references'] if n == 45 else []
        if (plan.get('shared_scope_requirement_ids') != expected_scope_ids
                or plan.get('cross_control_evidence_refs') != expected_cross_refs):
            raise ValueError('Per-control scope or cross-control references were forged')
    controls = result.get('controls')
    if not isinstance(controls, list) or len(controls) != 46:
        raise ValueError('Classification must contain all 46 controls')
    identifiers = [(r.get('number') if type(r.get('number')) is int else None)
                   if isinstance(r, dict) else None for r in controls]
    if identifiers != list(range(1, 47)):
        raise ValueError('Classifications must be ordered No.1 to No.46 exactly once')
    plan_lookup = {p['number']: p for p in plans}
    supplemental = _supplemental_ids(bundle)
    counts = Counter()
    advisory_warnings = []
    for row in controls:
        number = row['number']
        state = row.get('resolution_state')
        label = row.get('final_classification')
        refs = row.get('evidence_refs')
        missing = row.get('missing_evidence')
        rationale = row.get('rationale')
        if (state not in ('FINALIZED', 'EVIDENCE_PENDING')
                or not isinstance(refs, list) or len(refs) != len(set(
                    x for x in refs if isinstance(x, str)))
                or any(not isinstance(x, str) for x in refs)
                or not isinstance(missing, list)
                or any(not isinstance(x, str) or not x.strip() for x in missing)
                or not isinstance(rationale, str) or not rationale.strip()):
            raise ValueError(f'Invalid classification fields for #{number}')
        permitted = {r['id'] for r in plan_lookup[number]['evidence_refs']}
        permitted.update(r['id'] for r in plan_lookup[number]['cross_control_evidence_refs'])
        permitted.update(ref for ref, scope in supplemental.items() if number in scope)
        if any(ref not in permitted for ref in refs):
            raise ValueError(f'Unrecognized or cross-control evidence reference for #{number}')
        source_refs = {r['id'] for r in plan_lookup[number]['evidence_refs']}
        if len(source_refs) > 2 and set(refs) == source_refs:
            advisory_warnings.append({
                'number': number,
                'code': 'ALL_SOURCE_REFS_CITED_UNSELECTIVELY',
                'detail': 'Every supplied source reference was cited; manually verify claim-level relevance.',
            })
        if state == 'EVIDENCE_PENDING':
            if label is not None or not missing:
                raise ValueError(f'Pending #{number} requires null classification and missing evidence')
            counts['pending'] += 1
        else:
            if label not in FINAL_LABELS or not refs or missing:
                raise ValueError(f'Finalized #{number} needs label, proof and no blocking gaps')
            counts['finalized'] += 1
            counts[label] += 1
    summary = result.get('summary')
    if (not isinstance(summary, dict)
            or summary.get('finalized_count') != counts['finalized']
            or summary.get('pending_count') != counts['pending']
            or counts['finalized'] + counts['pending'] != 46):
        raise ValueError('Classification summary totals inconsistent with 46 rows')
    for label in FINAL_LABELS:
        if summary.get(label, 0) != counts[label]:
            raise ValueError('Business-label summary does not match rows')
    return {
        'schema': 'aws-security-classification-validation-v1',
        'structure_and_reference_check': 'PASS',
        'semantic_compliance_verified': False,
        'owner_adoption_verified': False,
        'finalized_count': counts['finalized'],
        'pending_count': counts['pending'],
        'counts': {label: counts[label] for label in sorted(FINAL_LABELS)},
        'citation_quality_warnings': advisory_warnings,
        'status': 'INCOMPLETE' if counts['pending'] else 'ALL_ROWS_CLASSIFIED_OWNER_REVIEW_PENDING',
    }
