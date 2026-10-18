"""R22: conservative offline citation pruning and machine-gap triage.

Only an exactly matching, redundant scanner-status boilerplate claim is
eligible for pruning, and only when other same-control resource-attribute
claims already support the row. No status, evidence observation, other claim,
human request or machine request can be created or silently reclassified.

The caller provides all evidence locally. This module makes no AWS/HTTP calls.
"""
from __future__ import annotations

import re
from collections import Counter
from copy import deepcopy

from .offline_classification import validate_classification_result

_GENERIC_SCANNER_CLAIM = re.compile(
    r'元監査の#([1-9][0-9]?)は'
    r'(PASS|FAIL|UNKNOWN|MANUAL_REVIEW|NOT_APPLICABLE)'
    r'であり、最終4区分の採用や全資産網羅をそれだけでは証明しない。\Z'
)

# These describe what to check against the existing source; they are NOT
# assertions that a resource is configured, misconfigured or in product scope.
_MACHINE_GAP_QUESTIONS = {
    'request:control-8-shield-subscription': (
        'Shield Advanced subscription/protected-resource coverage has not been '
        'verified for the approved ROS public endpoint set.'
    ),
    'request:control-24-cloudtrail-ros-data-coverage': (
        'Do not repeat the acquired multi-region/is_logging/S3 event-type '
        'facts. Check ROS S3 selector resource coverage and delivery-error state.'
    ),
    'request:control-27-vpc-flow-logs': (
        'VPC/subnet Flow Logs configurations were observed. Limit any next '
        'read to applicable ENI-level coverage and destinations.'
    ),
    'request:control-33-securityhub-state': (
        'Security Hub describe_hub returned InvalidAccessException: cause '
        'and service status remain unverified; obtain authorized export.'
    ),
    'request:control-39-inspector-ecr-scans': (
        'Verify Inspector/ECR scanning only against an Owner-confirmed '
        'AMI/container inventory; do not infer application inventory.'
    ),
    'request:control-40-app-dependency-scans': (
        'Obtain machine-exported repository/CI dependency-scan configuration '
        'and last run, with Owner-confirmed repository mapping.'
    ),
}


def _source_status(bundle: dict, number: int, index: int) -> str | None:
    findings = bundle['controls'][number - 1].get('findings', [])
    if index < len(findings) and isinstance(findings[index], dict):
        return findings[index].get('status')
    return None


def _machine_triage(bundle: dict, result: dict) -> list[dict]:
    plans = bundle['decision_support']['plans']
    by_number = {row['number']: row for row in result['controls']}
    triage = []
    for request in result['evidence_requests']:
        channel = request['acquisition_channel']
        if channel == 'OWNER_CONFIRMATION':
            continue
        applicable = request['applies_to_controls']
        facts = []
        for number in applicable:
            plan = plans[number - 1]
            for fact in plan['evidence_reconciliation']['verified_facts']:
                facts.append({
                    'control': number,
                    'code': fact['code'],
                    'evidence_refs': list(fact['evidence_refs']),
                })
        triage.append({
            'id': request['id'],
            'channel': channel,
            'applies_to_controls': list(applicable),
            'requested_artifact': request['requested_artifact'],
            'already_cited_evidence_refs': {
                str(number): list(by_number[number]['evidence_refs'])
                for number in applicable
            },
            'reconciled_verified_facts': facts,
            'review_question_not_yet_answered': _MACHINE_GAP_QUESTIONS.get(
                request['id'], 'Requires criterion-specific human review of '
                'previously acquired source facts before any new machine read.'
            ),
            'action': 'OFFLINE_EVIDENCE_REVIEW_BEFORE_ANY_READ',
            'fulfilled': False,
        })
    return triage


def refine_r22_citations(bundle: dict, original: dict) -> tuple[dict, dict]:
    """Return a copy, with only redundant boilerplate citation pairs removed.

    The real R21 validator runs both before and after correction. A reviewer
    should still verify claim relevance; zero warnings is NOT semantic PASS.
    """
    before = validate_classification_result(bundle, original)
    if before['result_contract'] != 'aws-security-offline-classification-v2':
        raise ValueError('R22 is limited to the R21 v2 contract')
    if before['r21']['r21_request_schema_check'] != 'PASS':
        raise ValueError('R21 source-request contract is not valid')

    changed = deepcopy(original)
    flagged = {w['number'] for w in before['citation_quality_warnings']
               if w['code'] == 'ALL_SOURCE_REFS_CITED_UNSELECTIVELY'}
    removed = []
    skipped = []
    for row in changed['controls']:
        n = row['number']
        if n not in flagged:
            continue

        candidates = []
        for claim in row['evidence_claims']:
            match = _GENERIC_SCANNER_CLAIM.fullmatch(claim['claim'])
            if not match or int(match.group(1)) != n:
                continue
            refs = claim['evidence_refs']
            if len(refs) != 1 or not refs[0].startswith(f'finding:{n}:'):
                continue
            try:
                index = int(refs[0].rsplit(':', 1)[1])
            except ValueError:
                continue
            if _source_status(bundle, n, index) != match.group(2):
                continue
            candidates.append((claim, refs[0]))

        if len(candidates) != 1:
            skipped.append({'number': n, 'reason': 'NO_UNIQUE_EXACT_GENERIC_CLAIM'})
            continue
        claim, ref = candidates[0]
        if (ref not in row['evidence_refs']
                or any(ref in c['evidence_refs']
                       for c in row['evidence_claims'] if c is not claim)):
            skipped.append({'number': n, 'reason': 'CITATION_SHARED_OR_UNLISTED'})
            continue
        observation_refs = [r for r in row['evidence_refs']
                            if r.startswith(f'observation:{n}:')]
        if not observation_refs or any(
                not any(r in c['evidence_refs'] for c in row['evidence_claims']
                        if c is not claim)
                for r in observation_refs):
            skipped.append({'number': n, 'reason': 'OBSERVATION_CLAIM_INCOMPLETE'})
            continue

        row['evidence_claims'].remove(claim)
        row['evidence_refs'].remove(ref)
        removed.append({'number': n, 'removed_generic_ref': ref,
                        'reason': 'EXACT_SCANNER_STATUS_BOILERPLATE_ONLY'})

    after = validate_classification_result(bundle, changed)
    if (after['counts'] != before['counts']
            or after['finalized_count'] != before['finalized_count']
            or after['pending_count'] != before['pending_count']
            or after['r21']['r21_request_schema_check'] != 'PASS'):
        raise ValueError('R22 validation or frozen classifications changed')

    for lhs, rhs in zip(original['controls'], changed['controls']):
        for field in ('number', 'rationale', 'resolution_state',
                      'final_classification', 'missing_evidence',
                      'missing_evidence_request_ids'):
            if lhs[field] != rhs[field]:
                raise ValueError(f'R22 altered forbidden field: #{lhs["number"]} {field}')
    if original['summary'] != changed['summary'] or original['evidence_requests'] != changed['evidence_requests']:
        raise ValueError('R22 changed Owner/machine requests or classification totals')

    machine = _machine_triage(bundle, changed)
    counts = Counter(request['acquisition_channel']
                     for request in changed['evidence_requests'])
    return changed, {
        'schema': 'ros-r22-offline-citation-and-machine-triage-v1',
        'status': 'VALIDATED_STRUCTURE_ONLY_SEMANTICS_UNPROVEN',
        'source_live_aws_access': False,
        'source_runtime_attested': False,
        'semantic_compliance_verified': False,
        'owner_adoption_verified': False,
        'citation_warnings_before': len(before['citation_quality_warnings']),
        'citation_warnings_after': len(after['citation_quality_warnings']),
        'boilerplate_citations_removed': removed,
        'citations_not_pruned': skipped,
        'unchanged_finalized': after['finalized_count'],
        'unchanged_pending': after['pending_count'],
        'root_request_containers': len(changed['evidence_requests']),
        'owner_request_containers': counts['OWNER_CONFIRMATION'],
        'machine_request_containers': (counts['AWS_LOCAL_READ_ONLY']
                                       + counts['NON_AWS_MACHINE_EXPORT']),
        'machine_gap_triage': machine,
        'human_actions_measured': 'NOT_PROVEN',
        'next_gate': 'HUMAN_SEMANTIC_SOURCE_REVIEW_AND_MISSING_EVIDENCE',
    }
