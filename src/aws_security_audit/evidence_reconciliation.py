"""Offline, narrowly scoped reconciliation of already-collected observations.

Do not recast a property into a final business verdict. These claims are based
solely on typed, allowlisted existing observation fields, never narrative
interpretations or candidate acquisition hints. No AWS clients or network.
"""
from __future__ import annotations

_BPA_FLAGS = ('BlockPublicAcls', 'IgnorePublicAcls',
              'BlockPublicPolicy', 'RestrictPublicBuckets')

# What belongs to the originally approved control (avoid borrowed criteria).
_CRITERION_BOUNDARIES = {
    17: {
        'not_required_by_original_criterion': [
            'Proving that every historical S3 object is encrypted is not the specified default-encryption criterion.'
        ],
        'remaining_decision_questions': [
            'Do the inspected DIRECT buckets cover all buckets in the declared ROS product scope?'
        ],
    },
    18: {
        'not_required_by_original_criterion': [
            'Do not infer effective public reachability solely from account or bucket BPA flags.'
        ],
        'remaining_decision_questions': [
            'Is account-wide BPA independently mandatory under the approved checklist interpretation, or can scoped bucket BPA satisfy the account/bucket criterion?',
            'Are other applicable bucket, access-point, multi-region or organization-level access paths excluded or verified?'
        ],
    },
    20: {
        'not_required_by_original_criterion': [
            'Restore drills and recovery success are control #45, not a prerequisite for control #20 storage/backup encryption.'
        ],
        'remaining_decision_questions': [
            'Do the observed encrypted RDS instances/clusters and snapshots cover all applicable RDS storage and automatic backups for ROS?'
        ],
    },
    23: {
        'not_required_by_original_criterion': [
            'Aurora member instance deletion/availability is separate from the original criterion: RDS DeletionProtection.'
        ],
        'remaining_decision_questions': [
            'Do the observed cluster deletion-protection settings cover every applicable ROS database cluster/instance?'
        ],
    },
}


def _fact(key: str, message: str, reference: str) -> dict:
    return {'code': key, 'observed_fact': message, 'evidence_refs': [reference]}


def reconcile_control(number: int, observations: list[dict]) -> dict:
    """Output only verified facts and specifically *still open* decisions.

    In particular, a non-configured account BPA is a verified read outcome,
    not a network/API failure. Direct observed property OK != full product PASS.
    """
    if number not in _CRITERION_BOUNDARIES:
        return {
            'status': 'NOT_SPECIALIZED',
            'verified_facts': [],
            'not_required_by_original_criterion': [],
            'remaining_decision_questions': [],
        }
    findings = []
    for index, row in enumerate(observations):
        if not isinstance(row, dict) or row.get('number') != number:
            continue
        value = row.get('observed_value')
        prop = row.get('property')
        state = row.get('property_result')
        ref = f'observation:{number}:{index}'
        resource = row.get('resource_id')
        if not isinstance(resource, str) or not resource:
            continue
        if number == 17:
            if (prop == 'default_encryption_algorithms'
                    and state == 'PROPERTY_OK' and row.get('attribution') == 'DIRECT'
                    and isinstance(value, list) and value
                    and all(x in ('AES256', 'aws:kms', 'aws:kms:dsse')
                            for x in value)):
                findings.append(_fact('DIRECT_BUCKET_DEFAULT_ENCRYPTION',
                                      f'DIRECT bucket {resource} default encryption: {", ".join(value)}.',
                                      ref))
        elif number == 18:
            if (prop == 'bucket_public_access_block' and state == 'PROPERTY_OK'
                    and row.get('attribution') == 'DIRECT'
                    and isinstance(value, dict)
                    and all(value.get(k) is True for k in _BPA_FLAGS)):
                findings.append(_fact('DIRECT_BUCKET_BPA_FOUR_FLAGS_ENABLED',
                                      f'DIRECT bucket {resource}: all four bucket BPA flags observed true.',
                                      ref))
            elif (prop == 'S3 selected bucket access point listing/detail configuration'
                    and state == 'CONTEXT_ONLY' and row.get('attribution') == 'DIRECT'
                    and isinstance(value, dict) and value.get('lookup') == 'LIST_VERIFIED'
                    and value.get('access_points') == []):
                findings.append(_fact('DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY',
                                      f'DIRECT bucket {resource}: regional bucket-filtered classic Access Point list verified empty.',
                                      ref))
            elif (prop == 'S3 account-level Block Public Access context'
                    and row.get('attribution') == 'SHARED_UNATTRIBUTED'
                    and state == 'PROPERTY_UNKNOWN'
                    and isinstance(value, dict) and value.get('lookup') == 'NOT_CONFIGURED'
                    and value.get('public_access_block') is None):
                findings.append(_fact('ACCOUNT_BPA_CONFIGURATION_ABSENT',
                                      'Account-level S3 BPA GetPublicAccessBlock returned NOT_CONFIGURED; this is a known result, not an unattempted lookup.',
                                      ref))
        elif number == 20:
            if (prop == 'effective storage encryption' and state == 'PROPERTY_OK'
                    and row.get('attribution') == 'DIRECT' and isinstance(value, dict)
                    and value.get('encrypted') is True
                    and value.get('encryption_state') == 'ENCRYPTED'
                    and value.get('storage_encryption_type') == 'sse-kms'
                    and row.get('resource_type') in (
                        'db-instance', 'db-cluster', 'db-cluster-snapshot')):
                findings.append(_fact('DIRECT_RDS_STORAGE_OR_SNAPSHOT_KMS_ENCRYPTED',
                                      f'DIRECT {row["resource_type"]} {resource}: storage/snapshot encryption observed sse-kms.',
                                      ref))
        elif number == 23:
            if (prop == 'DeletionProtection' and state == 'PROPERTY_OK'
                    and row.get('attribution') == 'DIRECT'
                    and row.get('resource_type') == 'db-cluster'
                    and value is True):
                findings.append(_fact('DIRECT_RDS_CLUSTER_DELETION_PROTECTION',
                                      f'DIRECT RDS cluster {resource}: DeletionProtection=True.',
                                      ref))
    rules = _CRITERION_BOUNDARIES[number]
    return {
        'status': 'VERIFIED_FACTS_RECONCILED' if findings else 'NO_MATCHING_VERIFIED_FACTS',
        'verified_facts': findings,
        'not_required_by_original_criterion': list(rules['not_required_by_original_criterion']),
        'remaining_decision_questions': list(rules['remaining_decision_questions']),
        'caveat': ('These are narrow observed configuration facts, never evidence of '
                   'complete product attribution, complete regions or final four-state compliance.'),
    }
