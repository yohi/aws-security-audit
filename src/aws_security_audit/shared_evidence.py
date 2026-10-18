"""Bounded, offline-only shared-scoping and cross-control evidence registry.

An inventory observation is not an Owner-approved product coverage claim. Keep
scope approval as PENDING and never automatically promote any final label.
Cross-control references are granted only for an allowlisted evidence purpose.
"""
from __future__ import annotations

_SHARED_SCOPE_CONTROLS = (2, 17, 20, 23)


def build_shared_scope_contract(inventory: dict) -> dict:
    """One reusable coverage question, never a fabricated Owner signoff."""
    scope = inventory.get('scope') or {}
    return {
        'schema': 'aws-security-shared-scope-v1',
        'id': 'scope:product-resource-and-region-coverage',
        'reused_by_controls': list(_SHARED_SCOPE_CONTROLS),
        'owner_approval': 'PENDING',
        'scope_coverage_proven': False,
        'observed_scope': {
            'product': scope.get('product'),
            'mode': scope.get('mode'),
            'regions_requested': inventory.get('regions_requested', []),
            'direct': scope.get('direct'),
            'related': scope.get('related'),
            'unassigned': scope.get('unassigned'),
            'attribution_complete': scope.get('attribution_complete') is True,
            'inventory_limitations': list(inventory.get('limitations', [])),
        },
        'single_owner_question': (
            'Confirm once the ROS product asset inventory, approved regions, '
            'inherited/shared services and unassigned-resource ownership relevant '
            'to controls #2/#17/#20/#23. Supply a dated, scoped approval or '
            'machine-readable owner register; do not repeat this same scope '
            'request independently for each control.'
        ),
        'caveat': ('This is a request for a later human-approved record. '
                   'It is NOT evidence that coverage is complete or that all '
                   'four referenced controls pass.'),
    }


def build_cross_control_evidence(inventory: dict) -> dict:
    """Allow only the observed automated RDS backup *existence* as #45 context.

    #20 typed observation says encrypted snapshot; a correlated inventory
    record saying snapshot_type=automated establishes a dated machine
    snapshot observation, NOT successful restore or backup coverage.
    """
    rows = (inventory.get('control_observations') or {}).get('rows', [])
    by_id = {
        r.get('resource_id'): r
        for r in inventory.get('resources', [])
        if isinstance(r, dict) and r.get('resource_type') == 'db-cluster-snapshot'
        and r.get('attribution') == 'DIRECT' and isinstance(r.get('resource_id'), str)
        and (r.get('attributes') or {}).get('snapshot_type') == 'automated'
    }
    allowed = []
    if isinstance(rows, list):
        seen = set()
        for index, row in enumerate(rows):
            if (not isinstance(row, dict) or row.get('number') != 20
                    or row.get('attribution') != 'DIRECT'
                    or row.get('resource_type') != 'db-cluster-snapshot'
                    or row.get('property') != 'effective storage encryption'
                    or row.get('property_result') != 'PROPERTY_OK'
                    or row.get('resource_id') not in by_id):
                continue
            original = row.get('observed_value')
            if (not isinstance(original, dict)
                    or original.get('encrypted') is not True
                    or original.get('encryption_state') != 'ENCRYPTED'
                    or original.get('storage_encryption_type') != 'sse-kms'
                    or row['resource_id'] in seen):
                continue
            seen.add(row['resource_id'])
            allowed.append({
                'id': f'observation:20:{index}',
                'source_control': 20,
                'target_control': 45,
                'resource_id': row['resource_id'],
                'fact_type': 'AUTOMATED_RDS_SNAPSHOT_EXISTS',
                'source_observation': f'resource_inventory.control_observations.rows[{index}]',
                'source_inventory': f'resource_inventory.resources[resource_id={row["resource_id"]}]',
                'does_not_prove': [
                    'successful restore drill',
                    'complete automated backup scope',
                    'required backup schedule compliance',
                ],
            })
    return {
        'schema': 'aws-security-cross-control-evidence-v1',
        'references': allowed,
        'caveat': 'These are corroborated automated snapshot observations only, not #45 final classification.',
    }
