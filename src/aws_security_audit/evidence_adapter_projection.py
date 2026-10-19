"""Validate and project bundle observations and local supplements into facts."""
from __future__ import annotations

import json
from hashlib import sha256
from typing import Final

from .control_observations import KINDS
from .evidence_ledger import evidence_id
from .evidence_types import (
    NOT_PROVEN, CallRecord, CollectionState, EvidenceFact, Execution,
    JsonObject, JsonValue, ProvenanceLevel as PL, strict_json_value,
)

_ROW_SCOPE = 'Legacy bundle row-scope only; no broadened coverage.'
_ROW_TEXT = 'Legacy bundle observation row without a description.'
BUNDLE_ACCOUNT_UNKNOWN: Final = 'unknown'


def _digest(data: JsonObject) -> str:
    """Canonical-bytes SHA-256; an artifact's execution identity."""
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True,
                         separators=(',', ':'), allow_nan=False)
    return sha256(payload.encode('utf-8')).hexdigest()


def _plain(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and value.strip() else fallback


def json_object(value: JsonValue, name: str) -> JsonObject:
    if not isinstance(value, dict):
        raise ValueError(f'{name}: expected an object')
    result: JsonObject = {}
    for key, child in value.items():
        result[key] = strict_json_value(child, key, name)
    return result


def text_member(data: JsonObject, name: str) -> str:
    value = data.get(name)
    if not isinstance(value, str):
        raise ValueError(f'{name}: expected a string')
    return value


def control_number(value: JsonValue, name: str) -> int:
    if type(value) is not int or not 1 <= value <= 46:
        raise ValueError(f'{name}: expected a control number from 1 to 46')
    return value


def _operation_key(name: str) -> str:
    """Case- and underscore-insensitive operation identity for joins."""
    return name.lower().replace('_', '')


def _operation_from_row(row: JsonObject) -> tuple[str | None, str | None]:
    """Return the service/operation pair a row claims, if any."""
    api = row.get('api')
    if isinstance(api, str) and '.' in api:
        service, operation = api.split('.', 1)
        return service, operation
    service, operation = row.get('service'), row.get('operation')
    return (service if isinstance(service, str) else None,
            operation if isinstance(operation, str) else None)


def observation_rows(bundle: JsonObject) -> list[JsonValue]:
    """Account-scope bundles carry no control_observations; absence means
    zero rows, while a present-but-malformed structure stays fail-closed."""
    inventory_value = bundle.get('resource_inventory')
    if inventory_value is None:
        return []
    inventory = json_object(inventory_value, 'resource_inventory')
    observations_value = inventory.get('control_observations')
    if not observations_value:
        return []
    observations = json_object(observations_value, 'control_observations')
    rows = observations.get('rows')
    if rows is not None and not isinstance(rows, list):
        raise ValueError('Invalid observed property evidence')
    return rows if isinstance(rows, list) else []


def _selector_values(selector: dict[str, JsonValue]) -> set[str]:
    return {item for item in selector.values() if isinstance(item, str)} | {
        entry for item in selector.values() if isinstance(item, list)
        for entry in item if isinstance(entry, str)}


def _joined_calls(row: JsonObject, calls: tuple[CallRecord, ...]) -> tuple[str, ...]:
    """One captured call only on a proven, unambiguous identity.

    Rows that include an explicit ``api`` or ``operation`` also require the
    call's operation to match; legacy rows carry neither, so the verified
    match falls back to service/region/resource identity only. Zero or
    several candidates, or any mismatch, joins nothing and never invents a
    reference.
    """
    resource_ids = {
        value for value in (row.get('resource_id'), row.get('arn'))
        if isinstance(value, str) and value
    }
    region = row.get('region')
    service, expected_operation = _operation_from_row(row)
    if not isinstance(service, str) or not isinstance(region, str) or not resource_ids:
        return ()
    matches = [
        call.id for call in calls
        if call.collection_state is CollectionState.OBSERVED
        and call.service == service and call.region == region
        and resource_ids.intersection(_selector_values(call.safe_selector))
        and (expected_operation is None
             or _operation_key(call.operation) == _operation_key(expected_operation))]
    return tuple(matches) if len(matches) == 1 else ()


def row_fact(index: int, row: JsonValue, exec_id: str,
             calls: tuple[CallRecord, ...]) -> EvidenceFact:
    data = json_object(row, f'bundle rows[{index}]')
    try:
        number = control_number(data.get('number'), 'number')
        property_name = text_member(data, 'property')
        property_result = text_member(data, 'property_result')
    except ValueError:
        raise ValueError(f'Invalid observation row at bundle rows[{index}]') from None
    if not property_name.strip() or property_result not in KINDS:
        raise ValueError(f'Invalid observation row at bundle rows[{index}]')
    ref = f'resource_inventory.control_observations.rows[{index}]'
    value = strict_json_value(data.get('observed_value'), 'observed_value', ref)
    scope = _plain(data.get('scope_limit'), _ROW_SCOPE)
    if isinstance(attribution := data.get('attribution'), str) and attribution:
        # Bundle attribution is record context, never an ownership proof.
        scope = f'{scope} Bundle attribution record at row level: {attribution}.'
    resource_key = data.get('resource_id')
    if resource_key is not None and not isinstance(resource_key, str):
        raise ValueError(f'Invalid resource_id at bundle rows[{index}]')
    return EvidenceFact(
        id=evidence_id('fact', {'execution': exec_id, 'ref': ref}),
        execution_id=exec_id, call_refs=_joined_calls(data, calls),
        source_ref=ref, number=number,
        resource_key=resource_key, field_path=property_name,
        field_present=value is not None, value=value,
        interpretation=_plain(data.get('interpretation'), _ROW_TEXT),
        scope_limit=scope, observed_at=None, provenance_level=PL.LEGACY_SOURCE)


def r24_fact(
    exec_id: str, key: str, number: int, data: JsonObject,
) -> EvidenceFact:
    ref = f'r24_targeted_evidence.{key}'
    return EvidenceFact(
        id=evidence_id('fact', {'execution': exec_id, 'ref': ref}),
        execution_id=exec_id, call_refs=(), source_ref=ref, number=number,
        resource_key=None, field_path=key, field_present=True,
        value=strict_json_value(data, 'r24 block', ref),
        interpretation=f'R24 targeted read-only result projected from {key}.',
        scope_limit=_plain(data.get('limitation'),
        'Operator-supplied R24 targeted read; scope limited to previously approved explicit targets.'),
        observed_at=None, provenance_level=PL.LEGACY_SOURCE)


def mcp_fact(exec_id: str, index: int, row: JsonObject,
             level: PL) -> EvidenceFact:
    number = control_number(row.get('number'), 'mcp.records[].number')
    api = text_member(row, 'api')
    state = text_member(row, 'state')
    fact = text_member(row, 'fact')
    scope_limit = text_member(row, 'scope_limit')
    verified = state == 'OBSERVED'
    return EvidenceFact(
        id=evidence_id('fact', {'execution': exec_id,
                                'ref': f'mcp_summary.records[{index}]'}),
        execution_id=exec_id, call_refs=(),
        source_ref=f'mcp_summary.records[{index}]',
        number=number, resource_key=None,
        field_path=api, field_present=verified,
        value={'state': state, 'fact': fact},
        interpretation=(
            'Verified curated MCP read-only summary; not a raw ' +
            'API payload and not an execution attestation.' if verified else
            'Unverified curated MCP summary; the collection outcome stays ' +
            'unknown.'),
        scope_limit=scope_limit, observed_at=None, provenance_level=level)


def artifact_execution(
    kind: str, artifact: JsonObject, account: str | None,
    regions: list[str] | tuple[str, ...], product: str | None,
) -> Execution:
    """Artifact identity (canonical digest), no minted times, no trust bump."""
    return Execution(
        id=f'exec:{_digest(artifact)}', source_kind=kind,
        account=account or BUNDLE_ACCOUNT_UNKNOWN,
        regions=tuple(regions), product=product,
        started_at=None, finished_at=None, source_digest=_digest(artifact),
        attestation=NOT_PROVEN)


def capture_execution(calls: tuple[CallRecord, ...]) -> Execution:
    """Marker execution for explicitly supplied captured call records."""
    owners = {call.execution_id for call in calls}
    if len(owners) != 1:
        raise ValueError('Captured calls must belong to one execution')
    started = sorted(call.started_at for call in calls if call.started_at)
    finished = sorted(call.finished_at for call in calls if call.finished_at)
    return Execution(
        id=owners.pop(), source_kind='live_capture_v1',
        account=BUNDLE_ACCOUNT_UNKNOWN,
        regions=tuple(sorted({c.region for c in calls if c.region})),
        product=None, started_at=started[0] if started else None,
        finished_at=finished[-1] if finished else None, source_digest=None,
        attestation=NOT_PROVEN)


def bundle_context(bundle: JsonValue) -> tuple[tuple[str, ...], str | None]:
    """Validate the projected bundle identity fields only."""
    if not isinstance(bundle, dict):
        raise ValueError('Invalid original web review evidence schema')
    bundle_data = json_object(bundle, 'bundle')
    if bundle_data.get('schema') != 'aws-security-audit-web-review-v1':
        raise ValueError('Invalid original web review evidence schema')
    execution = bundle_data.get('execution')
    if not isinstance(execution, dict):
        raise ValueError('Invalid original web review execution metadata')
    execution_data = json_object(execution, 'bundle.execution')
    raw_regions = execution_data.get('requested_regions')
    product = execution_data.get('product')
    if (not isinstance(raw_regions, list)
            or product is not None and not isinstance(product, str)):
        raise ValueError('Invalid original web review execution metadata')
    regions: list[str] = []
    for region in raw_regions:
        if not isinstance(region, str) or not region:
            raise ValueError('Invalid original web review execution metadata')
        regions.append(region)
    return tuple(regions), product
