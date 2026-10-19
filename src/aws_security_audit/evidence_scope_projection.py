from __future__ import annotations

from .evidence_adapter_projection import BUNDLE_ACCOUNT_UNKNOWN
from .evidence_ledger import evidence_id, ledger_to_json, parse_ledger
from .evidence_types import (
    CoverageState,
    LEDGER_SCHEMA,
    NOT_PROVEN,
    CallRecord,
    EvidenceFact,
    EvidenceLedger,
    Execution,
    JsonValue,
    ScopeCheck,
    strict_json_value,
)
from .scope_coverage import build_scope_checks

JsonObject = dict[str, JsonValue]


def _json_object(value: JsonValue, name: str) -> JsonObject:
    normalized = strict_json_value(value, name, 'scope bundle')
    if not isinstance(normalized, dict):
        raise ValueError(f'Scope bundle {name} must be an object')
    return normalized


def _execution_id(scope: JsonObject) -> str:
    return evidence_id('execution', {
        'kind': 'scope_diagnostics', 'mode': scope.get('mode'),
        'product': scope.get('product'),
    })


def _ensure_execution(
    executions: list[Execution], regions: tuple[str, ...], product: str | None,
    scope: JsonObject,
) -> None:
    execution_id = _execution_id(scope)
    if any(execution.id == execution_id for execution in executions):
        return
    executions.append(Execution(
        id=execution_id, source_kind='scope_diagnostics',
        account=BUNDLE_ACCOUNT_UNKNOWN, regions=regions, product=product,
        started_at=None, finished_at=None, source_digest=None,
        attestation=NOT_PROVEN,
    ))


def scope_checks_for_ledger(
    bundle: JsonObject, executions: list[Execution], calls: tuple[CallRecord, ...],
    facts: tuple[EvidenceFact, ...], regions: tuple[str, ...], product: str | None,
) -> tuple[ScopeCheck, ...]:
    """Rebuild verifiable checks and validate preserved candidate hints."""
    inventory_value = bundle.get('resource_inventory')
    if inventory_value is None:
        inventory: JsonObject = {}
    elif isinstance(inventory_value, dict):
        inventory = inventory_value
    else:
        raise ValueError('Bundle resource_inventory must be an object')
    resources_value = inventory.get('resources')
    if resources_value is None:
        resources: list[JsonObject] = []
    elif isinstance(resources_value, list):
        resources = [
            _json_object(resource, 'resource_inventory.resources[]')
            for resource in resources_value
        ]
    else:
        raise ValueError('Bundle resource_inventory.resources must be an array of objects')
    selected = [resource for resource in resources
                if resource.get('attribution') != 'UNCLASSIFIED']
    scope_value = inventory.get('scope')
    if scope_value is None:
        scope: JsonObject = {}
    elif isinstance(scope_value, dict):
        scope = scope_value
    else:
        raise ValueError('Bundle resource_inventory.scope must be an object')
    metadata_value = bundle.get('execution')
    if metadata_value is None:
        metadata: JsonObject = {}
    elif isinstance(metadata_value, dict):
        metadata = metadata_value
    else:
        raise ValueError('Bundle execution metadata must be an object')
    if not scope:
        metadata_product = metadata.get('product')
        if metadata_product is not None and not isinstance(metadata_product, str):
            raise ValueError('Bundle execution product must be a string or null')
        scope = {
            'mode': 'product' if metadata.get('audit_scope') == 'product' else 'account',
            'product': metadata_product,
        }
    candidate_source_keys: list[str] | None = None
    if ('scope_candidate_resource_keys' in scope
            and 'scope_checks' not in scope):
        candidate_source = scope['scope_candidate_resource_keys']
        if (not isinstance(candidate_source, list)
                or any(not isinstance(key, str) for key in candidate_source)
                or len(set(candidate_source)) != len(candidate_source)):
            raise ValueError('Bundle scope candidate keys are invalid')
        candidate_source_keys = [
            key for key in candidate_source if isinstance(key, str)
        ]
    if 'scope_checks' in scope:
        raw_checks = scope['scope_checks']
        if not isinstance(raw_checks, list):
            raise ValueError('Bundle scope_checks must be an array')
        if raw_checks and not calls:
            _ensure_execution(executions, regions, product, scope)
        root = ledger_to_json(EvidenceLedger(
            schema=LEDGER_SCHEMA, executions=tuple(executions), calls=calls,
            facts=facts, scope_checks=()))
        root['scope_checks'] = raw_checks
        supplied = parse_ledger(root).scope_checks
        recomputed_all = build_scope_checks(resources, selected, scope, calls)
        recomputed = tuple(
            check for check in recomputed_all
            if check.selector_basis != 'NAME:product-token-hint')
        recomputed_candidates = tuple(sorted(
            key for check in recomputed_all
            if check.selector_basis == 'NAME:product-token-hint'
            for key in check.candidate_resource_keys
        ))
        candidates = tuple(
            check for check in supplied
            if check.selector_basis == 'NAME:product-token-hint')
        observed = tuple(
            check for check in supplied
            if check.selector_basis != 'NAME:product-token-hint')

        def sort_key(check: ScopeCheck) -> tuple[str, str]:
            return check.service, check.selector_basis

        if tuple(sorted(observed, key=sort_key)) != recomputed:
            raise ValueError('Bundle scope_checks do not match inventory and calls')
        expected_execution_id = (calls[0].execution_id if calls
                                 else _execution_id(scope))
        selected_keys = {
            key for check in recomputed for key in check.selected_resource_keys
        }
        candidate_source = scope.get('scope_candidate_resource_keys')
        if candidate_source is None:
            expected_candidates = recomputed_candidates
        else:
            if (not isinstance(candidate_source, list)
                    or any(not isinstance(key, str) for key in candidate_source)
                    or len(set(candidate_source)) != len(candidate_source)):
                raise ValueError('Bundle scope candidate keys are invalid')
            expected_candidates = tuple(sorted(
                key for key in candidate_source if isinstance(key, str)))
            if (recomputed_candidates
                    and expected_candidates != recomputed_candidates):
                raise ValueError('Bundle scope candidate source does not match inventory')
        supplied_candidates = tuple(sorted(
            key for check in candidates for key in check.candidate_resource_keys))
        if supplied_candidates != expected_candidates:
            raise ValueError('Bundle scope candidate keys do not match diagnostics')
        if (
            len(candidates) > 1
            or any(
                check.service != 'selector'
                or check.call_refs
                or check.selected_resource_keys
                or check.coverage_state is not CoverageState.PARTIAL
                or not check.candidate_resource_keys
                or check.execution_id != expected_execution_id
                or check.id != evidence_id('scope', {
                    'execution': expected_execution_id,
                    'kind': 'candidates', 'identity': 'hints',
                })
                or selected_keys.intersection(check.candidate_resource_keys)
                or not check.limitations
                for check in candidates
            )
        ):
            raise ValueError('Bundle scope candidate hints are invalid')
        return tuple(sorted((*recomputed, *candidates), key=sort_key))
    if not resources and not calls:
        if candidate_source_keys:
            raise ValueError('Bundle scope candidate keys do not match scope_checks')
        return ()
    checks = build_scope_checks(resources, selected, scope, calls)
    if candidate_source_keys is not None:
        projected_candidates = tuple(sorted(
            key for check in checks
            if check.selector_basis == 'NAME:product-token-hint'
            for key in check.candidate_resource_keys
        ))
        if projected_candidates != tuple(sorted(candidate_source_keys)):
            raise ValueError('Bundle scope candidate keys do not match scope_checks')
    if checks and not calls:
        _ensure_execution(executions, regions, product, scope)
    return checks
