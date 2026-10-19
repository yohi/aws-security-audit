"""Offline scope-selection diagnostics; derived only from already returned data.

`build_scope_checks` projects how the product selector chose records and what
it cannot prove, solely from the inventory list and captured `CallRecord`
values that existing collection already produced. It never performs AWS reads,
never mutates any resource and never promotes a candidate into the selected
set. Candidate name/ID tokens are hints only.
"""
from __future__ import annotations

from collections.abc import Sequence

from .evidence_ledger import evidence_id
from .evidence_types import (
    CallRecord, CollectionState, CoverageState, JsonValue, ScopeCheck,
)

_FAILED = frozenset({
    CollectionState.ACCESS_DENIED, CollectionState.FAILED,
    CollectionState.PARTIAL,
})
_EMPTY_STATES = frozenset({
    CollectionState.OBSERVED, CollectionState.VERIFIED_EMPTY,
})
_TAG = 'TAG:'

_TAG_LIMIT = ('Tag equality required a readable tag; failed tag reads and '
              'absent tags can hide product resources and absence cannot be '
              'proven.')
_PREFIX_LIMIT = ('Bounded Name/ID prefix matching is heuristic; untagged or '
                 'differently named product resources may be omitted and '
                 'completeness is not proven.')
_HINT_LIMIT = ('Candidate names/IDs contain the product token but bounded '
               'matching did not select them; tokens are hints only, not '
               'attribution, and candidates are never auto-selected.')
_TOPOLOGY_LIMIT = ('One-hop topology links may be shared with other products; '
                   'related status is not exclusive ownership and never a '
                   'product-wide PASS.')
_ACCOUNT_LIMIT = ('Account mode selects every collected resource; inventory '
                  'is not exhaustive and does not cover every AWS service or '
                  'resource type.')


def _text_field(resource: dict[str, JsonValue], name: str) -> str:
    value = resource.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f'Scope resource field {name} must be a non-empty string')
    return value


def _key(resource: dict[str, JsonValue]) -> str:
    return '/'.join(_text_field(resource, name)
                    for name in ('region', 'resource_type', 'resource_id'))


def _token_hint(resource: dict[str, JsonValue], product: str) -> bool:
    """A name/ID containing the product token is a hint, never attribution."""
    token = product.casefold()
    name = resource.get('name')
    resource_id = resource.get('resource_id')
    return bool(token) and (
        isinstance(name, str) and token in name.casefold()
        or isinstance(resource_id, str) and token in resource_id.casefold())


def _filtered_selector(selector: dict[str, JsonValue]) -> bool:
    """Non-empty string values suggest the call was bounded by a filter."""
    for value in (selector or {}).values():
        if isinstance(value, str) and value:
            return True
        if (isinstance(value, (list, tuple)) and value
                and all(isinstance(item, str) and item
                        for item in value)):
            return True
    return False


def _exec_id(scope: dict[str, JsonValue], calls: tuple[CallRecord, ...]) -> str:
    if calls:
        return calls[0].execution_id
    return evidence_id('execution', {
        'kind': 'scope_diagnostics', 'mode': scope.get('mode'),
        'product': scope.get('product')})


def scope_candidate_resource_keys(
    resources: list[dict[str, JsonValue]], scope: dict[str, JsonValue],
) -> tuple[str, ...]:
    product = scope.get('product')
    if scope.get('mode') != 'product' or not isinstance(product, str):
        return ()
    return tuple(sorted(
        _key(resource) for resource in resources
        if resource.get('attribution') == 'UNCLASSIFIED'
        and _token_hint(resource, product)
    ))


def _check(exec_id: str, kind: str, identity: str, service: str, basis: str,
           selected: Sequence[str], candidates: Sequence[str],
           coverage: CoverageState, limitations: tuple[str, ...],
           call_refs: tuple[str, ...] = ()) -> ScopeCheck:
    return ScopeCheck(
        id=evidence_id('scope', {'execution': exec_id, 'kind': kind,
                                 'identity': identity}),
        execution_id=exec_id, service=service, selector_basis=basis,
        call_refs=call_refs, selected_resource_keys=tuple(selected),
        candidate_resource_keys=tuple(candidates),
        coverage_state=coverage, limitations=limitations)


def _selector_checks(resources: list[dict[str, JsonValue]],
                     selected: list[dict[str, JsonValue]],
                     scope: dict[str, JsonValue],
                     exec_id: str) -> tuple[ScopeCheck, ...]:
    checks: list[ScopeCheck] = []
    product = scope.get('product')
    if scope.get('mode') != 'product' or not isinstance(product, str):
        keys = sorted(map(_key, selected))
        return (_check(exec_id, 'selector', 'account', 'selector', 'account',
                       keys, [], CoverageState.PARTIAL, (_ACCOUNT_LIMIT,)),)
    direct = [r for r in selected if r.get('attribution') == 'DIRECT']
    evidence_values = {
        value for resource in direct
        if isinstance((value := resource.get('attribution_evidence')), str)
    }
    for evidence in sorted(evidence_values):
        if not evidence.startswith(_TAG):
            continue
        basis = evidence[len(_TAG):]
        keys = sorted(_key(resource) for resource in direct
                      if resource.get('attribution_evidence') == evidence)
        checks.append(_check(
            exec_id, 'selector', evidence, 'selector', basis, keys, [],
            CoverageState.PARTIAL, (_TAG_LIMIT,)))
    prefix = [
        resource for resource in direct
        if isinstance((evidence := resource.get('attribution_evidence')), str)
        and evidence.startswith('PREFIX:')
    ]
    if prefix:
        checks.append(_check(
            exec_id, 'selector', 'prefix', 'selector', 'PREFIX:NameOrId',
            sorted(_key(r) for r in prefix), [], CoverageState.PARTIAL,
            (_PREFIX_LIMIT,)))
    related = [r for r in selected if r.get('attribution') == 'RELATED']
    if related:
        checks.append(_check(
            exec_id, 'selector', 'topology', 'topology', 'TOPOLOGY:one-hop',
            sorted(_key(r) for r in related), [], CoverageState.PARTIAL,
            (_TOPOLOGY_LIMIT,)))
    hints = scope_candidate_resource_keys(resources, scope)
    if hints:
        checks.append(_check(
            exec_id, 'candidates', 'hints', 'selector',
            'NAME:product-token-hint', [], hints, CoverageState.PARTIAL,
            (_HINT_LIMIT,)))
    return tuple(checks)


def _call_checks(calls: tuple[CallRecord, ...], exec_id: str
                 ) -> tuple[ScopeCheck, ...]:
    """Limitations retained from already captured calls; nothing re-read."""
    failed: dict[tuple[str, str, CollectionState], list[CallRecord]] = {}
    partial: dict[tuple[str, str], list[CallRecord]] = {}
    empty: dict[tuple[str, str], list[CallRecord]] = {}
    for call in calls:
        if call.collection_state in _FAILED:
            failed.setdefault((call.service, call.operation,
                               call.collection_state), []).append(call)
        elif call.collection_state is CollectionState.OBSERVED \
                and call.pagination_complete is False:
            partial.setdefault((call.service, call.operation), []).append(call)
        elif (call.collection_state in _EMPTY_STATES and call.returned_count == 0
                and call.operation.startswith(('list_', 'describe_'))
                and _filtered_selector(call.safe_selector)):
            empty.setdefault((call.service, call.operation), []).append(call)
    checks: list[ScopeCheck] = []
    for (service, operation, state), group in sorted(
            failed.items(),
            key=lambda item: (item[0][0], item[0][1], item[0][2].value)):
        coverage = (CoverageState.PARTIAL
                    if state is CollectionState.PARTIAL
                    else CoverageState.UNKNOWN)
        checks.append(_check(
            exec_id, 'collection', f'{service}.{operation}.{state.value}',
            service, f'{service}.{operation}', [], [], coverage,
            (f'{operation} did not complete ({state.value}); collected data '
             + 'may be missing and absence cannot be proven.',
             'Completeness of the selector result is not proven.'),
            call_refs=tuple(call.id for call in group)))
    for (service, operation), group in sorted(partial.items()):
        checks.append(_check(
            exec_id, 'collection', f'{service}.{operation}.pagination',
            service, f'{service}.{operation}', [], [], CoverageState.PARTIAL,
            (f'{operation} pagination did not complete; enumerated results '
             + 'are partial and completeness is not proven.',),
            call_refs=tuple(call.id for call in group)))
    for (service, operation), group in sorted(empty.items()):
        checks.append(_check(
            exec_id, 'collection', f'{service}.{operation}.zero', service,
            f'{service}.{operation}', [], [], CoverageState.PARTIAL,
            (f'{operation} returned 0 results with a filtered selector; the '
             + 'filter bounds the result and zero does not prove absence.',),
            call_refs=tuple(call.id for call in group)))
    return tuple(checks)


def build_scope_checks(resources: list[dict[str, JsonValue]],
                       selected: list[dict[str, JsonValue]],
                       scope: dict[str, JsonValue],
                       calls: tuple[CallRecord, ...]) -> tuple[ScopeCheck, ...]:
    """Project selection and coverage limits from data already in hand.

    `resources` is the full collected list (selected and unclassified), as
    existing collection returned it. No resource is mutated, no candidate is
    promoted and no additional AWS read happens here.
    """
    exec_id = _exec_id(scope, calls)
    checks = (*_selector_checks(resources, selected, scope, exec_id),
              *_call_checks(calls, exec_id))
    return tuple(sorted(checks, key=lambda c: (c.service, c.selector_basis)))


def scope_checks_to_json(
    checks: tuple[ScopeCheck, ...],
) -> list[dict[str, JsonValue]]:
    """Report-ready plain dicts; enum values projected as their strings."""
    return [{
        'id': check.id,
        'execution_id': check.execution_id,
        'service': check.service,
        'selector_basis': check.selector_basis,
        'call_refs': list(check.call_refs),
        'selected_resource_keys': list(check.selected_resource_keys),
        'candidate_resource_keys': list(check.candidate_resource_keys),
        'coverage_state': check.coverage_state.value,
        'limitations': list(check.limitations),
    } for check in checks]


def scope_diagnostics_to_json(
    resources: list[dict[str, JsonValue]],
    selected: list[dict[str, JsonValue]],
    scope: dict[str, JsonValue],
    calls: tuple[CallRecord, ...],
) -> dict[str, list[str] | list[dict[str, JsonValue]]]:
    checks = build_scope_checks(resources, selected, scope, calls)
    return {
        'scope_candidate_resource_keys': list(
            scope_candidate_resource_keys(resources, scope)),
        'scope_checks': scope_checks_to_json(checks),
    }
