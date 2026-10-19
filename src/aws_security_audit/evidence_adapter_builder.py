from __future__ import annotations

from .evidence_adapter_projection import (
    BUNDLE_ACCOUNT_UNKNOWN,
    artifact_execution,
    bundle_context,
    capture_execution as execution_from_calls,
    mcp_fact,
    observation_rows,
    r24_fact,
    row_fact,
    json_object,
)
from .evidence_supplement_validation import (
    R24_FIELDS,
    validate_mcp_summary,
    validate_r24_supplement,
)
from .evidence_ledger import ledger_to_json, parse_ledger
from .evidence_types import (
    LEDGER_SCHEMA,
    CallRecord,
    EvidenceFact,
    EvidenceLedger,
    Execution,
    JsonObject,
    JsonValue,
    ProvenanceLevel as PL,
)
from .read_capture import active_capture
from .evidence_scope_projection import scope_checks_for_ledger


def _supplements(
    r24: JsonObject | None, mcp_summary: JsonObject | None,
) -> tuple[list[Execution], list[EvidenceFact]]:
    executions: list[Execution] = []
    facts: list[EvidenceFact] = []
    if r24 is not None:
        execution = artifact_execution(
            'r24_targeted_evidence_v1', r24, _required_text(r24, 'account'),
            [_required_text(r24, 'region')], _optional_text(r24, 'product'))
        executions.append(execution)
        facts.extend(
            r24_fact(execution.id, key, number, json_object(r24[key], key))
            for number, keys in R24_FIELDS.items() for key in keys
            if isinstance(r24.get(key), dict)
        )
    if mcp_summary is not None:
        curated = _required_text(mcp_summary, 'source').startswith('OPERATOR')
        execution = artifact_execution(
            'mcp_operator_curated_summary' if curated
            else 'mcp_assistant_curated_summary', mcp_summary,
            _required_text(mcp_summary, 'account'),
            [_required_text(mcp_summary, 'region')],
            _optional_text(mcp_summary, 'product'))
        executions.append(execution)
        level = PL.OPERATOR_CURATED if curated else PL.ASSISTANT_CURATED
        records = mcp_summary.get('records')
        if not isinstance(records, list):
            raise ValueError('MCP summary records must be an array')
        facts.extend(
            mcp_fact(execution.id, index, json_object(row, 'mcp record'), level)
            for index, row in enumerate(records)
        )
    return executions, facts


def _required_text(data: JsonObject, key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f'Supplement field {key} must be a string')
    return value


def _optional_text(data: JsonObject, key: str) -> str | None:
    value = data.get(key)
    if value is not None and not isinstance(value, str):
        raise ValueError(f'Supplement field {key} must be a string or null')
    return value


def _verify_embedded_facts(
    ledger: EvidenceLedger, base_bundle: JsonObject, legacy_execution: Execution,
    r24: JsonObject | None, mcp_summary: JsonObject | None,
) -> tuple[list[Execution], tuple[EvidenceFact, ...]]:
    expected_rows = tuple(
        row_fact(index, row, legacy_execution.id, ledger.calls)
        for index, row in enumerate(observation_rows(base_bundle))
    )
    row_refs = {fact.source_ref for fact in expected_rows}
    actual_rows = tuple(
        fact for fact in ledger.facts
        if fact.source_ref.startswith('resource_inventory.control_observations.rows[')
    )
    if actual_rows != expected_rows:
        raise ValueError('Embedded evidence_ledger fact does not match bundle evidence')

    extra_executions, expected_extra_facts = _supplements(r24, mcp_summary)
    expected_by_ref = {fact.source_ref: fact for fact in expected_extra_facts}
    actual_extra = [fact for fact in ledger.facts if fact.source_ref not in row_refs]
    actual_by_ref = {fact.source_ref: fact for fact in actual_extra}
    if (len(actual_extra) != len(actual_by_ref)
            or any(expected_by_ref.get(ref) != fact
                   for ref, fact in actual_by_ref.items())):
        raise ValueError('Embedded evidence_ledger fact does not match supplied supplements')

    expected_execution_by_id = {execution.id: execution
                                for execution in extra_executions}
    actual_supplement_executions = [
        execution for execution in ledger.executions
        if execution.source_kind in (
            'r24_targeted_evidence_v1', 'mcp_operator_curated_summary',
            'mcp_assistant_curated_summary')
    ]
    actual_execution_by_id = {execution.id: execution
                              for execution in actual_supplement_executions}
    if (len(actual_supplement_executions) != len(actual_execution_by_id)
            or any(expected_execution_by_id.get(execution_id) != execution
                   for execution_id, execution in actual_execution_by_id.items())):
        raise ValueError('Embedded evidence_ledger execution does not match supplied supplements')
    missing_executions = [
        execution for execution in extra_executions
        if execution.id not in actual_execution_by_id
    ]
    return missing_executions, (*expected_extra_facts, *expected_rows)


def _reuse_embedded_ledger(
    bundle: JsonObject, embedded: JsonValue, regions: tuple[str, ...], product: str | None,
    r24: JsonObject | None, mcp_summary: JsonObject | None,
    calls: tuple[CallRecord, ...] | None, execution: Execution | None,
) -> EvidenceLedger:
    ledger = parse_ledger(embedded)
    base_bundle = {
        key: value for key, value in bundle.items()
        if key not in ('evidence_ledger', 'control_review')
    }
    legacy_executions = [
        execution for execution in ledger.executions
        if execution.source_kind == 'legacy_bundle_v1'
    ]
    expected_legacy = artifact_execution(
        'legacy_bundle_v1', base_bundle, BUNDLE_ACCOUNT_UNKNOWN, regions, product)
    if legacy_executions != [expected_legacy]:
        raise ValueError('Embedded evidence_ledger source digest does not match bundle')
    if calls is not None and tuple(calls) != ledger.calls:
        raise ValueError('Captured calls conflict with embedded evidence_ledger')
    if execution is not None and not any(
            candidate == execution for candidate in ledger.executions):
        raise ValueError('Execution conflicts with embedded evidence_ledger')
    call_execution_ids = {call.execution_id for call in ledger.calls}
    live_executions = [
        execution for execution in ledger.executions
        if execution.source_kind == 'live_capture_v1'
    ]
    if (len(call_execution_ids) > 1
            or call_execution_ids and (len(live_executions) != 1
                                       or live_executions[0].id not in call_execution_ids)):
        raise ValueError('Embedded evidence_ledger calls have inconsistent execution')
    for live_execution in live_executions:
        if (live_execution.regions
                and set(live_execution.regions) != set(regions)
                or live_execution.product is not None
                and live_execution.product != product):
            raise ValueError('Embedded live execution scope does not match bundle')

    executions = list(ledger.executions)
    legacy_execution = legacy_executions[0]
    missing_supplement_executions, facts = _verify_embedded_facts(
        ledger, base_bundle, legacy_execution, r24, mcp_summary)
    allowed_kinds = {
        'legacy_bundle_v1', 'live_capture_v1', 'scope_diagnostics',
        *(execution.source_kind for execution in ledger.executions
          if execution.source_kind in (
              'r24_targeted_evidence_v1', 'mcp_operator_curated_summary',
              'mcp_assistant_curated_summary')),
    }
    if any(execution.source_kind not in allowed_kinds for execution in executions):
        raise ValueError('Embedded evidence_ledger has an unsupported execution source')
    executions.extend(missing_supplement_executions)
    scope_checks = scope_checks_for_ledger(
        base_bundle, executions, ledger.calls, facts, regions, product)
    if scope_checks != ledger.scope_checks:
        raise ValueError('Embedded scope checks do not match bundle scope diagnostics')
    result = EvidenceLedger(
        schema=LEDGER_SCHEMA, executions=tuple(executions), calls=ledger.calls,
        facts=facts, scope_checks=scope_checks)
    return parse_ledger(ledger_to_json(result))


def build_ledger(
    bundle: JsonObject,
    *,
    r24: JsonObject | None = None,
    mcp_summary: JsonObject | None = None,
    expected_account: str | None = None,
    calls: tuple[CallRecord, ...] | None = None,
    execution: Execution | None = None,
) -> EvidenceLedger:
    """Build a ledger from a bundle and its explicit local supplements."""
    regions, product = bundle_context(bundle)
    _ = validate_r24_supplement(bundle, r24, expected_account)
    _ = validate_mcp_summary(bundle, mcp_summary, expected_account)
    embedded = bundle.get('evidence_ledger')
    if embedded is not None:
        if not isinstance(embedded, dict):
            raise ValueError('Embedded evidence_ledger must be an object')
        return _reuse_embedded_ledger(
            bundle, embedded, regions, product, r24, mcp_summary, calls,
            execution)

    capture = None if calls is not None else active_capture()
    capture_execution = (capture.execution if capture is not None else execution)
    captured_calls = tuple(calls) if calls is not None else (
        capture.snapshot() if capture is not None else ())
    if (capture_execution is not None
            and any(call.execution_id != capture_execution.id for call in captured_calls)):
        raise ValueError('Captured calls do not belong to the supplied execution')
    executions = [artifact_execution(
        'legacy_bundle_v1', bundle, BUNDLE_ACCOUNT_UNKNOWN, regions, product)]
    if capture_execution is not None:
        executions.append(capture_execution)
    elif captured_calls:
        executions.append(execution_from_calls(captured_calls))
    supplement_executions, supplement_facts = _supplements(r24, mcp_summary)
    executions.extend(supplement_executions)
    facts = tuple(
        row_fact(index, row, executions[0].id, captured_calls)
        for index, row in enumerate(observation_rows(bundle))
    ) + tuple(supplement_facts)
    scope_checks = scope_checks_for_ledger(
        bundle, executions, captured_calls, facts, regions, product)
    ledger = EvidenceLedger(
        schema=LEDGER_SCHEMA, executions=tuple(executions),
        calls=captured_calls, facts=facts, scope_checks=scope_checks)
    return parse_ledger(ledger_to_json(ledger))
