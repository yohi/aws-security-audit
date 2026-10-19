"""Evidence-ledger parsing, deterministic IDs and JSON projection.

`parse_ledger` is the strict boundary for aws-security-evidence-ledger-v1:
unsupported schemas, unknown and credential-like fields, invalid enums,
types or UTC timestamps, malformed IDs, duplicate IDs and dangling
references raise ValueError. `evidence_id` derives stable IDs as kind
prefix + SHA-256 over canonical identity JSON; no dynamic evaluation,
arbitrary-object serialization or secret retention happens here.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from datetime import datetime, timedelta
from enum import Enum

from .evidence_types import (
    LEDGER_SCHEMA, NOT_PROVEN, CallRecord, CollectionState, CoverageState,
    EvidenceFact, EvidenceLedger, Execution, JsonValue, ProvenanceLevel,
    ScopeCheck, strict_json_value,
)

# The run identity is a once-per-run UUID; record identities embed the
# execution ID, so regenerating reports from an unchanged bundle keeps IDs
# while separate runs never merge. Review-side kinds ('criterion', 'gap',
# 'request') share this deterministic scheme for later tasks.
_PREFIX_BY_KIND = {
    'execution': 'exec', 'call': 'call', 'fact': 'fact', 'scope': 'scope',
    'criterion': 'check', 'gap': 'gap', 'request': 'request',
}
    # root keys are validated inline in parse_ledger below

# Concrete credential field names only; audit attributes such as IAM
# access-key ages or Secrets Manager fields stay untouched as data values.
_CREDENTIAL_PATTERN = re.compile(
    r'(?i)passwd|password|secrets?[_-]|token|credential|bearer|'
    r'authorization|api[_-]?key|access[_-]?key[_-]?id|session[_-]?token')


def _object_of(value: object, what: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f'{what}: expected a JSON object')
    return value


def _string(value: object, name: str, what: str, optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f'{what}.{name}: expected a non-empty string')
    return value


def _strings(value: object, name: str, what: str) -> tuple[str, ...]:
    if (not isinstance(value, list)
            or not all(isinstance(item, str) and item.strip() for item in value)):
        raise ValueError(f'{what}.{name}: expected a list of non-empty strings')
    if len(set(value)) != len(value):
        raise ValueError(f'{what}.{name}: duplicate entries are not allowed')
    return tuple(value)


def _timestamp(value: object, name: str, what: str,
               optional: bool = False) -> str | None:
    if optional and value is None:
        return None
    try:
        stamp = datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        stamp = None
    if stamp is None or stamp.tzinfo is None or stamp.utcoffset() != timedelta(0):
        raise ValueError(f'{what}.{name}: expected an ISO-8601 UTC timestamp')
    return value


def _boolean(value: object, name: str, what: str,
             optional: bool = False) -> bool | None:
    if optional and value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f'{what}.{name}: expected a boolean')
    return value


def _integer(value: object, name: str, what: str, low: int,
             high: int | None, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < low or high is not None and value > high):
        raise ValueError(f'{what}.{name}: expected an integer in {low}..{high}')
    return value


def _enum_of(value: object, name: str, what: str, cls: type[Enum]) -> Enum:
    try:
        return cls(value)
    except ValueError:
        raise ValueError(
            f'{what}.{name}: unknown {cls.__name__} value {value!r}') from None


def _hex64(value: object, name: str, what: str, prefix: str | None) -> str | None:
    """Require 'prefix:<64 hex>' ids, or a bare 64-hex digest when id-less."""
    if value is None and prefix is None:
        return None
    okay = isinstance(value, str) and re.fullmatch(
        (rf'{prefix}:[0-9a-f]{{64}}' if prefix else r'[0-9a-f]{64}') + r'\Z', value)
    if not okay:
        expected = (f'{prefix}:<64 lowercase hex> id' if prefix
                    else 'a 64-hex SHA-256 digest')
        raise ValueError(f'{what}.{name}: expected {expected}')
    return value


def _attestation(value: object, name: str, what: str) -> str:
    if _string(value, name, what) != NOT_PROVEN:
        raise ValueError(f'{what}.{name}: attestation must stay {NOT_PROVEN!r}')
    return NOT_PROVEN


def _selector(value: object, name: str, what: str) -> dict[str, JsonValue]:
    """Allowlisted selector data; nested keys and values all stay strict JSON."""
    data = strict_json_value(_object_of(value, f'{what}.{name}'), name, what)
    return dict(data)


def _reject_credentials(node: object, what: str) -> None:
    if isinstance(node, dict):
        children = node.items()
    elif isinstance(node, list):
        children = enumerate(node)
    else:
        return
    for key, child in children:
        if isinstance(key, str) and _CREDENTIAL_PATTERN.search(key):
            raise ValueError(
                f'{what}: credential-like field name {key!r} is not allowed')
        _reject_credentials(child, f'{what}.{key}')


def _allowed_keys(data: dict, allowed: set[str], what: str) -> None:
    unknown = sorted(
        key for key in data if not isinstance(key, str) or key not in allowed)
    if unknown:
        raise ValueError(f'{what}: unsupported field(s) {unknown!r}')


# Each field entry: (name, converter, extra args after name and what).
# Allowed record fields are exactly these names; unapproved extensions fail
# validation instead of being silently ignored.
_EXECUTION = (
    ('id', _hex64, ('exec',)),
    ('source_kind', _string, ()),
    ('account', _string, ()),
    ('regions', _strings, ()),
    ('product', _string, (True,)),
    ('started_at', _timestamp, (True,)),
    ('finished_at', _timestamp, (True,)),
    ('source_digest', _hex64, (None,)),
    ('attestation', _attestation, ()),
)
_CALL = (
    ('id', _hex64, ('call',)),
    ('execution_id', _hex64, ('exec',)),
    ('service', _string, ()),
    ('operation', _string, ()),
    ('region', _string, (True,)),
    ('safe_selector', _selector, ()),
    ('started_at', _timestamp, (True,)),
    ('finished_at', _timestamp, (True,)),
    ('collection_state', _enum_of, (CollectionState,)),
    ('error_code', _string, (True,)),
    ('page_count', _integer, (0, None, True)),
    ('pagination_complete', _boolean, (True,)),
    ('returned_count', _integer, (0, None, True)),
)
_FACT = (
    ('id', _hex64, ('fact',)),
    ('execution_id', _hex64, ('exec',)),
    ('call_refs', _strings, ()),
    ('source_ref', _string, ()),
    ('number', _integer, (1, 46, False)),
    ('resource_key', _string, (True,)),
    ('field_path', _string, ()),
    ('field_present', _boolean, ()),
    ('value', strict_json_value, ()),
    ('interpretation', _string, ()),
    ('scope_limit', _string, ()),
    ('observed_at', _timestamp, (True,)),
    ('provenance_level', _enum_of, (ProvenanceLevel,)),
)
_SCOPE = (
    ('id', _hex64, ('scope',)),
    ('execution_id', _hex64, ('exec',)),
    ('service', _string, ()),
    ('selector_basis', _string, ()),
    ('call_refs', _strings, ()),
    ('selected_resource_keys', _strings, ()),
    ('candidate_resource_keys', _strings, ()),
    ('coverage_state', _enum_of, (CoverageState,)),
    ('limitations', _strings, ()),
)
_RECORDS = {
    'executions': (Execution, _EXECUTION),
    'calls': (CallRecord, _CALL),
    'facts': (EvidenceFact, _FACT),
    'scope_checks': (ScopeCheck, _SCOPE),
}


def _parse_record(section: str, record: object, index: int):
    cls, spec = _RECORDS[section]
    what = f'{section}[{index}]'
    data = _object_of(record, what)
    _allowed_keys(data, {name for name, _, _ in spec}, what)
    _reject_credentials(data, what)
    kwargs = {
        name: convert(*((data.get(name), name, what) + args))
        for name, convert, args in spec
    }
    return cls(**kwargs)


def _validate_references(ledger: EvidenceLedger) -> None:
    """Duplicate IDs are global; execution and call refs must resolve."""
    seen: dict[str, str] = {}
    owned = (
        ('executions', ledger.executions), ('calls', ledger.calls),
        ('facts', ledger.facts), ('scope_checks', ledger.scope_checks),
    )
    for section, records in owned:
        for record in records:
            if record.id in seen:
                raise ValueError(
                    f'{seen[record.id]} and {section}: duplicate id {record.id}')
            seen[record.id] = section
    for record in (*ledger.calls, *ledger.facts, *ledger.scope_checks):
        if record.execution_id not in seen:
            raise ValueError(f'{record.id}: dangling execution ref {record.execution_id}')
    calls = {record.id for record in ledger.calls}
    for record in (*ledger.facts, *ledger.scope_checks):
        for ref in record.call_refs:
            if ref not in calls:
                raise ValueError(f'{record.id}: dangling reference to call {ref}')


def parse_ledger(data: object) -> EvidenceLedger:
    """Strictly parse a v1 evidence ledger; ValueError on any violation."""
    root = _object_of(data, 'ledger')
    _allowed_keys(root,
                 {'schema', 'executions', 'calls', 'facts', 'scope_checks'},
                 'ledger')
    _reject_credentials(root, 'ledger')
    if root.get('schema') != LEDGER_SCHEMA:
        raise ValueError(f'ledger.schema: unsupported schema {root.get("schema")!r}')
    parsed = {}
    for section in _RECORDS:
        items = root.get(section)
        if not isinstance(items, list):
            raise ValueError(f'ledger.{section}: expected a list of records')
        parsed[section] = tuple(
            _parse_record(section, item, index) for index, item in enumerate(items)
        )
    ledger = EvidenceLedger(**parsed, schema=root['schema'])
    _validate_references(ledger)
    return ledger


def _plain(value: object) -> JsonValue:
    """Canonical cells: enums to values, tuples to lists (asdict keeps tuples)."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_plain(child) for child in value]
    if isinstance(value, dict):
        return {key: _plain(child) for key, child in value.items()}
    return value


def ledger_to_json(ledger: EvidenceLedger) -> dict[str, JsonValue]:
    """Project the typed ledger back to exactly its canonical shape."""
    if not isinstance(ledger, EvidenceLedger):
        raise ValueError('ledger_to_json expects an EvidenceLedger instance')
    return _plain(asdict(ledger))


def evidence_id(kind: str, identity: JsonValue) -> str:
    """Deterministic ID: kind prefix plus SHA-256 of canonical identity JSON."""
    prefix = _PREFIX_BY_KIND.get(kind)
    if prefix is None:
        raise ValueError(f'evidence_id: unknown kind {kind!r}')
    payload = json.dumps(
        identity, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False,
    ).encode('utf-8')
    return f'{prefix}:{hashlib.sha256(payload).hexdigest()}'
