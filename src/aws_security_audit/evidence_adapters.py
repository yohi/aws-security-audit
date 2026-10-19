from __future__ import annotations

from .evidence_supplement_validation import (  # noqa: F401
    MCP_SCHEMA,
    R24_FIELDS,
    validate_mcp_summary,
    validate_r24_supplement,
)
from .evidence_types import CallRecord, EvidenceLedger, Execution, JsonObject


def build_ledger(
    bundle: JsonObject,
    *,
    r24: JsonObject | None = None,
    mcp_summary: JsonObject | None = None,
    expected_account: str | None = None,
    calls: tuple[CallRecord, ...] | None = None,
    execution: Execution | None = None,
) -> EvidenceLedger:
    from .evidence_adapter_builder import build_ledger as build

    return build(
        bundle, r24=r24, mcp_summary=mcp_summary,
        expected_account=expected_account, calls=calls, execution=execution)
