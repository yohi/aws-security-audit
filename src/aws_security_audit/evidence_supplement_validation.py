from __future__ import annotations

from typing import Final

from .evidence_adapter_projection import (
    control_number, json_object, text_member,
)
from .evidence_types import JsonObject, JsonValue

MCP_SCHEMA: Final = 'aws-security-mcp-observation-summary-v1'
R24_SCHEMA: Final = 'aws-ros-r24-targeted-evidence-v1'
R24_FIELDS: Final[dict[int, tuple[str, ...]]] = {
    8: ('control_8_shield',),
    24: ('control_24_cloudtrail',),
    27: ('control_27_flow_logs',),
    33: ('control_33_securityhub',),
    39: ('control_39_inspector', 'control_39_ecr'),
    40: ('control_40_ci',),
}


def validate_r24_supplement(
    bundle: JsonObject, r24: JsonValue | None, account: str | None,
) -> dict[int, list[JsonObject]]:
    """Strict R24 scope/account compatibility, unchanged from upstream."""
    if r24 is None:
        return {}
    data = json_object(r24, 'R24 supplement')
    execution_value = bundle.get('execution')
    if execution_value is None:
        raise ValueError('R24 product/region/account mismatch')
    execution = json_object(execution_value, 'bundle.execution')
    regions = execution.get('requested_regions')
    if (not isinstance(regions, list)
            or any(not isinstance(region, str) for region in regions)
            or not isinstance(data.get('account'), str)
            or data.get('schema') != R24_SCHEMA
            or data.get('product') != execution.get('product')
            or data.get('region') not in regions
            or account is not None and data.get('account') != account):
        raise ValueError('R24 product/region/account mismatch')
    grouped: dict[int, list[JsonObject]] = {}
    for number, keys in R24_FIELDS.items():
        for key in keys:
            if key not in data:
                continue
            block = json_object(data[key], key)
            grouped.setdefault(number, []).append({
                'source': key, 'state': block.get('state'),
            })
    return grouped


def validate_mcp_summary(
    bundle: JsonObject, mcp: JsonValue | None, account: str | None,
) -> dict[int, list[JsonObject]]:
    """Only bounded attributed summaries, not raw payloads or attestations."""
    if mcp is None:
        return {}
    data = json_object(mcp, 'MCP summary')
    execution_value = bundle.get('execution')
    if execution_value is None:
        raise ValueError('Untrusted MCP summary schema/scope')
    execution = json_object(execution_value, 'bundle.execution')
    if set(data) != {
            'schema', 'account', 'region', 'product', 'source', 'records'}:
        raise ValueError('Untrusted MCP summary schema/scope')
    schema = text_member(data, 'schema')
    source = text_member(data, 'source')
    region = text_member(data, 'region')
    account_value = text_member(data, 'account')
    requested_regions = execution.get('requested_regions')
    if not isinstance(requested_regions, list):
        raise ValueError('Untrusted MCP summary schema/scope')
    region_values: list[str] = []
    for requested_region in requested_regions:
        if not isinstance(requested_region, str):
            raise ValueError('Untrusted MCP summary schema/scope')
        region_values.append(requested_region)
    records_value = data.get('records')
    if (schema != MCP_SCHEMA
            or source not in ('OPERATOR_CURATED_MCP_READONLY_SUMMARY',
                              'ASSISTANT_CURATED_MCP_READONLY_SUMMARY')
            or data.get('product') != execution.get('product')
            or region not in region_values
            or len(account_value) != 12 or not account_value.isdigit()
            or (account is not None and account_value != account)
            or not isinstance(records_value, list) or len(records_value) > 150):
        raise ValueError('Untrusted MCP summary schema/scope')
    grouped: dict[int, list[JsonObject]] = {}
    for item in records_value:
        row = json_object(item, 'mcp.records[]')
        if set(row) != {'number', 'api', 'state', 'fact', 'scope_limit'}:
            raise ValueError('MCP summary row invalid or not a read-only operation')
        number = control_number(row.get('number'), 'mcp.records[].number')
        api = text_member(row, 'api')
        state = text_member(row, 'state')
        fact = text_member(row, 'fact')
        scope_limit = text_member(row, 'scope_limit')
        if (not api.split('.')[-1].startswith(
                ('Get', 'Describe', 'List', 'BatchGet'))
                or not fact.strip() or len(fact) > 600
                or state not in ('OBSERVED', 'UNVERIFIED')
                or not scope_limit.strip() or len(scope_limit) > 400):
            raise ValueError('MCP summary row invalid or not a read-only operation')
        grouped.setdefault(number, []).append(row)
    return grouped
