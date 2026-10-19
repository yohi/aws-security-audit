"""Legacy bundle and supplementary-source projection into the evidence ledger.

Synthetic fixtures only: every identifier, account and observation is inert
test data and no AWS access happens anywhere.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json

import pytest

from aws_security_audit.evidence_adapters import build_ledger
from aws_security_audit.evidence_ledger import (
    evidence_id,
    ledger_to_json,
    parse_ledger,
)
from aws_security_audit.evidence_types import (
    LEDGER_SCHEMA,
    CallRecord,
    CollectionState,
    Execution,
    ProvenanceLevel,
)
from aws_security_audit.read_capture import capture_reads


ACCOUNT = '111122223333'
REGION = 'ap-northeast-1'
BUNDLE_ROW_REF = 'resource_inventory.control_observations.rows[0]'


def canonical_digest(data) -> str:
    """The module's documented canonical-bytes hash, recomputed for asserts."""
    return sha256(json.dumps(
        data, ensure_ascii=False, sort_keys=True,
        separators=(',', ':'), allow_nan=False,
    ).encode('utf-8')).hexdigest()


def live_execution() -> Execution:
    return Execution(
        id=evidence_id('execution', {'run': 'synthetic-live-run-1'}),
        source_kind='live_capture_v1',
        account=ACCOUNT,
        regions=(REGION,),
        product='synthetic',
        started_at=None,
        finished_at=None,
        source_digest=None,
        attestation='NOT_PROVEN',
    )


def make_call(sequence: int = 1, **overrides) -> CallRecord:
    """A detached synthetic CallRecord on the shared live execution identity."""
    execution_id = live_execution().id
    values = dict(
        service='s3',
        operation='get_bucket_versioning',
        region=REGION,
        selector={'Bucket': 'synthetic-bucket-1'},
        started_at='2026-10-19T00:00:01Z',
        finished_at='2026-10-19T00:00:02Z',
        collection_state=CollectionState.OBSERVED,
        error_code=None,
        page_count=1,
        pagination_complete=True,
        returned_count=1,
    )
    values.update(overrides)
    return CallRecord(
        id=evidence_id('call', {
            'execution': execution_id,
            'service': values['service'],
            'operation': values['operation'],
            'region': values['region'],
            'selector': values['selector'],
            'sequence': sequence,
        }),
        execution_id=execution_id,
        service=values['service'],
        operation=values['operation'],
        region=values['region'],
        safe_selector=values['selector'],
        started_at=values['started_at'],
        finished_at=values['finished_at'],
        collection_state=values['collection_state'],
        error_code=values['error_code'],
        page_count=values['page_count'],
        pagination_complete=values['pagination_complete'],
        returned_count=values['returned_count'],
    )


def control_row(**overrides) -> dict:
    entry = {
        'number': 22, 'service': 's3', 'resource_type': 'bucket',
        'region': REGION, 'resource_id': 'synthetic-bucket-1',
        'attribution': 'DIRECT', 'property': 'versioning_status',
        'observed_value': {'versioning': 'Enabled', 'object_lock': None},
        'property_result': 'PROPERTY_OK',
        'interpretation': 'Selected bucket versioning is explicitly enabled.',
        'scope_limit': 'Single selected bucket; not product-wide versioning.',
    }
    entry.update(overrides)
    return entry


def synthetic_web_review_bundle() -> dict:
    """A minimal legacy aws_web_review bundle with one observation row."""
    from aws_security_audit.offline_classification import CONTROL_EVIDENCE_PLAN
    controls = []
    plans = []
    for number in range(1, 47):
        route, requirement, owner = CONTROL_EVIDENCE_PLAN[number]
        controls.append({
            'number': number, 'title': f'Synthetic #{number}',
            'criterion': 'Synthetic criterion only',
            'account_status': 'FAIL' if number == 22 else 'MANUAL_REVIEW',
            'regional_status': 'MANUAL_REVIEW',
        })
        plans.append({
            'number': number, 'acquisition_route': route,
            'preferred_evidence_request': requirement,
            'human_context_required_by_criterion': owner,
        })
    return {
        'schema': 'aws-security-audit-web-review-v1',
        'purpose': 'INVESTIGATION_ONLY',
        'decision_support': {'plans': plans},
        'execution': {
            'scanner_version': 'synthetic-0.0.0',
            'timestamp_utc': '2026-10-19T00:00:00+00:00',
            'requested_regions': [REGION],
            'available_regions': [REGION],
            'region_coverage_full': False,
            'audit_scope': 'product', 'product': 'synthetic',
            'product_selector': {'mode': 'tag', 'value': 'synthetic'},
            'product_attribution_complete': False,
        },
        'resource_inventory': {'control_observations': {
            'rows': [control_row()],
            'by_control': {
                str(number): {
                    'ok': 1 if number == 22 else 0,
                    'fail': 0, 'unknown': 0, 'context': 0,
                }
                for number in range(1, 47)
            },
        }},
        'controls': controls,
    }


def synthetic_r24_supplement(account: str = ACCOUNT) -> dict:
    """A minimal R24 targeted-evidence artifact for control #39."""
    return {
        'schema': 'aws-ros-r24-targeted-evidence-v1',
        'product': 'synthetic', 'account': account, 'region': REGION,
        'control_39_inspector': {
            'state': 'OBSERVED_PARTIAL', 'error_code': None,
            'provenance_level': 'COLLECTOR_PROJECTED',
        },
        'control_39_ecr': {'state': 'NOT_REQUESTED'},
    }


def synthetic_mcp_summary(
        source: str = 'OPERATOR_CURATED_MCP_READONLY_SUMMARY') -> dict:
    """A minimal bounded MCP summary with one read-only record."""
    return {
        'schema': 'aws-security-mcp-observation-summary-v1',
        'account': ACCOUNT, 'region': REGION, 'product': 'synthetic',
        'source': source,
        'records': [{
            'number': 8, 'api': 'shield.GetSubscriptionState',
            'state': 'OBSERVED', 'fact': 'SubscriptionState=ACTIVE',
            'scope_limit': 'Account subscription only, not an Owner '
                           'classification.',
        }],
    }


def joint_bundle(row_overrides: dict | None = None,
                 extra_row: dict | None = None) -> dict:
    """The synthetic bundle with its observation row optionally modified."""
    bundle = deepcopy(synthetic_web_review_bundle())
    row = bundle['resource_inventory']['control_observations']['rows'][0]
    row.update(row_overrides or {})
    if extra_row is not None:
        bundle['resource_inventory']['control_observations'][
            'rows'].append(extra_row)
    return bundle


# --- Legacy bundle projection -------------------------------------------


def test_legacy_values_and_source_refs_survive():
    ledger = build_ledger(joint_bundle())
    fact = ledger.facts[0]
    assert fact.source_ref == BUNDLE_ROW_REF
    assert fact.number == 22
    assert fact.field_path == 'versioning_status'
    assert fact.field_present is True
    assert fact.value == {'versioning': 'Enabled', 'object_lock': None}
    assert fact.resource_key == 'synthetic-bucket-1'
    assert fact.interpretation == \
        'Selected bucket versioning is explicitly enabled.'
    assert fact.scope_limit == ('Single selected bucket; not product-wide '
                                'versioning. Bundle attribution record at '
                                'row level: DIRECT.')
    assert fact.provenance_level is ProvenanceLevel.LEGACY_SOURCE
    assert ledger.schema == LEDGER_SCHEMA
    assert ledger.scope_checks == ()


def test_absent_observed_value_stays_null_not_false():
    bundle = joint_bundle()
    bundle['resource_inventory']['control_observations']['rows'][0].pop(
        'observed_value')
    ledger = build_ledger(bundle)
    fact = ledger.facts[0]
    assert fact.field_present is False
    assert fact.value is None


def test_absent_observed_time_and_call_records_stay_unknown():
    ledger = build_ledger(joint_bundle())
    execution = ledger.executions[0]
    assert len(ledger.executions) == 1
    assert ledger.calls == ()
    assert all(fact.observed_at is None for fact in ledger.facts)
    assert all(fact.call_refs == () for fact in ledger.facts)
    assert execution.started_at is None
    assert execution.finished_at is None
    assert execution.account == 'unknown'


def test_execution_identity_is_artifact_digest():
    bundle = joint_bundle()
    ledger = build_ledger(bundle)
    execution = ledger.executions[0]
    assert execution.id == f'exec:{canonical_digest(bundle)}'
    assert execution.source_kind == 'legacy_bundle_v1'
    assert execution.source_digest == canonical_digest(bundle)
    assert execution.attestation == 'NOT_PROVEN'
    assert execution.regions == (REGION,)
    assert execution.product == 'synthetic'
    assert ledger.schema == LEDGER_SCHEMA
    assert ledger.scope_checks == ()


def test_round_trip_is_strict_and_stable():
    bundle = joint_bundle()
    ledger = build_ledger(bundle)
    reparsed = parse_ledger(ledger_to_json(ledger))
    assert ledger_to_json(reparsed) == ledger_to_json(ledger)
    again = build_ledger(json.loads(json.dumps(bundle)))
    assert ledger_to_json(again) == ledger_to_json(ledger)


def test_altered_input_bytes_rebind_identity():
    ledger_before = build_ledger(joint_bundle())
    ledger_after = build_ledger(joint_bundle(
        {'observed_value': {'versioning': 'Disabled', 'object_lock': None}}))
    assert ledger_after.executions[0].id != ledger_before.executions[0].id
    assert ledger_after.facts[0].id != ledger_before.facts[0].id
    assert ledger_after.facts[0].value == {
        'versioning': 'Disabled', 'object_lock': None}


def test_bundle_schema_mismatch_rejected():
    with pytest.raises(ValueError):
        build_ledger({'schema': 'other-file'})


def test_malformed_bundle_row_rejected():
    bundle = joint_bundle()
    row = bundle['resource_inventory']['control_observations']['rows'][0]
    del row['property']
    with pytest.raises(ValueError):
        build_ledger(bundle)


# --- Joining current captured calls -------------------------------------


def test_verified_call_joins_only_matching_fact():
    call = make_call()
    ledger = build_ledger(joint_bundle(), calls=(call,))
    assert ledger.facts[0].call_refs == (call.id,)
    live = [e for e in ledger.executions if e.source_kind == 'live_capture_v1']
    assert len(live) == 1
    assert ledger.calls[0].id == call.id


@pytest.mark.parametrize('row_overrides, call_overrides', [
    ({'service': 'kinesis'}, {}),
    ({'region': 'us-west-2'}, {}),
    ({'service': None}, {}),
    ({'resource_id': 'synthetic-bucket-9'}, {}),
    ({}, {'service': 'kinesis'}),
    ({}, {'region': 'us-east-1'}),
    ({}, {'selector': {'Bucket': 'synthetic-bucket-2'}}),
    ({}, {'selector': {}}),
    ({}, {'collection_state': CollectionState.ACCESS_DENIED}),
])
def test_join_requires_verified_identity(row_overrides, call_overrides):
    ledger = build_ledger(
        joint_bundle(row_overrides=row_overrides),
        calls=(make_call(**call_overrides),))
    assert ledger.facts[0].call_refs == ()


def test_ambiguous_join_has_no_invented_call_ref():
    ledger = build_ledger(
        joint_bundle(), calls=(make_call(sequence=1), make_call(sequence=2)))
    assert ledger.facts[0].call_refs == ()
    assert len(ledger.calls) == 2
    assert len({call.id for call in ledger.calls}) == 2


def test_active_capture_join_uses_real_execution():
    execution = live_execution()
    with capture_reads(execution) as capture:
        capture.record(
            service='s3',
            operation='get_bucket_versioning',
            region=REGION,
            selector={'Bucket': 'synthetic-bucket-1'},
            started_at='2026-10-19T00:00:01Z',
            finished_at='2026-10-19T00:00:02Z',
            collection_state=CollectionState.OBSERVED,
            error_code=None,
            page_count=1,
            pagination_complete=True,
            returned_count=1,
        )
        ledger = build_ledger(joint_bundle())
    assert ledger.facts[0].call_refs == (ledger.calls[0].id,)
    assert [e.account for e in ledger.executions if e.id == execution.id] \
        == [ACCOUNT]


# --- Supplementary sources ----------------------------------------------


@pytest.mark.parametrize('source', [
    'OPERATOR_CURATED_MCP_READONLY_SUMMARY',
    'ASSISTANT_CURATED_MCP_READONLY_SUMMARY',
])
def test_mcp_curated_sources_projection(source):
    ledger = build_ledger(
        joint_bundle(), mcp_summary=synthetic_mcp_summary(source),
        expected_account=ACCOUNT)
    ref = 'mcp_summary.records[0]'
    fact = [f for f in ledger.facts if f.source_ref == ref][0]
    expected = (ProvenanceLevel.ASSISTANT_CURATED
                if source.startswith('ASSISTANT')
                else ProvenanceLevel.OPERATOR_CURATED)
    assert fact.provenance_level is expected
    assert fact.number == 8
    assert fact.call_refs == ()
    assert fact.observed_at is None
    assert fact.field_path == 'shield.GetSubscriptionState'
    assert fact.value == {'state': 'OBSERVED',
                          'fact': 'SubscriptionState=ACTIVE'}
    assert fact.scope_limit == \
        'Account subscription only, not an Owner classification.'
    execution = [e for e in ledger.executions
                 if e.source_kind.startswith('mcp_')][0]
    assert execution.account == ACCOUNT
    assert execution.regions == (REGION,)
    assert execution.source_kind == (
        'mcp_assistant_curated_summary' if source.startswith('ASSISTANT')
        else 'mcp_operator_curated_summary')


def test_r24_supplement_projection():
    ledger = build_ledger(
        joint_bundle(), r24=synthetic_r24_supplement(),
        expected_account=ACCOUNT)
    facts = {f.field_path: f for f in ledger.facts
             if f.source_ref.startswith('r24_targeted_evidence.')}
    assert set(facts) == {'control_39_inspector', 'control_39_ecr'}
    inspector = facts['control_39_inspector']
    assert inspector.number == 39
    assert inspector.value == {
        'state': 'OBSERVED_PARTIAL', 'error_code': None,
        'provenance_level': 'COLLECTOR_PROJECTED',
    }
    assert inspector.provenance_level is ProvenanceLevel.LEGACY_SOURCE
    assert inspector.call_refs == ()
    assert inspector.observed_at is None
    execution = [e for e in ledger.executions
                 if e.source_kind == 'r24_targeted_evidence_v1'][0]
    assert execution.account == ACCOUNT
    assert execution.regions == (REGION,)
    assert execution.product == 'synthetic'


def test_supplements_absent_produce_no_supplement_facts():
    ledger = build_ledger(joint_bundle())
    assert not [f for f in ledger.facts
                if f.source_ref.startswith(('r24_targeted_evidence.',
                                            'mcp_summary.'))]
    assert [e.source_kind for e in ledger.executions] == ['legacy_bundle_v1']


@pytest.mark.parametrize('mutate, supplement', [
    (lambda a: a.update(account='999999999999'), 'r24'),
    (lambda a: a.update(product='other'), 'r24'),
    (lambda a: a.update(region='us-east-1'), 'r24'),
    (lambda a: a.update(account='999999999999'), 'mcp'),
    (lambda a: a.update(product='other'), 'mcp'),
    (lambda a: a.update(region='us-east-1'), 'mcp'),
    (lambda a: a.update(source='UNTRUSTED_MCP'), 'mcp'),
])
def test_mismatched_supplement_context_rejected(mutate, supplement):
    given = synthetic_r24_supplement() if supplement == 'r24' \
        else synthetic_mcp_summary()
    mutate(given)
    kwargs = {'r24': given} if supplement == 'r24' else {'mcp_summary': given}
    with pytest.raises(ValueError):
        build_ledger(joint_bundle(), expected_account=ACCOUNT, **kwargs)


def test_expected_account_check_only_when_given():
    ledger = build_ledger(
        joint_bundle(),
        r24=synthetic_r24_supplement('999999999999'),
        mcp_summary=synthetic_mcp_summary(),
    )
    assert {e.account for e in ledger.executions} == {
        'unknown', ACCOUNT, '999999999999'}


def test_malformed_mcp_records_rejected():
    summary = synthetic_mcp_summary()
    summary['records'][0]['scope_limit'] = ''
    with pytest.raises(ValueError):
        build_ledger(joint_bundle(), mcp_summary=summary)


def test_malformed_present_r24_block_rejected():
    malformed = synthetic_r24_supplement()
    malformed['control_39_inspector'] = 'not-an-object'

    with pytest.raises(ValueError, match='control_39_inspector'):
        build_ledger(joint_bundle(), r24=malformed, expected_account=ACCOUNT)


def test_conflicting_facts_stay_visible():
    extra = control_row(
        observed_value={'versioning': 'Disabled', 'object_lock': None},
        attribution='SHARED_UNATTRIBUTED')
    ledger = build_ledger(joint_bundle(extra_row=extra))
    facts = ledger.facts
    assert len(facts) == 2
    assert {f.value['versioning'] for f in facts} == {'Enabled', 'Disabled'}
    assert {f.source_ref for f in facts} == {
        BUNDLE_ROW_REF,
        'resource_inventory.control_observations.rows[1]',
    }
    assert len({f.id for f in facts}) == 2


def test_forged_source_levels_and_digests_never_upgrade_trust():
    r24 = synthetic_r24_supplement()
    r24['source_digest'] = 'ff' * 32
    r24['attestation'] = 'PROVEN'
    ledger = build_ledger(
        joint_bundle(), r24=r24,
        mcp_summary=synthetic_mcp_summary(), expected_account=ACCOUNT)
    assert all(e.attestation == 'NOT_PROVEN' for e in ledger.executions)
    assert [e.source_digest for e in ledger.executions
            if e.source_kind == 'r24_targeted_evidence_v1'] \
        == [canonical_digest(r24)]
    fact = [f for f in ledger.facts
            if f.source_ref == 'r24_targeted_evidence.control_39_inspector'][0]
    assert fact.provenance_level is ProvenanceLevel.LEGACY_SOURCE


def test_progress_report_embeds_projected_ledger():
    from aws_security_audit.evidence_progress_report import (
        build_evidence_progress,
    )
    report = build_evidence_progress(
        joint_bundle(),
        r24=synthetic_r24_supplement(),
        mcp_summary=synthetic_mcp_summary(),
        expected_account=ACCOUNT,
    )
    ledger = report['evidence_ledger']
    assert ledger['schema'] == LEDGER_SCHEMA
    sources = {e['source_kind'] for e in ledger['executions']}
    assert sources == {
        'legacy_bundle_v1', 'r24_targeted_evidence_v1',
        'mcp_operator_curated_summary',
    }


def test_account_scope_bundle_without_observations_builds_ledger():
    from aws_security_audit.evidence_progress_report import (
        build_evidence_progress,
    )
    bundle = joint_bundle()
    bundle['execution']['audit_scope'] = 'account'
    bundle['resource_inventory'] = {'resources': [],
                                    'collection_errors': []}
    ledger = build_ledger(bundle)
    # Account-scope bundles tolerate the missing observation section.
    assert ledger.facts == ()
    assert ledger.executions[0].source_kind == 'legacy_bundle_v1'
    report = build_evidence_progress(bundle)
    assert report['summary']['original_attribute_observation_rows'] == 0
    assert report['evidence_ledger'] == ledger_to_json(ledger)


def test_malformed_observation_rows_still_fail_closed():
    bundle = joint_bundle()
    bundle['resource_inventory']['control_observations']['rows'] = 'bad'
    with pytest.raises(ValueError):
        build_ledger(bundle)


# --- Embedded ledger extension handling ---------------------------------

def test_embedded_ledger_is_reused():
    bundle = joint_bundle()
    first = build_ledger(bundle)
    bundle['evidence_ledger'] = ledger_to_json(first)
    second = build_ledger(bundle)
    assert ledger_to_json(second) == ledger_to_json(first)


def test_embedded_ledger_rejects_changed_source_bundle():
    bundle = joint_bundle()
    bundle['evidence_ledger'] = ledger_to_json(build_ledger(bundle))
    bundle['resource_inventory']['control_observations']['rows'][0][
        'interpretation'] = 'Modified after ledger generation.'

    with pytest.raises(ValueError, match='source digest'):
        build_ledger(bundle)


def test_embedded_ledger_rejects_modified_fact_value():
    bundle = joint_bundle()
    embedded = ledger_to_json(build_ledger(bundle))
    embedded['facts'][0]['value'] = {'versioning': 'Disabled'}
    bundle['evidence_ledger'] = embedded

    with pytest.raises(ValueError, match='does not match bundle evidence'):
        build_ledger(bundle)


def test_embedded_ledger_rejects_live_execution_scope_mismatch():
    bundle = joint_bundle()
    ledger = build_ledger(
        bundle, calls=(make_call(),), execution=live_execution())
    embedded = ledger_to_json(ledger)
    live = next(
        execution for execution in embedded['executions']
        if execution['source_kind'] == 'live_capture_v1')
    live['product'] = 'different-product'
    bundle['evidence_ledger'] = embedded

    with pytest.raises(ValueError, match='live execution scope'):
        build_ledger(bundle)


def test_invalid_embedded_ledger_rejected():
    bundle = joint_bundle()
    bundle['evidence_ledger'] = {'schema': 'aws-security-evidence-ledger-v1'}
    with pytest.raises(ValueError):
        build_ledger(bundle)


def test_embedded_ledger_with_supplement_appended():
    bundle = joint_bundle()
    first = build_ledger(bundle)
    bundle['evidence_ledger'] = ledger_to_json(first)
    ledger = build_ledger(
        bundle, r24=synthetic_r24_supplement(), expected_account=ACCOUNT)
    r24_refs = {f.source_ref for f in ledger.facts
                if f.source_ref.startswith('r24_targeted_evidence.')}
    assert r24_refs == {
        'r24_targeted_evidence.control_39_inspector',
        'r24_targeted_evidence.control_39_ecr',
    }


# --- Operation-aware call joins ------------------------------------------

def test_join_verifies_operation_when_row_has_api():
    matching = make_call(operation='get_bucket_versioning')
    mismatch = make_call(
        operation='get_bucket_encryption', sequence=2,
        selector={'Bucket': 'synthetic-bucket-1'})
    bundle = joint_bundle({'api': 's3.GetBucketVersioning'})
    ledger = build_ledger(bundle, calls=(matching, mismatch))
    assert ledger.facts[0].call_refs == (matching.id,)


def test_join_falls_back_when_row_has_no_operation():
    call = make_call()
    ledger = build_ledger(joint_bundle(), calls=(call,))
    assert ledger.facts[0].call_refs == (call.id,)


# --- Scope diagnostics attached to ledger --------------------------------

def test_scope_checks_attached_when_resources_present():
    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [{
        'service': 's3',
        'resource_type': 'bucket',
        'region': REGION,
        'resource_id': 'synthetic-bucket-1',
        'name': 'synthetic-bucket-1',
        'attribution': 'DIRECT',
        'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {},
    }]
    ledger = build_ledger(bundle)
    assert len(ledger.scope_checks) == 1
    assert ledger.scope_checks[0].service == 'selector'


def test_embedded_scope_checks_preserve_candidate_hints():
    from aws_security_audit.scope_coverage import (
        build_scope_checks, scope_checks_to_json,
    )

    selected = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'resource_id': 'selected-bucket', 'name': 'selected-bucket',
        'attribution': 'DIRECT', 'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {},
    }
    candidate = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'resource_id': 'synthetic-candidate', 'name': 'synthetic-candidate',
        'attribution': 'UNCLASSIFIED', 'attributes': {},
    }
    scope = {'mode': 'product', 'product': 'synthetic'}
    checks = scope_checks_to_json(
        build_scope_checks([selected, candidate], [selected], scope, ()))
    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [selected]
    bundle['resource_inventory']['scope'] = {
        **scope,
        'scope_candidate_resource_keys': [
            f'{REGION}/bucket/synthetic-candidate',
        ],
        'scope_checks': json.loads(json.dumps(checks)),
    }

    ledger = build_ledger(bundle)

    candidate_keys = [
        key for check in ledger.scope_checks
        for key in check.candidate_resource_keys
    ]
    assert candidate_keys == [f'{REGION}/bucket/synthetic-candidate']


def test_scope_checks_reject_selected_resources_not_in_inventory():
    from aws_security_audit.scope_coverage import (
        build_scope_checks, scope_checks_to_json,
    )

    selected = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'resource_id': 'selected-bucket', 'name': 'selected-bucket',
        'attribution': 'DIRECT', 'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {},
    }
    scope = {'mode': 'product', 'product': 'synthetic'}
    raw_checks = scope_checks_to_json(
        build_scope_checks([selected], [selected], scope, ()))
    raw_checks[0]['selected_resource_keys'] = [
        f'{REGION}/bucket/forged-bucket',
    ]
    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [selected]
    bundle['resource_inventory']['scope'] = {
        **scope, 'scope_checks': json.loads(json.dumps(raw_checks)),
    }

    with pytest.raises(ValueError, match='scope_checks'):
        build_ledger(bundle)


def test_scope_checks_reject_candidate_keys_not_in_inventory_source():
    from aws_security_audit.scope_coverage import (
        build_scope_checks, scope_checks_to_json,
    )

    selected = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'resource_id': 'selected-bucket', 'name': 'selected-bucket',
        'attribution': 'DIRECT', 'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {},
    }
    candidate = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'resource_id': 'synthetic-candidate', 'name': 'synthetic-candidate',
        'attribution': 'UNCLASSIFIED', 'attributes': {},
    }
    scope = {'mode': 'product', 'product': 'synthetic'}
    checks = scope_checks_to_json(
        build_scope_checks([selected, candidate], [selected], scope, ()))
    candidate_check = next(
        check for check in checks
        if check['selector_basis'] == 'NAME:product-token-hint')
    candidate_check['candidate_resource_keys'] = [
        f'{REGION}/bucket/forged-candidate',
    ]
    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [selected]
    bundle['resource_inventory']['scope'] = {
        **scope,
        'scope_candidate_resource_keys': [
            f'{REGION}/bucket/synthetic-candidate',
        ],
        'scope_checks': json.loads(json.dumps(checks)),
    }

    with pytest.raises(ValueError, match='candidate keys'):
        build_ledger(bundle)


def test_scope_candidate_source_requires_scope_diagnostics():
    bundle = joint_bundle()
    bundle['resource_inventory']['scope'] = {
        'mode': 'product',
        'product': 'synthetic',
        'scope_candidate_resource_keys': [
            f'{REGION}/bucket/synthetic-candidate',
        ],
    }

    with pytest.raises(ValueError, match='scope_checks'):
        build_ledger(bundle)


def test_product_observation_operation_provenance_joins_matching_call():
    from aws_security_audit.control_observations import build_product_observations

    bucket = {
        'service': 's3', 'resource_type': 'bucket', 'region': REGION,
        'name': 'synthetic-bucket-1', 'resource_id': 'synthetic-bucket-1',
        'arn': '', 'attribution': 'DIRECT',
        'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {'default_encryption_algorithms': ['AES256']},
    }
    observations = build_product_observations({'resources': [bucket]}, [REGION])
    row = next(row for row in observations['rows'] if row['number'] == 17)
    assert row['api'] == 's3.GetBucketEncryption'

    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [bucket]
    bundle['resource_inventory']['control_observations'] = observations
    call = make_call(operation='get_bucket_encryption')
    ledger = build_ledger(bundle, calls=(call,))
    fact = next(fact for fact in ledger.facts if fact.number == 17)
    assert fact.call_refs == (call.id,)


def test_api_join_matches_resource_arn_selector():
    from aws_security_audit.control_observations import build_product_observations

    arn = (
        'arn:aws:elasticloadbalancing:ap-northeast-1:111122223333:'
        'loadbalancer/app/synthetic/abc123'
    )
    load_balancer = {
        'service': 'elbv2', 'resource_type': 'application', 'region': REGION,
        'name': 'synthetic-alb', 'resource_id': 'synthetic-alb', 'arn': arn,
        'attribution': 'DIRECT',
        'attribution_evidence': 'TAG:Project=synthetic',
        'attributes': {'waf_web_acl_arn': 'arn:aws:wafv2:...'},
    }
    observations = build_product_observations(
        {'resources': [load_balancer]}, [REGION])
    bundle = joint_bundle()
    bundle['resource_inventory']['resources'] = [load_balancer]
    bundle['resource_inventory']['control_observations'] = observations
    call = make_call(
        service='wafv2', operation='get_web_acl_for_resource',
        selector={'ResourceArn': arn})

    ledger = build_ledger(bundle, calls=(call,))

    fact = next(fact for fact in ledger.facts if fact.number == 6)
    assert fact.call_refs == (call.id,)
