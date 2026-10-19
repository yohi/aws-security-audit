"""Evidence ledger v1: round trip, stable IDs and strict offline parsing.

Malformed inputs (invalid enums/types, duplicate or dangling references,
invalid UTC timestamps, unsupported schemas, credential-like and other
unknown fields) must raise ValueError at parse boundaries. Synthetic data
only: no private account values appear in any fixture.
"""
from __future__ import annotations

import copy

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.evidence_ledger import (
    evidence_id,
    ledger_to_json,
    parse_ledger,
)
from aws_security_audit.evidence_types import (
    BusinessResolutionState,
    ControlReview,
)

FACT_KIND = 'fact'


def test_ledger_round_trip_and_stable_ids(ledger_json):
    parsed = parse_ledger(ledger_json)
    assert ledger_to_json(parsed) == ledger_json
    assert evidence_id(FACT_KIND, {'a': 1, 'b': 2}) == evidence_id(
        FACT_KIND, {'b': 2, 'a': 1}
    )
    # Repeated canonical identity keeps the same derived ID, while another
    # run identity (execution) never collides with it.
    first = evidence_id('execution', {'run': 'synthetic-run-0001'})
    second = evidence_id('execution', {'run': 'synthetic-run-0002'})
    assert first != second
    assert evidence_id(FACT_KIND, {'execution': first}) != evidence_id(
        FACT_KIND, {'execution': second}
    )
    assert ledger_json['executions'][0]['id'] == evidence_id('execution', {
        'run': 'synthetic-run-0001',
        'account': '111122223333',
    })


def test_round_trip_survives_reparsing(ledger_json):
    once = ledger_to_json(parse_ledger(ledger_json))
    twice = ledger_to_json(parse_ledger(once))
    assert twice == once


def test_review_factory_preserves_catalog_and_adoption(review_model):
    assert isinstance(review_model, ControlReview)
    assert [row.number for row in review_model.rows] == list(range(1, 47))
    assert [row.title for row in review_model.rows] == [
        definition.title for definition in CHECKS
    ]
    assert all(
        row.business_resolution_state is BusinessResolutionState.NOT_EVALUATED
        for row in review_model.rows
    )
    assert all(not row.owner_adoption_verified for row in review_model.rows)


def test_evidence_id_rejects_unknown_kind():
    with pytest.raises(ValueError):
        evidence_id('mystery-kind', {})


def test_evidence_id_rejects_arbitrary_object():
    with pytest.raises(TypeError):
        evidence_id(FACT_KIND, {'value': {1, 2}})


def test_ledger_to_json_rejects_non_ledger():
    with pytest.raises(ValueError):
        ledger_to_json({'schema': 'aws-security-evidence-ledger-v1'})


# --- malformed-input rejection matrix --------------------------------------


def _unsupported_schema(data):
    data['schema'] = 'aws-security-evidence-ledger-v2'

def _selector_nonstring_key(data):
    data['calls'][0]['safe_selector'] = {1: 'x'}



def _unknown_field(data):
    data['executions'][0]['weather'] = 'sunny'


def _credential_like_field(data):
    data['executions'][0]['safe_selector'] = {'aws_secret_access_key': 'x'}


def _credential_like_nested(data):
    data['calls'][0]['safe_selector'] = {
        'region': 'ap-northeast-1',
        'tags': {
            'session_token': 'synthetic-leaky-value',  # must never be accepted
        },
    }


def _invalid_enum(data):
    data['calls'][0]['collection_state'] = 'OBSERVED_ENOUGH'


def _invalid_type(data):
    data['calls'][0]['page_count'] = 'one'


def _invalid_bool(data):
    data['calls'][0]['pagination_complete'] = 'true'


def _invalid_control_number(data):
    data['facts'][0]['number'] = 0


def _invalid_value_type(data):
    data['facts'][0]['value'] = {'nested': {1: 2}}  # non-string object key


def _duplicate_execution_id(data):
    data['executions'].append(data['executions'][0])


def _duplicate_id_across_sections(data):
    data['scope_checks'][0]['id'] = data['facts'][0]['id']


def _dangling_call_ref(data):
    data['facts'][0]['call_refs'] = ['call:' + '0' * 64]


def _dangling_execution_ref(data):
    data['calls'][0]['execution_id'] = 'exec:' + '0' * 64


def _execution_ref_with_call_id_prefix(data):
    data['calls'][0]['execution_id'] = data['calls'][0]['id']


def _invalid_utc_timestamp(data):
    data['executions'][0]['started_at'] = '2026-10-19T00:00:00'


def _non_utc_timestamp(data):
    data['executions'][0]['started_at'] = '2026-10-19T09:00:00+09:00'


def _not_a_string_timestamp(data):
    data['calls'][0]['started_at'] = 20261019


def _malformed_id(data):
    data['executions'][0]['id'] = 'exec-' + 'a' * 64


def _invalid_coverage_state(data):
    data['scope_checks'][0]['coverage_state'] = 'COMPLETE'


def _unsupported_attestation(data):
    data['executions'][0]['attestation'] = 'OWNER_SIGNED'


def _scope_limit_not_list(data):
    data['scope_checks'][0]['limitations'] = 'plain string instead of list'


@pytest.mark.parametrize('mangle', [
    pytest.param(_unsupported_schema, id='unsupported-schema'),
    pytest.param(_unknown_field, id='unknown-field'),
    pytest.param(_credential_like_field, id='credential-like-field'),
    pytest.param(_credential_like_nested, id='credential-like-nested'),
    pytest.param(_invalid_enum, id='invalid-enum'),
    pytest.param(_invalid_type, id='invalid-type'),
    pytest.param(_invalid_bool, id='invalid-bool'),
    pytest.param(_invalid_control_number, id='invalid-control-number'),
    pytest.param(_invalid_value_type, id='invalid-value-type'),
    pytest.param(_selector_nonstring_key, id='selector-nonstring-key'),
    pytest.param(_duplicate_execution_id, id='duplicate-id'),
    pytest.param(_duplicate_id_across_sections, id='duplicate-id-cross-section'),
    pytest.param(_dangling_call_ref, id='dangling-call-ref'),
    pytest.param(_dangling_execution_ref, id='dangling-execution-ref'),
    pytest.param(_execution_ref_with_call_id_prefix,
                 id='execution-ref-with-call-id-prefix'),
    pytest.param(_invalid_utc_timestamp, id='invalid-utc-timestamp'),
    pytest.param(_non_utc_timestamp, id='non-utc-timestamp'),
    pytest.param(_not_a_string_timestamp, id='non-string-timestamp'),
    pytest.param(_malformed_id, id='malformed-id'),
    pytest.param(_invalid_coverage_state, id='invalid-coverage-state'),
    pytest.param(_unsupported_attestation, id='unsupported-attestation'),
    pytest.param(_scope_limit_not_list, id='scope-limit-not-list'),
])
def test_malformed_ledgers_raise_value_error(ledger_json, mangle):
    data = copy.deepcopy(ledger_json)
    mangle(data)
    with pytest.raises(ValueError):
        parse_ledger(data)


def test_malformed_root_container_rejected():
    with pytest.raises(ValueError):
        parse_ledger([])
    with pytest.raises(ValueError):
        parse_ledger({'schema': None, 'executions': 'nope'})
