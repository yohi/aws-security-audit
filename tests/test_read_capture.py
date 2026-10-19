"""Tests for ContextVar-scoped read capture.

The capture must be a passive side-channel: existing api_call/paged
invocation arguments, counts and returned data stay identical to the
baseline without an active capture, and the recorded CallRecord
projections never contain credential slots, tokens or raw SDK text.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from aws_security_audit.core import EvidenceUnavailable, api_call, paged
from aws_security_audit.evidence_ledger import LEDGER_SCHEMA, evidence_id, parse_ledger
from aws_security_audit.evidence_types import CollectionState, Execution
from aws_security_audit.read_capture import ReadCapture, active_capture, capture_reads

REGION = 'ap-northeast-1'
SERVICE = 'ec2'

# Sentinels planted where credentials/SDK text could appear; none of them
# may ever surface inside serialized records.
BAD_ACCESS_KEY = 'AKIAIOSFODNN7SENTINEL'
BAD_SECRET_KEY = 'sentinel-secret-access-key-chars'
BAD_SESSION_TOKEN = 'sentinel-session-token-value'
BAD_SDK_MESSAGE = 'sentinel raw SDK failure text'


def execution(run: str = 'task2-tests') -> Execution:
    return Execution(
        id=evidence_id('execution', {'run': run}),
        source_kind='capture',
        account='111122223333',
        regions=(REGION,),
        product=None,
        started_at='2026-10-19T00:00:00+00:00',
        finished_at=None,
        source_digest=None,
        attestation='NOT_PROVEN',
    )


def denied(code: str = 'AccessDenied', operation: str = 'list_things') -> ClientError:
    return ClientError(
        {
            'Error': {'Code': code, 'Message': BAD_SDK_MESSAGE},
            'ResponseMetadata': {'HTTPStatusCode': 400},
        },
        operation,
    )


def no_code_error(operation: str = 'get_status') -> ClientError:
    """S3-style error payload where the Code key itself is absent."""
    return ClientError(
        {
            'Error': {'Message': BAD_SDK_MESSAGE},
            'ResponseMetadata': {'HTTPStatusCode': 404},
        },
        operation,
    )


class _Paginator:
    def __init__(self, client):
        self.client = client

    def paginate(self, **kwargs):
        self.client.invocations.append(('paginate', dict(kwargs)))
        for index, page in enumerate(self.client.pages):
            if self.client.fail_at is not None and index == self.client.fail_at:
                raise self.client.error
            yield page


class FakeClient:
    """Fake boto3 client: pages for native paginators, behaviors for manual."""

    def __init__(self, *, service=SERVICE, region=REGION, pages=None,
                 fail_at=None, error=None, behaviors=None, can_paginate=None):
        self.meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name=service),
            region_name=region,
        )
        self.pages = list(pages or [])
        self.fail_at = fail_at
        self.error = error
        self.behaviors = list(behaviors or [])
        self.default_response = {}
        self._can_paginate = can_paginate
        self.invocations = []

    def can_paginate(self, operation):
        self.invocations.append(('can_paginate', (operation,)))
        if self._can_paginate is None:
            return bool(self.pages)
        return self._can_paginate

    def get_paginator(self, operation):
        self.invocations.append(('get_paginator', (operation,)))
        return _Paginator(self)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)

        def dispatch(**kwargs):
            self.invocations.append((name, dict(kwargs)))
            if self.behaviors:
                kind, payload = self.behaviors[0]
                if not callable(payload):  # callable behaviors stay available
                    self.behaviors.pop(0)
            else:
                kind, payload = 'return', dict(self.default_response)
            if kind == 'raise':
                raise payload
            return payload(**kwargs) if callable(payload) else payload

        return dispatch


def records_json(snapshot):
    """Strict-JSON projection; proves nothing unserializable leaks in."""
    data = []
    for record in snapshot:
        row = asdict(record)
        row['collection_state'] = record.collection_state.value
        data.append(row)
    return json.loads(json.dumps(data))


# ---------------------------------------------------------------- baseline


def test_invocation_arguments_and_counts_match_baseline():
    def scenario():
        client = FakeClient(behaviors=[
            ('return', {'Arn': 'arn:ok'}),
            ('return', {'Items': ['a'], 'NextToken': 't1'}),
            ('return', {'Items': ['b']}),
        ])
        direct = api_call(client, 'get_status', Bucket='bucket-a')
        listed = paged(client, 'list_things', 'Items', Bucket='bucket-a')
        return list(client.invocations), [direct, listed]

    without_capture = scenario()
    with capture_reads(execution()) as capture:
        with_capture = scenario()
    assert without_capture[0] == with_capture[0], 'invocation traces differ'
    assert without_capture[1] == with_capture[1], 'returned data differs'
    assert len(capture.snapshot()) >= 1


def test_direct_api_call_records_one_observed_call():
    client = FakeClient(behaviors=[('return', {'Watchers': 3})])
    with capture_reads(execution()) as capture:
        api_call(client, 'get_status', Bucket='bucket-a', MaxResults=10)
    records = capture.snapshot()
    assert len(records) == 1
    record = records[0]
    assert record.execution_id == execution().id
    assert record.service == SERVICE
    assert record.operation == 'get_status'
    assert record.region == REGION
    assert record.collection_state is CollectionState.OBSERVED
    assert record.error_code is None
    assert record.page_count == 1
    assert record.pagination_complete is True
    assert record.returned_count is None
    assert record.safe_selector == {'Bucket': 'bucket-a', 'MaxResults': 10}
    assert record.id.startswith('call:')


def test_identical_calls_get_distinct_reproducible_ids():
    def scenario():
        with capture_reads(execution()) as capture:
            client = FakeClient(behaviors=[('return', {}), ('return', {})])
            api_call(client, 'get_status', Bucket='same')
            api_call(client, 'get_status', Bucket='same')
        return capture.snapshot()

    first, second = scenario(), scenario()
    assert first[1].id != first[0].id, 'two logical calls need distinct ids'
    assert first[0].id == second[0].id, 'same logical call has a stable id'


def test_record_timestamps_are_iso_utc():
    client = FakeClient(behaviors=[('return', {})])
    with capture_reads(execution()) as capture:
        api_call(client, 'get_status')
    record = capture.snapshot()[0]
    for stamp in (record.started_at, record.finished_at):
        assert stamp is not None
        parsed = datetime.fromisoformat(stamp)
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timedelta(0)


# ------------------------------------------------------------------- paged


def test_native_paginator_records_all_pages_as_one_call():
    client = FakeClient(pages=[
        {'Items': [1, 2]},
        {'Items': [3]},
        {'Items': []},
    ])
    with capture_reads(execution()) as capture:
        got = paged(client, 'list_things', 'Items', Bucket='bucket-a')
    assert got == [1, 2, 3]
    records = capture.snapshot()
    assert len(records) == 1, 'one logical paged call is one record'
    record = records[0]
    assert record.collection_state is CollectionState.OBSERVED
    assert record.page_count == 3
    assert record.pagination_complete is True
    assert record.returned_count == 3
    assert record.error_code is None


def test_denied_second_page_is_partial():
    client = FakeClient(
        pages=[{'Items': [1, 2]}, {'Items': []}],
        fail_at=1, error=denied('AccessDenied'),
    )
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable):
            paged(client, 'list_things', 'Items', Bucket='bucket-a')
    records = capture.snapshot()
    assert len(records) == 1
    record = records[0]
    assert record.collection_state is CollectionState.PARTIAL
    assert record.pagination_complete is False
    assert record.error_code == 'AccessDenied'
    assert record.returned_count == 2
    assert record.page_count == 2


def test_denied_first_page_is_access_denied():
    client = FakeClient(pages=[{'Items': [1]}], fail_at=0, error=denied())
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable):
            paged(client, 'list_things', 'Items', Bucket='bucket-a')
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.ACCESS_DENIED
    assert record.pagination_complete is False
    assert record.page_count == 1
    assert record.returned_count == 0


def test_zero_completed_rows_is_verified_empty():
    client = FakeClient(pages=[{'Items': []}, {'Items': []}])
    with capture_reads(execution()) as capture:
        got = paged(client, 'list_things', 'Items', Bucket='bucket-a')
    assert got == []
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.VERIFIED_EMPTY
    assert record.returned_count == 0
    assert record.page_count == 2
    assert record.pagination_complete is True


def test_successful_missing_result_field_is_verified_empty():
    client = FakeClient(pages=[{'Something': [1]}, {'Other': 2}])
    with capture_reads(execution()) as capture:
        got = paged(client, 'list_things', 'Items')
    assert got == []
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.VERIFIED_EMPTY
    assert record.page_count == 2
    assert record.pagination_complete is True


def test_manual_token_traversal_records_all_pages():
    client = FakeClient(behaviors=[
        ('return', {'Items': ['a'], 'NextToken': 't1'}),
        ('return', {'Items': ['b'], 'NextToken': 't2'}),
        ('return', {'Items': ['c']}),
    ])
    with capture_reads(execution()) as capture:
        got = paged(client, 'list_things', 'Items', Bucket='bucket-a')
    assert got == ['a', 'b', 'c']
    records = capture.snapshot()
    assert len(records) == 1, 'token pages must not become separate records'
    record = records[0]
    assert record.collection_state is CollectionState.OBSERVED
    assert record.page_count == 3
    assert record.pagination_complete is True
    assert record.returned_count == 3
    assert 'NextToken' not in record.safe_selector


def test_token_cycle_is_faulted_traversal_in_one_record():
    client = FakeClient(behaviors=[
        ('return', {'Items': ['a'], 'NextToken': 't1'}),
        ('return', {'Items': ['b'], 'NextToken': 't1'}),
    ])
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable, match='pagination cycle'):
            paged(client, 'list_things', 'Items')
    records = capture.snapshot()
    assert len(records) == 1
    record = records[0]
    assert record.collection_state is CollectionState.FAILED
    assert record.pagination_complete is False
    assert record.page_count == 2
    assert record.returned_count == 2
    assert record.error_code is None


def test_pagination_limit_is_faulted_traversal():
    counter = []
    def endless(**kwargs):
        counter.append(len(kwargs))
        return {'Items': [1], 'NextToken': f'next-{len(counter)}'}
    # Callable behavior keeps producing fresh tokens: the 10000-page
    # traversal guard has to trip before any token repeats.
    client = FakeClient(behaviors=[('return', endless)])
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable, match='pagination limit'):
            paged(client, 'list_things', 'Items')
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.FAILED
    assert record.pagination_complete is False
    assert record.page_count == 10000


def test_expired_session_failure_is_not_access_denied():
    client = FakeClient(behaviors=[('raise', denied('ExpiredToken'))])
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable):
            paged(client, 'list_things', 'Items')
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.FAILED
    assert record.error_code == 'ExpiredToken'
    assert record.pagination_complete is False


def test_botocore_failure_is_faulted():
    client = FakeClient(behaviors=[('raise', NoCredentialsError())])
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable):
            api_call(client, 'get_status')
    record = capture.snapshot()[0]
    assert record.collection_state is CollectionState.FAILED
    assert record.error_code == 'NoCredentialsError'


def test_s3_error_without_code_uses_fallback():
    client = FakeClient(service='s3', behaviors=[('raise', no_code_error())])
    with capture_reads(execution()) as capture:
        with pytest.raises(EvidenceUnavailable) as err:
            api_call(client, 'get_status', Bucket='bucket-a')
    assert str(err.value).endswith('get_status: ClientError')
    record = capture.snapshot()[0]
    assert record.service == 's3'
    assert record.error_code == 'ClientError'
    assert record.collection_state is CollectionState.FAILED


# ----------------------------------------------- exceptions stay compatible


def test_evidence_unavailable_keeps_message_only_construction():
    plain = EvidenceUnavailable('plain message')
    assert str(plain) == 'plain message'
    assert plain.service is None
    assert plain.operation is None
    assert plain.code is None
    assert plain.collection_state is None


def test_failure_exception_carries_optional_context():
    client = FakeClient(behaviors=[('raise', denied())])
    with capture_reads(execution()):
        with pytest.raises(EvidenceUnavailable) as err:
            api_call(client, 'get_status')
    assert err.value.service == SERVICE
    assert err.value.operation == 'get_status'
    assert err.value.code == 'AccessDenied'
    assert err.value.collection_state is CollectionState.ACCESS_DENIED


# --------------------------------------------------------- context scoping


def test_nested_contexts_route_records_to_the_inner_scope():
    with capture_reads(execution()) as outer:
        api_call(FakeClient(), 'get_status')
        with capture_reads(execution('task2-inner')) as inner:
            api_call(FakeClient(), 'get_status')
        api_call(FakeClient(), 'get_status')
    assert len(inner.snapshot()) == 1
    assert inner.snapshot()[0].execution_id == execution('task2-inner').id
    assert len(outer.snapshot()) == 2
    with capture_reads(execution('after')) as later:
        pass
    assert later.snapshot() == ()


def test_context_cleans_up_after_an_error():
    failing = FakeClient(behaviors=[('raise', denied())])
    with capture_reads(execution()) as capture:
        api_call(FakeClient(), 'get_status')
        with pytest.raises(EvidenceUnavailable):
            api_call(failing, 'get_status')
        assert len(capture.snapshot()) == 2
        after = FakeClient(behaviors=[('return', {})])
        api_call(after, 'get_status')
        assert len(capture.snapshot()) == 3
    assert active_capture() is None
    outside = FakeClient()
    api_call(outside, 'get_status')
    assert len(capture.snapshot()) == 3, 'no records after the context ended'


# -------------------------------------------------------- selector hygiene


def test_selector_allowlist_drops_tokens_and_unsafe_values():
    client = FakeClient(behaviors=[('return', {'NextToken': BAD_SESSION_TOKEN})])
    kwargs = {
        'Bucket': 'bucket-a',
        'Prefix': 'logs/',
        'NextToken': BAD_SESSION_TOKEN,
        'SecretAccessKey': BAD_SECRET_KEY,
        'SessionFactory': 'opaque-session',
        'Authorization': BAD_ACCESS_KEY,
        'VolumeIds': ['vol-1', 'vol-2'],
        'MaxResults': 5,
        'RoleArn': 'arn:aws:iam::111122223333:role/some-role',
        'OwnerInfo': {'Topic': 'complex object dropped'},
        'NextMarker': 'opaque-marker',
    }
    with capture_reads(execution()) as capture:
        api_call(client, 'get_status', **kwargs)
    record = capture.snapshot()[0]
    assert record.safe_selector == {
        'Bucket': 'bucket-a',
        'Prefix': 'logs/',
        'VolumeIds': ['vol-1', 'vol-2'],
        'MaxResults': 5,
        'RoleArn': 'arn:aws:iam::111122223333:role/some-role',
    }


def test_sentinels_never_occur_in_serialized_records():
    mixed = FakeClient(behaviors=[
        ('return', {'Items': ['x'], 'NextToken': f'{BAD_SESSION_TOKEN}-1'}),
        ('return', {'Items': ['y'], 'NextToken': f'{BAD_SESSION_TOKEN}-2'}),
        ('return', {'Items': ['z']}),
    ], pages=[], can_paginate=False)
    client_with_key = FakeClient(behaviors=[
        ('return', {'Marker': BAD_SESSION_TOKEN}),
        ('return', {'Quota': 7, 'SessionToken': BAD_SESSION_TOKEN}),
    ], pages=[], can_paginate=False)
    with capture_reads(execution()) as capture:
        paged(mixed, 'list_things', 'Items', Bucket='bucket-a')
        api_call(client_with_key, 'get_status', SecretAccessKey=BAD_SECRET_KEY)
        with pytest.raises(EvidenceUnavailable):
            api_call(FakeClient(behaviors=[('raise', denied())]), 'get_status')
    serialized = json.dumps(records_json(capture.snapshot()))
    for sentinel in (BAD_ACCESS_KEY, BAD_SECRET_KEY, BAD_SESSION_TOKEN, BAD_SDK_MESSAGE):
        assert sentinel not in serialized


def test_records_round_trip_through_v1_ledger_parse():
    native = FakeClient(pages=[{'Items': [1]}, {'Items': [2]}])
    partial = FakeClient(pages=[{'Items': [3]}, {'Items': []}], fail_at=1,
                         error=denied('AccessDenied'))
    empty = FakeClient(behaviors=[('return', {'No': 'result field'})], can_paginate=False)
    cycle = FakeClient(behaviors=[
        ('return', {'Items': ['a'], 'NextToken': 't1'}),
        ('return', {'Items': ['b'], 'NextToken': 't1'}),
    ])
    expired = FakeClient(behaviors=[('raise', denied('ExpiredToken'))])
    with capture_reads(execution()) as capture:
        paged(native, 'list_things', 'Items')
        with pytest.raises(EvidenceUnavailable):
            paged(partial, 'list_things', 'Items')
        paged(empty, 'list_things', 'Items')
        with pytest.raises(EvidenceUnavailable, match='pagination cycle'):
            paged(cycle, 'list_things', 'Items')
        with pytest.raises(EvidenceUnavailable):
            paged(expired, 'list_things', 'Items')
    records = records_json(capture.snapshot())
    execution_row = asdict(execution())
    execution_row['regions'] = [REGION]
    ledger = parse_ledger({
        'schema': LEDGER_SCHEMA,
        'executions': [execution_row],
        'calls': records,
        'facts': [],
        'scope_checks': [],
    })
    assert len(ledger.calls) == len(records)
    assert all(
        isinstance(call.collection_state, CollectionState)
        for call in ledger.calls
    )


def test_capture_without_exception_records_transparently():
    client = FakeClient(pages=[{'Items': [1]}])
    with capture_reads(execution()) as capture:
        paged(client, 'list_things', 'Items', Bucket='bucket-a')
    assert isinstance(capture, ReadCapture)
    assert capture.snapshot() == tuple(capture.snapshot())
    assert active_capture() is None
