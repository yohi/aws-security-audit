"""Synthetic evidence-ledger and control-review fixtures for offline tests.

Factories derive all IDs via evidence_id() so repeated builds are stable, and
contain no private account IDs, ARNs, IPs or real observations. No AWS access
happens here and no credentials appear anywhere.
"""
from __future__ import annotations

import pytest

from aws_security_audit.catalog import CHECKS
from aws_security_audit.evidence_ledger import evidence_id, parse_ledger
from aws_security_audit.evidence_types import (
    LEDGER_SCHEMA,
    REVIEW_SCHEMA,
    BusinessResolutionState,
    CallRecord,
    CollectionState,
    ControlReview,
    ControlReviewRow,
    EvidenceFact,
    EvidenceGap,
    EvidenceLedger,
    EvidenceRequest,
    EvidenceState,
    GapKind,
    ProvenanceLevel,
    ScannerStatus,
)

RUN = 'synthetic-run-0001'
ACCOUNT = '111122223333'
REGION = 'ap-northeast-1'


def synthetic_ledger_json() -> dict:
    """A complete v1 ledger with one execution, call, fact and scope check."""
    execution_id = evidence_id('execution', {'run': RUN, 'account': ACCOUNT})
    call_id = evidence_id('call', {
        'execution': execution_id,
        'service': 's3',
        'operation': 'list_buckets',
        'region': REGION,
    })
    fact_id = evidence_id('fact', {
        'execution': execution_id,
        'control': 22,
        'field_path': 'Status',
        'resource': 'synthetic-bucket-1',
    })
    scope_id = evidence_id('scope', {'execution': execution_id, 'service': 's3'})
    return {
        'schema': LEDGER_SCHEMA,
        'executions': [{
            'id': execution_id,
            'source_kind': 'capture',
            'account': ACCOUNT,
            'regions': [REGION],
            'product': 'synthetic',
            'started_at': '2026-10-19T00:00:00Z',
            'finished_at': '2026-10-19T00:00:05Z',
            'source_digest': 'ab' * 32,
            'attestation': 'NOT_PROVEN',
        }],
        'calls': [{
            'id': call_id,
            'execution_id': execution_id,
            'service': 's3',
            'operation': 'list_buckets',
            'region': REGION,
            'safe_selector': {'region': REGION},
            'started_at': '2026-10-19T00:00:01Z',
            'finished_at': '2026-10-19T00:00:02Z',
            'collection_state': 'OBSERVED',
            'error_code': None,
            'page_count': 1,
            'pagination_complete': True,
            'returned_count': 1,
        }],
        'facts': [{
            'id': fact_id,
            'execution_id': execution_id,
            'call_refs': [call_id],
            'source_ref': f'calls/{call_id}/returned[0]',
            'number': 22,
            'resource_key': 'synthetic-bucket-1',
            'field_path': 'Status',
            'field_present': True,
            'value': 'Enabled',
            'interpretation': 'Explicit versioning status is enabled for the selected bucket.',
            'scope_limit': 'Single resource observation; not a complete product verdict.',
            'observed_at': '2026-10-19T00:00:02Z',
            'provenance_level': 'COLLECTOR_PROJECTED',
        }],
        'scope_checks': [{
            'id': scope_id,
            'execution_id': execution_id,
            'service': 's3',
            'selector_basis': 'synthetic name-prefix selection',
            'call_refs': [call_id],
            'selected_resource_keys': ['synthetic-bucket-1'],
            'candidate_resource_keys': [
                'synthetic-bucket-1',
                'synthetic-untagged-candidate',
            ],
            'coverage_state': 'PARTIAL',
            'limitations': [
                'Name-prefix hints may omit untagged resources; not product-wide coverage.',
            ],
        }],
    }


def synthetic_ledger() -> EvidenceLedger:
    """The synthetic ledger as parsed dataclasses."""
    return parse_ledger(synthetic_ledger_json())


def synthetic_control_review() -> ControlReview:
    """46 review rows from the normative catalog; no evidence granted yet."""
    regional = {REGION: ScannerStatus.MANUAL_REVIEW}
    rows = [
        ControlReviewRow(
            number=definition.number,
            category=definition.category,
            title=definition.title,
            criterion=definition.criterion,
            severity=definition.severity,
            purpose=definition.purpose,
            scanner_status=ScannerStatus.MANUAL_REVIEW,
            scanner_regional_status=regional,
            fact_refs=(),
            scope_refs=(),
            criterion_checks=(),
            evidence_state=EvidenceState.NO_EVIDENCE,
            gaps=(),
            request_ids=(),
            business_resolution_state=BusinessResolutionState.NOT_EVALUATED,
            business_label_provisional=None,
            owner_adoption_verified=False,
        )
        for definition in CHECKS
    ]
    requests = (
        EvidenceRequest(
            id=evidence_id('request', {
                'kind': 'OWNER_CONTEXT',
                'scope_key': 'account',
                'requirement_key': 'synthetic-oncall-contacts',
            }),
            kind=GapKind.OWNER_CONTEXT,
            scope_key='account',
            requirement_key='synthetic-oncall-contacts',
            controls=(46,),
            evidence_refs=(),
            required_evidence='Owner-provided synthetic on-call contact document.',
            acquisition_route='OWNER_DOCUMENTATION',
        ),
    )
    return ControlReview(
        schema=REVIEW_SCHEMA,
        rows=tuple(rows),
        requests=requests,
    )


def synthetic_gap(row_number: int) -> EvidenceGap:
    """A minimal stable gap usable by review rows and request builders."""
    return EvidenceGap(
        id=evidence_id('gap', {
            'kind': 'MACHINE_EVIDENCE',
            'scope_key': f'product:{REGION}',
            'requirement_key': 'synthetic-missing-setting',
        }),
        kind=GapKind.MACHINE_EVIDENCE,
        scope_key=f'product:{REGION}',
        requirement_key='synthetic-missing-setting',
        controls=(row_number,),
        evidence_refs=(),
        required_evidence='Machine-readable configuration export naming one synthetic setting.',
        acquisition_route='AWS_READ_ONLY_CANDIDATE',
    )


def synthetic_call_record() -> CallRecord:
    """Representative call record for capture-facing tests (Task 2 and later)."""
    execution_id = evidence_id('execution', {'run': RUN, 'account': ACCOUNT})
    return CallRecord(
        id=evidence_id('call', {
            'execution': execution_id,
            'service': 'ec2',
            'operation': 'describe_snapshots',
            'region': REGION,
        }),
        execution_id=execution_id,
        service='ec2',
        operation='describe_snapshots',
        region=REGION,
        safe_selector={},
        started_at='2026-10-19T00:00:01Z',
        finished_at='2026-10-19T00:00:03Z',
        collection_state=CollectionState.PARTIAL,
        error_code='ThrottlingException',
        page_count=2,
        pagination_complete=False,
        returned_count=30,
    )


def synthetic_legacy_fact(observed_at: str | None) -> EvidenceFact:
    """The synthetic fact as a legacy observation with curated provenance."""
    base = synthetic_ledger().facts[0]
    return EvidenceFact(
        id=base.id,
        execution_id=base.execution_id,
        call_refs=base.call_refs,
        source_ref=base.source_ref,
        number=base.number,
        resource_key=base.resource_key,
        field_path=base.field_path,
        field_present=base.field_present,
        value=base.value,
        interpretation=base.interpretation,
        scope_limit=base.scope_limit,
        observed_at=observed_at,
        provenance_level=ProvenanceLevel.LEGACY_SOURCE,
    )


@pytest.fixture
def ledger_json() -> dict:
    return synthetic_ledger_json()


@pytest.fixture
def ledger_model() -> EvidenceLedger:
    return synthetic_ledger()


@pytest.fixture
def review_model() -> ControlReview:
    return synthetic_control_review()
