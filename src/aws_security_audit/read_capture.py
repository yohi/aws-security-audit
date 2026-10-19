"""ContextVar-scoped capture of existing read-only API call outcomes.

`capture_reads(execution)` is a pure side-channel: `api_call` and `paged`
keep their signatures, call counts and returned data, and while a capture
is active they additionally project each logical call into a metadata-only
`CallRecord`. Nothing here retries, adds an API call, captures
authentication artifacts or grants permissions.

Safety rules:
- one logical `paged` traversal (native paginator or manual token walk)
  becomes exactly one record, whatever happens per page;
- selectors are allowlisted: credential/token-like keys and values, complex
  objects and opaque markers are dropped before anything is stored;
- error contents other than the AWS symbolic code are never recorded;
- record IDs are deterministic per execution via `evidence_id`, with a
  per-capture sequence distinguishing repeated identical calls.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import re
from datetime import datetime, timezone

from .evidence_ledger import evidence_id
from .evidence_types import CallRecord, CollectionState, Execution, JsonValue

# Credential-shaped key/content fragments; deliberately broader than the
# ledger schema boundary (evidence_ledger._CREDENTIAL_PATTERN): dropping
# more is always safe, keeping something secret-shaped never is.
_CREDENTIAL_HINT = re.compile(
    r'(?i)pass|secret|token|credential|auth|bearer|signature|'
    r'api[_-]?key|key[_-]?id|marker|continuation|session|nonce')

# Selector keys are conservative: short identifier-style names only.
_KEY_SHAPE = re.compile(r'[A-Za-z][A-Za-z0-9]{0,63}')

# Opaque strings longer than this are treated as unclassifiable and dropped.
_VALUE_LIMIT = 128

# AWS symbolic codes that prove a permission denial; anything else maps to
# FAILED. An expired session is an availability failure, never evidence of
# a permission gap.
DENIED_CODES = frozenset({
    'AccessDenied',
    'AccessDeniedException',
    'UnauthorizedOperation',
    'Forbidden',
    'Unauthorized',
})
_FALLBACK_CODE = 'ClientError'


def utc_now() -> str:
    """ISO-8601 UTC instant acceptable to the v1 ledger timestamp rule."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def state_for(code: str | None) -> CollectionState:
    """Map an AWS symbolic error code to a collection state."""
    if code in DENIED_CODES:
        return CollectionState.ACCESS_DENIED
    return CollectionState.FAILED


def sanitized_code(code: object) -> str | None:
    """Symbolic-code projection: reject everything but a short safe label."""
    if code is None:
        return None
    safe = re.sub(r'[^A-Za-z0-9_-]', '', str(code))[:64]
    return safe or None


def client_meta(client: object) -> tuple[str | None, str | None]:
    """Service name and region projected from the client, without secrets."""
    meta = getattr(client, 'meta', None)
    service = getattr(getattr(meta, 'service_model', None), 'service_name', None)
    region = getattr(meta, 'region_name', None)
    return service, region


_DROP = object()


def _clean_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if (value == value and abs(value) != float('inf')) else _DROP
    if isinstance(value, str):
        if len(value) > _VALUE_LIMIT or _CREDENTIAL_HINT.search(value):
            return _DROP
        return value
    if isinstance(value, (list, tuple)):
        cleaned = [_clean_value(item) for item in value]
        if any(item is _DROP or isinstance(item, (list, tuple, dict)) for item in cleaned):
            return _DROP
        return cleaned
    # Dictionaries and everything else stay out of selectors.
    return _DROP


def safe_selector(kwargs: dict) -> dict[str, JsonValue]:
    """Allowlisted projection of call kwargs; token/credential-like excluded."""
    selector: dict[str, JsonValue] = {}
    for key, value in kwargs.items():
        if not isinstance(key, str) or not _KEY_SHAPE.fullmatch(key):
            continue
        if _CREDENTIAL_HINT.search(key):
            continue
        cleaned = _clean_value(value)
        if cleaned is not _DROP:
            selector[key] = cleaned
    return selector


class ReadCapture:
    """Accumulates CallRecord projections for one capture_reads scope."""

    def __init__(self, execution: Execution):
        self._execution = execution
        self._records: list[CallRecord] = []
        # Repeated identical calls need distinct record IDs: count per
        # identity key so IDs stay deterministic within the same run shape.
        self._sequence: dict[str, int] = {}
        self._page_recording = True

    @property
    def execution(self) -> Execution:
        return self._execution

    @property
    def page_recording(self) -> bool:
        return self._page_recording

    @contextmanager
    def suppress_page_records(self):
        """Internal: core's manual token traversal routes pages through
        api_call; the logical paged call must record pages itself instead
        of letting each page become its own record."""
        previous = self._page_recording
        self._page_recording = False
        try:
            yield
        finally:
            self._page_recording = previous

    def record(
        self,
        *,
        service: str | None,
        operation: str,
        region: str | None,
        selector: dict[str, JsonValue],
        started_at: str | None,
        finished_at: str | None,
        collection_state: CollectionState,
        error_code: str | None,
        page_count: int | None,
        pagination_complete: bool | None,
        returned_count: int | None,
    ) -> CallRecord:
        identity_key = json.dumps(
            [service, operation, region, selector],
            sort_keys=True, separators=(',', ':'), allow_nan=False,
        )
        sequence = self._sequence.get(identity_key, 0) + 1
        self._sequence[identity_key] = sequence
        record = CallRecord(
            id=evidence_id('call', {
                'execution': self._execution.id,
                'service': service,
                'operation': operation,
                'region': region,
                'selector': selector,
                'sequence': sequence,
            }),
            execution_id=self._execution.id,
            service=service or 'unknown',
            operation=operation,
            region=region,
            safe_selector=selector,
            started_at=started_at,
            finished_at=finished_at,
            collection_state=collection_state,
            error_code=error_code,
            page_count=page_count,
            pagination_complete=pagination_complete,
            returned_count=returned_count,
        )
        self._records.append(record)
        return record

    def snapshot(self) -> tuple[CallRecord, ...]:
        return tuple(self._records)


_CAPTURE: ContextVar[ReadCapture | None] = ContextVar(
    'aws_audit_read_capture', default=None)


def active_capture() -> ReadCapture | None:
    """The ReadCapture active for this execution context, if any."""
    return _CAPTURE.get()


@contextmanager
def capture_reads(execution: Execution):
    """Scope ReadCapture to the current execution context; stackable."""
    capture = ReadCapture(execution)
    token = _CAPTURE.set(capture)
    try:
        yield capture
    finally:
        _CAPTURE.reset(token)
