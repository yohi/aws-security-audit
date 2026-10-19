"""Criterion-aware 46-row offline control review (control review v1).

Projects the bundle and typed ledger into one ControlReview: originals stay
verbatim, criterion checks separate observed facts from open questions,
legacy/curated sources never grant SUPPORTED_FOR_DECLARED_SCOPE, Owner
adoption stays false, and requests are supplied by the later task.
"""
from __future__ import annotations

from dataclasses import asdict

from .catalog import CHECKS
from .evidence_adapter_projection import observation_rows
from .evidence_ledger import _plain as _plain_json, evidence_id
from .evidence_reconciliation import reconcile_control
from .evidence_requests import is_observation_fact
from .evidence_types import (REVIEW_SCHEMA, BusinessResolutionState,
                             ControlReview, ControlReviewRow, CriterionCheck,
                             CriterionState, EvidenceGap, EvidenceLedger,
                             EvidenceState, GapKind, ScannerStatus)
from .offline_classification import (CONTROL_EVIDENCE_PLAN,
                                     validate_classification_result)
from .shared_evidence import build_cross_control_evidence

SCANNER = {'PASS', 'FAIL', 'UNKNOWN', 'MANUAL_REVIEW', 'NOT_APPLICABLE'}
_SPECIALIZED = frozenset({5, 17, 18, 20, 23, 45})
_ROW_PREFIX = 'resource_inventory.control_observations.rows['
_SHARED_SCOPE = (2, 17, 20, 23)
_SUPPORT_NOTE = ('Automated snapshot existence reused from #20 never proves '
                 'a successful restore drill, backup scope or schedule.')
# Plan: an observed mismatch cannot alone resolve 未対応 versus 対応中, so a
# mismatched criterion check always leaves a REMEDIATION_STATUS question.
_REMEDIATION_NOTE = 'Dated owner record of the remediation status after the mismatch.'
_EGRESS = 'public ingress and all-protocol public egress'
_ACCOUNT_BPA = 'S3 account-level Block Public Access context'
_ACCESS_POINTS = 'S3 selected bucket access point listing/detail configuration'
_KEY_PROP = {17: 'default_encryption_algorithms',
             20: 'effective storage encryption'}
_MATCH_NAME = {17: 'bucket default encryption algorithm',
               20: 'RDS storage and automated snapshot encryption'}
_COVERAGE_NAME = {17: 'declared-scope bucket inspection coverage',
                  20: 'RDS storage declared-scope coverage'}


def validated_head(bundle: object) -> tuple[list[dict], list[dict]]:
    """Strict 46-control bundle head; same rules as the progress report."""
    if not isinstance(bundle, dict) or bundle.get('schema') != 'aws-security-audit-web-review-v1':
        raise ValueError('Invalid original web review evidence schema')
    controls = bundle.get('controls')
    plans = (bundle.get('decision_support') or {}).get('plans')
    if (not isinstance(controls, list) or not isinstance(plans, list)
            or len(controls) != 46 or len(plans) != 46):
        raise ValueError('Exactly 46 controls and acquisition plans required')
    for i, (control, plan) in enumerate(zip(controls, plans), 1):
        if (not isinstance(control, dict) or not isinstance(plan, dict)
                or type(control.get('number')) is not int or control['number'] != i
                or type(plan.get('number')) is not int or plan['number'] != i
                or plan.get('acquisition_route') != CONTROL_EVIDENCE_PLAN[i][0]
                or control.get('account_status') not in SCANNER
                or not isinstance(control.get('title'), str)):
            raise ValueError('Control identity/route/status mismatch')
    return controls, plans


def _comp(number, name, state, fact_refs=(), scope_refs=(), limitation=None):
    return CriterionCheck(
        id=evidence_id('criterion', {'control': number, 'component': name}),
        component=name, state=state, fact_refs=tuple(fact_refs),
        scope_refs=tuple(scope_refs or ()), limitation=limitation)


def _obs(number, rows, facts, name, prop, rtype=None, limit=None):
    return _comp(number, name, _state(number, rows, prop, rtype),
                 _picked(_indexes(rows, number, prop, rtype), facts), limitation=limit)


def _open(number, name, refs, scoped, limit):
    return _comp(number, name, CriterionState.UNRESOLVED, refs, scoped, limit)

def _indexes(rows, number, prop=None, rtype=None) -> list:
    return [i for i, row in enumerate(rows)
            if isinstance(row, dict) and row.get('number') == number
            and (prop is None or row.get('property') == prop)
            and (rtype is None or row.get('resource_type') == rtype)]


def _state(number, rows, prop=None, rtype=None) -> CriterionState:
    results = {row.get('property_result') for row in rows
               if isinstance(row, dict) and row.get('number') == number
               and (prop is None or row.get('property') == prop)
               and (rtype is None or row.get('resource_type') == rtype)}
    if 'PROPERTY_OK' in results and 'PROPERTY_FAIL' in results:
        return CriterionState.CONFLICTING
    for token, state in (('PROPERTY_FAIL', CriterionState.OBSERVED_MISMATCH),
                         ('PROPERTY_OK', CriterionState.OBSERVED_MATCH)):
        if token in results:
            return state
    return CriterionState.UNRESOLVED


def _picked(indexes, facts: dict) -> list:
    return [facts[i].id for i in indexes if i in facts]


def _join_scopes(ledger: EvidenceLedger, fact_ids: tuple) -> tuple:
    wanted = set(fact_ids)
    keys = {f.resource_key for f in ledger.facts if f.id in wanted} - {None}
    return tuple(check.id for check in ledger.scope_checks
                 if set(check.selected_resource_keys) & keys)


def _specialized(number, rows, rules, scoped, facts, cross) -> tuple:
    m = (rules['not_required_by_original_criterion'] or [''])[0]
    o = (rules['remaining_decision_questions'] or [''])[0]
    if number == 5:
        return (
            _obs(number, rows, facts, 'unnecessary inbound rule coverage', None,
                 limit='Resource-level rule observations never close the '
                       'necessity question for these security groups.'),
            _open(number, 'allow-all outbound rule necessity',
_picked(_indexes(rows, number, _EGRESS), facts), scoped,
f'{m} {o}'),
        )
    if number in (17, 20):
        return (
            _obs(number, rows, facts, _MATCH_NAME[number], _KEY_PROP[number], limit=m),
            _open(number, _COVERAGE_NAME[number], (), scoped, o),
        )
    if number == 18:
        return (
            _obs(number, rows, facts, 'bucket BPA four flags',
                 'bucket_public_access_block', limit=m),
            _open(number, 'account-level BPA obligation',
                  _picked(_indexes(rows, number, _ACCOUNT_BPA), facts),
                  scoped, f'{m} {o}'),
            _open(number, 'other public reachability paths',
                  _picked(_indexes(rows, number, _ACCESS_POINTS), facts),
                  scoped, f'{m} {o}'),
        )
    if number == 23:
        member = _indexes(rows, number, 'DeletionProtection', 'db-instance')
        return (
            _obs(number, rows, facts, 'RDS cluster DeletionProtection',
                 'DeletionProtection', 'db-cluster'),
            _open(number, 'Aurora member instance availability',
                  _picked(member, facts), scoped,
                  f'{o} Member instance deletion stays separate from cluster deletion '
                  'protection; only the cluster attribute satisfies the stated criterion.'),
        )
    if number == 45:
        refs = [facts[i].id for ref in cross
                if (i := int(ref['id'].rsplit(':', 1)[1])) in facts]
        return (
            _open(number, 'automated snapshot existence coverage', refs,
                  scoped, _SUPPORT_NOTE),
            _open(number, 'restore drill performed and successful', (), scoped,
                  'No snapshot observation proves a performed or successful '
                  'restore drill; dated drill records are required '
                  'separately.'),
        )
    raise ValueError(f'No criterion decomposition for control #{number}')


_GAP_SPEC = {5: (GapKind.OWNER_CONTEXT, 'egress-rule-business-necessity',
        'Dated owner confirmation that observed allow-all outbound '
        'rules are required for these security groups.'),
    18: (GapKind.CRITERION_INTERPRETATION, 'account-vs-bucket-bpa-obligation',
         'Interpreter-approved decision whether account-wide or scoped '
         'bucket BPA satisfies the account/bucket criterion.'),
    45: (GapKind.OWNER_DOCUMENT, 'restore-drill-success-record',
         'Dated record of a performed and successful restore drill.')}


def _gap(number, kind, key, required, scope_key, refs=()) -> EvidenceGap:
    return EvidenceGap(
        id=evidence_id('gap', {'control': number, 'kind': kind.value,
                               'requirement': key}),
        kind=kind, scope_key=scope_key, requirement_key=key,
        controls=(number,), evidence_refs=tuple(refs),
        required_evidence=required,
        acquisition_route=CONTROL_EVIDENCE_PLAN[number][0])


def _gaps(number, scope_key, fact_ids, facts, checks, scope_ids) -> tuple:
    out = []
    if number in _GAP_SPEC:
        kind, key, required = _GAP_SPEC[number]
        out.append(_gap(number, kind, key, required, scope_key, fact_ids))
    if number in _SHARED_SCOPE:
        out.append(_gap(number, GapKind.OWNER_CONTEXT,
                        'product-resource-and-region-coverage',
                        'Owner-approved record of the declared '
                        'product/region asset scope shared by controls '
                        '2/17/20/23.', scope_key, scope_ids))
    # Only validated observations may remove the machine gap; unverified
    # R24/MCP supplements and assistant-curated claims never count.
    if not any(is_observation_fact(fact) for fact in facts):
        out.append(_gap(number, GapKind.MACHINE_EVIDENCE,
                        'missing-machine-observation',
                        'A machine-readable observation of the '
                        'control-relevant resource attributes.',
                        scope_key))
    if (mism := [c for c in checks if c.state is CriterionState.OBSERVED_MISMATCH]):
        out.append(_gap(number, GapKind.REMEDIATION_STATUS,
                        'observed-mismatch-remediation-status', _REMEDIATION_NOTE,
                        scope_key, tuple(dict.fromkeys(
                            r for c in mism for r in c.fact_refs))))
    return tuple(out)


def _evidence_state(checks, has_facts, cross) -> EvidenceState:
    if CriterionState.CONFLICTING in {c.state for c in checks}:
        return EvidenceState.CONFLICTING
    return EvidenceState.PARTIAL if has_facts or cross else EvidenceState.NO_EVIDENCE


def _field(control: dict, definition, key: str) -> str:
    value = control.get(key)
    return value if isinstance(value, str) and value else getattr(definition, key)


def _regional(control: dict) -> dict:
    out = {}
    for finding in control.get('findings', []) or []:
        if not isinstance(finding, dict):
            continue
        region, status = finding.get('region'), finding.get('status')
        if not isinstance(region, str) or not region or status not in SCANNER:
            raise ValueError('Unknown regional finding status in bundle')
        out.setdefault(region, ScannerStatus(status))
    return out


def build_control_review(bundle: dict, ledger: EvidenceLedger,
                         classification: dict | None = None) -> ControlReview:
    if not isinstance(ledger, EvidenceLedger):
        raise ValueError('build_control_review expects an EvidenceLedger')
    controls, _ = validated_head(bundle)
    if classification is not None:
        validate_classification_result(bundle, classification)
    rows_source = observation_rows(bundle)
    cross = build_cross_control_evidence(
        bundle.get('resource_inventory') or {}).get('references', [])
    by_number = {control['number']: control for control in controls}
    execution = bundle.get('execution') or {}
    scope_key = 'product' if execution.get('audit_scope') == 'product' else 'account'
    by_index = {int(fact.source_ref[len(_ROW_PREFIX):-1]): fact
                for fact in ledger.facts
                if fact.source_ref.startswith(_ROW_PREFIX)}
    rows = []
    for definition in CHECKS:
        control = by_number[definition.number]
        facts = [f for f in ledger.facts if f.number == definition.number]
        fact_ids = tuple(fact.id for fact in facts)
        scoped = _join_scopes(ledger, fact_ids)
        if definition.number in _SPECIALIZED:
            rules = reconcile_control(definition.number, rows_source)
            checks = _specialized(definition.number, rows_source, rules,
                                  scoped, by_index, cross)
        else:
            checks = (_comp(definition.number, 'criterion component coverage',
                            CriterionState.UNRESOLVED, fact_ids, scoped,
                            'No automated criterion decomposition exists '
                            'for this control in this milestone.'),)
        draft = (classification['controls'][definition.number - 1]
                 if classification is not None else {})
        rows.append(ControlReviewRow(
            number=definition.number,
            **{key: _field(control, definition, key) for key in
               ('category', 'title', 'criterion', 'severity', 'purpose')},
            scanner_status=ScannerStatus(control['account_status']),
            scanner_regional_status=_regional(control),
            fact_refs=fact_ids, scope_refs=scoped, criterion_checks=checks,
            evidence_state=_evidence_state(checks, bool(fact_ids),
                definition.number == 45 and bool(cross)),
            gaps=_gaps(definition.number, scope_key, fact_ids, facts, checks,
                       scoped),
            request_ids=(),
            business_resolution_state=BusinessResolutionState(
                draft.get('resolution_state', 'NOT_EVALUATED')),
            business_label_provisional=draft.get('final_classification'),
            owner_adoption_verified=False
))
    return ControlReview(schema=REVIEW_SCHEMA, rows=tuple(rows), requests=())


def control_review_to_json(review: ControlReview) -> dict:
    if not isinstance(review, ControlReview):
        raise ValueError('control_review_to_json expects a ControlReview')
    return _plain_json(asdict(review))
