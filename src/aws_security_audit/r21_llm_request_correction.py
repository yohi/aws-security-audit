"""Bounded, offline-only correction of the observed R21 LLM request mistakes.

This function modifies a *copy* of an already structurally valid v2 response.
It never changes the 46 original scanner findings, measured property values,
the LLM's evidence citations, Owner approval or the four-state labels.
It deliberately fails closed on unexpected source observations or input shape.
"""
from __future__ import annotations

from copy import deepcopy

from .offline_classification import validate_classification_result

_ORIGINAL = (
    'request:control-18-s3-bpa-interpretation',
    'request:control-24-cloudtrail-selectors',
    'request:control-25-cloudtrail-validation',
    'request:control-32-guardduty-status',
)
_SHARED = 'request:shared-account-service-applicability'
_NEW_24 = 'request:control-24-cloudtrail-ros-data-coverage'


def _observed_values(bundle: dict, number: int) -> list[dict]:
    refs = bundle['decision_support']['plans'][number - 1]['evidence_refs']
    rows = bundle['resource_inventory']['control_observations']['rows']
    values = []
    for ref in refs:
        source_id = ref['id']
        if source_id.startswith(f'observation:{number}:'):
            index = int(source_id.rsplit(':', 1)[1])
            item = rows[index]
            if item['number'] != number:
                raise ValueError('Observation index/number mismatch')
            value = item.get('observed_value')
            if isinstance(value, dict):
                values.append(value)
    return values


def _assert_source_preconditions(bundle: dict) -> None:
    support = bundle['decision_support']
    if (support.get('output_contract', {}).get('classification_schema')
            != 'aws-security-offline-classification-v2'):
        raise ValueError('Expected original R21 Web evidence, not legacy/v1')
    scope = support['shared_scope_contract']
    if (scope['owner_approval'] != 'PENDING'
            or scope['scope_coverage_proven'] is not False
            or scope['reused_by_controls'] != [2, 17, 20, 23]
            or scope['observed_scope'].get('product') != 'ros'
            or scope['observed_scope'].get('attribution_complete') is not False
            or scope['observed_scope'].get('regions_requested') != ['ap-northeast-1']):
        raise ValueError('Source product scope has changed; review is required')

    fact_codes = [f['code'] for f in
                  support['plans'][17]['evidence_reconciliation']['verified_facts']]
    for code, count in (
        ('DIRECT_BUCKET_BPA_FOUR_FLAGS_ENABLED', 2),
        ('DIRECT_BUCKET_CLASSIC_AP_LIST_EMPTY', 2),
        ('ACCOUNT_BPA_CONFIGURATION_ABSENT', 1),
    ):
        if fact_codes.count(code) != count:
            raise ValueError(f'Unexpected S3 BPA observation: {code}')

    if not any(v.get('multi_region') is True
                   and v.get('is_logging') is True
                   and v.get('log_status') == 'VERIFIED'
                   and 'AWS::S3::Object' in
                       v.get('selectors', {}).get('basic_data_event_types', [])
               for v in _observed_values(bundle, 24)):
        raise ValueError('Missing acquired CloudTrail multi-region/source facts')
    if not any(v.get('log_file_validation_enabled') is True
                   and v.get('log_status') == 'VERIFIED'
               for v in _observed_values(bundle, 25)):
        raise ValueError('CloudTrail validation setting not verified')
    if not any(v.get('state') == 'LIST_VERIFIED' and
                   any(d.get('status') == 'ENABLED' for d in v.get('detectors', []))
               for v in _observed_values(bundle, 32)):
        raise ValueError('GuardDuty enabled detector not verified')
    if not any(v.get('state') == 'UNVERIFIED'
               for v in _observed_values(bundle, 33)):
        raise ValueError('Security Hub exception context unexpectedly changed')


def correct_r21_semantic_requests(bundle: dict, original: dict) -> tuple[dict, dict]:
    """Correct the known 14-request operator LLM result without AWS access.

    Returns a new JSON-ready result and a non-decisional counts/quality report.
    The original input is left untouched. Raises ValueError on source drift.
    """
    _assert_source_preconditions(bundle)
    pre = validate_classification_result(bundle, original)
    if (pre['result_contract'] != 'aws-security-offline-classification-v2'
            or pre['finalized_count'] != 3 or pre['pending_count'] != 43
            or {row['number'] for row in original['controls']
                if row['resolution_state'] == 'FINALIZED'} != {16, 19, 22}
            or any(original['controls'][n - 1]['final_classification'] != '未対応'
                   for n in (16, 19, 22))):
        raise ValueError('Unexpected starting classification; manual review required')

    changed = deepcopy(original)
    rows = {r['number']: r for r in changed['controls']}
    requests = changed['evidence_requests']
    by_id = {r['id']: r for r in requests}
    if (len(requests) != 14 or len(by_id) != 14
            or not all(k in by_id for k in _ORIGINAL)
            or _SHARED in by_id or _NEW_24 in by_id
            or changed['summary'].get('owner_confirmation_request_count') != 5
            or changed['summary'].get('machine_acquisition_request_count') != 9):
        raise ValueError('Unexpected original root request set; refuse to patch')
    for rid, number in zip(_ORIGINAL, (18, 24, 25, 32)):
        r = by_id[rid]
        if (r['acquisition_channel'] != 'AWS_LOCAL_READ_ONLY'
                or r['applies_to_controls'] != [number]
                or rows[number]['resolution_state'] != 'EVIDENCE_PENDING'
                or rows[number]['missing_evidence_request_ids'] != [rid]):
            raise ValueError(f'Original R21 row/request changed: #{number}')

    r18 = by_id[_ORIGINAL[0]]
    r18['acquisition_channel'] = 'OWNER_CONFIRMATION'
    r18['requested_artifact'] = (
        'ROSの承認済みBPA基準（アカウント単位とバケット単位の必須条件・例外）を提示し、'
        '取得済みアカウントBPA NOT_CONFIGURED、対象バケットのBPA trueと'
        'Access Pointリスト空という構成が要件を満たすかOwnerが判断する。'
        'AWS設定の再取得ではない。')
    rows[18]['missing_evidence'] = [
        'アカウント単位BPAとバケット単位BPAの基準解釈・例外に関するOwner承認。'
    ]
    rows[18]['rationale'] = (
        'バケット単位BPA4項目trueとclassic Access Point一覧空を観測し、'
        'アカウント単位BPAはNOT_CONFIGURED（取得済み未設定）。'
        'AWS追加取得でなく元の基準に対するOwner解釈が未決定。')

    requests[:] = [r for r in requests if r['id'] not in _ORIGINAL[2:]]
    requests.append({
        'id': _SHARED,
        'acquisition_channel': 'OWNER_CONFIRMATION',
        'status': 'REQUESTED_NOT_FULFILLED',
        'applies_to_controls': [24, 25, 32],
        'requested_artifact': (
            'ROSが利用するAWSアカウント・リージョンの承認済み一覧、および'
            '既に観測された共通CloudTrailと東京リージョンGuardDutyを'
            'ROS統制に適用する根拠をまとめて提示する。'
            '未承認の他アカウント・リージョンを存在すると仮定しない。'),
    })
    r24 = by_id[_ORIGINAL[1]]
    r24['id'] = _NEW_24
    r24['requested_artifact'] = (
        '取得済みCloudTrail multi_region=true、is_logging=true、管理イベントと'
        'S3 Objectカテゴリを再取得せず、未確認のROSバケット実効'
        'データイベントセレクター範囲とS3ログ配信エラー状態だけを'
        'Ownerがローカルで読み取りエクスポートする。')

    rows[24]['missing_evidence_request_ids'] = [_NEW_24, _SHARED]
    rows[24]['missing_evidence'] = [
        'ROS対象S3イベントの実効セレクター範囲と配信エラー状態。',
        '共通CloudTrailのROS適用アカウント・リージョン承認。',
    ]
    rows[24]['rationale'] = (
        'CloudTrailのマルチリージョン設定、ログ有効化、基本管理/S3 Object'
        'イベントカテゴリは既に観測済み。ROS対象バケットへの実効適用と'
        '配信状態、および共通サービスのOwner承認が未完了。')
    rows[25]['missing_evidence_request_ids'] = [_SHARED]
    rows[25]['missing_evidence'] = [
        '検証有効な共通CloudTrailをROS対象アカウント・リージョンへ適用する承認済み根拠。'
    ]
    rows[25]['rationale'] = (
        '共通CloudTrailでLogFileValidationEnabled=true、log_status=VERIFIED'
        'を取得済み。元の設定有効化基準にダイジェスト配信成功を'
        '新たに加えず、共通サービスのROS適用範囲だけ保留。')
    rows[32]['missing_evidence_request_ids'] = [_SHARED]
    rows[32]['missing_evidence'] = [
        'GuardDuty ENABLEDを取得済みの東京リージョンとROS対象スコープの対応に関する承認済み根拠。'
    ]
    rows[32]['rationale'] = (
        'ap-northeast-1でGuardDutyのENABLED状態を取得済み。'
        '他リージョン・アカウントの有無を仮定せず対象範囲の承認を求める。'
        '通知設定は別項目#34。')
    rows[33]['rationale'] = (
        'Security Hub describe_hubはInvalidAccessExceptionとなり、'
        '有効化と標準チェック状態はUNVERIFIED。'
        'IAM権限だけを根本原因と確定せず、正規の読み取り証拠が不足。')

    # Do not leave a now-withdrawn digest-delivery requirement in the
    # natural-language claim attributed to an original scanner finding.
    for n in (18, 24, 25):
        for claim in rows[n]['evidence_claims']:
            if f'finding:{n}:0' in claim['evidence_refs']:
                claim['claim'] = (
                    f'Scanner finding #{n} covers limited observed configuration; '
                    'full ROS applicability is not established by these references. '
                    'No extra digest-delivery requirement is inferred.')

    by_channel = {
        channel: sum(req['acquisition_channel'] == channel for req in requests)
        for channel in ('OWNER_CONFIRMATION', 'AWS_LOCAL_READ_ONLY',
                        'NON_AWS_MACHINE_EXPORT')
    }
    changed['summary'].update({
        'distinct_evidence_request_count': len(requests),
        'owner_confirmation_request_count': by_channel['OWNER_CONFIRMATION'],
        'machine_acquisition_request_count': (
            by_channel['AWS_LOCAL_READ_ONLY']
            + by_channel['NON_AWS_MACHINE_EXPORT']),
    })
    post = validate_classification_result(bundle, changed)
    if (len(requests) != 13
            or by_channel != {'OWNER_CONFIRMATION': 7,
                              'AWS_LOCAL_READ_ONLY': 5,
                              'NON_AWS_MACHINE_EXPORT': 1}
            or post['pending_count'] != 43
            or post['finalized_count'] != 3
            or post['structure_and_reference_check'] != 'PASS'
            or post['r21']['r21_request_schema_check'] != 'PASS'):
        raise ValueError('Corrected output failed the fixed semantic contract')
    return changed, {
        'status': 'OFFLINE_LIMITED_RECONCILIATION_STRUCTURE_PASS',
        'source_runtime_attested': False,
        'semantic_compliance_verified': False,
        'owner_adoption_verified': False,
        'original_result_unchanged': True,
        'finalized_count': 3,
        'pending_count': 43,
        'root_requests_before': 14,
        'root_requests_after': 13,
        'owner_containers': by_channel['OWNER_CONFIRMATION'],
        'aws_local_read_containers': by_channel['AWS_LOCAL_READ_ONLY'],
        'non_aws_export_containers': by_channel['NON_AWS_MACHINE_EXPORT'],
        'observed_human_actions': 'NOT_MEASURED',
        'validator_status': post['status'],
        'expected_cli_exit_code': 2,
    }
