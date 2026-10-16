"""Conservative AWS control-plane checks. API responses alone are never mistaken for operational proofs."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from .core import AuditContext, EvidenceUnavailable, Finding, api_call, manual, paged, verdict


def ec2_inventory(ctx: AuditContext, region: str) -> list[dict]:
    ec2 = ctx.client_cached('ec2', region)
    reservations = paged(ec2, 'describe_instances', 'Reservations')
    return [i for r in reservations for i in r.get('Instances', []) if i.get('State', {}).get('Name') != 'terminated']


def tag_matches(resource: dict, spec: str | None) -> bool:
    if not spec:
        return False
    key, _, val = spec.partition('=')
    return any(t.get('Key') == key and t.get('Value') == val for t in resource.get('Tags', []))


def check_1(ctx: AuditContext, region: str, options: dict) -> Finding:
    tag = options.get('ap_tag')
    if not tag:
        instances = ec2_inventory(ctx, region)
        return manual(1, region, 'APサーバーの識別が必要です。--ap-tag Key=Valueを指定', [f'稼働中EC2: {len(instances)}台'])
    inventory = ec2_inventory(ctx, region)
    instances = [i for i in inventory if tag_matches(i, tag)]
    fails = [i['InstanceId'] for i in instances if i.get('PublicIpAddress') or any(eni.get('Association', {}).get('PublicIp') for eni in i.get('NetworkInterfaces', []))]
    # Private subnet requires route table verification; no public IP alone is not enough.
    if fails:
        return verdict(1, region, len(instances), [f'Public IP: {i}' for i in fails], '')
    if not instances:
        if inventory:
            return manual(1, region, 'APタグに一致するEC2がありません。対象APサーバーの特定・タグ設定を確認してください', [f'指定タグ: {tag}', f'稼働中EC2: {len(inventory)}台', 'APサーバーが存在しないことは未証明'])
        return Finding(1, 'NOT_APPLICABLE', region, '稼働中EC2が存在しません。EC2以外のAPは対象外')
    return manual(1, region, 'APサーバーのPublic IPは検査済み。プライベートサブネットの経路表を追加確認', [f'タグ一致: {len(instances)}台'])


def check_2(ctx: AuditContext, region: str, options: dict) -> Finding:
    rds = ctx.client_cached('rds', region)
    dbs = paged(rds, 'describe_db_instances', 'DBInstances')
    bad = [i['DBInstanceIdentifier'] for i in dbs if i.get('PubliclyAccessible')]
    if bad:
        return verdict(2, region, len(dbs), [f'Public RDS: {i}' for i in bad], '')
    instances = ec2_inventory(ctx, region)
    return manual(2, region, 'RDSのPubliclyAccessibleは検査済み。EC2上のDBの識別とサブネット経路は要確認', [f'RDS {len(dbs)}件 / EC2 {len(instances)}件'])


def check_3(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(3, region, '踏み台サーバーの特定と許可する社内IP/CIDRの証跡が必要')


def check_4(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(4, region, 'コンソールアクセス元IPを制限するIAM/SCP/IdP条件の実効性確認が必要')


def is_unrestricted(permission: dict) -> bool:
    return any(r.get('CidrIp') == '0.0.0.0/0' for r in permission.get('IpRanges', [])) or any(r.get('CidrIpv6') == '::/0' for r in permission.get('Ipv6Ranges', []))


def dangerous_inbound(permission: dict) -> bool:
    if not is_unrestricted(permission):
        return False
    protocol = permission.get('IpProtocol')
    if protocol in ('-1', 'all'):
        return True
    if protocol in ('tcp', 'udp', '6', '17'):
        low, high = permission.get('FromPort'), permission.get('ToPort')
        if low is None or high is None:
            return True
        return any(low <= port <= high for port in (22, 3389)) or (low == 0 and high >= 65535)
    return False


def check_5(ctx: AuditContext, region: str, options: dict) -> Finding:
    sgs = paged(ctx.client_cached('ec2', region), 'describe_security_groups', 'SecurityGroups')
    failures = []
    broadly_open = []
    for sg in sgs:
        for perm in sg.get('IpPermissions', []):
            if dangerous_inbound(perm):
                failures.append(f"SG {sg['GroupId']}: broad SSH/RDP/all inbound")
            elif is_unrestricted(perm):
                broadly_open.append(sg['GroupId'])
    if failures:
        return verdict(5, region, len(sgs), failures, '')
    if not sgs:
        return Finding(5, 'NOT_APPLICABLE', region, 'セキュリティグループがありません')
    return manual(5, region, '危険な全公開ポートは検出なし。業務上必要なポートとアウトバウンドの最小権限は要レビュー', [f'セキュリティグループ {len(sgs)}件 / その他のインターネット公開許可を持つSG {len(set(broadly_open))}件'])


def check_6(ctx: AuditContext, region: str, options: dict) -> Finding:
    elb = ctx.client_cached('elbv2', region)
    load_balancers = [lb for lb in paged(elb, 'describe_load_balancers', 'LoadBalancers') if lb.get('Type') == 'application']
    waf = ctx.client_cached('wafv2', region)
    bad = []
    for lb in load_balancers:
        try:
            association = api_call(waf, 'get_web_acl_for_resource', ResourceArn=lb['LoadBalancerArn'])
            acl = association.get('WebACL')
            if not acl:
                bad.append(f"ALB WAF not associated: {lb['LoadBalancerName']}")
            else:
                # WAF association alone does not prove effective managed SQLi/XSS rules.
                bad.append(f"ALB rules require review: {lb['LoadBalancerName']}")
        except EvidenceUnavailable as exc:
            if 'WAFNonexistentItemException' in str(exc):
                bad.append(f"ALB WAF not associated: {lb['LoadBalancerName']}")
            else:
                raise
    cf = ctx.client_cached('cloudfront', 'us-east-1')
    page = api_call(cf, 'list_distributions')
    distributions = page.get('DistributionList', {}).get('Items', [])
    if page.get('DistributionList', {}).get('IsTruncated'):
        # Without full enumeration a PASS/FAIL for the entire scope is unsafe.
        raise EvidenceUnavailable('CloudFront distribution enumeration truncated')
    for dist in distributions:
        if not dist.get('WebACLId'):
            bad.append(f"CloudFront WAF not associated: {dist['Id']}")
        else:
            bad.append(f"CloudFront rules require review: {dist['Id']}")
    if not load_balancers and not distributions:
        return Finding(6, 'NOT_APPLICABLE', region, 'ALB/CloudFrontがありません')
    hard = [x for x in bad if 'not associated' in x]
    if hard:
        return verdict(6, region, len(load_balancers) + len(distributions), hard, '', evidence=[f'ルール内容の確認が別途必要: {len(bad) - len(hard)}件'])
    return manual(6, region, 'WAFの関連付けを検出。一般的なWeb攻撃ルールの内容・有効性は追加レビューが必要', bad)


def check_7(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(7, region, '海外アクセスの監視・Geo制限の必要性はWAFルールとログ運用の確認が必要')


def check_8(ctx: AuditContext, region: str, options: dict) -> Finding:
    if region != options['regions'][0]:
        return Finding(8, 'NOT_APPLICABLE', region, 'アカウント単位で別途評価')
    try:
        sub = api_call(ctx.client_cached('shield', 'us-east-1'), 'describe_subscription')
    except EvidenceUnavailable as exc:
        if 'ResourceNotFoundException' in str(exc):
            return Finding(8, 'FAIL', region, 'AWS Shield Advancedのサブスクリプションがありません')
        raise
    if sub.get('Subscription', {}).get('SubscriptionState') in ('ACTIVE', 'Active'):
        return manual(8, region, 'Shield Advanced契約を確認。必要な対象リソースへの適用と対策を確認してください')
    return manual(8, region, 'Shield Advancedの契約情報は取得したが、適用状況を確認してください')


def check_9(ctx: AuditContext, region: str, options: dict) -> Finding:
    users = paged(ctx.client_cached('iam', region), 'list_users', 'Users')
    return manual(9, region, 'IAMユーザーの一覧は取得可能。共有アカウントか個人かは利用者台帳と照合が必要', [f'IAM users: {len(users)}'])


def check_10(ctx: AuditContext, region: str, options: dict) -> Finding:
    iam = ctx.client_cached('iam', region)
    users = paged(iam, 'list_users', 'Users')
    missing = []
    console = 0
    for user in users:
        name = user['UserName']
        try:
            api_call(iam, 'get_login_profile', UserName=name)
        except EvidenceUnavailable as exc:
            if 'NoSuchEntity' in str(exc):
                continue
            raise
        console += 1
        if not paged(iam, 'list_mfa_devices', 'MFADevices', UserName=name):
            missing.append(f'Console user without MFA: {name}')
    if missing:
        return verdict(10, region, console, missing, '')
    return manual(10, region, 'IAMコンソールユーザーのMFAを確認。IAM Identity Center/フェデレーションとルートMFAは別途確認', [f'コンソールユーザー: {console}'])


def check_11(ctx: AuditContext, region: str, options: dict) -> Finding:
    iam = ctx.client_cached('iam', region)
    failures = []
    users = paged(iam, 'list_users', 'Users')
    roles = paged(iam, 'list_roles', 'Roles')
    for typ, entries, operation, name_key in (
        ('IAM user', users, 'list_attached_user_policies', 'UserName'),
        ('IAM role', roles, 'list_attached_role_policies', 'RoleName'),
    ):
        for ent in entries:
            name = ent[name_key]
            policies = paged(iam, operation, 'AttachedPolicies', **{name_key: name})
            for p in policies:
                if p.get('PolicyArn', '').endswith('/AdministratorAccess'):
                    failures.append(f'{typ} {name}: AdministratorAccess')
    if failures:
        return verdict(11, region, len(users) + len(roles), failures, '')
    return manual(11, region, 'AdministratorAccessの直接アタッチは検出なし。インライン・カスタム・グループ・リソースポリシー等は未評価', [f'IAM users {len(users)}, roles {len(roles)}'])


def check_12(ctx: AuditContext, region: str, options: dict) -> Finding:
    iam = ctx.client_cached('iam', region)
    users = paged(iam, 'list_users', 'Users')
    keys = []
    for user in users:
        for key in paged(iam, 'list_access_keys', 'AccessKeyMetadata', UserName=user['UserName']):
            if key.get('Status') == 'Active':
                age = (datetime.now(timezone.utc) - key['CreateDate']).days
                keys.append(f"{user['UserName']}: active key age {age} days")
    summary = api_call(iam, 'get_account_summary').get('SummaryMap', {})
    root_key_count = summary.get('AccountAccessKeysPresent', 0)
    if not keys and root_key_count == 0:
        return Finding(12, 'PASS', region, 'IAMユーザー/ルートに有効な長期アクセスキーがなくローテーション不要')
    if root_key_count:
        keys.append(f'Root access keys present: {root_key_count}')
    return manual(12, region, '有効な長期アクセスキーがあります。ローテーション周期が指定されていないため合否は要確認', keys)


def check_13(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(13, region, 'アプリ用・管理者用DBアカウントと個人別権限はDB内の権限表/監査証跡が必要')


def check_14(ctx: AuditContext, region: str, options: dict) -> Finding:
    instances = ec2_inventory(ctx, region)
    ssm = ctx.client_cached('ssm', region)
    managed = paged(ssm, 'describe_instance_information', 'InstanceInformationList')
    managed_ids = {x.get('InstanceId') for x in managed}
    unmatched = [i['InstanceId'] for i in instances if i.get('InstanceId') not in managed_ids]
    if not instances:
        return Finding(14, 'NOT_APPLICABLE', region, 'EC2インスタンスがありません')
    return manual(14, region, 'SSM登録状況を確認。SSH直接経路や踏み台利用統一の最終確認は必要', [f'EC2 {len(instances)}件 / SSM未登録 {len(unmatched)}件'] + unmatched[:30])


def check_15(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(15, region, 'アプリ内の認可と個人情報テーブルアクセスはコードとDB監査のレビューが必要')


def check_16(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(16, region, '外部HTTPSに加え内部TLSまで必要なため、ALB/CloudFront/アプリ通信の両側の検証が必要')


def s3_buckets(ctx: AuditContext) -> list[dict]:
    return api_call(ctx.client_cached('s3'), 'list_buckets').get('Buckets', [])


def check_17(ctx: AuditContext, region: str, options: dict) -> Finding:
    s3 = ctx.client_cached('s3')
    buckets = s3_buckets(ctx)
    bad = []
    for b in buckets:
        try:
            rules = api_call(s3, 'get_bucket_encryption', Bucket=b['Name']).get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        except EvidenceUnavailable as exc:
            if 'ServerSideEncryptionConfigurationNotFoundError' in str(exc):
                bad.append(b['Name'])
                continue
            raise
        if not any(x.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm') in ('AES256', 'aws:kms', 'aws:kms:dsse') for x in rules):
            bad.append(b['Name'])
    return verdict(17, region, len(buckets), [f'S3 default encryption missing: {s}' for s in bad], '全バケットでデフォルト暗号化を確認')


def s3_block_all(bpa: dict) -> bool:
    return all(bpa.get(k) is True for k in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'))


def check_18(ctx: AuditContext, region: str, options: dict) -> Finding:
    s3 = ctx.client_cached('s3')
    s3control = ctx.client_cached('s3control')
    account_bpa = None
    try:
        account_bpa = api_call(s3control, 'get_public_access_block', AccountId=ctx.account)['PublicAccessBlockConfiguration']
    except EvidenceUnavailable as exc:
        if 'NoSuchPublicAccessBlockConfiguration' not in str(exc):
            raise
    buckets = s3_buckets(ctx)
    bad = []
    if not s3_block_all(account_bpa or {}):
        for bucket in buckets:
            try:
                bpa = api_call(s3, 'get_public_access_block', Bucket=bucket['Name'])['PublicAccessBlockConfiguration']
            except EvidenceUnavailable as exc:
                if 'NoSuchPublicAccessBlockConfiguration' in str(exc):
                    bad.append(bucket['Name'])
                    continue
                raise
            if not s3_block_all(bpa):
                bad.append(bucket['Name'])
    if not buckets and not s3_block_all(account_bpa or {}):
        return Finding(18, 'FAIL', region, 'アカウント単位のS3 Block Public Access設定が不完全')
    return verdict(18, region, len(buckets) or 1, [f'S3 public access block incomplete: {name}' for name in bad], 'アカウントまたは各バケットの4設定が有効')


def check_19(ctx: AuditContext, region: str, options: dict) -> Finding:
    ec2 = ctx.client_cached('ec2', region)
    volumes = paged(ec2, 'describe_volumes', 'Volumes')
    snapshots = paged(ec2, 'describe_snapshots', 'Snapshots', OwnerIds=['self'])
    bad = [f"EBS {v['VolumeId']}" for v in volumes if not v.get('Encrypted')]
    bad += [f"Snapshot {s['SnapshotId']}" for s in snapshots if not s.get('Encrypted')]
    return verdict(19, region, len(volumes) + len(snapshots), bad, '暗号化済み')


def check_20(ctx: AuditContext, region: str, options: dict) -> Finding:
    rds = ctx.client_cached('rds', region)
    instances = paged(rds, 'describe_db_instances', 'DBInstances')
    clusters = paged(rds, 'describe_db_clusters', 'DBClusters')
    snaps = paged(rds, 'describe_db_snapshots', 'DBSnapshots', SnapshotType='automated')
    csnaps = paged(rds, 'describe_db_cluster_snapshots', 'DBClusterSnapshots', SnapshotType='automated')
    bad = [x['DBInstanceIdentifier'] for x in instances if not x.get('StorageEncrypted')]
    bad += [x['DBClusterIdentifier'] for x in clusters if not x.get('StorageEncrypted')]
    bad += [x['DBSnapshotIdentifier'] for x in snaps if not x.get('Encrypted')]
    bad += [x['DBClusterSnapshotIdentifier'] for x in csnaps if not x.get('StorageEncrypted')]
    return verdict(20, region, len(instances)+len(clusters)+len(snaps)+len(csnaps), bad, 'RDSストレージと自動スナップショットが暗号化済み')


def check_21(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(21, region, 'ソースコード・実行時設定に平文シークレットがないことはAWS設定取得だけでは証明不能')


def check_22(ctx: AuditContext, region: str, options: dict) -> Finding:
    s3 = ctx.client_cached('s3')
    buckets = s3_buckets(ctx)
    bad = []
    for b in buckets:
        name = b['Name']
        versioned = api_call(s3, 'get_bucket_versioning', Bucket=name).get('Status') == 'Enabled'
        locked = False
        if not versioned:
            try:
                locked = api_call(s3, 'get_object_lock_configuration', Bucket=name).get('ObjectLockConfiguration', {}).get('ObjectLockEnabled') == 'Enabled'
            except EvidenceUnavailable as exc:
                if 'ObjectLockConfigurationNotFoundError' not in str(exc):
                    raise
        if not (versioned or locked):
            bad.append(name)
    return verdict(22, region, len(buckets), [f'Versioning/ObjectLock off: {x}' for x in bad], 'VersioningまたはObject Lockが有効')


def check_23(ctx: AuditContext, region: str, options: dict) -> Finding:
    rds = ctx.client_cached('rds', region)
    instances = paged(rds, 'describe_db_instances', 'DBInstances')
    clusters = paged(rds, 'describe_db_clusters', 'DBClusters')
    cluster_by_id = {x['DBClusterIdentifier']: x for x in clusters}
    bad = []
    for db in instances:
        cluster_name = db.get('DBClusterIdentifier')
        # For Aurora, deletion protection is evaluated on the parent DB cluster.
        if cluster_name in cluster_by_id:
            continue
        if not db.get('DeletionProtection'):
            bad.append(db['DBInstanceIdentifier'])
    bad += [x['DBClusterIdentifier'] for x in clusters if not x.get('DeletionProtection')]
    return verdict(23, region, len(instances) + len(clusters), bad, 'DeletionProtection有効')


def cloudtrails(ctx: AuditContext, regions: list[str]) -> list[tuple[str, dict]]:
    result = []
    seen = set()
    for region in regions:
        cloudtrail = ctx.client_cached('cloudtrail', region)
        for trail in api_call(cloudtrail, 'describe_trails', includeShadowTrails=True).get('trailList', []):
            arn = trail.get('TrailARN', trail['Name'])
            if arn not in seen:
                result.append((trail.get('HomeRegion', region), trail))
                seen.add(arn)
    return result


def management_event_enabled(selectors: dict) -> bool:
    advanced = selectors.get('AdvancedEventSelectors', [])
    if advanced:
        return any(
            any(field.get('Field') == 'eventCategory' and 'Management' in field.get('Equals', [])
                for field in selector.get('FieldSelectors', []))
            for selector in advanced
        )
    return any(selector.get('IncludeManagementEvents', False) for selector in selectors.get('EventSelectors', []))


def data_event_enabled(selectors: dict) -> bool:
    for advanced in selectors.get('AdvancedEventSelectors', []):
        fields = advanced.get('FieldSelectors', [])
        if any(f.get('Field') == 'eventCategory' and 'Data' in f.get('Equals', []) for f in fields):
            return True
    for sel in selectors.get('EventSelectors', []):
        if sel.get('DataResources'):
            return True
    return False


def check_24(ctx: AuditContext, region: str, options: dict) -> Finding:
    trails = cloudtrails(ctx, options['all_account_regions'])
    if not trails:
        return Finding(24, 'FAIL', region, 'CloudTrail証跡がありません')

    healthy_management, healthy_data = set(), set()
    delivery_failed, delivery_unknown, checked = [], [], []
    logging_multi_region = 0
    for home, trail in trails:
        if not trail.get('IsMultiRegionTrail'):
            continue
        arn = trail['TrailARN']
        cli = ctx.client_cached('cloudtrail', home)
        selectors = api_call(cli, 'get_event_selectors', TrailName=arn)
        status = api_call(cli, 'get_trail_status', Name=arn)
        if not status.get('IsLogging'):
            checked.append(f'{arn}: IsLogging=False')
            continue
        logging_multi_region += 1
        if status.get('LatestDeliveryError'):
            # Do not include the raw service error: it can carry arbitrary text.
            delivery_failed.append(f'{arn}: CloudTrail S3 log delivery error present')
            continue
        delivered = status.get('LatestDeliveryTime')
        if delivered is None:
            delivery_unknown.append(f'{arn}: LatestDeliveryTime unavailable')
            continue
        checked.append(f'{arn}: LatestDeliveryTime={delivered.isoformat() if isinstance(delivered, datetime) else str(delivered)}')
        if management_event_enabled(selectors):
            healthy_management.add(arn)
        if data_event_enabled(selectors):
            healthy_data.add(arn)

    if not logging_multi_region:
        return Finding(24, 'FAIL', region, 'ログ記録中のマルチリージョンCloudTrailがありません', checked[:30])
    evidence = (delivery_failed + delivery_unknown + checked)[:100]
    if not healthy_management or not healthy_data:
        if delivery_failed and not delivery_unknown:
            return Finding(24, 'FAIL', region, 'CloudTrail配信失敗または必要なイベント収集が確認できません', evidence)
        if delivery_unknown:
            return Finding(24, 'UNKNOWN', region, 'CloudTrailの最終配信成功が確認できず、イベント収集を証明できません', evidence)
        return Finding(24, 'FAIL', region, '配信済みマルチリージョンCloudTrailで管理・データイベントの両方を確認できません', evidence)

    # Data selector presence does not prove coverage of all required resources.
    evidence += [f'管理イベント選択: {len(healthy_management)}証跡', f'データイベント選択: {len(healthy_data)}証跡']
    return manual(24, region, '配信成功時刻とイベント選択設定を確認。Data Event対象範囲・実際のログ配送・必要なイベントの網羅性を検証してください', evidence)


def check_25(ctx: AuditContext, region: str, options: dict) -> Finding:
    trails = cloudtrails(ctx, options['all_account_regions'])
    if not trails:
        return Finding(25, 'FAIL', region, 'CloudTrail証跡がありません')
    bad = [t['TrailARN'] for _, t in trails if not t.get('LogFileValidationEnabled')]
    return verdict(25, region, len(trails), bad, 'ログファイル検証を有効化')


def check_26(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(26, region, 'CloudTrail格納S3の厳格なアクセス制限・削除禁止はポリシー全文と権限経路のレビューが必要')


def check_27(ctx: AuditContext, region: str, options: dict) -> Finding:
    ec2 = ctx.client_cached('ec2', region)
    vpcs = paged(ec2, 'describe_vpcs', 'Vpcs')
    subnets = paged(ec2, 'describe_subnets', 'Subnets')
    flow_logs = paged(ec2, 'describe_flow_logs', 'FlowLogs')
    if not vpcs:
        return Finding(27, 'NOT_APPLICABLE', region, '対象VPCがありません')

    delivered = set()
    unverified = set()
    delivery_failed = set()
    for entry in flow_logs:
        if entry.get('FlowLogStatus') != 'ACTIVE' or entry.get('TrafficType') != 'ALL':
            continue
        resource = entry.get('ResourceId')
        delivery = entry.get('DeliverLogsStatus')
        if delivery == 'SUCCESS':
            delivered.add(resource)
        elif delivery == 'FAILED':
            delivery_failed.add(resource)
        else:
            # Missing, pending or unrecognized statuses can never imply PASS.
            unverified.add(resource)

    failures, unknowns = [], []
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        if vpc_id in delivered:
            continue
        vpc_subnets = {x['SubnetId'] for x in subnets if x['VpcId'] == vpc_id}
        required = vpc_subnets or {vpc_id}
        if vpc_subnets and required.issubset(delivered):
            continue
        unresolved = required - delivered
        if vpc_id in unverified or unresolved & unverified:
            unknowns.append(f'{vpc_id}: 配信状態が未確認のFlow Logがあります')
        elif vpc_id in delivery_failed or unresolved & delivery_failed:
            failures.append(f'{vpc_id}: Flow Log delivery FAILED / 未網羅')
        else:
            failures.append(f'{vpc_id}: ACTIVEかつALLかつ配信SUCCESSのFlow Logsが不足')
    if failures:
        return Finding(27, 'FAIL', region, 'VPC Flow Logsの配信失敗・未設定を確認', (failures + unknowns)[:100])
    if unknowns:
        return Finding(27, 'UNKNOWN', region, 'VPC Flow Logsの配送成功が証明できません', unknowns[:100])
    return Finding(27, 'PASS', region, f'{len(vpcs)}件のVPCでACTIVE/ALL/配信SUCCESSを確認')


def check_28(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(28, region, 'DB監査拡張の設定とSQLレベルの取得・保存の証跡はDBエンジン別の調査が必要')


def check_29(ctx: AuditContext, region: str, options: dict) -> Finding:
    elb = ctx.client_cached('elbv2', region)
    lbs = [lb for lb in paged(elb, 'describe_load_balancers', 'LoadBalancers') if lb.get('Type') == 'application']
    off = []
    for lb in lbs:
        attr = api_call(elb, 'describe_load_balancer_attributes', LoadBalancerArn=lb['LoadBalancerArn']).get('Attributes', [])
        settings = {x['Key']: x['Value'] for x in attr}
        if settings.get('access_logs.s3.enabled') != 'true':
            off.append(lb['LoadBalancerName'])
    if off:
        return Finding(29, 'FAIL', region, 'ALB/NLBアクセスログが無効のリソースあり', off)
    return manual(29, region, 'ロードバランサーのアクセスログ設定を確認。AP/Nginx/FireLens側のログ集約は別途確認', [f'LB: {len(lbs)}件'])


def check_30(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(30, region, '実ログの接続元IP・国コードの出力と識別可能性はログサンプルの確認が必要')


def check_31(ctx: AuditContext, region: str, options: dict) -> Finding:
    groups = paged(ctx.client_cached('logs', region), 'describe_log_groups', 'logGroups')
    not_defined = [x['logGroupName'] for x in groups if 'retentionInDays' not in x]
    return manual(31, region, 'コンプライアンス要件とS3等を含むログ保存期間を照合する必要あり', [f'CloudWatch log groups {len(groups)}, 未設定 {len(not_defined)}'] + not_defined[:20])


def check_32(ctx: AuditContext, region: str, options: dict) -> Finding:
    gd = ctx.client_cached('guardduty', region)
    detector_ids = paged(gd, 'list_detectors', 'DetectorIds')
    if not detector_ids:
        return Finding(32, 'FAIL', region, 'GuardDuty detectorがありません')
    bad = []
    for id_ in detector_ids:
        data = api_call(gd, 'get_detector', DetectorId=id_)
        if data.get('Status') != 'ENABLED':
            bad.append(id_)
    return verdict(32, region, len(detector_ids), bad, 'GuardDuty有効')


def check_33(ctx: AuditContext, region: str, options: dict) -> Finding:
    sh = ctx.client_cached('securityhub', region)
    try:
        api_call(sh, 'describe_hub')
    except EvidenceUnavailable as exc:
        if 'InvalidAccessException' in str(exc):
            return Finding(33, 'FAIL', region, 'Security Hub CSPMは有効化されていません')
        raise
    standards = paged(sh, 'get_enabled_standards', 'StandardsSubscriptions')
    active = [s for s in standards if s.get('StandardsStatus') == 'READY']
    if not active:
        return Finding(33, 'FAIL', region, 'Security Hubは有効ですが、検査用標準が有効ではありません')

    enabled = disabled = other = 0
    evidence = []
    for standard in active:
        subscription = standard.get('StandardsSubscriptionArn')
        if not subscription:
            return Finding(33, 'UNKNOWN', region, '標準のSubscription ARNを確認できません')
        controls = paged(sh, 'describe_standards_controls', 'Controls', StandardsSubscriptionArn=subscription)
        for control in controls:
            state = control.get('ControlStatus')
            if state == 'ENABLED':
                enabled += 1
            elif state == 'DISABLED':
                disabled += 1
            else:
                other += 1
        evidence.append(f'{subscription}: 有効/無効/不明={sum(x.get("ControlStatus") == "ENABLED" for x in controls)}/{sum(x.get("ControlStatus") == "DISABLED" for x in controls)}/{sum(x.get("ControlStatus") not in ("ENABLED", "DISABLED") for x in controls)}')

    if not enabled and disabled and not other:
        return Finding(33, 'FAIL', region, 'Security HubのREADY標準ではすべてのコントロールが無効です', evidence[:30])
    if not enabled:
        return Finding(33, 'UNKNOWN', region, 'Security Hub標準がREADYでも有効な個別コントロールを確認できません', evidence[:30])
    evidence.append(f'Control totals: enabled={enabled} disabled={disabled} unknown={other}')
    return manual(33, region, 'Security Hub個別コントロールの設定を確認。実際のチェック実施履歴・無効化されたControlの妥当性は未証明', evidence[:30])


def check_34(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(34, region, '不正ログイン検知から通知先までEventBridge/CloudWatch/SNS/Slack配送の疎通確認が必要')


def check_35(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(35, region, 'SG変更イベントの検知・通知連携はルールと実際の配送検証が必要')


def check_36(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(36, region, 'IAM権限昇格の監視条件と通知先はEventBridge等の設定と運用検証が必要')


def check_37(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(37, region, 'CPU/メモリ/通信量のアラーム条件と異常検知範囲はリソース別の監査が必要')


def check_38(ctx: AuditContext, region: str, options: dict) -> Finding:
    instances = ec2_inventory(ctx, region)
    ssm = ctx.client_cached('ssm', region)
    managed = paged(ssm, 'describe_instance_information', 'InstanceInformationList')
    ids = [x['InstanceId'] for x in managed if x.get('InstanceId', '').startswith('i-')]
    patches = []
    for start in range(0, len(ids), 50):
        patches.extend(api_call(ssm, 'describe_instance_patch_states', InstanceIds=ids[start:start + 50]).get('InstancePatchStates', []))
    problems = [p['InstanceId'] for p in patches if p.get('MissingCount', 0) or p.get('FailedCount', 0) or p.get('InstalledPendingRebootCount', 0)]
    if problems:
        return Finding(38, 'FAIL', region, 'SSM Patch Managerでパッチの未適用/失敗/再起動待ちを確認', problems)
    return manual(38, region, 'SSM Patch Managerで重大な未適用は未検出。OS・ミドルウェア全体と適用頻度の証跡確認が必要', [f'EC2 {len(instances)}台 / Patch State {len(patches)}件'])


def check_39(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(39, region, 'Inspector・ECRのスキャン設定、対象AMI/イメージと実行履歴を突き合わせて確認')


def check_40(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(40, region, 'Dependabot/Snyk等の設定と検知運用にはリポジトリ側の証拠が必要')


def check_41(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(41, region, '棚卸し実施頻度と放置リソース判定には台帳・削除記録の証拠が必要')


def check_42(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(42, region, '封じ込め初動Runbookと権限・訓練記録の提出が必要')


def check_43(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(43, region, 'スナップショット/IaCによる復旧Runbookのレビューが必要')


def check_44(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(44, region, '顧客・社内・関係各所への通知フローの文書・連絡先・演習結果が必要')


def check_45(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(45, region, 'バックアップの自動取得設定と実際のリストア訓練記録の確認が必要')


def check_46(ctx: AuditContext, region: str, options: dict) -> Finding:
    return manual(46, region, '責任者・代行者・夜間休日連絡網の文書確認が必要')


CHECK_RUNNERS = {i: globals()[f'check_{i}'] for i in range(1, 47)}
GLOBAL_CHECKS = {8, 9, 10, 11, 12, 17, 18, 22, 24, 25, 26}
