from __future__ import annotations

from typing import Final

_API_BY_PROPERTY: Final[dict[tuple[str, str, str], str]] = {
    ('ec2', 'instance', 'EC2 public address and subnet'): 'ec2.DescribeInstances',
    ('ec2', 'instance', 'EC2 selected subnet route table context'): 'ec2.DescribeRouteTables',
    ('ec2', 'instance', 'EC2 attached security group SSH port 22 ingress summary'): 'ec2.DescribeSecurityGroups',
    ('ec2', 'instance', 'EC2 connectivity observation'): 'ec2.DescribeInstances',
    ('ec2', 'security-group', 'public ingress and all-protocol public egress'): 'ec2.DescribeSecurityGroups',
    ('ec2', 'security-group', 'dangerous_ingress_permission_count'): 'ec2.DescribeSecurityGroups',
    ('ec2', 'ebs-volume', 'encrypted'): 'ec2.DescribeVolumes',
    ('ec2', 'ebs-snapshot', 'encrypted'): 'ec2.DescribeSnapshots',
    ('ec2', 'vpc', 'Flow Logs at resource scope'): 'ec2.DescribeFlowLogs',
    ('ec2', 'subnet', 'Flow Logs at resource scope'): 'ec2.DescribeFlowLogs',
    ('elbv2', 'application', 'direct_alb_waf_web_acl_arn'): 'wafv2.GetWebACLForResource',
    ('elbv2', 'application', 'ALB WAF rule configuration summary'): 'wafv2.GetWebACLForResource',
    ('elbv2', 'application', 'ALB access logs configured'): 'elbv2.DescribeLoadBalancerAttributes',
    ('rds', 'db-instance', 'PubliclyAccessible'): 'rds.DescribeDBInstances',
    ('rds', 'db-instance', 'DeletionProtection'): 'rds.DescribeDBInstances',
    ('rds', 'db-instance', 'effective storage encryption'): 'rds.DescribeDBInstances',
    ('rds', 'db-cluster', 'DeletionProtection'): 'rds.DescribeDBClusters',
    ('rds', 'db-cluster', 'effective storage encryption'): 'rds.DescribeDBClusters',
    ('rds', 'db-snapshot', 'effective storage encryption'): 'rds.DescribeDBSnapshots',
    ('rds', 'db-cluster-snapshot', 'effective storage encryption'): 'rds.DescribeDBClusterSnapshots',
    ('s3', 'bucket', 'default_encryption_algorithms'): 's3.GetBucketEncryption',
    ('s3', 'bucket', 'bucket_public_access_block'): 's3.GetPublicAccessBlock',
    ('s3', 'bucket', 'S3 bucket policy public status'): 's3.GetBucketPolicyStatus',
    ('s3', 'bucket', 'S3 bucket object ownership mode'): 's3.GetBucketOwnershipControls',
    ('cloudfront', 'distribution', 'CloudFront configured Web ACL association'): 'cloudfront.ListDistributions',
    ('cloudfront', 'distribution', 'CloudFront WAF rule configuration summary'): 'wafv2.GetWebACL',
    ('cloudfront', 'distribution', 'CloudFront GeoRestriction configuration'): 'cloudfront.ListDistributions',
    ('cloudfront', 'distribution', 'CloudFront viewer minimum protocol policy'): 'cloudfront.ListDistributions',
    ('s3control', 'shared-s3-account-control', 'S3 account-level Block Public Access context'): 's3control.GetPublicAccessBlock',
}


def api_for_observation(
    service: str, resource_type: str, property_name: str,
) -> str | None:
    return _API_BY_PROPERTY.get((service, resource_type, property_name))
