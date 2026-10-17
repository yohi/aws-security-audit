# Issue #8 — R7 CloudFront → ALB Origin and WAF Evidence

Base commit: `c21b3748f2975e327444a937eca75993939e9f85` (PR #9 merged).  
Change: `feat/issue-8-cloudfront-waf-origin-r7` · Draft PR #10.  
Contract: read-only product audit, **no AWS changes or IAM permission modifications**.

## Motivation

ROS R6 identified two internet-facing ALBs with no directly associated Web ACL, but the auditor could not tell whether a CloudFront distribution was configured to front either ALB and whether it had its own AWS WAF Web ACL. A direct ALB Web ACL absence is **not** evidence that CloudFront/WAF protection is absent upstream.

## Limited evidence collected from the existing API response

`cloudfront:ListDistributions` already yields the `DistributionSummary` fields necessary for:

- CloudFront `Origins.Items[].DomainName` (hostnames only, never custom header values or origin credentials)
- `WebACLId` (nonempty WAF Classic ID or WAFv2 WebACL ARN, or explicitly empty string meaning no CloudFront association)
- `Restrictions.GeoRestriction.RestrictionType` and configured location count
- `ViewerCertificate.MinimumProtocolVersion` as a raw security policy name
- distribution `Status` / `Enabled`

CloudFront list/read tag errors continue to appear in `collection_errors`. No additional CloudFront API is called and existing manual pagination remains intact.

The product attribution algorithm may label an otherwise unselected CloudFront distribution `RELATED` when one of its *exact* normalized origin hostnames equals the `DNSName` of a directly selected **ALB**. Normalization accepts only a valid DNS hostname (case-insensitive, optional trailing dot), not substring matches, URLs, wildcard patterns, suffix guesses, CloudFront aliases, arbitrary EC2 hosts or CIDR. The evidence record explicitly says the distribution **may be shared**. CloudFront resources remain `DIRECT` only if independently matched via existing product tag/name rules. Ownership, actual traffic path, end-to-end WAF coverage, DNS forwarding, ALB direct bypass, all origin behaviors and rules remain unproven.

## Reporting and classifications

- **#6 WAF:** CloudFront Web ACL association, upstream ALB hostname relationship and direct ALB WAF metadata are `CONTEXT_ONLY` if observed, `PROPERTY_UNKNOWN` if absent or inaccessible. A non-empty WebACL ARN proves *association*, not SQLi/XSS rule coverage or effectiveness. An empty WebACL ID does not establish complete product WAF absence. Original #6 remains `MANUAL_REVIEW`.
- **#7 Geography:** CloudFront geo restriction mode and location count are `CONTEXT_ONLY`, not pass/fail. WAF geographic conditions and business rule necessity are not assessed.
- **#16 TLS:** CloudFront minimum viewer protocol policy name is `CONTEXT_ONLY` when present; no fabricated mapping from policy name to effective protocol acceptance and no override of existing direct ALB `DescribeSSLPolicies` FAIL.
- All original product verdicts are retained: `PASS=0` is expected even with better evidence, unless a separate deterministic negative finding has been proven by existing rules.
- JSON / Web / CSV / XLSX outputs reuse the current 46-control and resource-property evidence contract. Because CloudFront can now enter the related resource inventory, selected resource counts may change; this is not a change to product attribution completeness.

## Tests and gates

Offline regression cases include tagged/untagged distributions, linked/unlinked origins, exactness and malicious hostname confusables, pagination, sensitive custom headers exclusion, empty/unknown Web ACL semantics, and preservation of #6/#7/#16 as MANUAL_REVIEW.

Before merging: fixed-HEAD CI; independent static review of new CloudFront attribution and complete source field extraction; explicitly authorized, read-only ROS R7 runtime check of `--product ros` with the existing scoped role. Verify whether new CloudFront resources are truly related and whether AWS response shape actually supplies required fields. Do not require a distribution to exist; zero relevant matches is a valid bounded result, not full network proof.

**Issue #8 remains OPEN** for CloudFront origin behavior coverage, WAF rule inspection / CloudFront-to-ALB bypass assessment, role/route attribution, centralized logging inheritance, IAM, Inspector/SSM, backup testing and human governance.

AWS primary reference: [DistributionSummary](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_DistributionSummary.html).
