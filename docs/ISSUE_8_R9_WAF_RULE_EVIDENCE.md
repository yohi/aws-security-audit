# Issue #8 R9 — Limited WAFv2 rule evidence contract

Base: `c1021a3874565d3315e3d9699d3cfbd96a410411` (PR #10 merged into master).  
Branch: `feat/issue-8-waf-rule-evidence-r9`. Product-scope read-only audit only; no AWS settings are changed.

## Objective

The previous ROS R8 read-only review successfully listed **29** account-level CloudFront distributions, matched **2** directly selected ROS ALBs by DNS hostname, and found **0** direct-origin associations. It did not establish that CloudFront is unused, nor prove that ALB WAF configuration is absent upstream. This increment gathers additional WAF **rule-configuration** evidence *only for product-selected resources*; it does not resolve DNS alias chains or route completeness.

## Source and collection boundary

| Resource | Source | Conditions | Data retained |
| --- | --- | --- | --- |
| ALB application | Existing regional `wafv2:GetWebACLForResource` response `WebACL` | Same collection scope as prior PRs; no additional AWS API | Associated WebACL ARN, source state, redacted rule summary |
| CloudFront distribution | `wafv2:GetWebACL` `Scope=CLOUDFRONT` via the **us-east-1** endpoint | **Only DIRECT or RELATED product-selected** CloudFront resources with a strictly valid WAFv2 `global/webacl` ARN; no query for the 29 unrelated distributions | Existing association metadata; redacted rule summary, fetch state |

The summary contains only `rule_count`, `default_action`, top-level statement-type counts, explicit outer action/override counts, and unclassified count. It deliberately **does not serialize** WebACL/Rule raw structures, rule names, managed-group names, regex/byte-match values, IP addresses, custom headers, CAPTCHA configuration, request samples or custom response bodies. Unknown/unsupported nested rule types remain partial/unverified.

Response failures remain `UNVERIFIED_READ_ERROR` and are recorded in `collection_errors`, not interpreted as lack of a WAF. An empty CloudFront Web ACL ID is `NOT_ASSOCIATED`; missing ID is `UNVERIFIED_ASSOCIATION`; unsupported/legacy identifiers are `UNSUPPORTED_WEB_ACL_IDENTIFIER` and never trigger `GetWebACL`. Rules with missing/default-action ambiguity are unverified.

## Verdict and trust limits

- #6 rule summary is `CONTEXT_ONLY` for a complete summary (or explicitly no association) and `PROPERTY_UNKNOWN` for incomplete or failed reads.
- **No change** to 46-item compliance criteria or deterministic PASS/FAIL engine; obtaining a WAF ACL is not proof that SQLi/XSS blocking is active.
- An apparent `Allow` default, `Count` action or single managed-rule statement is evidence of *configuration*, not sufficient to classify the product control.
- Even WAF attached to an ALB cannot certify all ROS access paths without DNS/routing/CloudFront bypass evidence.
- WAF ownership, organization policy, all region/account coverage and runtime write prohibition remain **NOT_PROVEN**.

## Gates

- Fixed-HEAD CI on Python 3.12/3.13 and adversarial offline fixtures for sensitive rule content, malformed scopes/ARNs, AccessDenied, selected vs unrelated distributions, no spurious PASS.
- Independent static review of source selection, API read-only surface, selective CloudFront lookup, no secrets in exports.
- Separate Owner-approved read-only ROS runtime verification (future R9 smoke check), inspect errors, selected resource count and attribute results. No IAM changes.
- Human Owner acceptance and merge authorization, **after** independent review. Parent Issue #8 remains OPEN for 28 property-unobserved controls and all other roadmap items.

AWS primary references: [GetWebACLForResource](https://docs.aws.amazon.com/boto3/latest/reference/services/wafv2/client/get_web_acl_for_resource.html) and [WAFV2 GetWebACL](https://docs.aws.amazon.com/waf/latest/APIReference/API_GetWebACL.html).
