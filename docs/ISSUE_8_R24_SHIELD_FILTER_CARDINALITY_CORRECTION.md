# R24 Shield API filter cardinality limited correction (Issue #8)

## Observed operator result

The approved first-pass ROS R24 operator read returned Shield `UNVERIFIED` with
two sanitized errors:

- `shield.describe_subscription: ResourceNotFoundException`
- `shield.list_protections: ValidationException`

The submitted scope includes **two** explicitly approved ALB ARNs. The R24
collector passed those two ARNs together in
`ListProtections.InclusionFilters.ResourceArns`, while the AWS Shield Advanced
API defines this filter as an array of **exactly one member**.

Authoritative AWS docs:
<https://docs.aws.amazon.com/waf/latest/DDOSAPIReference/API_InclusionProtectionFilters.html>

This is a deterministic code/API-contract mismatch. It is a **probable**
cause of the observed `ValidationException`, not proof of the sole cause
of all errors. The independently observed `DescribeSubscription`
`ResourceNotFoundException` is not the result of filter cardinality and
does not prove a final Shield Advanced subscription status.

## Bounded fix

- Keep the existing manually approved target ARN list and account/region guard.
- Call `ListProtections` separately for each exact selected ARN using
  `ResourceArns: [arn]`; never request the account-wide protection list.
- Preserve source order and individual result states.
- On a failed ARN request, record `protection_listed=null`, not `false`;
  the overall state remains `UNVERIFIED` if any target fails.
- If `DescribeSubscription` fails, overall state remains `UNVERIFIED`
  even if per-resource evidence is observed. No service-disabled inference.
- Do not add `GetSubscriptionState` in this patch: that is an additional
  read API needing its own review/authorization.
- No change to normal `assess`, STS role permissions, 46 controls, final
  classification labels, original R24 evidence or 13 request containers.

## Verification/authority

Synthetic offline tests cover two-resource API filter cardinality, per-target
partial errors and the ban on classifying API failure as no protection.

**This PR does not authorize a re-run.** The previous operator capture stays
immutable and `#8=UNVERIFIED`. A later AWS read must be separately
approved, use this fixed revision, new private output path, and independently
review the outstanding Shield subscription state. No automatic retries, IAM
changes, CodeRabbit, PR merge or product-wide classification.
