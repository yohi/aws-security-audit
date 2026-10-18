# Issue #8 R16 — Selected EC2 route/SSH context, owner role pending

Base: merged PR #12, `master` commit
`2d67216225928860e758a39951a68d36a20b0725`.

## Objective

Make controls #1 (application instance placement) and #3 (bastion IP
restrictions) **more inspectable, not automatically compliant**.

**There is no owner-supplied authoritative mapping of EC2 instance IDs to
AP or bastion functions.** The code reports `owner_approved_role=NOT_PROVIDED`
for the instances; names such as `ros-sftp`, `bastion`, `api`, or `web` do
not define a verified technical role. The 46 original formal verdict
algorithms remain unchanged.

## Collection contract

New AWS operation: `ec2:DescribeRouteTables` (read-only).

In product mode only, for instances already classified as **DIRECT** by the
existing product-selection logic:

1. Gather distinct instance `(region, VpcId)` pairs. Call
   `DescribeRouteTables` once per selected VPC, scoped with the `vpc-id`
   filter. Never query an unrelated VPC for this feature.
2. Resolve an explicitly associated subnet route table first. If none is
   explicitly associated, use the *unique* VPC main table. A main table
   association is not the same as an explicit subnet association.
3. Export only a route table ID, `EXPLICIT_SUBNET` versus `IMPLICIT_MAIN`,
   and for default IPv4/IPv6 routes, their family, route state and
   **allowlisted target class** (e.g., INTERNET_GATEWAY, NAT_GATEWAY).
   Do not export raw gateway target IDs, unrelated routes, or destination
   networks from other subnets.
4. On missing/contradictory/malformed associations, invalid route target
   variants or permission failure, mark
   `UNVERIFIED_SCHEMA`/`UNVERIFIED_READ_ERROR`. Record bounded
   `describe_route_tables` collection errors tied to each selected
   instance. An absent default route is **not proof of no reachability**.

For **the same DIRECT instances**, correlate attached SG IDs against
already selected SG inventory and summarize only whether TCP/22 (or all
protocol) ingress is configured: number of rules, IPv4/IPv6/SG/prefix-list
source counts and 0.0.0.0/0 or ::/0 flags. No **new SG API calls** are added.
Unknown SG source/missing rule fields => `UNVERIFIED_SG_COVERAGE` or
`UNVERIFIED_SG_SCHEMA`, not a proof of restriction.

## Control mapping

- **#1:** existing EC2 public-address/subnet row + new
  `EC2 selected subnet route table context` row. Valid configuration is
  **CONTEXT_ONLY**; missing/denied/malformed evidence is
  **PROPERTY_UNKNOWN**. Route read errors affect only #1, tied to the
  directly selected EC2 ID.
- **#3:** new `EC2 attached security group SSH port 22 ingress summary`
  row, **CONTEXT_ONLY** for complete selected-SG configuration,
  **PROPERTY_UNKNOWN** otherwise. This expands the controls with *some*
  property evidence without certifying bastion identity or access control.
- Neither signal changes formal PASS/FAIL, determines a product
  `AP`/`BASTION` role, or proves internet/SSH reachability.
- **Unproven:** owner-approved role classification; traffic paths through
  other ENIs, NACLs, IPv6 or centralized firewalls; ingress via tunnels,
  Security Manager/session access; effective privileges; all possible
  source-IP and user access; complete route reachability.

AWS contract:
- https://docs.aws.amazon.com/vpc/latest/userguide/subnet-route-tables.html
- https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-route-tables.html

## Verification / approval gates

- [ ] Offline Python 3.12/3.13 fixed-HEAD CI.
- [ ] Independent limited code/security review (role non-inference,
  route/SG parser fail closed, output minimization and product scoping).
  **Do not trigger CodeRabbit** without explicit Human Owner permission.
- [ ] Separate Human Owner authorization of a single read-only ROS R16
  AWS smoke test if required, with distinct output directory and
  fixed-HEAD installed source verification.
- [ ] Compare R16 evidence with R15 (46 verdicts preserved,
  selected inventory, #1 and #3 observations, new collection errors).
  Do not claim effective AWS No-Write from STS session policy.
- [ ] Separate Human Owner merge decision; keep Issue #8 OPEN.

Do not infer that a public-IP SFTP instance violates AP-only
requirements. Human ownership/role mapping is an independent prerequisite
for a product-level control verdict.
