# R22 — offline citation relevance / acquisition gap review

Issue [#8](https://github.com/yohi/aws-security-audit/issues/8) is still OPEN.
Parent R21 implementation PRs [#18](https://github.com/yohi/aws-security-audit/pull/18)
and [#19](https://github.com/yohi/aws-security-audit/pull/19) are **merged**.
This R22 follow-up **does not change AWS collection or the original Japanese
46-control checklist**, and it does not automatically reclassify even one row.

## Evidence and scope

Frozen operator evidence: 2026-10-18 ROS `master` audit in `ap-northeast-1`,
46 scanner controls, 80 attribute observations, 3 scanner FAIL (#16/#19/#22),
43 scanner MANUAL_REVIEW. Original seven reports, operator
`run_provenance.json`, and `SHA256SUMS.txt` had 8/8 original-file SHA256
checks and operator-run formal classification CLI exit 2 (structure PASS,
INCOMPLETE). Master commit `68741b365ca15c82ef50f6a0e106cb7fb4fd87d8`.

The 46-row v2 classification result and original AWS JSON are **not placed
in Git**; both remain local to the operator/LLM offline session. Avoid using
an old Web bundle with a newer result. Provenance is operator-recorded, **not
independent cryptographic runtime attestation**. `EFFECTIVE_NO_WRITE`,
product/region coverage and Owner adoption remain `NOT_PROVEN`.

## R22 changes

1. `refine_r22_citations(bundle, result)` calls the **actual R21 validator
   before and after** making any change. It only considers rows that the
   existing validator flagged `ALL_SOURCE_REFS_CITED_UNSELECTIVELY`.
2. A scanner citation can be omitted **only** when its claim exactly matches
   the known Japanese generic `元監査の#...はSTATUSであり...` wording,
   the STATUS is the actual status of the exact indexed source finding,
   the citation is exclusive to that boilerplate claim, and **all retained
   same-control resource observations still have claim-level bindings**.
   Otherwise it is left unchanged and flagged for human review.
3. The original source finding remains in the Web JSON. All real measured
   observation claims, typed fact codes, cross-control #45 snapshot proof,
   original evidence-request registry, 46 normative items, Japanese business
   labels, missing evidence, state, rationale and Owner approval state remain
   byte-for-byte equivalent **as parsed JSON fields**.
4. A private machine-gap report lists each outstanding request, the source
   refs and typed observed facts already present, the remaining question and
   the requirement to review these *before* any new AWS read. It is a
   **triage aid**, not a certificate that more AWS reads are required.

For the particular 2026-10-18 source and derived v2 draft, an offline
precheck identified the following 13 exact generic claims as eligible:
`#1,#2,#3,#6,#14,#16,#17,#19,#20,#22,#23,#27,#29`. This is
an **expected result**, not a claim that live/Owner semantic review is done.
Not every warning in future reports should be blindly eliminated.

## Six machine request containers: narrow read-first assessment

| Control / channel | Already supplied | Truly unresolved or still to adjudicate |
|---|---|---|
| #8 AWS read | General selected ROS ALB/network inventory | Shield Advanced subscription and protected-resource mapping need source evidence |
| #24 AWS read | CloudTrail `multi_region`, `is_logging`, event-type/selector flags | Effective selection of ROS S3 buckets and actual delivery-error state. No duplicate existing configuration read |
| #27 AWS read | Flow Logs `[]` observed at VPC/subnet scope | Whether ENI-level Flow Logs provide coverage; avoid repeating VPC/subnet reads |
| #33 AWS read/authorized export | `describe_hub InvalidAccessException` recorded | Root cause **unverified**, Security Hub enabled/standards/check states unverified; do not conclude IAM-only error or service disabled |
| #39 AWS read | Selected ROS resource inventory exists, not full app image ownership | Inspector/ECR scan coverage of Owner-confirmed AMI/container set and dated results |
| #40 non-AWS export | AWS source report does not contain repository/CI scan records | GitHub/CI dependency-scan configuration/results and Owner mapping of ROS repositories |

**Important:** the above are 6 *request containers*, not six automated tools,
six new APIs, or a commitment to run new AWS calls. Eleven controls within
four broad Owner batches may each require different documentation. Seven
Owner containers must not be represented as seven actual human actions.

## Private, disconnected execution after approval/merge

Use new output paths. Do not use the 14→13 R21 historical fixer for an
already compliant 13-request result.

```bash
cd "$HOME/program/private/aws-security-audit"
uv run --locked --no-sync python scripts/r22_offline_quality.py \
  --bundle "$REPORT_DIR/aws_web_review_08e009d671ef45f48610b5d2aeb6f53a.json" \
  --result /private/classification_r21_v2.json \
  --output /private/classification_r22_review_candidate.json \
  --report /private/r22_machine_gap_quality_report.json

set +e
uv run --locked --no-sync aws-security-audit validate-classification \
  --bundle "$REPORT_DIR/aws_web_review_08e009d671ef45f48610b5d2aeb6f53a.json" \
  --result /private/classification_r22_review_candidate.json
RC=$?
set -e
echo "CLI_EXIT=$RC"
```

For 43 pending, formal CLI exit **2 is expected**, with the same 3
provisional `未対応` labels, all 43 `EVIDENCE_PENDING`, all 13
root evidence-request containers and source claims for observed configurations.
A reduced citation-warning count is **not** evidence that semantic compliance
or Owner adoption has been proven.

The private output must be reviewed. If the original is malformed, evidence
refs disagree with the source, or the generic-scanner-status claim is not
unique/exact, the process **fails closed or leaves the warning**. Never
replace missing proof with a claim invented by a model.

## Required gates

- [ ] CI Python 3.12/3.13 and fixed-HEAD reviewer pass
- [ ] Operator-private real-data R22 script replay, input/output digest capture
      and actual merged CLI stdout/exit
- [ ] Human semantic audit for each remaining cited claim, especially
      #16 TLS, #19 EBS **RELATED** attribution, #22 S3; finalize actual
      Owner status and remediation progress separately
- [ ] Obtain actual missing evidence, preferably machine export before Owner
      interviews; only extend AWS collector after a **separate scoped review**
      proves existing read APIs cannot satisfy a specific unresolved criterion
- [ ] Keep Issue #8 OPEN until 46/46 authoritative Owner classification,
      source scope completeness and full governance gates are satisfied

No AWS API, secrets, automatic upload, infrastructure changes, CodeRabbit,
automatic merge or retroactive provenance claim is part of R22.
