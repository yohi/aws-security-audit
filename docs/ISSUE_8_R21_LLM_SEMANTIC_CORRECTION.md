# R21 — bounded correction of the real LLM evidence-request misclassification

Parent [Issue #8](https://github.com/yohi/aws-security-audit/issues/8).
This change is intentionally **stacked on the unmerged R21 v2 base PR #18**.
The source Web report and LLM classifier contain security/resource names and must stay
in private operator working storage, **not** be committed to the public repository.

## Scope of this PR

Adds `correct_r21_semantic_requests(bundle, original)` and a standalone operator CLI,
not a new AWS collector, a new business-status decision engine or a generic rewrite
of 46 criteria. The patch only operates on a saved, structurally valid original
**R21 v2 46-row** output matching the observed 14-request state and read-only
Web evidence. Unexpected evidence state, previously changed request sets,
different scoped region or finalized-label changes cause an explicit refusal.

The correction:
- #18: account-vs-bucket BPA **policy interpretation** -> `OWNER_CONFIRMATION`,
  not an AWS read to repeat known `NOT_CONFIGURED` account and 2 selected
  bucket BPA `true` / classic Access Point lists empty.
- #25: CloudTrail `LogFileValidationEnabled=true` is already observed,
  so remove its duplicate AWS acquisition and unrequired digest-delivery gate.
- #32: GuardDuty regional detector `ENABLED` is observed, so remove its
  duplicate AWS read, without presuming additional region coverage.
- #24: narrow the machine read to *actual ROS S3 event selector reach*
  and unresolved CloudTrail delivery errors; use one shared Owner account/
  region-applicability question for #24, #25 and #32.
- #33: `SecurityHub.describe_hub` error remains `UNVERIFIED`; no claim
  that IAM misconfiguration is proven as the sole cause.

Original 46 business labels and every `evidence_refs` ID are untouched.
The 3 technical negative controls (#16/#19/#22) remain **provisional 未対応**,
not Owner-approved. No `対応済み` or completed Owner evidence is fabricated.

## Expected root request containers

| | Original LLM v2 | Bounded correction |
|---|---:|---:|
| 46 controls | 46 | 46 |
| Pending | 43 | 43 |
| Provisional 未対応 | 3 | 3 |
| Distinct root request containers | 14 | **13** |
| Owner confirmation containers | 5 | **7** |
| AWS local read-only containers | 8 | **5** |
| Non-AWS machine export containers | 1 | **1** |

These are **request containers**, not confirmed counts of human decisions.
Four broad Owner batches may require many underlying documents or machine
exports. No claim of actual human labor reduction follows from this table.

## Operator-only offline use

Save the **original** LLM v2 JSON locally, without modifying its bytes first.
At a checkout containing this PR and its parent PR #18:

```bash
uv run --locked --no-sync python scripts/correct_r21_llm_requests.py \
  --bundle /private/aws_web_review_r21.json \
  --original /private/classification_r21_original.json \
  --output /private/classification_r21_limited_corrected.json

set +e
uv run --locked --no-sync aws-security-audit validate-classification \
  --bundle /private/aws_web_review_r21.json \
  --result /private/classification_r21_limited_corrected.json
rc=$?
set -e
printf 'classification_exit=%s\n' "$rc"
```

The operator CLI refuses existing output and overwrites neither the source
Web evidence nor the original LLM response. The code validates **both**
original and corrected outputs with the real imported R21 repository validator;
a historical, syntactically invalid original **must not** be silently fixed.
The fixed script is a narrow repair, not an autonomous data acquisition agent.
The formal CLI exit is **expected to be 2** for still-valid 43 pending cases.
An exit 2 means **INCOMPLETE**, not 46/46 adopted.

The user's earlier copied 46-row LLM answer did not arrive as a standalone,
byte-identifiable JSON file. The independent derived private correction
`ROS_R21_46_Control_Classification_v2_Limited_Corrected_20261018.json`
is a *separate* output artifact. **Do not put it in Git**; without the saved
original JSON, this PR's original-preserving patch cannot truthfully claim
to have replayed that original file.

## Acceptance

- [ ] Full CI Python 3.12/3.13; synthetic 14→13 regression + source-drift
  refusals, no real AWS data in tests.
- [ ] Operator runs the script on a saved original and matching private
  R21 Web bundle; retains input/output file hashes and actual CLI log/exit.
- [ ] Parent PR #18 fixed-head independent code/security review and missing
  original seven-report runtime sidecars are addressed or explicitly dispositioned.
- [ ] Separate Owner adoption/merge authorization, no automatic merge.
- [ ] Issue #8 remains OPEN: 46/46 documented final business labels and
  proved manual workload savings are still not established.

No AWS calls, permission expansion, secrets, CodeRabbit, production writes,
automatic uploads, or effective-NO-WRITE claims are part of this patch.
