# R25 — evidence-first audit reporting (Issue #8)

## Why

The previous 2026-10-18 ROS product scan had 43 scanner MANUAL_REVIEW
and 3 FAIL flags, but 80 **resource-property observations** already existed.
A scanner status is **not** a count of distinct human checks, and 43 pending
four-label classifications do not imply 43 human actions. Previous messaging
conflated the axes.

R25 adds two **additive** private progress sidecars:
- aws_evidence_progress_<timestamp>.json
- aws_evidence_progress_<timestamp>.md

Both are produced automatically by the existing assess command, including
--llm off. The original JSON/CSV/XLSX 46-row summaries gain **three additive
columns**: 判定の意味 (explicitly MANUAL_REVIEW != a human work item),
機械観測の状態 and 次の証拠取得経路. Existing columns, the 46 normative
checklist, historical scanner status VALUES, report filenames, web handoff,
R21 v2 classification schema and Owner adoption requirements are unchanged.

## What it reports

For each of the 46 controls, R25 separates:
1. Original scanner regional/account status (PASS/FAIL/MANUAL_REVIEW/etc).
2. Direct, related or shared property evidence counts by
   PROPERTY_OK/PROPERTY_FAIL/PROPERTY_UNKNOWN/CONTEXT_ONLY.
3. Independent evidence acquisition route: AWS only, AWS+Owner scope,
   non-AWS machine export, or Owner documentation.
4. Optional R21/R22 validated, **provisional** four-label classification
   status if supplied (strict source/reference validation only).
5. Optional R24 read evidence states and separately curated MCP configuration
   facts, with **no automatic compliance reclassification**.

Counts for the original acquisition routes are 15 AWS read-only candidates,
24 AWS+Owner scope, 3 non-AWS machine evidence and 4 Owner documentation
controls (#42/#43/#44/#46). This means four DOCUMENTATION ROUTES, not exactly
four human actions.

### Historical 2026-10-18 report refresh: NO AWS calls

Use the existing local bundle and v2 classification already saved by
the operator, without repeating the 46-item scan:

    cd /var/tmp/aws-security-audit-r25
    uv run --locked --no-sync aws-security-audit report-progress \
      --bundle /var/tmp/aws-security-audit-r22-input/aws_web_review_08e009d671ef45f48610b5d2aeb6f53a.json \
      --classification /home/y_ohi/Downloads/ROS_MASTER_20261018_Offline_Classification_v2_DRAFT.json \
      --out /var/tmp/ros-report-progress-private

The paths above are **examples only**; use the actual current private
input paths, and an owner-controlled 0700 output directory.

Optional previously captured local R24 evidence:

    --r24 /var/tmp/ros-r24-evidence-M0j8jpJf/r24_targeted_evidence.json \
    --account 456720798575

Optional operator-curated MCP summary (must never be committed publicly):

    --mcp-summary /var/tmp/ros-mcp-summary-private.json --account 456720798575

The MCP summary is a minimal, manually captured report adapter:

    {
      "schema": "aws-security-mcp-observation-summary-v1",
      "account": "456720798575",
      "region": "ap-northeast-1",
      "product": "ros",
      "source": "OPERATOR_CURATED_MCP_READONLY_SUMMARY",
      "records": [
        {
          "number": 8,
          "api": "shield.GetSubscriptionState",
          "state": "OBSERVED",
          "fact": "SubscriptionState=INACTIVE",
          "scope_limit": "Account-level subscription; applicability/Owner adoption not yet proven"
        }
      ]
    }

MCP summary source is exactly one of
`OPERATOR_CURATED_MCP_READONLY_SUMMARY` or
`ASSISTANT_CURATED_MCP_READONLY_SUMMARY`; the latter describes the ROS
snapshot distilled from the ChatGPT MCP conversation. Do not label
assistant-authored summaries as operator-authored.

MCP summary facts are **not** raw independent runtime attestation.
All user-provided observation fields are treated as evidence data, not
executable instructions. The optional supplementary inputs are checked
against the product/region and an explicit expected account. They cannot
override old findings or classifications.

## Constraints and acceptance

- No AWS calls or STS credential access from report-progress.
- No AWS mutations anywhere in R25; do not weaken STS fail-closed rules.
- Do not convert partial PROPERTY_OK to full product PASS.
- Do not convert Shield INACTIVE, Inspector DISABLED, Security Hub errors,
  absent ALB WAF, or partial CloudTrail selector observations into Owner
  adopted labels. These are machine states with scope/applicability caveats.
- The 46 controls and R21 strict input/source-reference validation are
  preserved. If an existing classification fails that validation, reporting
  fails rather than silently trusting it.
- The optional MCP file is private operator input, not a connector pull.
- No automatic upload or GitHub evidence commit of private resource IDs.
- Independent implementation/security review required before merge.
