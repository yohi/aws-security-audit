# Investigation-only one-command assessment (Draft)

This feature is **strictly for research/investigation, not remediation**. The repository changes extend the audit tool only. They do not approve, recommend executing, or automate AWS changes.

## Scope / prohibitions

- Allowed AWS calls: STS AssumeRole bootstrap, then `list_*`, `get_*`, and `describe_*` via the existing approved read-only API guard.
- **No** IAM policy change, security-group rule modification, EC2 stop/start, EBS encryption toggle, S3 block changes, AWS Config/Security Hub activation, Reachability Analyzer path creation, write-side verification, or any other AWS-side mutation.
- **No** AWS mutation even when a security finding is critical.
- No active network scanning, port probing, or production traffic.
- No automatic AI API call or transfer of AWS evidence. Optional LLM handoff is a **local file**, and the operator chooses whether to share it.
- Do not mark any `UNKNOWN` / `MANUAL_REVIEW` as `PASS` without sufficient independent evidence.
- `EFFECTIVE_NO_WRITE=NOT_PROVEN` remains so until independently authorized and demonstrated; the STS managed session policy alone is not effective write denial proof.

## One command (after local checkout + locked dependency installation)

```bash
uv run --locked --no-sync aws-security-audit assess \
  --source-profile default \
  --role-arn arn:aws:iam::168975706502:role/scs2-stg-ecs-tasks-role \
  --regions all \
  --llm export \
  --out ./reports
```

`--llm export` is the default and generates a **single evidence-rich JSON attachment plus a separate Markdown prompt** for manual use in ChatGPT Web or Gemini Web. It does not call an LLM API, upload files, or send data to an AI service. `--llm off` disables these two handoff files. Restrict access to private local files and explicitly review the attachment before manually uploading it: the JSON contains original finding evidence, resource IDs, and potentially sensitive names. The program cannot guarantee that arbitrary source evidence is anonymized.

`--regions all` targets all enabled account regions. A single STS session lasts one hour and is not refreshed automatically. Expired credentials cause `UNKNOWN` or failure; never use a fallback identity. If only `--regions ap-northeast-1` is requested, account-wide PASS remains withheld.

Outputs:
- Existing 46-control JSON/CSV/XLSX summaries, unchanged.
- `aws_investigation_*.json`: additional per-region observations for controls #5 and #19; resource IDs are present and file permission is 0600 on POSIX.
- `aws_web_review_*.json`: **one manually uploadable file** containing all 46 original outcomes, per-region evidence, and supplemental #5/#19 investigation; potentially sensitive, mode 0600.
- `aws_web_prompt_*.md`: **copy/paste prompt** for ChatGPT Web / Gemini Web explicitly restricting analysis to evidence assessment and forbidding remediation; mode 0600.
- The earlier aggregated-only Markdown packet is no longer the default output of `assess`.

## Supplemental investigation rules

### #5 Security groups

Inspect flagged unrestricted SSH/RDP/all-protocol ingress, deduplicate SGs, check ENI attachment count and interface types and public IPv4/IPv6 observations. **Never assert live internet reachability** from SG settings alone. Routes, NACL, endpoint service behavior, listeners and actual traffic are not proven.

### #19 EBS volumes

Enumerate volumes, find `Encrypted=False`, and inspect attachment, EC2 running/stopped state, root-device mapping, ASG instance membership, and region's default EBS encryption setting. A volume marked `in-use` is only attached, not necessarily to a running EC2. ASG evidence failures become `UNKNOWN` rather than `False`.

### All other 44 controls

Retain the existing scanner's original judgments and evidence. No claim is made that all 46 are now deterministically decidable. Further evidence collectors may be implemented after separately reviewing read-only scope and reliability.

## LLM review contract

The user manually attaches `aws_web_review_*.json` to ChatGPT Web or Gemini Web and pastes the content of `aws_web_prompt_*.md` into the browser chat. The LLM may summarize observations, uncertainty, risk, and evidence gaps. It must not:
- make up API evidence or remove account-wide partial-region restrictions;
- elevate incomplete evidence to PASS;
- recommend or trigger resource configuration changes as part of this assignment;
- claim the model itself proved IAM effective No-Write.

LLM judgments are **advisory annotations**, never changes to original machine statuses. No remediation advice, AWS modifications, or infrastructure configuration improvements belong to this workflow.

## Verification

Unit tests use offline fake API responses. AWS production state is not changed, and CI does not authenticate to AWS. Actual account tests require the human operator to run the command and inspect its private outputs.


## Resource inventory / product scope (draft, conservative)

- `assess` exports `aws_resource_inventory_<uuid>.json/.csv` and a `リソース台帳` Excel sheet containing the available `Name` tag, resource ID, ARN, identity tags (Name/Product/Project/Application/Service/Environment/Owner), non-secret identifying attributes and scope attribution. The web handoff JSON includes the same resource inventory.
- `--product scs2` selects exact `Product`/`Project`/`Application`/`Service` tag values `scs2` or identifier/Name prefix `scs2-`, `scs2_`, `scs2/`. It will **not** treat `scs20` as `scs2`.
- `--product scs2 --product-tag Project=scs2` requires that explicit allowlisted identity tag (not arbitrary case-insensitive string matching). Product mode does not reproduce/account-wide errors across unrelated products.
- EC2-linked EBS volumes and SGs may be included with `RELATED` attribution; this does **not** imply exclusive product ownership. VPC/subnet shared ownership is **not** inferred from EC2 links.
- Product mode only asserts observed FAIL for #2/#5/#19/#20/#23 when the selected resource evidence explicitly supports it. All other 46 checks retain `MANUAL_REVIEW` or `UNKNOWN`; PASS is never asserted while incomplete matching/coverage remains. The account-wide scanner is **not invoked** in product mode.
- IAM users/roles can have application-style names but are not definitively linked to a product from naming alone; S3/CloudFront and other global resources may require manual ownership validation. Inventory does not cover every AWS service. Errors or absent tags imply incomplete selection, not resource absence.
- With all 46 account-wide checks, identity inventory collection adds AWS read traffic after the scanner; an expiring one-hour STS session can leave evidence incomplete. In that case, the inventory contains collection errors and must not be represented as fully comprehensive.
- Exported files are local-only and may contain account infrastructure names/IDs; review before attaching to any Web LLM. No remediation / AWS write APIs or automated LLM calls are introduced.
