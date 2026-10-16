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

`--llm export` is the default, and writes a **privacy-reduced local Markdown review packet only**. `--llm off` disables even that packet. Neither calls any AI API. Restrict access to both output files and any manually uploaded files as security-sensitive material.

`--regions all` targets all enabled account regions. A single STS session lasts one hour and is not refreshed automatically. Expired credentials cause `UNKNOWN` or failure; never use a fallback identity. If only `--regions ap-northeast-1` is requested, account-wide PASS remains withheld.

Outputs:
- Existing 46-control JSON/CSV/XLSX summaries, unchanged.
- `aws_investigation_*.json`: additional per-region observations for controls #5 and #19; resource IDs are present and file permission is 0600 on POSIX.
- `aws_llm_review_*.md`: aggregate, resource-ID-free offline LLM review handoff, also 0600.

## Supplemental investigation rules

### #5 Security groups

Inspect flagged unrestricted SSH/RDP/all-protocol ingress, deduplicate SGs, check ENI attachment count and interface types and public IPv4/IPv6 observations. **Never assert live internet reachability** from SG settings alone. Routes, NACL, endpoint service behavior, listeners and actual traffic are not proven.

### #19 EBS volumes

Enumerate volumes, find `Encrypted=False`, and inspect attachment, EC2 running/stopped state, root-device mapping, ASG instance membership, and region's default EBS encryption setting. A volume marked `in-use` is only attached, not necessarily to a running EC2. ASG evidence failures become `UNKNOWN` rather than `False`.

### All other 44 controls

Retain the existing scanner's original judgments and evidence. No claim is made that all 46 are now deterministically decidable. Further evidence collectors may be implemented after separately reviewing read-only scope and reliability.

## LLM review contract

If the operator separately gives the Markdown packet to an LLM, that LLM may summarize observations, uncertainty, risk, and evidence gaps. It must not:
- make up API evidence or remove account-wide partial-region restrictions;
- elevate incomplete evidence to PASS;
- recommend or trigger resource configuration changes as part of this assignment;
- claim the model itself proved IAM effective No-Write.

LLM judgments are **advisory annotations**, never changes to original machine statuses.

## Verification

Unit tests use offline fake API responses. AWS production state is not changed, and CI does not authenticate to AWS. Actual account tests require the human operator to run the command and inspect its private outputs.
