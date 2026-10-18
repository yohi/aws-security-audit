#!/usr/bin/env python3
"""Read-only R22 evidence quality pass for a locally saved R21 v2 result.

Example (run on the operator machine, without AWS credentials):
  uv run --locked --no-sync python scripts/r22_offline_quality.py \
    --bundle /private/aws_web_review.json \
    --result /private/classification_r21_v2.json \
    --output /private/classification_r22_review_candidate.json \
    --report /private/r22_quality_and_machine_gaps.json

No AWS connections, automatic uploads, Owner status changes or remediation.
Both output files must not exist already, and input files are not overwritten.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from aws_security_audit.r22_evidence_quality import refine_r22_citations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--result', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    inputs = {args.bundle.resolve(), args.result.resolve()}
    outputs = (args.output.resolve(), args.report.resolve())
    if len(set(outputs)) != 2 or any(path in inputs for path in outputs):
        parser.error('Outputs must be distinct from each other and both inputs')
    if any(path.exists() or path.is_symlink() for path in outputs):
        parser.error('Refuse to overwrite output or symlink')
    created = []
    try:
        bundle = json.loads(args.bundle.read_text(encoding='utf-8'))
        original = json.loads(args.result.read_text(encoding='utf-8'))
        corrected, report = refine_r22_citations(bundle, original)
        for path, document in ((args.output, corrected), (args.report, report)):
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(path, flags, 0o600)
            created.append(path)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(document, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        for path in created:
            path.unlink(missing_ok=True)
        parser.exit(1, f'R22 offline quality pass refused: {type(error).__name__}: {error}\n')

    print(json.dumps({
        'status': report['status'],
        'citation_warnings_before': report['citation_warnings_before'],
        'citation_warnings_after': report['citation_warnings_after'],
        'pruned_count': len(report['boilerplate_citations_removed']),
        'machine_gap_count': len(report['machine_gap_triage']),
        'pending_controls': report['unchanged_pending'],
        'classification_is_owner_approved': False,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
