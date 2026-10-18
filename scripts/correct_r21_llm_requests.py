#!/usr/bin/env python3
"""Offline patch of the *saved original* R21 LLM v2 JSON.

Example:
  uv run --locked --no-sync python scripts/correct_r21_llm_requests.py \
    --bundle /private/aws_web_review_r21.json \
    --original /private/classification_r21_original.json \
    --output /private/classification_r21_corrected.json

Does not access AWS, URLs, credentials or the repository network.
The source JSON and the original LLM JSON must be kept unchanged.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aws_security_audit.r21_llm_request_correction import correct_r21_semantic_requests


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--original', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output
    if out.resolve() in (args.bundle.resolve(), args.original.resolve()):
        parser.error('Output path must differ from both read-only inputs')
    if out.exists():
        parser.error('Refuse to overwrite a prior correction: choose an unused output path')
    try:
        bundle = json.loads(args.bundle.read_text(encoding='utf-8'))
        original = json.loads(args.original.read_text(encoding='utf-8'))
        corrected, report = correct_r21_semantic_requests(bundle, original)
        # Exclusive create is intentional: do not overwrite forensic inputs.
        with out.open('x', encoding='utf-8') as stream:
            json.dump(corrected, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    except (ValueError, KeyError, TypeError, IndexError, OSError) as error:
        parser.exit(1, f'R21 correction refused: {error}\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
