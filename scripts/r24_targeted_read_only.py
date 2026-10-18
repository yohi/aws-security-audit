#!/usr/bin/env python3
"""R24 operator-only targeted AWS read, disabled unless explicitly opted in.

Offline preflight, no AWS credentials or network:
  uv run --locked --no-sync python scripts/r24_targeted_read_only.py \
    --manifest /var/tmp/r24_owner_scope.json

A separate, explicitly approved human operator action is required to add:
  --execute-approved-read --source-profile default --role-arn arn:aws:iam::...:role/...
  --out /var/tmp/r24_private_evidence.json

No AWS write APIs, cloud upload, business status changes or auto-remediation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from aws_security_audit.core import AuditContext, AuditError
from aws_security_audit.r24_targeted_evidence import collect_r24, validate_manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--execute-approved-read', action='store_true',
                        help='Explicit local operator action; does NOT prove Owner approval')
    parser.add_argument('--source-profile')
    parser.add_argument('--role-arn')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    try:
        manifest = validate_manifest(json.loads(args.manifest.read_text(encoding='utf-8')))
    except (ValueError, KeyError, TypeError, OSError, AuditError) as exc:
        parser.exit(1, f'R24 preflight refused: {type(exc).__name__}: {exc}\n')
    targets = manifest['targets']
    if not args.execute_approved_read:
        print(json.dumps({
            'status': 'PREVIEW_ONLY_NO_AWS',
            'account': manifest['account'], 'region': manifest['region'],
            'target_counts': {k: len(v) if isinstance(v, list) else int(v)
                              for k, v in targets.items()},
            'scope_owner_approval_independently_verified': False,
            'live_execution_authorized_by_preview': False,
        }, ensure_ascii=False, sort_keys=True))
        return 0
    if not args.source_profile or not args.role_arn or args.out is None:
        parser.error('Live read requires profile, role ARN and private output path')
    out = args.out
    if (out.resolve() == args.manifest.resolve() or out.exists() or out.is_symlink()
            or not out.parent.is_dir()):
        parser.error('Output must be new, distinct and have an existing private parent directory')
    try:
        ctx = AuditContext(args.source_profile, args.role_arn, manifest['region'])
        record = collect_r24(ctx, manifest)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(out, flags, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(record, f, ensure_ascii=False, indent=2)
            f.write('\n')
    except (AuditError, OSError, ValueError, TypeError) as exc:
        parser.exit(1, f'R24 targeted read refused: {type(exc).__name__}: {exc}\n')
    print(json.dumps({
        'status': 'OPERATOR_TARGETED_READ_OUTPUT_WRITTEN_NOT_ADOPTED',
        'path': str(out),
        'effective_no_write': 'NOT_PROVEN',
        'owner_approval_independently_verified': False,
    }, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
