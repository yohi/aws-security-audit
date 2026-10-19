"""Private export manifests and exclusive, fail-closed export-set writing.

`build_manifest` hashes every final payload byte into one JSON manifest of
relative filenames, SHA-256 digests and caller-supplied input digests; the
manifest excludes itself by rejecting manifest-named payloads. `write_export_set`
writes each file exclusively (0600 on POSIX, never overwriting a previous run)
and, on any failure, removes only the files created by that invocation so prior
outputs stay untouched. Integrity hashes are not provenance: nothing here
attests execution, ownership or effective no-write.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath
from typing import Mapping

from .report import _private_bytes

MANIFEST_SCHEMA = 'aws-security-export-manifest-v1'
MANIFEST_SUFFIX = '.manifest.json'


def _relative_name(name: str) -> str:
    """Accept only a single non-empty, flat, relative filename."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise ValueError(
            f'manifest filenames must be non-empty relative names: {name!r}')
    pure = PureWindowsPath(name)
    # A single flat filename; path separators, dot roots or drive anchors
    # would let an export escape the target directory.
    if (pure.is_absolute() or pure.anchor or len(pure.parts) > 1
            or '/' in name or '\\' in name or name in ('.', '..')):
        raise ValueError(
            f'manifest filenames must be flat and relative: {name!r}')
    return name


def build_manifest(files: Mapping[str, bytes],
                   input_digests: Mapping[str, str]) -> bytes:
    """One integrity manifest over all final payload bytes, excluding itself."""
    entries = []
    for name, payload in files.items():
        checked = _relative_name(name)
        if checked.endswith(MANIFEST_SUFFIX):
            raise ValueError('manifest excludes itself: '
                             f'{name!r} already names the manifest')
        entries.append({
            'filename': name,
            'sha256': hashlib.sha256(bytes(payload)).hexdigest(),
            'byte_size': len(payload),
        })
    digests = {}
    for key, value in dict(input_digests).items():
        if not isinstance(key, str) or not key or not isinstance(value, str) \
                or not value:
            raise ValueError('manifest input digests must be non-empty strings')
        digests[key] = value
    if len({e['filename'] for e in entries}) != len(entries):
        raise ValueError('manifest filenames must be unique')
    payload = {
        'schema': MANIFEST_SCHEMA,
        'purpose': 'PRIVATE_EXPORT_INTEGRITY_HASHES_NOT_PROVENANCE',
        'files': sorted(entries, key=lambda e: e['filename']),
        'input_digests': digests,
    }
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + '\n'
    return text.encode('utf-8')


def write_export_set(out_dir: Path,
                     files: Mapping[str, bytes]) -> tuple[Path, ...]:
    """Exclusively write every file; clean only this invocation on failure."""
    names = [_relative_name(name) for name in files]
    if len(set(names)) != len(names):
        raise ValueError('export-set filenames must be unique')
    directory = Path(out_dir).expanduser().resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    written: list[Path] = []
    try:
        for name in sorted(names):
            path = directory / name
            _private_bytes(path, bytes(files[name]))
            written.append(path)
    except BaseException:
        for path in written:
            # Cleanup must never mask the original failure.
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return tuple(written)
