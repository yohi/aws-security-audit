"""Private export manifests and exclusive fail-closed export-set writing.

Synthetic payloads only; never touches files outside the failed invocation.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from aws_security_audit.report_manifest import (
    MANIFEST_SCHEMA,
    MANIFEST_SUFFIX,
    build_manifest,
    write_export_set,
)


PAYLOADS = {
    'a.json': b'{"x": 1}',
    'b.csv': 'あ,い\n1,2\n'.encode('utf-8'),
}


def test_manifest_hashes_files_and_keeps_input_digests():
    data = json.loads(build_manifest(PAYLOADS, {'source_bundle_sha256': 'ab' * 32}))
    assert data['schema'] == MANIFEST_SCHEMA
    assert [e['filename'] for e in data['files']] == sorted(PAYLOADS)
    for entry in data['files']:
        payload = PAYLOADS[entry['filename']]
        assert entry['sha256'] == hashlib.sha256(payload).hexdigest()
        assert entry['byte_size'] == len(payload)
    assert data['input_digests'] == {'source_bundle_sha256': 'ab' * 32}


def test_manifest_hash_changes_byte_level():
    tampered = {**PAYLOADS, 'a.json': PAYLOADS['a.json'] + b' '}
    first = json.loads(build_manifest(PAYLOADS, {}))['files'][0]['sha256']
    second = json.loads(build_manifest(tampered, {}))['files'][0]['sha256']
    assert first != second


def test_manifest_excludes_itself_and_rejects_manifest_payloads():
    # The manifest covers only payload files; a manifest-named entry in the
    # input set would be self-referential, so it fails closed instead.
    with pytest.raises(ValueError, match='excludes itself'):
        build_manifest({**PAYLOADS, 'out' + MANIFEST_SUFFIX: b'{}'}, {})
    # The manifest covers exactly the payload files; a manifest-named entry
    # in the input set would be self-referential, so it fails closed instead.
    data = json.loads(build_manifest(PAYLOADS, {}))
    assert [e['filename'] for e in data['files']] == sorted(PAYLOADS)


@pytest.mark.parametrize('name', ['/tmp/abs.json', 'sub/dir.json', 'a/../x.json',
                                  '../escape.json'])
def test_manifest_rejects_non_flat_relative_names(name):
    with pytest.raises(ValueError, match='relative'):
        build_manifest({name: b'{}'}, {})


def test_manifest_rejects_empty_names_and_ghost_digests():
    with pytest.raises(ValueError):
        build_manifest({'': b'{}'}, {})
    with pytest.raises(ValueError):
        build_manifest(PAYLOADS, {'k': ''})
    with pytest.raises(ValueError):
        build_manifest(PAYLOADS, {'k': 3})


def test_write_export_set_is_exclusive_private_and_sorted(tmp_path):
    manifest = build_manifest(PAYLOADS, {'k': 'v'})
    files = {**PAYLOADS, 'out' + MANIFEST_SUFFIX: manifest}
    paths = write_export_set(tmp_path, files)
    assert [p.name for p in paths] == sorted(files)
    assert all((p.stat().st_mode & 0o777) == 0o600 for p in paths)
    assert paths[0].read_bytes() == PAYLOADS['a.json']
    assert json.loads(paths[-1].read_text())['files'][0]['filename'] == 'a.json'


def test_write_failure_cleans_only_this_invocation(tmp_path):
    (tmp_path / 'b.csv').write_bytes(b'pre-existing')
    other = tmp_path / 'keep.json'
    other.write_bytes(b'untouched')
    with pytest.raises(FileExistsError):
        write_export_set(tmp_path, {**PAYLOADS, 'out.json': b'{}'})
    assert not (tmp_path / 'a.json').exists()
    assert (tmp_path / 'b.csv').read_bytes() == b'pre-existing'
    assert other.read_bytes() == b'untouched'


def test_previous_outputs_remain_unchanged(tmp_path):
    first = {f'round1{ext}': b'payload-one' for ext in ('.json', '.csv')}
    write_export_set(tmp_path, first)
    second = {f'round2{ext}': b'payload-two' for ext in ('.json', '.csv')}
    write_export_set(tmp_path, second)
    for name, payload in first.items():
        assert (tmp_path / name).read_bytes() == payload


def test_write_export_set_validates_names_before_writing(tmp_path):
    with pytest.raises(ValueError, match='relative'):
        write_export_set(tmp_path, {'x.json': b'{}', 'sub/y.json': b'{}'})
    assert list(tmp_path.iterdir()) == []
