"""Prepare an explicit unpublished release, full-object CAS and offline package.

Only five selected public inputs and fixed transport sources are copied. The
root must review the exact output inventory before authorizing any upload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from trusted_util import c, checked_source, VENDOR

BUFFER = 1_048_576
NOTICE = b'''EXPERIMENTAL PUBLIC DEVELOPMENT RECOVERY MATERIAL - DO NOT FUND
Native test-KAS research only. Known public unsafe canary; never deposit funds.
No backup, seed, private witness, owner map or operator main history is included.
The proving parameters use a development setup, not a soundness qualification.
Authenticating these bytes proves no current balance, accepted chain state,
independent provider, retention, permissionless exit or production safety.
Externally authenticate the complete role/manifest/VK/PK/software selection.
Never execute a downloaded program merely because this package inventories it.
'''


def save(path, raw):
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o444)


def copy_selected(source, destination, length, digest, forbidden):
    stream, before = c._open_public(source, forbidden)
    total, actual = 0, hashlib.sha256()
    temporary = destination.with_name(destination.name + '.part')
    try:
        with stream, temporary.open('xb') as target:
            c.need(before.st_size == length, 'selected-public-length')
            while raw := stream.read(min(BUFFER, length - total + 1)):
                total += len(raw)
                c.need(total <= length, 'selected-public-trailing-bytes')
                target.write(raw)
                actual.update(raw)
            after = os.fstat(stream.fileno())
            names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            c.need(tuple(getattr(before, n) for n in names) ==
                   tuple(getattr(after, n) for n in names), 'selected-public-file-changed')
            c.need(total == length and actual.hexdigest() == digest,
                   'selected-public-whole-identity')
            target.flush()
            os.fsync(target.fileno())
        temporary.chmod(0o444)
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)


def prepare(selection_path, expected_selection_sha256, source_paths, pk_path,
            output, forbidden_paths=()):
    forbidden_paths = tuple(forbidden_paths)
    forbidden = c._metadata_forbidden(forbidden_paths)
    raw_selection = c.read_public(selection_path, forbidden_paths, maximum=65536)
    c.need(c.sha(raw_selection) == expected_selection_sha256, 'external-selection-mismatch')
    selection = c.TrustedSelection.from_dict(c.parse(raw_selection))
    c.need(set(source_paths) == c.SMALL_KINDS, 'exact-four-public-JSON-inputs')
    owned = {kind: c.read_public(source_paths[kind], forbidden_paths)
             for kind in sorted(c.SMALL_KINDS)}
    for kind, pin in [('descriptor', selection.descriptor_sha256),
                      ('parameters_manifest', selection.parameters_manifest_sha256),
                      ('software_inventory', selection.software_inventory_sha256)]:
        c.need(c.sha(owned[kind]) == pin, 'selected-public-JSON-identity')
    descriptor = c._descriptor(owned['descriptor'], selection)
    c._parameters(owned['parameters_manifest'], selection, descriptor)
    c._history(owned['history'], selection)
    c._software(owned['software_inventory'], selection)
    output = c._path(output)
    c.need(not output.exists() and not any(p.is_symlink() for p in output.parents),
           'fresh-preparation-directory-required')
    output.mkdir(mode=0o700)
    assets, objects = output / 'assets', output / 'objects' / 'sha256'
    assets.mkdir(mode=0o700)
    objects.mkdir(parents=True, mode=0o700)
    chunk_tool, _ = checked_source('chunk_public.py')
    checked_source('capsule.py')
    command = [sys.executable, '-B', str(chunk_tool), 'pack', '--source', str(pk_path),
        '--expected-bytes', str(selection.public_parameters_bytes), '--expected-sha256',
        selection.public_parameters_sha256, '--output-dir', str(output / 'chunks')]
    for path in forbidden_paths:
        command.extend(['--forbidden', str(path)])
    child = subprocess.run(command, capture_output=True, text=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    c.need(child.returncode == 0, 'selected-chunk-pack-failed')
    chunk_result = json.loads(child.stdout)
    chunks_raw = c.read_public(output / 'chunks' / 'manifest.json')
    chunks = c.parse(chunks_raw)
    copy_selected(pk_path, objects / selection.public_parameters_sha256,
                  selection.public_parameters_bytes, selection.public_parameters_sha256, forbidden)
    refs, rows = [], []

    def asset(kind, basename, raw):
        digest = c.sha(raw)
        save(assets / basename, raw)
        target = objects / digest
        if not target.exists():
            save(target, raw)
        rows.append({'kind': kind, 'basename': basename, 'bytes': len(raw), 'sha256': digest})
        return digest

    for kind, raw in sorted(owned.items()):
        digest = asset(kind, kind + '.json', raw)
        refs.append({'kind': kind, 'bytes': len(raw), 'sha256': digest})
    refs.append({'kind': 'public_parameters', 'bytes': selection.public_parameters_bytes,
                 'sha256': selection.public_parameters_sha256})
    capsule = {'schema': 'kpx4-public-recovery-capsule/v1',
        'network_id': selection.network_id, 'genesis_hash_hex': selection.genesis_hash_hex,
        'domain_hex32': selection.domain_hex32, 'program_label': selection.program_label,
        'role': selection.role, 'objects': sorted(refs, key=lambda x: x['kind'])}
    capsule_sha = asset('capsule_index', 'capsule.json', c.encoded(capsule))
    asset('chunk_index', 'compact2-chunks.json', chunks_raw)
    for chunk in chunks['chunks']:
        source = output / 'chunks' / chunk['basename']
        destination = assets / chunk['basename']
        # Public owned chunk bytes are already authenticated by the selected
        # packer. A second full copy verifies each asset's identity separately.
        copy_selected(source, destination, chunk['bytes'], chunk['sha256'], forbidden)
        if not (objects / chunk['sha256']).exists():
            os.link(destination, objects / chunk['sha256'], follow_symlinks=False)
        rows.append({'kind': 'public_parameter_chunk', 'basename': chunk['basename'],
                     'bytes': chunk['bytes'], 'sha256': chunk['sha256']})
    asset('notice', 'NOTICE.txt', NOTICE)
    source_inventory = []
    here = Path(__file__).absolute().parent
    for relative in ('trusted_util.py', 'public_fetch.py', 'prepare.py', 'retrieve.py',
                     'vendor/capsule.py', 'vendor/chunk_public.py'):
        raw = c.read_public(here / relative, forbidden_paths)
        basename = 'source-' + c.sha(raw) + '.py'
        asset('transport_source', basename, raw)
        source_inventory.append({'path': relative, 'basename': basename,
                                 'bytes': len(raw), 'sha256': c.sha(raw)})
    asset('transport_source_inventory', 'transport-source-inventory.json',
          c.encoded({'schema': 'kpx4-offline-public-transport-source-inventory/v1',
                     'files': source_inventory, 'automatically_executable': False}))
    publication = {'schema': 'kpx4-public-recovery-distribution/v1',
        'classification': 'PUBLIC_UNSAFE_CANARY_DEVELOPMENT_PARAMETERS_DO_NOT_FUND',
        'role': selection.role, 'domain_hex32': selection.domain_hex32,
        'parameter_manifest_sha256': selection.parameters_manifest_sha256,
        'vk_sha256': selection.vk_sha256,
        'whole_parameters': {'bytes': selection.public_parameters_bytes,
                             'sha256': selection.public_parameters_sha256},
        'capsule_sha256': capsule_sha,
        'assets': sorted(rows, key=lambda x: x['basename']),
        'current_state_verified': False, 'spend_authorized': False,
        'publication_authorized': False}
    publication_raw = c.encoded(publication)
    save(output / 'PUBLICATION.json', publication_raw)
    save(objects / c.sha(publication_raw), publication_raw)
    save(output / 'EXTERNAL-SELECTION.json', raw_selection)
    return {'schema': 'kpx4-public-distribution-preparation-result/v1',
        'publication_sha256': c.sha(c.encoded(publication)), 'capsule_sha256': capsule_sha,
        'external_selection_sha256': expected_selection_sha256, 'asset_count': len(rows),
        'asset_bytes': sum(row['bytes'] for row in rows), 'compact_parameters_verified': True,
        'chunk_count': chunk_result['chunk_count'], 'unpublished': True,
        'no_backup_witness_main_private_history': True,
        'current_state_verified': False, 'spend_authorized': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True, type=Path)
    parser.add_argument('--expected-selection-sha256', required=True)
    parser.add_argument('--public-parameters', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    for kind in sorted(c.SMALL_KINDS):
        parser.add_argument('--' + kind.replace('_', '-'), required=True, type=Path)
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.selection, args.expected_selection_sha256,
            {kind: getattr(args, kind) for kind in c.SMALL_KINDS}, args.public_parameters,
            args.output, args.forbidden)
        print(json.dumps(result, sort_keys=True))
    except (c.Invalid, OSError):
        print(json.dumps({'status': 'PUBLIC_PREPARATION_INCOMPLETE',
                          'current_state_verified': False, 'spend_authorized': False}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
