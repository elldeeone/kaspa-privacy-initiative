#!/usr/bin/env python3
"""Build an unpublished local public-format CAS from five explicit inputs only.

No directory/archive scan, upload, proof, backup parsing or currentness claim.
Unbroadcast main Auth/NF histories stay private even though their wire format is
public; this builder never authorizes publication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

import capsule as c


def pack_local(selection, source_paths, new_output_directory, forbidden_paths=(), *, mode='spend_material'):
    forbidden_paths = tuple(forbidden_paths)
    c.need(type(selection) is c.TrustedSelection, 'trusted-selection-required')
    c.need(mode in ('recognition', 'spend_material'), 'staging-mode')
    required = c.KINDS if mode == 'spend_material' else c.SMALL_KINDS
    c.need(type(source_paths) is dict and set(source_paths) == required, 'explicit-source-kinds')
    forbidden = c._metadata_forbidden(forbidden_paths)
    owned = {kind: c.read_public(source_paths[kind], forbidden_paths)
             for kind in sorted(c.SMALL_KINDS)}
    for kind, digest in (('descriptor', selection.descriptor_sha256),
        ('parameters_manifest', selection.parameters_manifest_sha256),
        ('software_inventory', selection.software_inventory_sha256)):
        c.need(c.sha(owned[kind]) == digest, 'selected-source-digest')
    descriptor = c._descriptor(owned['descriptor'], selection)
    c._parameters(owned['parameters_manifest'], selection, descriptor)
    c._history(owned['history'], selection)
    c._software(owned['software_inventory'], selection)
    output = c._path(new_output_directory)
    c.need(not output.exists() and not any(p.is_symlink() for p in output.parents),
           'fresh-pack-directory-required')
    output.mkdir(mode=0o700)
    objects = output / 'objects/sha256'
    objects.mkdir(parents=True, mode=0o700)
    refs = []
    for kind, raw in sorted(owned.items()):
        digest = c.sha(raw)
        target = objects / digest
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(0o400)
        refs.append({'kind': kind, 'sha256': digest, 'bytes': len(raw)})
    refs.append({'kind': 'public_parameters', 'sha256': selection.public_parameters_sha256,
                 'bytes': selection.public_parameters_bytes})
    if mode == 'spend_material':
        stream, before = c._open_public(source_paths['public_parameters'], forbidden)
        temporary = objects / 'PUBLIC-PARAMETERS.part'
        with stream:
            c.need(before.st_size == selection.public_parameters_bytes, 'selected-PK-length')
            total, digest = 0, hashlib.sha256()
            with temporary.open('xb') as target:
                while chunk := stream.read(min(1024 * 1024, selection.public_parameters_bytes - total + 1)):
                    total += len(chunk)
                    c.need(total <= selection.public_parameters_bytes, 'selected-PK-length')
                    digest.update(chunk)
                    target.write(chunk)
                target.flush()
                os.fsync(target.fileno())
            after = os.fstat(stream.fileno())
        c.need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns), 'public-object-changed')
        c.need(total == selection.public_parameters_bytes
               and digest.hexdigest() == selection.public_parameters_sha256,
               'selected-PK-digest')
        temporary.chmod(0o400)
        temporary.rename(objects / selection.public_parameters_sha256)
    index = {'schema': 'kpx4-public-recovery-capsule/v1',
        'network_id': selection.network_id, 'genesis_hash_hex': selection.genesis_hash_hex,
        'domain_hex32': selection.domain_hex32, 'program_label': selection.program_label,
        'role': selection.role, 'objects': sorted(refs, key=lambda row: row['kind'])}
    raw = c.encoded(index)
    digest = c.sha(raw)
    (output / 'capsule.json').write_bytes(raw)
    (objects / digest).write_bytes(raw)
    (output / 'capsule.json').chmod(0o400)
    (objects / digest).chmod(0o400)
    receipt = {'schema': 'kpx4-local-public-format-capsule-pack/v1',
        'status': 'LOCAL_PUBLIC_FORMAT_CAPSULE_BUILT_NOT_PUBLISHED', 'mode': mode,
        'capsule_sha256': digest, 'capsule_bytes': len(raw),
        'compact_PK_included': mode == 'spend_material',
        'current_state_verified': False, 'spend_authorized': False,
        'publication_authorized': False, 'private_input_paths_or_hashes_emitted': False}
    (output / 'PUBLIC-PACK-RECEIPT.json').write_bytes(c.encoded(receipt) + b'\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trusted_selection', type=Path)
    parser.add_argument('new_output', type=Path)
    for kind in sorted(c.SMALL_KINDS):
        parser.add_argument('--' + kind.replace('_', '-'), required=True, type=Path)
    parser.add_argument('--public-parameters', type=Path)
    parser.add_argument('--forbidden', action='append', default=[], type=Path)
    parser.add_argument('--mode', choices=('recognition', 'spend_material'), default='spend_material')
    args = parser.parse_args()
    try:
        selection = c.TrustedSelection.from_dict(c.parse(c.read_public(args.trusted_selection,
            args.forbidden, maximum=65536)))
        paths = {kind: getattr(args, kind) for kind in c.SMALL_KINDS}
        if args.mode == 'spend_material':
            c.need(args.public_parameters is not None, 'PK-source-required')
            paths['public_parameters'] = args.public_parameters
        else:
            c.need(args.public_parameters is None, 'recognition-must-not-select-PK-source')
        print(json.dumps(pack_local(selection, paths, args.new_output,
            args.forbidden, mode=args.mode), sort_keys=True))
    except (c.Invalid, OSError):
        print(json.dumps({'status': 'INCOMPLETE_OR_INVALID', 'current_state_verified': False,
                          'spend_authorized': False}), file=__import__('sys').stderr)
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
