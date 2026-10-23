#!/usr/bin/env python3
"""Record exact public source/body/proof inputs for the reviewed offline run.

The root coordinator selects --authorize only after source/artifact review.
It is a local execution record, not a cryptographic approval mechanism.
"""
import argparse
import hashlib
import json
from pathlib import Path

import assemble as a


def add_path(paths, path):
    original = Path(path).absolute()
    if original.suffix in ('.pk', '.uncompressed'):
        raise ValueError('unexpected proving key in public input packet')
    if any(part.is_symlink() for part in (original, *original.parents)):
        raise ValueError('symlink component in public input packet: ' + str(original))
    if not original.is_file():
        raise ValueError('missing public input: ' + str(original))
    paths.add(original.resolve(strict=True))


def add_tree(paths, directory):
    if any(part.is_symlink() for part in (directory.absolute(), *directory.absolute().parents)):
        raise ValueError('symlink component in public input tree')
    if not directory.is_dir():
        raise ValueError('missing public input tree')
    for file in directory.rglob('*'):
        if file.is_symlink():
            raise ValueError('symlink in public input tree')
        if file.is_file() and '__pycache__' not in file.parts:
            add_path(paths, file)


def create(args):
    paths = set()
    here = Path(__file__).resolve().parent
    for pattern in ('*.py', '*.md'):
        for file in here.glob(pattern):
            add_path(paths, file)
    for binary in (args.native, args.crypto):
        add_path(paths, binary)
        with binary.open('rb') as file:
            if file.read(4) != b'\x7fELF':
                raise ValueError('selected executable is not ELF')
    add_path(paths, a.ROOT / 'poc/future-recipient/v2/recipient.py')
    add_tree(paths, args.prepared)
    if args.prefix:
        add_tree(paths, args.prefix)
    if args.setup_report:
        add_path(paths, args.setup_report)
    if args.proof_source:
        for name in ('lib.rs', 'circuit.rs', 'exact_sha256.rs', 'fixture.rs', 'main.rs'):
            add_path(paths, args.proof_source / name)
    if args.proof_root:
        stages = list(a.STAGES) + (['race-after-reveal'] if args.controls else [])
        for stage in stages:
            for filename in ('report.json', 'proof128.bin', 'verification-key.bin', 'authorization528.bin'):
                add_path(paths, args.proof_root / stage / filename)
    if args.controls:
        add_tree(paths, args.controls)
    if args.main_execution:
        add_tree(paths, args.main_execution)
    entries = []
    for path in sorted(paths):
        if not path.is_file() or path.is_symlink():
            raise ValueError('missing or symlink input: ' + str(path))
        raw = path.read_bytes()
        entries.append({'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    result = {'classification': a.CLASS, 'scope': 'UNFUNDED_PRIVATE_EXIT_LIFECYCLE',
        'runtime_authorized': args.authorize, 'review_note': args.review_note,
        'proving_keys_excluded': True, 'network_or_funding_authorized': False,
        'files': entries}
    a.save(args.output, result)
    return {'freeze_path': str(args.output), 'sha256': a.digest(args.output), 'files': len(entries),
            'runtime_authorized': args.authorize}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'crypto', 'prepared', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('prefix', 'setup-report', 'proof-source', 'proof-root', 'controls', 'main-execution'):
        parser.add_argument('--' + name, type=Path)
    parser.add_argument('--authorize', action='store_true')
    parser.add_argument('--review-note', required=True)
    args = parser.parse_args()
    print(json.dumps(create(args), sort_keys=True))


if __name__ == '__main__':
    main()
