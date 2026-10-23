#!/usr/bin/env python3
"""Public-key-only local measurement controller; no backup/proof/main history.

Caller supplies source files and an independently selected whole anchor for each
role. Paths are operational arguments, excluded from the public outcome. The
actual pack/restore CLI and readback authenticate raw public bytes only.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def run(command):
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        # Tool errors are fixed public categories; never export issued paths.
        raise RuntimeError('public-chunk-child-failed: ' + result.stdout.strip())
    return json.loads(result.stdout), time.monotonic() - start


def digest_file(path):
    hasher = hashlib.sha256()
    total = 0
    with path.open('rb') as stream:
        while raw := stream.read(1_048_576):
            hasher.update(raw)
            total += len(raw)
    return total, hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--new-output', required=True, type=Path)
    parser.add_argument('--chunk-source', required=True, type=Path)
    parser.add_argument('--capsule-source', required=True, type=Path)
    parser.add_argument('--original-repo', required=True, type=Path)
    parser.add_argument('--profile', required=True, action='append', nargs=4,
                        metavar=('ROLE', 'BYTES', 'SHA256', 'PUBLIC_SOURCE'))
    args = parser.parse_args()
    args.new_output.mkdir(mode=0o700, parents=False, exist_ok=False)
    relative = Path('/proc/self/cgroup').read_text().split(':', 2)[2].strip()
    group = Path('/sys/fs/cgroup') / relative.lstrip('/')
    caps = {name: (group / name).read_text().strip()
            for name in ('cpu.max', 'memory.max', 'memory.swap.max')}
    expected_caps = {'cpu.max': '400000 100000', 'memory.max': '4294967296',
                     'memory.swap.max': '0'}
    if caps != expected_caps:
        raise RuntimeError('unexpected-controller-resource-caps')
    rows = []
    for role, raw_length, sha256, raw_source in args.profile:
        if role not in ('compact2', 'wide32'):
            raise RuntimeError('unknown-public-profile-label')
        length = int(raw_length)
        source = Path(raw_source).absolute()
        output = args.new_output / role
        output.mkdir(mode=0o700, exist_ok=False)
        chunks = output / 'chunks'
        restored = output / 'restored'
        restored.mkdir(mode=0o700, exist_ok=False)
        anchor = ['--expected-bytes', str(length), '--expected-sha256', sha256]
        packed, pack_seconds = run(['/usr/bin/python3', '-B',
            str(args.chunk_source), 'pack', '--source', str(source),
            '--output-dir', str(chunks), *anchor])
        bwrap = ['/usr/bin/bwrap', '--unshare-all', '--clearenv',
                 '--die-with-parent', '--new-session', '--ro-bind', '/usr',
                 '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib',
                 '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc',
                 '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/work',
                 '--ro-bind', str(args.chunk_source), '/work/chunk_public.py',
                 '--ro-bind', str(args.capsule_source), '/work/capsule.py',
                 '--ro-bind', str(chunks), '/chunks', '--bind', str(restored),
                 '/output', '--chdir', '/work', '--setenv', 'PATH',
                 '/usr/bin:/bin', '/usr/bin/python3', '-B',
                 '/work/chunk_public.py', 'restore', '--manifest',
                 '/chunks/manifest.json', '--mirror', '/chunks', '--output',
                 '/output/reconstructed.pk', *anchor,
                 '--must-be-absent', str(source), '--must-be-absent',
                 str(source.parent), '--must-be-absent',
                 str(args.original_repo.absolute())]
        recovered, restore_seconds = run(bwrap)
        readback_start = time.monotonic()
        actual = digest_file(restored / 'reconstructed.pk')
        if actual != (length, sha256):
            raise RuntimeError('independent-readback-anchor-mismatch')
        row = {'role': role, 'pack': packed, 'restore': recovered,
               'pack_wall_seconds': pack_seconds,
               'restore_wall_seconds': restore_seconds,
               'independent_output_readback_wall_seconds':
                   time.monotonic() - readback_start,
               'independent_output_readback_matches_selected_whole_anchor': True,
               'restore_source_and_original_cache_repo_mounted': False,
               'restore_mount_scope': {'system_usr': 'read-only',
                   'selected_transport_files': 2,
                   'public_chunk_directory': 'read-only',
                   'fresh_output_directory': 'read-write',
                   'private_inputs_or_prover_or_original_source': False,
                   'network_unshared': True}}
        write(output / 'RESULT.json', row)
        rows.append(row)
    write(args.new_output / 'RESULT.json', {
        'schema': 'kpx4-public-key-offline-chunk-roundtrips/v1',
        'actual_observed_caps': caps, 'profiles': rows,
        'only_public_PK_bytes_no_backups_proofs_main_history': True,
        'same_host_offline_transport_not_independent_provider_retention': True,
        'parameter_decode_native_or_chain_currentness_claimed': False})
    print(json.dumps({'status': 'BOTH_PUBLIC_PK_CHUNK_ROUNDTRIPS_VERIFIED',
                      'profiles': [row['role'] for row in rows]}, sort_keys=True))


if __name__ == '__main__':
    main()
