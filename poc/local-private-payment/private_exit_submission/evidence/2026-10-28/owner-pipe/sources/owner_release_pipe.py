#!/usr/bin/env python3
"""Optional network-off owner release role: validated candidate -> pipe frame.

The unchanged direct release remains available separately. This role reads one
already prepared private candidate, needs no Original or proving key, and emits
only the established 4096-byte frame on stdout FD1. Fixed status uses stderr
only. A selected launcher must admit the entry/configuration and mount exactly
the declared sources, public context/runtime, and that owner's candidate.
"""
import argparse
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
WALLET = ROOT / 'poc/local-private-payment/private_batch_trial'
VALIDATOR = WALLET / 'exit_release.py'
PACKET = ROOT / 'poc/local-private-payment/private_exit_submission/packet.py'
SOURCE_PINS = {
    str(VALIDATOR): 'cafb737b2957b6a11743de8a319add82dc1dab520e708cd2ea0ca669b4577d4e',
    str(WALLET / 'exit_wire.py'): 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a',
    str(WALLET.parent / 'verification/wire.py'): '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8',
    str(PACKET): '7c0ad5f630a94a1481384c8726d98ebcfbab7ff1f6ba5395b3d8da9fafda38a6'}
RUNTIME_PINS = {
    '/runtime/prover': '930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6',
    '/parameters/MANIFEST.json': 'bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f'}


def need(value, category):
    if not value:
        raise ValueError(category)


def unique(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'owner-pipe-duplicate-public-config-field')
        value[key] = item
    return value


def parse(raw):
    return json.loads(raw, object_pairs_hook=unique)


def public_leaf(path, expected=None):
    """Bootstrap public config/code only; private reads use selected validator."""
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'owner-pipe-public-regular-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'owner-pipe-public-single-leaf')
        raw = handle.read()
        after = os.fstat(handle.fileno())
        need(all(getattr(before, key) == getattr(after, key) for key in
             ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')),
             'owner-pipe-public-stable-leaf')
    need(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'owner-pipe-public-selected-hash')
    return raw


def selected_module(name, path, raw):
    spec = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def emit_validated_frame(validated, output_fd, packet):
    # validate_candidate has already selected/reconstructed the finite public
    # schema and checked the exact context, statement and genuine AuthExit proof.
    frame = packet.encode(bytes.fromhex(validated['projection_hex']),
                          bytes.fromhex(validated['proof_hex128']))
    need(len(frame) == 4096, 'owner-pipe-established-frame-size')
    remaining = memoryview(frame)
    while remaining:
        written = os.write(output_fd, remaining)
        need(written > 0, 'owner-pipe-incomplete-write')
        remaining = remaining[written:]


def close_setup_fds():
    # Namespace setup may retain regular O_PATH descriptors after the mounts
    # are installed. The role needs only stdio; remove all ambient setup FDs
    # before any candidate or project validation, then assert that invariant.
    for text in os.listdir('/proc/self/fd'):
        descriptor = int(text)
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise


def worker(output_fd):
    need(output_fd == 1, 'owner-pipe-standard-stdout-data-channel')
    info = os.fstat(output_fd)
    flags = fcntl.fcntl(output_fd, fcntl.F_GETFL)
    need(stat.S_ISFIFO(info.st_mode) and flags & os.O_ACCMODE == os.O_WRONLY
         and not flags & os.O_NONBLOCK,
         'owner-pipe-write-only-pipe-capability')
    try:
        for text in os.listdir('/proc/self/fd'):
            descriptor = int(text)
            if descriptor > 2:
                try:
                    os.fstat(descriptor)
                except OSError as error:
                    if error.errno == errno.EBADF:  # The completed listdir's own FD.
                        continue
                    raise
                raise ValueError('owner-pipe-unselected-inherited-descriptor')
        marker = parse(public_leaf('/NAMESPACE.json'))
        need(marker == {'schema': 'kpb-owner-exit-pipe-namespace/v1', 'network': 'disabled',
             'private_candidate_slots': 1, 'Original_slots': 0, 'output_fd': 1, 'frame_bytes': 4096},
             'owner-pipe-exact-isolation-marker')
        interfaces = [line.split(':', 1)[0].strip()
                      for line in Path('/proc/net/dev').read_text().splitlines()[2:]]
        need(interfaces == ['lo'] and not Path('/original').exists()
             and not Path('/parameters/parameters.pk').exists()
             and not Path('/home/luke/.codex').exists() and not Path('/home/luke/.ssh').exists(),
             'owner-pipe-network-off-no-Original-or-host-private-mount')
        config = parse(public_leaf('/CONFIG.json'))
        expected = {'schema', 'chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32',
                    'service_hex32', 'history_sha256', 'tail_sha256', 'manifest_sha256',
                    'source_members', 'runtime_members'}
        need(type(config) is dict and set(config) == expected
             and config['schema'] == 'kpb-owner-exit-pipe-config/v1', 'owner-pipe-exact-public-config')
        source_rows = config['source_members']
        need(type(source_rows) is list and all(type(row) is dict and set(row) == {'path', 'sha256'}
             for row in source_rows), 'owner-pipe-source-selection-rows')
        source_map = {row['path']: row['sha256'] for row in source_rows}
        need(len(source_map) == len(source_rows) == 5
             and set(source_map) == set(SOURCE_PINS) | {str(Path(__file__).absolute())}
             and all(source_map[path] == pin for path, pin in SOURCE_PINS.items()),
             'owner-pipe-exact-existing-validation-and-packet-sources')
        runtime_rows = config['runtime_members']
        need(type(runtime_rows) is list and all(type(row) is dict and set(row) == {'path', 'sha256'}
             for row in runtime_rows)
             and len(runtime_rows) == 2
             and {row['path']: row['sha256'] for row in runtime_rows} == RUNTIME_PINS
             and config['manifest_sha256'] == RUNTIME_PINS['/parameters/MANIFEST.json'],
             'owner-pipe-public-verifier-only-no-proving-key')
        sources = {path: public_leaf(path, pin) for path, pin in source_map.items()}
        for path, pin in RUNTIME_PINS.items():
            public_leaf(path, pin)
        # The namespace contains these exact selected leaves at their original
        # virtual paths. Explicitly initialize them, bypassing bytecode caches.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(WALLET))
        selected_module('exit_wire', WALLET / 'exit_wire.py', sources[str(WALLET / 'exit_wire.py')])
        validator = selected_module('selected_owner_exit_validator', VALIDATOR, sources[str(VALIDATOR)])
        packet = selected_module('selected_owner_exit_packet', PACKET, sources[str(PACKET)])
        tail = validator.stable_read('/public/IMMUTABLE-TAIL.bin', config['tail_sha256'])
        history = validator.parse(validator.stable_read('/public/PUBLIC-HISTORY.json', config['history_sha256']))
        identity = tuple(validator.hx(config[name], 32) for name in
                         ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32'))
        context = validator.selected_head(history, identity)

        def genuine_proof(statement, proof):
            request = {'operation': 'verify', 'role': 'new-auth-exit',
                'profile': {'domain_hex32': config['domain_hex32'], 'profile_id_hex32': config['profile_hex32']},
                'statement_hex': statement.hex(), 'proof_hex128': proof.hex(),
                'parameters': {'manifest': '/parameters/MANIFEST.json',
                               'manifest_sha256': config['manifest_sha256']}}
            completed = subprocess.run(['/runtime/prover'], input=validator.encoded(request),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
            need(completed.returncode == 0, 'owner-pipe-selected-proof-verifier-refused')
            return validator.parse(completed.stdout).get('accepted') is True

        validated = validator.validate_candidate(
            validator.parse(validator.stable_read('/candidate/EXIT-CANDIDATE.json', private=True)),
            context, tail, genuine_proof)
        emit_validated_frame(validated, output_fd, packet)
    finally:
        os.close(output_fd)  # EOF is part of the one-frame transport contract.


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument('--output-fd', type=int, choices=(1,), required=True)
    args = parser.parse_args()
    try:
        close_setup_fds()
        worker(args.output_fd)
    except BaseException:
        print('{"schema":"kpb-owner-exit-pipe-status/v1","status":"REFUSED","financial_or_chain_acceptance":false}', file=sys.stderr, flush=True)
        os._exit(1)
    print('{"schema":"kpb-owner-exit-pipe-status/v1","status":"FRAME_WRITTEN","financial_or_chain_acceptance":false}', file=sys.stderr, flush=True)
    os._exit(0)  # stdout FD1 is deliberately closed; do not flush it again.


if __name__ == '__main__':
    main()
