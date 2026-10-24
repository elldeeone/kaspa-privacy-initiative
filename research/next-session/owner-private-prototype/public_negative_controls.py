#!/usr/bin/env python3
"""Finite public-input rejection controls for the genuine ADR0063 projection.

This checks the selected host financial predicate, not R0 or Native acceptance.
No owner witnesses, input streams or ownership maps are opened. Every case keeps
the original authorization unless its name explicitly selects a damaged proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PREFIX, CORE, WIDTH = 193, 10396, 10973


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    p = Path(value).absolute()
    need(p == p.resolve(strict=True), 'canonical-existing-no-symlink-path')
    return p


class Guard:
    def __init__(self, old_roots, private_runtime_root):
        need(len(old_roots) == 2, 'required-private-exclusions')
        runtime = canonical(private_runtime_root)
        private_roots = [runtime / name for name in
                         ('party-0', 'party-1', 'party-2', 'controller-private')]
        self.roots, self.inodes = [], set()
        for root in old_roots:
            for role in 'ABCD':
                directory = canonical(Path(root) / 'owners' / role)
                leaf = canonical(directory / 'backup.json')
                s = leaf.stat()
                need(stat.S_ISREG(s.st_mode), 'original-private-metadata')
                self.roots.append(directory)
                self.inodes.add((s.st_dev, s.st_ino))
        need(len(self.inodes) == 8, 'eight-distinct-original-private-inodes')
        for root in private_roots:
            directory = canonical(root)
            need(directory.is_dir(), 'whole-private-directory')
            self.roots.append(directory)
            for current, dirs, files in os.walk(directory, followlinks=False):
                for name in dirs + files:
                    s = (Path(current) / name).lstat()
                    if stat.S_ISREG(s.st_mode):
                        self.inodes.add((s.st_dev, s.st_ino))

    def read(self, value, expected):
        p = canonical(value)
        before = p.stat()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and before.st_size <= 32 * 1024 * 1024
             and (before.st_dev, before.st_ino) not in self.inodes
             and all(not p.is_relative_to(root) for root in self.roots), 'public-ingress-only')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            opened = os.fstat(f.fileno())
            need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'stable-open')
            raw = f.read(32 * 1024 * 1024 + 1)
            after = os.fstat(f.fileno())
        attrs = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, k) == getattr(after, k) for k in attrs)
             and len(raw) == before.st_size and digest(raw) == expected, 'stable-selected-public-bytes')
        return raw


def variants(raw):
    cases = []

    def replace(name, offset, data):
        b = bytearray(raw)
        b[offset:offset + len(data)] = data
        cases.append((name, bytes(b)))

    def flip(name, offset):
        replace(name, offset, bytes([raw[offset] ^ 1]))

    def body(name, offset):
        flip(name, PREFIX + offset)

    cases.extend([('truncated_projection', raw[:-1]), ('trailing_projection_byte', raw + b'\0')])
    for name, offset in [('projection_magic', 0), ('native_sequence', 48),
                         ('native_input_amount', 56), ('native_input_spk', 70),
                         ('native_output_count', 103), ('native_successor_amount', 105),
                         ('native_successor_spk', 120), ('native_locktime', 153),
                         ('native_subnetwork', 161), ('native_gas', 181)]:
        flip(name, offset)
    for name, offset in [('body_magic', 0), ('domain', 16), ('session', 48), ('roster', 80),
                         ('previous_point', 112), ('old_cm_root', 188), ('old_nf_root', 224),
                         ('old_cm_count', 220), ('old_nf_count', 256), ('old_reserve', 260),
                         ('successor_cm_root', 308), ('successor_nf_root', 344),
                         ('successor_reserve', 380), ('fee', 388), ('extra_payout', 396),
                         ('stale_nf_path', 3844 + 72), ('stale_cm_append_path', 7324),
                         ('ciphertext', 724 + 96), ('ciphertext_hash', 724 + 360)]:
        body(name, offset)
    delta = int.from_bytes(raw[PREFIX + 404:PREFIX + 436], 'little')
    replace('changed_canonical_delta', PREFIX + 404, ((delta + 1) % Q).to_bytes(32, 'little'))
    replace('noncanonical_delta_q', PREFIX + 404, Q.to_bytes(32, 'little'))
    replace('zero_nf', PREFIX + 436, bytes(32))
    replace('duplicate_nf', PREFIX + 436 + 96, raw[PREFIX + 436:PREFIX + 468])
    replace('identity_input_cv', PREFIX + 468, bytes(32) + (1).to_bytes(32, 'little'))
    replace('noncanonical_input_cv_coordinate', PREFIX + 468, P.to_bytes(32, 'little'))
    replace('zero_output_proof', PREFIX + 724 + 392, bytes(128))
    replace('zero_spend_proof', PREFIX + CORE, bytes(128))
    replace('cross_role_proof', PREFIX + CORE, raw[PREFIX + 724 + 392:PREFIX + 724 + 520])
    replace('duplicate_output_tuple', PREFIX + 724 + 520, raw[PREFIX + 724:PREFIX + 724 + 520])
    b = bytearray(raw)
    b[PREFIX + CORE:PREFIX + CORE + 128], b[PREFIX + CORE + 128:PREFIX + CORE + 256] = (
        raw[PREFIX + CORE + 128:PREFIX + CORE + 256], raw[PREFIX + CORE:PREFIX + CORE + 128])
    cases.append(('swapped_spend_proofs', bytes(b)))
    return cases


def run(a):
    guard = Guard(a.exclude_old_trial, a.private_runtime_root)
    source = guard.read(a.projection, a.projection_sha256)
    host = guard.read(a.host, a.host_sha256)
    need(len(source) == WIDTH, 'exact-genuine-projection-width')
    root = Path(a.output).absolute()
    need(not root.exists(), 'fresh-output')
    parent = canonical(root.parent)
    need(all(not root.is_relative_to(p) for p in guard.roots), 'public-output-only')
    inside = subprocess.run(['/usr/bin/git', '-C', str(parent), 'rev-parse', '--is-inside-work-tree'],
                            stdin=subprocess.DEVNULL, capture_output=True, env={})
    need(inside.stdout.strip() != b'true', 'runtime-outside-git')
    root.mkdir(mode=0o700)
    (root / 'host').write_bytes(host)
    (root / 'host').chmod(0o500)
    results = []
    cases = [('genuine_positive', source)] + variants(source)
    for name, raw in cases:
        directory = root / name
        directory.mkdir(mode=0o700)
        (directory / 'projection.bin').write_bytes(raw)
        (directory / 'projection.bin').chmod(0o400)
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
                   '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib',
                   '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev',
                   '--tmpfs', '/tmp', '--ro-bind', str(root / 'host'), '/host',
                   '--ro-bind', str(directory / 'projection.bin'), '/projection.bin',
                   '--bind', str(directory), '/out', '--chdir', '/out',
                   '/host', 'host-check', '/projection.bin', '/out/result']
        child = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, env={})
        (directory / 'stdout.txt').write_bytes(child.stdout)
        (directory / 'stderr.txt').write_bytes(child.stderr)
        passed = child.returncode == 0
        need(passed == (name == 'genuine_positive'), 'unexpected-predicate-result:' + name)
        results.append({'case': name, 'projection_sha256': digest(raw),
                        'exit_code': child.returncode, 'accepted': passed,
                        'stdout_sha256': digest(child.stdout), 'stderr_sha256': digest(child.stderr)})
    changed_spend = next(raw for name, raw in cases if name == 'zero_spend_proof')
    effects = lambda b: digest(b'KPX7EF01' + b[:PREFIX + CORE])
    need(effects(source) == effects(changed_spend), 'documented-proof-witness-distinction')
    result = {'schema': 'kpx7-genuine-public-negative-controls/v1',
              'classification': 'UNFUNDED_HOST_PREDICATE_NOT_R0_OR_NATIVE_ACCEPTANCE',
              'source_projection_sha256': digest(source), 'selected_host_sha256': digest(host),
              'positive_count': 1, 'rejected_negative_count': len(results) - 1,
              'spend_proof_change_keeps_effects_digest': True,
              'private_content_read': False, 'ownership_map_or_anonymity_score': False,
              'cases': results}
    (root / 'RESULTS.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'positive_count': 1, 'rejected_negative_count': len(results) - 1,
                      'results_sha256': digest((root / 'RESULTS.json').read_bytes())}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for option in ('projection', 'projection-sha256', 'host', 'host-sha256', 'output'):
        p.add_argument('--' + option, required=True)
    p.add_argument('--exclude-old-trial', action='append', required=True)
    p.add_argument('--private-runtime-root', required=True)
    run(p.parse_args())
