#!/usr/bin/env python3
"""Verify PUBLIC capacity-profile predicates with its separately selected Rust ELF.

No proving key, private note witness, backup, signer or network interface.
This verifies the private relation only; native NF absence/state/body obligations
and current chain authority remain the transcript consumer's responsibility.
"""
from pathlib import Path
import argparse
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import time

DEFAULT_BINARY = Path('/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-selected-prover-01/prover')
BINARY_SHA256 = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
BUILD_SHA256 = 'fcf6e8c757613e6fea9a5dd776727f1c2456865f1185c545ac9751ef9fb26419'
DOMAIN = bytes.fromhex('d55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb')
VK_SHA256 = {
    'compact2': '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987',
    'wide32': '160c879f984151c49648490e3b7e1f5aecc8a62b838a085cf9dfa8e9808c8f8d',
}


class CheckerUnavailable(RuntimeError):
    """Infrastructure/identity error, NEVER evidence that a proof is invalid."""


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def sealed_fd(label, raw, executable=False):
    fd = os.memfd_create(label, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
        os.fchmod(fd, 0o500 if executable else 0o400)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        return fd
    except BaseException:
        os.close(fd)
        raise


def checker_bytes(binary):
    fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
            raise CheckerUnavailable('checker_file_type_or_size')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(64 * 1024 * 1024 + 1)
        if len(raw) != st.st_size or digest(raw) != BINARY_SHA256:
            raise CheckerUnavailable('checker_identity')
        return raw
    finally:
        os.close(fd)


def verify(role, auth, proof, binary=DEFAULT_BINARY):
    """Return a genuine cryptographic predicate result, or raise on checker error.

    `role` is a trusted consumer choice, never read from a witness or loose VK.
    Curve decoding, canonical serialization, range/role semantics and actual
    Groth16 verification are performed by the authenticated old Rust code.
    """
    if role not in VK_SHA256:
        raise ValueError('trusted_role_required')
    if type(auth) is not bytes or type(proof) is not bytes:
        raise TypeError('public_bytes_required')
    base = {'schema': 'kpx5-public-g16-check/v1', 'role': role,
            'checker_elf_sha256': BINARY_SHA256,
            'compiled_build_identity_sha256': BUILD_SHA256,
            'domain_hex32': DOMAIN.hex(), 'vk_sha256': VK_SHA256[role],
            'authorization_sha256': digest(auth), 'proof_sha256': digest(proof),
            'native_settlement_or_chain_currentness_claimed': False,
            'PK_backup_or_private_note_witness_read': False}
    if len(auth) != 528 or len(proof) != 128:
        return dict(base, verified=False, rust_verifier_executed=False, reason='public_width')
    if auth[:8] != b'KPX4AU01' or auth[8:40] != DOMAIN:
        return dict(base, verified=False, rust_verifier_executed=False, reason='public_magic_or_domain')
    fds = []
    try:
        # Execute a sealed copy of the authenticated bytes: path replacement or
        # later writes cannot change the code after the whole-file hash check.
        fds.append(sealed_fd('public-g16-checker', checker_bytes(binary), True))
        fds.append(sealed_fd('public-auth528', auth))
        fds.append(sealed_fd('public-proof128', proof))
        began = time.monotonic()
        result = subprocess.run([f'/proc/self/fd/{fds[0]}', 'verify', role,
            f'/proc/self/fd/{fds[1]}', f'/proc/self/fd/{fds[2]}'],
            pass_fds=tuple(fds), stdin=subprocess.DEVNULL, capture_output=True,
            env={'PATH': '/usr/bin:/bin'}, timeout=3600, check=False)
        seconds = time.monotonic() - began
        if result.stderr or len(result.stdout) > 4096:
            raise CheckerUnavailable('checker_output')
        try:
            event = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            raise CheckerUnavailable('checker_protocol') from None
        if result.returncode == 1 and event in (
                {'event': 'error', 'code': 'public_auth_invalid'},
                {'event': 'error', 'code': 'public_proof_invalid'}):
            return dict(base, verified=False, rust_verifier_executed=True,
                        reason=event['code'], seconds=seconds)
        expected = {'event': 'proof-verified', 'role': role,
                    'authorization_sha256': base['authorization_sha256'],
                    'proof_sha256': base['proof_sha256'], 'vk_sha256': VK_SHA256[role]}
        if result.returncode != 0 or event != expected:
            raise CheckerUnavailable('checker_identity_or_protocol')
        return dict(base, verified=True, rust_verifier_executed=True,
                    reason='genuine_Groth16_verified', seconds=seconds)
    finally:
        for fd in reversed(fds):
            os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('role', choices=tuple(VK_SHA256))
    parser.add_argument('authorization', type=Path)
    parser.add_argument('proof', type=Path)
    parser.add_argument('--binary', type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()
    # Public inputs only. Bound oversized reads while retaining strict widths.
    with args.authorization.open('rb') as source:
        auth = source.read(529)
    with args.proof.open('rb') as source:
        proof = source.read(129)
    try:
        value = verify(args.role, auth, proof, args.binary)
    except (CheckerUnavailable, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'event': 'checker-unavailable', 'error_type': type(error).__name__}))
        return 2
    print(json.dumps(value, sort_keys=True))
    return 0 if value['verified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
