"""Reuse the pinned established V2 receiver; adapt its scan to sparse positions.

No global accepted-state oracle is created here. Input state is public data and
must first be derived from independently approved native history by the caller.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import types

from primitives import ZERO, fixed, need, parse

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'poc/future-recipient/v2/recipient.py'
SOURCE_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CRYPTO = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'


def no_symlinks(path):
    path = Path(path).absolute()
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'symlink-path')
    return path


def module():
    name = '_kpx4_compact_batch_receiver_v2'
    if name not in sys.modules:
        raw = no_symlinks(SOURCE).read_bytes()
        need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA, 'selected-V2-receiver-source')
        target = types.ModuleType(name)
        target.__file__ = str(SOURCE)
        sys.modules[name] = target
        try:
            exec(compile(raw, str(SOURCE), 'exec'), target.__dict__)
        except BaseException:
            del sys.modules[name]
            raise
    return sys.modules[name]


class Crypto:
    """Ordinary checked read-only established RustCrypto/libsecp adapter."""
    def __init__(self, path=CRYPTO):
        self.path = no_symlinks(path)
        info = self.path.stat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500
             and os.access(self.path, os.X_OK) and not os.access(self.path, os.W_OK),
             'selected-readonly-crypto-executable')
        raw = self.path.read_bytes()
        need(raw.startswith(b'\x7fELF') and hashlib.sha256(raw).hexdigest() == CRYPTO_SHA,
             'selected-crypto-executable-identity')

    def call(self, op, *, secret=None, public=None, payload=None):
        request = {'op': op}
        for key, value in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
            if value is not None:
                request[key] = value.hex()
        process = subprocess.run([str(self.path)], input=json.dumps(request), text=True,
            capture_output=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
        try:
            result = json.loads(process.stdout)
        except (ValueError, TypeError):
            raise module().Invalid('crypto-adapter') from None
        if process.returncode or type(result) is not dict or 'error' in result:
            error = result.get('error', 'adapter') if type(result) is dict else 'adapter'
            import re
            if type(error) is not str or re.fullmatch('[a-z0-9-]{1,80}', error) is None:
                error = 'adapter'
            raise module().Invalid('crypto-' + error)
        need(set(result) == {'hex'}, 'crypto-response-fields')
        try:
            return bytes.fromhex(result['hex'])
        except (ValueError, TypeError):
            raise module().Invalid('crypto-adapter') from None

    def xonly(self, secret):
        return fixed(self.call('derive-xonly', secret=fixed(secret)))

    def delivery_public(self, secret):
        return fixed(self.call('derive-delivery', secret=fixed(secret)))

    def seal(self, public, plaintext):
        return self.call('seal', public=fixed(public), payload=plaintext)

    def unseal(self, secret, ciphertext):
        return self.call('unseal', secret=fixed(secret), payload=ciphertext)


def backup(path, domain):
    path = no_symlinks(path)
    need(stat.S_IMODE(path.stat().st_mode) == 0o600, 'original-backup-mode')
    data = parse(path.read_bytes())
    need(set(data) == {'schema', 'network_id', 'genesis_hash_hex', 'domain_hex32', 'seed_hex32'}
         and data['schema'] == 'kpx4-compact-batch-seed-backup/v1'
         and data['network_id'] == 'testnet-10'
         and data['genesis_hash_hex'] == 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
         and data['domain_hex32'] == fixed(domain).hex(), 'original-backup-instance')
    value = data['seed_hex32']
    need(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value),
         'canonical-backup-seed')
    return bytes.fromhex(value)


def recover(receiver, snapshot, expected_state):
    """Caller-authenticated history only; no self-declared acceptance/currentness."""
    v2 = module()
    need(snapshot.state(receiver.domain) == fixed(expected_state, 112), 'authenticated-sparse-state')
    spent = {row.value for row in snapshot.nullifiers}
    result, first, groups = v2.Recovery(), {}, {}
    for delivery in snapshot.deliveries:
        try:
            receipt = receiver.open(delivery.ciphertext)
            if receipt.commitment() != delivery.cm:
                raise v2.Invalid('receipt-cm')
            nf = receiver.nullifier(receipt, delivery.position)
            if nf == ZERO:
                raise v2.Invalid('nf-zero')
        except v2.Invalid as error:
            result.rejected.append({'position': delivery.position, 'reason': str(error)})
            continue
        duplicate = receipt.index in first
        first.setdefault(receipt.index, delivery.position)
        claim = v2.OwnedClaim(delivery.position, receipt, nf, nf in spent, duplicate)
        result.owned.append(claim)
        groups.setdefault(receipt.index, []).append(claim)
    for group in groups.values():
        if len(group) > 1:
            for claim in group:
                claim.privacy_contaminated = True
    return result
