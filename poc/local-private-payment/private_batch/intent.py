"""Canonical owner-intent bytes for the proposed NEW private-batch profile.

This codec does not validate a signature, note, output, backing or native state.
The new aggregate relation must constrain these exact bytes and their financial
predicates. A host-computed digest is never proof of authorized effects.
"""
from dataclasses import dataclass
import hashlib

TAG = b'KPBINT01'
OUTPUT_BYTES = 520
INTENT_BYTES = 1460
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1


def _fixed(value: bytes, size: int) -> bytes:
    if type(value) is not bytes or len(value) != size:
        raise ValueError('invalid restricted-intent encoding')
    return value


def _uint(value: int, size: int) -> bytes:
    if type(value) is not int or not 0 <= value < 1 << (8 * size):
        raise ValueError('invalid restricted-intent integer')
    return value.to_bytes(size, 'little')


@dataclass(frozen=True)
class RestrictedIntent:
    chain_genesis: bytes
    pool_lineage: bytes
    profile_id: bytes
    domain: bytes
    service_policy: bytes
    reserve_outpoint: bytes
    old_cm_root: bytes
    old_nf_root: bytes
    old_cm_count: int
    old_nf_count: int
    old_reserve: int
    nullifier: bytes
    input_cv: bytes
    fee_sompi: int
    nonce: bytes
    outputs: tuple[bytes, bytes]

    def encode(self) -> bytes:
        context = b''.join(_fixed(v, 32) for v in (
            self.chain_genesis, self.pool_lineage, self.profile_id,
            self.domain, self.service_policy,
        ))
        if type(self.outputs) is not tuple or len(self.outputs) != 2:
            raise ValueError('invalid restricted-intent outputs')
        outputs = tuple(_fixed(v, OUTPUT_BYTES) for v in self.outputs)
        nf = _fixed(self.nullifier, 32)
        if nf == bytes(32) or outputs[0][:32] == outputs[1][:32]:
            raise ValueError('invalid restricted-intent resources')
        encoded = b''.join((
            TAG, context, _fixed(self.reserve_outpoint, 36),
            _fixed(self.old_cm_root, 32), _fixed(self.old_nf_root, 32),
            _uint(self.old_cm_count, 4), _uint(self.old_nf_count, 4),
            _uint(self.old_reserve, 8), nf, _fixed(self.input_cv, 64),
            _uint(self.fee_sompi, 8), _fixed(self.nonce, 32), *outputs,
        ))
        if len(encoded) != INTENT_BYTES:
            raise AssertionError('restricted-intent size mismatch')
        return encoded

    def authorization_digest(self) -> bytes:
        """SHA256 of canonical bytes; signature circuit must recompute it."""
        return hashlib.sha256(self.encode()).digest()

    def authorization_limbs(self) -> tuple[int, int]:
        """Inputs to existing stock Poseidon(2), not the Poseidon2 algorithm."""
        digest = self.authorization_digest()
        return int.from_bytes(digest[:16], 'little'), int.from_bytes(digest[16:], 'little')

    @classmethod
    def decode(cls, encoded: bytes) -> 'RestrictedIntent':
        _fixed(encoded, INTENT_BYTES)
        if encoded[:8] != TAG:
            raise ValueError('invalid restricted-intent version')
        offset = 8

        def take(size: int) -> bytes:
            nonlocal offset
            value = encoded[offset:offset + size]
            offset += size
            return value

        context = [take(32) for _ in range(5)]
        outpoint, cm_root, nf_root = take(36), take(32), take(32)
        cm_count, nf_count = int.from_bytes(take(4), 'little'), int.from_bytes(take(4), 'little')
        reserve, nf, cv = int.from_bytes(take(8), 'little'), take(32), take(64)
        fee, nonce = int.from_bytes(take(8), 'little'), take(32)
        outputs = (take(OUTPUT_BYTES), take(OUTPUT_BYTES))
        result = cls(*context, outpoint, cm_root, nf_root, cm_count, nf_count,
                     reserve, nf, cv, fee, nonce, outputs)
        if offset != INTENT_BYTES or result.encode() != encoded:
            raise ValueError('noncanonical restricted-intent encoding')
        return result
