"""Untrusted transport framing only; never proof or spend authorization."""
from dataclasses import dataclass
import secrets

MAGIC = b'KPBXNET1'
FRAME_BYTES = 4096
PROJECTION_BYTES = (1796, 1844)
PROOF_BYTES = 128


class InvalidFrame(ValueError):
    pass


@dataclass(frozen=True)
class CandidateBytes:
    projection: bytes
    proof: bytes


def need(value):
    if not value:
        raise InvalidFrame('invalid Exit transport frame')


def encode(projection, proof, *, padding=None):
    need(type(projection) is bytes and len(projection) in PROJECTION_BYTES)
    need(projection[:8] == b'KPBXFX01')
    need(type(proof) is bytes and len(proof) == PROOF_BYTES)
    body = MAGIC + len(projection).to_bytes(2, 'little') + projection + proof
    remaining = FRAME_BYTES - len(body)
    if padding is None:
        padding = secrets.token_bytes(remaining)
    need(type(padding) is bytes and len(padding) == remaining)
    return body + padding


def decode(frame):
    need(type(frame) is bytes and len(frame) == FRAME_BYTES and frame[:8] == MAGIC)
    width = int.from_bytes(frame[8:10], 'little')
    need(width in PROJECTION_BYTES)
    projection = frame[10:10 + width]
    proof = frame[10 + width:10 + width + PROOF_BYTES]
    need(projection[:8] == b'KPBXFX01' and len(proof) == PROOF_BYTES)
    # Padding has no authorization meaning. Financial admission must consume
    # these exact bytes with the existing selected verifier/current-head path.
    return CandidateBytes(projection, proof)
