# NEW SOURCE-ONLY RESEARCH FRAME. Not a Native policy, accepted profile or genuine-proof verifier.
# Transfer-prefix adaptation of exact public wire6727e00a. Exit deliberately omitted.
"""ADR-0066 independent public codec and path verifier.

This module has no note openings, key material, prover, network, or acceptance
flag. Rust must separately check canonical curve/proof encodings, three genuine
component proofs and commitment balance. The selected native policy must check
the actual transaction and current reserve. Public framing alone proves neither.
"""
from dataclasses import dataclass
import hashlib
import struct

DOMAIN = bytes.fromhex('a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6')
BODY_LEN, BODY_CORE_LEN, PREFIX_LEN = 3884, 3756, 193
PROJECTION_LEN = PREFIX_LEN + BODY_LEN
MAX_VALUE, NOTE_FLOOR, PAYOUT_FLOOR = 2_870_000_000_000_000_000, 60_000_000, 10_000_000
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
CM_DEPTH, NF_DEPTH = 16, 17
ZERO = bytes(32)


class WireError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise WireError(code)


def sha(*parts):
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


CM_EMPTY, NF_EMPTY = sha(b'KPX1CME\0'), sha(b'KPX1NFE\0')


def exact(raw, width, code):
    need(type(raw) is bytes and len(raw) == width, code)
    return raw


def integer(value, low, high, code):
    need(type(value) is int and low <= value <= high, code)
    return value


def u32(raw):
    return int.from_bytes(exact(raw, 4, 'u32-width'), 'little')


def u64(raw):
    return int.from_bytes(exact(raw, 8, 'u64-width'), 'little')


def fold(leaf, index, path, tag, depth):
    exact(leaf, 32, 'merkle-leaf-width')
    exact(path, depth * 32, 'merkle-path-width')
    integer(index, 0, (1 << depth) - 1, 'merkle-index')
    current = leaf
    for level in range(depth):
        sibling = path[32 * level:32 * (level + 1)]
        current = sha(tag, sibling, current) if (index >> level) & 1 else sha(tag, current, sibling)
    return current


def nf_leaf(value, successor, successor_index):
    exact(value, 32, 'nf-leaf-value-width')
    exact(successor, 32, 'nf-leaf-successor-width')
    integer(successor_index, 0, (1 << NF_DEPTH) - 1, 'nf-leaf-successor-index')
    return sha(b'KPX1NFL\0', value, successor, successor_index.to_bytes(4, 'little'))


def insert_nf(root, count, nf, witness):
    """Verify indexed predecessor replacement followed by an empty-slot append."""
    exact(root, 32, 'nf-root-width')
    exact(nf, 32, 'nf-width')
    exact(witness, 1160, 'nf-witness-width')
    integer(count, 1, (1 << NF_DEPTH) - 1, 'nf-count-capacity')
    index, value = u32(witness[:4]), witness[4:36]
    successor, successor_index = witness[36:68], u32(witness[68:72])
    need(index < count and successor_index < count and nf != ZERO
         and (index == 0) == (value == ZERO)
         and (successor_index == 0) == (successor == ZERO), 'nf-predecessor-indices')
    number = int.from_bytes(nf, 'little')
    need(int.from_bytes(value, 'little') < number
         and (successor == ZERO or number < int.from_bytes(successor, 'little')), 'nf-strict-interval')
    before, append = witness[72:616], witness[616:]
    need(fold(nf_leaf(value, successor, successor_index), index, before, b'KPX1NFN\0', NF_DEPTH)
         == root, 'nf-predecessor-root')
    middle = fold(nf_leaf(value, nf, count), index, before, b'KPX1NFN\0', NF_DEPTH)
    need(fold(NF_EMPTY, count, append, b'KPX1NFN\0', NF_DEPTH) == middle, 'nf-empty-append')
    return fold(nf_leaf(nf, successor, successor_index), count, append, b'KPX1NFN\0', NF_DEPTH)


@dataclass(frozen=True)
class State:
    raw: bytes
    cm_root: bytes
    cm_count: int
    nf_root: bytes
    nf_count: int


@dataclass(frozen=True)
class Spend:
    nf: bytes
    cv: bytes
    proof: bytes


@dataclass(frozen=True)
class Output:
    cm: bytes
    cv: bytes
    cf: bytes
    cfh: bytes
    proof: bytes
    tuple_bytes: bytes


@dataclass(frozen=True)
class Body:
    raw: bytes
    action_id: bytes
    reserved: bytes
    point: bytes
    old_state: State
    new_state: State
    old_reserve: int
    new_reserve: int
    fee: int
    payout: int
    delta: bytes
    spends: tuple
    outputs: tuple
    nf_witnesses: tuple
    cm_paths: tuple


@dataclass(frozen=True)
class Projection:
    raw: bytes
    prefix: bytes
    body: Body
    point: bytes
    input_amount: int
    input_spk: bytes
    output_amount: int
    output_spk: bytes


def parse_state(raw):
    exact(raw, 112, 'state-width')
    need(raw[:8] == b'KPBPST01' and raw[8:40] == DOMAIN, 'state-identity')
    cm_count, nf_count = u32(raw[72:76]), u32(raw[108:112])
    integer(cm_count, 1, 1 << CM_DEPTH, 'state-CM-count-range')
    integer(nf_count, 1, 1 << NF_DEPTH, 'state-NF-count-range')
    return State(raw, raw[40:72], cm_count, raw[76:108], nf_count)


def encode_state(cm_root, cm_count, nf_root, nf_count):
    exact(cm_root, 32, 'state-CM-root-width')
    exact(nf_root, 32, 'state-NF-root-width')
    integer(cm_count, 1, 1 << CM_DEPTH, 'state-CM-count-range')
    integer(nf_count, 1, 1 << NF_DEPTH, 'state-NF-count-range')
    return b'KPBPST01' + DOMAIN + cm_root + cm_count.to_bytes(4, 'little') + nf_root + nf_count.to_bytes(4, 'little')


def state_redeem(state112, immutable_tail_bytes):
    parse_state(state112)
    need(type(immutable_tail_bytes) is bytes and 0 < len(immutable_tail_bytes) <= 65535 - 114,
         'selected-immutable-tail-width')
    return b'\x4c\x70' + state112 + immutable_tail_bytes


def state_spk(state112, immutable_tail_bytes):
    return b'\0\0\xaa\x20' + hashlib.blake2b(state_redeem(state112, immutable_tail_bytes), digest_size=32).digest() + b'\x87'


def parse_output(row):
    exact(row, 520, 'output-tuple-width')
    need(row[:32] not in (ZERO, CM_EMPTY), 'output-CM-empty')
    need(sha(row[96:360]) == row[360:392], 'ciphertext-hash')
    return Output(row[:32], row[32:96], row[96:360], row[360:392], row[392:], row)


def build_output(cm, cv, cf, proof):
    row = (exact(cm, 32, 'output-CM-width') + exact(cv, 64, 'output-CV-width')
           + exact(cf, 264, 'output-CF-width') + sha(cf) + exact(proof, 128, 'output-proof-width'))
    parse_output(row)
    return row


def parse_body(raw):
    exact(raw, BODY_LEN, 'body-width')
    need(raw[:8] == b'KPBPBD01' and raw[8:16] == struct.pack('<4H', 1, 1, 2, 0)
         and raw[16:48] == DOMAIN, 'body-domain-version-shape')
    need(raw[48:80] != ZERO and raw[80:112] == ZERO and raw[112:144] != ZERO,
         'body-action-reserved-or-point')
    old, new = parse_state(raw[148:260]), parse_state(raw[268:380])
    reserve, remaining, fee, payout = (u64(raw[at:at + 8]) for at in (260, 380, 388, 396))
    need(NOTE_FLOOR <= reserve <= MAX_VALUE and NOTE_FLOOR <= remaining <= MAX_VALUE
         and 1 <= fee <= MAX_VALUE and payout == 0 and remaining + fee == reserve,
         'body-reserve-fee-or-payout')
    need(old.cm_count <= (1 << CM_DEPTH) - 2 and old.nf_count < 1 << NF_DEPTH
         and new.cm_count == old.cm_count + 2 and new.nf_count == old.nf_count + 1,
         'body-transition-counts')
    need(int.from_bytes(raw[404:436], 'little') < Q, 'canonical-delta-scalar')
    spend = Spend(raw[436:468], raw[468:532], raw[BODY_CORE_LEN:])
    need(spend.nf != ZERO, 'nonzero-original-NF')
    outputs = tuple(parse_output(raw[532 + 520 * i:1052 + 520 * i]) for i in range(2))
    need(outputs[0].cm != outputs[1].cm and outputs[0].tuple_bytes != outputs[1].tuple_bytes,
         'two-distinct-output-components')
    return Body(raw, raw[48:80], raw[80:112], raw[112:148], old, new, reserve, remaining,
                fee, payout, raw[404:436], (spend,), outputs, (raw[1572:2732],),
                (raw[2732:3244], raw[3244:3756]))


def parse_projection(raw):
    exact(raw, PROJECTION_LEN, 'projection-width')
    prefix, body = raw[:PREFIX_LEN], parse_body(raw[PREFIX_LEN:])
    need(prefix[:8] == b'KPBPFX01' and prefix[8:12] == b'\x01\0\x01\0'
         and prefix[48:56] == b'\xff' * 8 and prefix[64:66] == b'\x25\0'
         and prefix[103:105] == b'\x01\0' and prefix[113:115] == b'\x25\0'
         and prefix[152:189] == bytes(37) and u32(prefix[189:193]) == BODY_LEN,
         'projection-native-header')
    input_spk, output_spk = prefix[66:103], prefix[115:152]
    need(all(spk[:4] == b'\0\0\xaa\x20' and spk[-1:] == b'\x87'
             for spk in (input_spk, output_spk)), 'projection-script-form')
    old, new = u64(prefix[56:64]), u64(prefix[105:113])
    need(prefix[12:48] == body.point and old == body.old_reserve and new == body.new_reserve
         and old - new == body.fee, 'projection-native-effects')
    return Projection(raw, prefix, body, body.point, old, input_spk, new, output_spk)


def effects_digest(raw_projection):
    p = parse_projection(raw_projection)
    return sha(b'KPBPEF01', p.prefix, p.body.raw[:BODY_CORE_LEN])


def spend_statement(raw_projection):
    p = parse_projection(raw_projection)
    spend = p.body.spends[0]
    return b'KPBPSP01' + DOMAIN + p.body.old_state.cm_root + spend.nf + spend.cv + effects_digest(raw_projection)


def output_statement(row):
    out = parse_output(row)
    return b'KPBPOU01' + DOMAIN + out.cm + out.cv + out.cfh


def journal(raw_projection, component_profile_sha256):
    parse_projection(raw_projection)
    return b'KPBPJR01' + DOMAIN + exact(component_profile_sha256, 32, 'profile-digest-width') + sha(raw_projection)


def validate_public(raw_projection):
    """Structural checks require an authenticated occupied prior-state prefix."""
    p = parse_projection(raw_projection)
    b = p.body
    root = insert_nf(b.old_state.nf_root, b.old_state.nf_count, b.spends[0].nf, b.nf_witnesses[0])
    need(root == b.new_state.nf_root, 'NF-successor-root')
    root, count = b.old_state.cm_root, b.old_state.cm_count
    for out, path in zip(b.outputs, b.cm_paths):
        need(fold(CM_EMPTY, count, path, b'KPX1CMN\0', CM_DEPTH) == root, 'CM-empty-append')
        root = fold(out.cm, count, path, b'KPX1CMN\0', CM_DEPTH)
        count += 1
    need(root == b.new_state.cm_root, 'CM-successor-root')
    return {'public_frame_and_transition_validated': True,
            'effects_digest_hex32': effects_digest(raw_projection).hex(),
            'full_projection_sha256': sha(raw_projection).hex(),
            'g16_verified': False, 'curve_and_global_balance_verified': False,
            'native_VM_executed': False, 'accepted_backing_or_currentness': False}


def build_body_core(*, action_id, point, old_state, new_state, old_reserve, new_reserve,
                    fee, delta, nf, cv, outputs, nf_witness, cm_paths):
    for value, low, high in ((old_reserve, NOTE_FLOOR, MAX_VALUE),
                             (new_reserve, NOTE_FLOOR, MAX_VALUE), (fee, 1, MAX_VALUE)):
        integer(value, low, high, 'integer-sompi-range')
    need(type(outputs) in (list, tuple) and len(outputs) == 2
         and type(cm_paths) in (list, tuple) and len(cm_paths) == 2, 'body-builder-counts')
    core = (b'KPBPBD01' + struct.pack('<4H', 1, 1, 2, 0) + DOMAIN
            + exact(action_id, 32, 'action-id-width') + ZERO + exact(point, 36, 'outpoint-width')
            + exact(old_state, 112, 'old-state-width') + old_reserve.to_bytes(8, 'little')
            + exact(new_state, 112, 'new-state-width') + new_reserve.to_bytes(8, 'little')
            + fee.to_bytes(8, 'little') + bytes(8) + exact(delta, 32, 'delta-width')
            + exact(nf, 32, 'nf-width') + exact(cv, 64, 'input-CV-width')
            + b''.join(exact(row, 520, 'output-tuple-width') for row in outputs)
            + exact(nf_witness, 1160, 'nf-witness-width')
            + b''.join(exact(path, 512, 'CM-path-width') for path in cm_paths))
    parse_body(core + bytes(128))
    return core


def build_projection(body, immutable_tail):
    b = parse_body(body)
    prefix = (b'KPBPFX01' + b'\x01\0\x01\0' + b.point + b'\xff' * 8
              + b.old_reserve.to_bytes(8, 'little') + b'\x25\0' + state_spk(b.old_state.raw, immutable_tail)
              + b'\x01\0' + b.new_reserve.to_bytes(8, 'little') + b'\x25\0'
              + state_spk(b.new_state.raw, immutable_tail) + bytes(37) + BODY_LEN.to_bytes(4, 'little'))
    result = prefix + body
    validate_public(result)
    return result


def attach_spend_proof(raw_projection, proof):
    before = effects_digest(raw_projection)
    result = raw_projection[:-128] + exact(proof, 128, 'Spend-proof-width')
    validate_public(result)
    need(effects_digest(result) == before, 'Spend-attachment-effects')
    return result


def require_current_head(raw_projection, state112, point36, reserve_sompi, immutable_tail):
    """Compare supplied context; this function cannot authenticate its source."""
    result = validate_public(raw_projection)
    p = parse_projection(raw_projection)
    integer(reserve_sompi, NOTE_FLOOR, MAX_VALUE, 'current-reserve-range')
    need(p.body.old_state.raw == exact(state112, 112, 'current-state-width')
         and p.point == exact(point36, 36, 'current-point-width')
         and p.input_amount == reserve_sompi, 'exact-current-head-required')
    need(p.input_spk == state_spk(state112, immutable_tail)
         and p.output_spk == state_spk(p.body.new_state.raw, immutable_tail), 'selected-immutable-policy')
    return result

