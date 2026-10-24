"""ADR0064 public fixed-width codecs and state transitions.

No note openings, keys, PK, signing, proving, network or accepted-chain authority.
G16/curve/balance checks are separately performed by the fixed Rust predicate.
"""
from dataclasses import dataclass
import hashlib
import struct

DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')
BODY_LEN = 10780
BODY_CORE_LEN = 10396
PREFIX_LEN = 193
PROJECTION_LEN = PREFIX_LEN + BODY_LEN
MAX_VALUE = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
CM_DEPTH = 16
NF_DEPTH = 17
ZERO = bytes(32)
CM_EMPTY = hashlib.sha256(b'KPX1CME\0').digest()
NF_EMPTY = hashlib.sha256(b'KPX1NFE\0').digest()


class WireError(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise WireError(code)


def sha(*parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def u32(raw):
    need(type(raw) is bytes and len(raw) == 4, 'u32-width')
    return int.from_bytes(raw, 'little')


def u64(raw):
    need(type(raw) is bytes and len(raw) == 8, 'u64-width')
    return int.from_bytes(raw, 'little')


def fold(leaf, index, path, tag, depth):
    need(type(leaf) is bytes and len(leaf) == 32 and type(path) is bytes
         and len(path) == 32 * depth and type(index) is int
         and 0 <= index < (1 << depth), 'merkle-path-width-or-index')
    current = leaf
    for level in range(depth):
        sibling = path[32 * level:32 * (level + 1)]
        current = sha(tag, sibling, current) if (index >> level) & 1 else sha(tag, current, sibling)
    return current


def nf_leaf(value, successor, successor_index):
    return sha(b'KPX1NFL\0', value, successor, successor_index.to_bytes(4, 'little'))


def insert_nf(root, count, nf, witness):
    """Established indexed-NF predecessor replacement and empty append."""
    need(type(witness) is bytes and len(witness) == 1160
         and type(count) is int and 1 <= count < (1 << NF_DEPTH), 'nf-witness-count')
    index, value = u32(witness[:4]), witness[4:36]
    successor, successor_index = witness[36:68], u32(witness[68:72])
    need(index < count and successor_index < count
         and (index == 0) == (value == ZERO)
         and (successor_index == 0) == (successor == ZERO)
         and nf != ZERO, 'nf-predecessor-indices')
    n = int.from_bytes(nf, 'little')
    need(int.from_bytes(value, 'little') < n
         and (successor == ZERO or n < int.from_bytes(successor, 'little')), 'nf-strict-interval')
    before_path, append_path = witness[72:616], witness[616:1160]
    need(fold(nf_leaf(value, successor, successor_index), index, before_path,
              b'KPX1NFN\0', NF_DEPTH) == root, 'nf-predecessor-root')
    middle = fold(nf_leaf(value, nf, count), index, before_path, b'KPX1NFN\0', NF_DEPTH)
    need(fold(NF_EMPTY, count, append_path, b'KPX1NFN\0', NF_DEPTH) == middle, 'nf-empty-append')
    return fold(nf_leaf(nf, successor, successor_index), count, append_path, b'KPX1NFN\0', NF_DEPTH)


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
    session: bytes
    roster: bytes
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
    need(type(raw) is bytes and len(raw) == 112
         and raw[:8] == b'KPX8ST01' and raw[8:40] == DOMAIN, 'state-identity')
    n, m = u32(raw[72:76]), u32(raw[108:112])
    need(1 <= n <= (1 << CM_DEPTH) and 1 <= m <= (1 << NF_DEPTH), 'state-count-range')
    return State(raw, raw[40:72], n, raw[76:108], m)


def state_redeem(state112, immutable_tail_bytes):
    """Tail means every emitted byte after 4c70|State112, including any DROP.

    Caller must independently select/authenticate the immutable new image tail.
    Computing this P2SH does not select a financial template or authenticate it.
    """
    parse_state(state112)
    need(type(immutable_tail_bytes) is bytes and 0 < len(immutable_tail_bytes) <= 65535 - 114,
         'selected-immutable-tail-width')
    return b'\x4c\x70' + state112 + immutable_tail_bytes


def state_spk(state112, immutable_tail_bytes):
    redeem = state_redeem(state112, immutable_tail_bytes)
    return b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87'


def parse_body(raw):
    need(type(raw) is bytes and len(raw) == BODY_LEN, 'body-width')
    need(raw[:8] == b'KPX8PB01' and struct.unpack('<4H', raw[8:16]) == (1, 3, 6, 0)
         and raw[16:48] == DOMAIN, 'body-domain-version-shape')
    old, new = parse_state(raw[148:260]), parse_state(raw[268:380])
    reserve, remaining, fee, payout = (u64(raw[at:at + 8]) for at in (260, 380, 388, 396))
    need(NOTE_FLOOR <= reserve <= MAX_VALUE and NOTE_FLOOR <= remaining <= MAX_VALUE
         and 1 <= fee <= MAX_VALUE and payout == 0 and remaining + fee == reserve,
         'body-reserve-fee-or-payout')
    need(raw[48:80] != ZERO and raw[80:112] != ZERO and raw[112:144] != ZERO,
         'body-session-roster-or-point')
    need(old.cm_count >= 3 and old.cm_count + 6 == new.cm_count
         and old.nf_count + 3 == new.nf_count, 'body-transition-counts')
    spends = tuple(Spend(raw[436 + 96 * i:468 + 96 * i],
                         raw[468 + 96 * i:532 + 96 * i],
                         raw[BODY_CORE_LEN + 128 * i:BODY_CORE_LEN + 128 * (i + 1)])
                   for i in range(3))
    outputs = []
    for i in range(6):
        row = raw[724 + 520 * i:724 + 520 * (i + 1)]
        outputs.append(Output(row[:32], row[32:96], row[96:360], row[360:392], row[392:], row))
    need(all(spend.nf != ZERO for spend in spends)
         and len({spend.nf for spend in spends}) == 3, 'distinct-nonzero-original-NFs')
    need(len({out.cm for out in outputs}) == 6 and len({out.tuple_bytes for out in outputs}) == 6,
         'six-distinct-output-components')
    need(all(sha(out.cf) == out.cfh for out in outputs), 'ciphertext-hash')
    return Body(raw, raw[48:80], raw[80:112], raw[112:148], old, new,
                reserve, remaining, fee, payout, raw[404:436], spends, tuple(outputs),
                tuple(raw[3844 + 1160 * i:3844 + 1160 * (i + 1)] for i in range(3)),
                tuple(raw[7324 + 512 * i:7324 + 512 * (i + 1)] for i in range(6)))


def parse_projection(raw):
    need(type(raw) is bytes and len(raw) == PROJECTION_LEN, 'projection-width')
    p = raw[:PREFIX_LEN]
    need(p[:8] == b'KPX8FX01' and p[8:12] == b'\x01\0\x01\0'
         and p[48:56] == bytes([255]) * 8 and p[64:66] == b'\x25\0'
         and p[103:105] == b'\x01\0' and p[113:115] == b'\x25\0'
         and p[152:153] == b'\0' and p[153:189] == bytes(36)
         and u32(p[189:193]) == BODY_LEN, 'projection-native-header')
    input_spk, output_spk = p[66:103], p[115:152]
    need(all(spk[:4] == b'\0\0\xaa\x20' and spk[-1:] == b'\x87'
             for spk in (input_spk, output_spk)), 'projection-script-form')
    body = parse_body(raw[PREFIX_LEN:])
    input_amount, output_amount = u64(p[56:64]), u64(p[105:113])
    need(p[12:48] == body.point and input_amount == body.old_reserve
         and output_amount == body.new_reserve and input_amount - output_amount == body.fee,
         'projection-native-effects')
    return Projection(raw, p, body, p[12:48], input_amount, input_spk, output_amount, output_spk)


def effects_digest(raw_projection):
    projection = parse_projection(raw_projection)
    return sha(b'KPX8EF01', projection.prefix, projection.body.raw[:BODY_CORE_LEN])


def validate_public(raw_projection):
    """Check framing, exact native P0 effects and public root transitions.

    Incoming state must already have the accepted occupied-CM-prefix invariant;
    this function cannot authenticate genesis/history or private note membership.
    CV decoding, subgroup checks, all nine G16s and global balance remain required.
    """
    projection = parse_projection(raw_projection)
    body = projection.body
    nf_root, count = body.old_state.nf_root, body.old_state.nf_count
    for spend, witness in zip(body.spends, body.nf_witnesses):
        nf_root = insert_nf(nf_root, count, spend.nf, witness)
        count += 1
    need(nf_root == body.new_state.nf_root and count == body.new_state.nf_count, 'NF-successor-root')
    cm_root, count = body.old_state.cm_root, body.old_state.cm_count
    for out, path in zip(body.outputs, body.cm_paths):
        need(fold(CM_EMPTY, count, path, b'KPX1CMN\0', CM_DEPTH) == cm_root, 'CM-empty-append')
        cm_root = fold(out.cm, count, path, b'KPX1CMN\0', CM_DEPTH)
        count += 1
    need(cm_root == body.new_state.cm_root and count == body.new_state.cm_count, 'CM-successor-root')
    return {'public_frame_and_transition_validated': True,
            'effects_digest_hex32': effects_digest(raw_projection).hex(),
            'full_projection_sha256': sha(raw_projection).hex(),
            'g16_verified': False, 'curve_and_global_balance_verified': False,
            'native_VM_executed': False, 'accepted_backing_or_currentness': False}

# Full-note direct exits never require the MPC or shared outer prover.
EXIT_BODY_LEN = 1632
EXIT_CONTINUING_PREFIX_LEN = 240
EXIT_TERMINAL_PREFIX_LEN = 192
PAYOUT_FLOOR = 10_000_000


@dataclass(frozen=True)
class ExitBody:
    raw: bytes
    session: bytes
    point: bytes
    old_state: State
    new_state: State
    old_reserve: int
    new_reserve: int
    fee: int
    payout: int
    payout_spk: bytes
    nf: bytes
    nf_witness: bytes


@dataclass(frozen=True)
class ExitProjection:
    raw: bytes
    prefix: bytes
    body: ExitBody
    point: bytes
    input_amount: int
    input_spk: bytes
    outputs: tuple


def parse_exit_body(raw):
    need(type(raw) is bytes and len(raw) == EXIT_BODY_LEN, 'exit-body-width')
    need(raw[:8] == b'KPX8XB01' and struct.unpack('<4H', raw[8:16]) == (1, 1, 0, 1)
         and raw[16:48] == DOMAIN and raw[80:112] == ZERO, 'exit-body-identity')
    old, new = parse_state(raw[148:260]), parse_state(raw[268:380])
    reserve, remaining, fee, payout = (u64(raw[at:at + 8]) for at in (260, 380, 388, 396))
    need(NOTE_FLOOR <= reserve <= MAX_VALUE and 1 <= fee <= MAX_VALUE
         and PAYOUT_FLOOR <= payout <= MAX_VALUE
         and (remaining == 0 or NOTE_FLOOR <= remaining <= MAX_VALUE)
         and remaining + payout + fee == reserve, 'exit-money')
    need(raw[48:80] != ZERO and raw[112:144] != ZERO, 'exit-session-or-point')
    need(old.cm_root == new.cm_root and old.cm_count == new.cm_count
         and old.nf_count + 1 == new.nf_count, 'exit-state-counts-or-CM')
    spk, nf = raw[404:440], raw[440:472]
    need(spk[:3] == b'\0\0\x20' and spk[-1:] == b'\xac' and nf != ZERO,
         'exit-payout-SPK-or-NF')
    return ExitBody(raw, raw[48:80], raw[112:148], old, new, reserve, remaining,
                    fee, payout, spk, nf, raw[472:1632])


def parse_exit_projection(raw):
    need(type(raw) is bytes and len(raw) in
         (EXIT_BODY_LEN + EXIT_CONTINUING_PREFIX_LEN, EXIT_BODY_LEN + EXIT_TERMINAL_PREFIX_LEN),
         'exit-projection-width')
    width = len(raw) - EXIT_BODY_LEN
    p, body = raw[:width], parse_exit_body(raw[width:])
    need(p[:8] == b'KPX8FX01' and p[8:12] == b'\x01\0\x01\0'
         and p[48:56] == bytes([255]) * 8 and p[64:66] == b'\x25\0',
         'exit-projection-native-header')
    need(p[66:70] == b'\0\0\xaa\x20' and p[102:103] == b'\x87',
         'exit-input-SPK')
    count = int.from_bytes(p[103:105], 'little')
    need(count == (2 if body.new_reserve else 1), 'exit-output-count')
    at, outputs = 105, []
    for i in range(count):
        value, length = u64(p[at:at + 8]), int.from_bytes(p[at + 8:at + 10], 'little')
        need(length in (36, 37) and at + 11 + length <= width, 'exit-output-width')
        spk = p[at + 10:at + 10 + length]
        need(p[at + 10 + length:at + 11 + length] == b'\0', 'exit-output-covenant')
        outputs.append((value, spk))
        at += 11 + length
    need(at + 40 == width and p[at:at + 36] == bytes(36)
         and u32(p[at + 36:at + 40]) == EXIT_BODY_LEN, 'exit-projection-tail')
    need(p[12:48] == body.point and u64(p[56:64]) == body.old_reserve,
         'exit-projection-input')
    need(outputs[-1] == (body.payout, body.payout_spk), 'exit-projection-payout')
    if body.new_reserve:
        need(outputs[0][0] == body.new_reserve and len(outputs[0][1]) == 37
             and outputs[0][1][:4] == b'\0\0\xaa\x20' and outputs[0][1][-1:] == b'\x87',
             'exit-projection-continuation')
    need(body.old_reserve - sum(value for value, _ in outputs) == body.fee,
         'exit-projection-fee')
    return ExitProjection(raw, p, body, body.point, body.old_reserve, p[66:103], tuple(outputs))


def exit_effects_digest(raw_projection):
    projection = parse_exit_projection(raw_projection)
    return sha(b'KPX8EF01', projection.prefix, projection.body.raw)


def exit_statement(raw_projection):
    p = parse_exit_projection(raw_projection)
    b = p.body
    return (b'KPX8EX01' + DOMAIN + b.old_state.cm_root + b.nf
            + exit_effects_digest(raw_projection) + b.payout.to_bytes(8, 'little')
            + b.fee.to_bytes(8, 'little'))


def validate_exit_public(raw_projection):
    """Public framing/NF update only; native policy and pinned Exit proof remain required."""
    projection = parse_exit_projection(raw_projection)
    b = projection.body
    need(insert_nf(b.old_state.nf_root, b.old_state.nf_count, b.nf, b.nf_witness)
         == b.new_state.nf_root, 'exit-NF-successor-root')
    return {'public_frame_and_transition_validated': True,
            'effects_digest_hex32': exit_effects_digest(raw_projection).hex(),
            'exit_statement_hex152': exit_statement(raw_projection).hex(),
            'full_projection_sha256': sha(raw_projection).hex(),
            'g16_verified': False, 'native_VM_executed': False,
            'accepted_backing_or_currentness': False}
