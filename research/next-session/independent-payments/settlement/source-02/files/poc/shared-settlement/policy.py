"""Public KPX4 transition semantics, independent of note openings and reports.

This mirrors the selected policy's public checks, not its ScriptEngine. A true
result is neither NativeFull nor accepted/current chain authority. G16 must be
checked separately. Reachable starting state/empty suffix are external premises.
"""
from dataclasses import dataclass

from wire import Invalid, h, hexbytes, need, p2sh, storage_mass, transaction_id, uint, validate_case

DOMAIN = bytes.fromhex('35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6')
TAIL_SHA256 = '67ffaf246b915dfd1835d9a39401d72c9a197ea1e148a976a4f70305c70ce284'
MAX = 2_870_000_000_000_000_000
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
ZERO = bytes(32)
CM_TAG, NF_TAG = b'KPX1CMN\0', b'KPX1NFN\0'


def number(raw):
    return int.from_bytes(raw, 'little')


def u32(value):
    return uint(value, 32).to_bytes(4, 'little')


def parts(raw, width):
    need(len(raw) % width == 0, 'public_array_width')
    return [raw[i:i + width] for i in range(0, len(raw), width)]


def fold(leaf, index, path, tag):
    need(len(leaf) == 32 and type(index) is int and 0 <= index < 1 << len(path), 'merkle_index')
    current = leaf
    for height, sibling in enumerate(path):
        need(len(sibling) == 32, 'merkle_sibling_width')
        left, right = (sibling, current) if index >> height & 1 else (current, sibling)
        current = h(tag, left, right)
    return current


def state(raw, domain=DOMAIN):
    need(type(raw) is bytes and len(raw) == 112, 'state_width')
    need(raw[:40] == b'KPX2ST01' + domain, 'state_magic_or_domain')
    n, m = number(raw[72:76]), number(raw[108:112])
    need(1 <= n <= 65535 and 1 <= m <= min(131071, 2 * n + 1), 'state_count_bounds')
    return {'cm': raw[40:72], 'n': n, 'nf': raw[76:108], 'm': m}


def auth_fields(raw, role, domain=DOMAIN, allow_no_append_exit=False):
    need(type(raw) is bytes and len(raw) == 528, 'auth_width')
    need(raw[:40] == b'KPX4AU01' + domain, 'auth_magic_or_domain')
    old, new = state(raw[76:188], domain), state(raw[364:476], domain)
    reserve, fee, remaining, payout = [number(raw[off:off + 8]) for off in (188, 196, 476, 484)]
    need(NOTE_FLOOR <= reserve <= MAX and 1 <= fee <= MAX and 0 <= payout <= MAX,
         'financial_bounds')
    need(remaining == reserve - fee - payout and (remaining == 0 or NOTE_FLOOR <= remaining <= MAX),
         'reserve_conservation')
    mode = raw[300]
    need(role in ('compact2', 'wide32') and mode in ((0, 2) if role == 'compact2' else (32,)),
         'trusted_role_mode')
    need((mode == 0 and (allow_no_append_exit or remaining == 0))
         or (mode != 0 and remaining != 0), 'terminal_mode_iff_reserve_zero')
    need(mode != 32 or payout == 0, 'wide_payout_zero')
    need(raw[301:304] == bytes(3) and raw[308:332] == bytes(24), 'reserved_zero')
    need(new['m'] == old['m'] + 2, 'NF_count_increment')
    nfs = (raw[204:236], raw[236:268])
    need(ZERO not in nfs and nfs[0] != nfs[1], 'two_distinct_nonzero_NFs')
    if payout:
        need(payout >= PAYOUT_FLOOR and raw[492:495] == b'\0\0\x20' and raw[527:] == b'\xac',
             'payout_floor_or_SPK')
    else:
        need(raw[492:] == bytes(36) and mode != 0, 'P0_destination_zero')
    return {'old': old, 'new': new, 'reserve': reserve, 'fee': fee, 'remaining': remaining,
            'payout': payout, 'mode': mode, 'nfs': nfs, 'start': number(raw[304:308])}


def nf_leaf(value, following, next_index):
    return h(b'KPX1NFL\0', value, following, u32(next_index))


def insert_public(root, count, nf, witness):
    """Authenticate exact strict indexed absence and derive its sequential root."""
    need(len(root) == len(nf) == 32 and len(witness) == 1160, 'NF_public_width')
    index, value, following, next_index = (number(witness[:4]), witness[4:36],
                                         witness[36:68], number(witness[68:72]))
    need(1 <= count < 131071 and index < count and next_index < count, 'NF_predecessor_indices')
    need((index == 0) == (value == ZERO) and (next_index == 0) == (following == ZERO),
         'NF_sentinel_index')
    need(nf != ZERO, 'NF_nonzero')
    predecessor_path, append_path = parts(witness[72:616], 32), parts(witness[616:], 32)
    need(fold(nf_leaf(value, following, next_index), index, predecessor_path, NF_TAG) == root,
         'NF_current_predecessor_root')
    need(number(value) < number(nf), 'NF_strict_predecessor')
    need(following == ZERO or number(nf) < number(following), 'NF_strict_successor')
    middle = fold(nf_leaf(value, nf, count), index, predecessor_path, NF_TAG)
    need(fold(h(b'KPX1NFE\0'), count, append_path, NF_TAG) == middle, 'NF_empty_append')
    return fold(nf_leaf(nf, following, next_index), count, append_path, NF_TAG)


def append_public(old, new, auth, payload, mode, start):
    if mode == 0:
        need(len(payload) == 2848 and auth[268:332] == bytes(64)
             and auth[332:364] == h(bytes(528)), 'terminal_public_sentinels')
        need(new['cm'] == old['cm'] and new['n'] == old['n'], 'terminal_CM_carry')
        return
    log_n = mode.bit_length() - 1
    need(mode in (2, 32) and len(payload) == 2848 + 296 * mode + 32 * (16 - log_n),
         'continuing_payload_width')
    need(start == (old['n'] + mode - 1) // mode * mode and new['n'] == start + mode
         and new['n'] <= 65535, 'CM_aligned_range')
    cms = payload[2848:2848 + 32 * mode]
    ciphers = payload[2848 + 32 * mode:2848 + 296 * mode]
    boundary = parts(payload[2848 + 296 * mode:], 32)
    need(h(cms) == auth[268:300], 'CM_ordered_array_digest')
    need(h(ciphers) == auth[332:364], 'CF_array_digest')
    empty = h(b'KPX1CME\0')
    for _ in range(log_n):
        empty = h(CM_TAG, empty, empty)
    need(fold(empty, start >> log_n, boundary, CM_TAG) == old['cm'], 'CM_empty_subtree')
    nodes = parts(cms, 32)
    while len(nodes) > 1:
        nodes = [h(CM_TAG, nodes[i], nodes[i + 1]) for i in range(0, len(nodes), 2)]
    need(fold(nodes[0], start >> log_n, boundary, CM_TAG) == new['cm'], 'CM_successor_root')


@dataclass(frozen=True)
class Head:
    transaction_id: str
    index: int
    state: bytes
    reserve: int
    scope: str = 'EXTERNALLY_SELECTED_SYNTHETIC_HEAD'
    domain: bytes = DOMAIN

    def __post_init__(self):
        hexbytes(self.transaction_id, 32)
        uint(self.index, 32)
        need(type(self.domain) is bytes and len(self.domain) == 32, 'external_head_domain')
        state(self.state, self.domain)
        need(type(self.reserve) is int and NOTE_FLOOR <= self.reserve <= MAX, 'external_head_reserve')
        need(type(self.scope) is str, 'external_head_scope')

    def point(self):
        return {'transactionId': self.transaction_id, 'index': self.index}


class Policy:
    def __init__(self, immutable_tail, compact_vk, wide_vk=None, *, domain=DOMAIN,
                 expected_tail_sha256=TAIL_SHA256, allow_no_append_exit=False):
        need(type(domain) is bytes and len(domain) == 32 and type(expected_tail_sha256) is str
             and type(allow_no_append_exit) is bool, 'trusted_child_profile')
        need(type(immutable_tail) is bytes and h(immutable_tail).hex() == expected_tail_sha256,
             'independently_selected_immutable_policy')
        need(len(immutable_tail) + 114 < 65536 and len(compact_vk) == 328
             and immutable_tail.count(compact_vk) == 1, 'selected_role_key_operands')
        if wide_vk is not None:
            need(len(wide_vk) == 328 and compact_vk != wide_vk and immutable_tail.count(wide_vk) == 1,
                 'selected_role_key_operands')
        self.tail = immutable_tail
        self.domain = domain
        self.tail_sha256 = expected_tail_sha256
        self.allow_no_append_exit = allow_no_append_exit

    def redeem(self, raw_state):
        state(raw_state, self.domain)
        return b'\x4c\x70' + raw_state + self.tail

    def apply(self, case, head, role, require_live=False):
        """Derive a successor from public bytes; never assert head currentness."""
        need(not require_live, 'accepted_current_head_authority_unavailable')
        need(type(head) is Head and head.scope == 'EXTERNALLY_SELECTED_SYNTHETIC_HEAD',
             'external_starting_head_required')
        body, entry = validate_case(case)
        need(body['id'] == transaction_id(body, entry), 'canonical_v1_body_id')
        need(body['lockTime'] == 0 and body['gas'] == 0 and body['subnetworkId'] == '00' * 20
             and body['inputs'][0]['sequence'] == (1 << 64) - 1,
             'native_fixed_header_and_sequence')
        payload = hexbytes(body['payload'])
        need(len(payload) >= 2848, 'private_payload_minimum')
        auth = payload[:528]
        fields = auth_fields(auth, role, self.domain, self.allow_no_append_exit)
        need(body['inputs'][0]['previousOutpoint'] == head.point()
             and auth[40:72].hex() == head.transaction_id and number(auth[72:76]) == head.index,
             'exact_current_outpoint')
        need(auth[76:188] == head.state and fields['reserve'] == head.reserve,
             'exact_current_state_reserve')
        redeem = self.redeem(head.state)
        frame = hexbytes(body['inputs'][0]['signatureScript'])
        need(frame[:68] == b'\x41' + bytes(65) + b'\x4c\x80'
             and frame[196:199] == b'\x4d' + len(redeem).to_bytes(2, 'little')
             and frame[199:] == redeem and len(frame) == 199 + len(redeem),
             'canonical_private_frame_and_selected_program')
        need(entry['amount'] == head.reserve and entry['scriptPublicKey'] == p2sh(redeem),
             'exact_input_UTXO_context')
        old, new = fields['old'], fields['new']
        append_public(old, new, auth, payload, fields['mode'], fields['start'])
        root = old['nf']
        for slot, nf in enumerate(fields['nfs']):
            root = insert_public(root, old['m'] + slot, nf, payload[528 + 1160 * slot:1688 + 1160 * slot])
        need(root == new['nf'], 'NF_successor_root')
        expected = []
        if fields['remaining']:
            expected.append({'value': fields['remaining'], 'scriptPublicKey': p2sh(self.redeem(auth[364:476])),
                             'covenant': None})
        if fields['payout']:
            expected.append({'value': fields['payout'], 'scriptPublicKey': auth[492:528].hex(), 'covenant': None})
        need(body['outputs'] == expected, 'exact_authorized_native_outputs')
        actual_fee = entry['amount'] - sum(output['value'] for output in body['outputs'])
        need(actual_fee == fields['fee'], 'exact_actual_native_fee')
        successor = (Head(body['id'], 0, auth[364:476], fields['remaining'], domain=self.domain)
                     if fields['remaining'] else None)
        return successor, {'role': role, 'mode': fields['mode'], 'fee_sompi': actual_fee,
                           'native_payout_sompi': fields['payout'], 'reserve_after_sompi': fields['remaining'],
                           'CM_cursor_after': new['n'], 'NF_count_after': new['m']}


def profile(case):
    """Selected research profile, separately from public native-policy binding."""
    body, entry = validate_case(case)
    need(body['inputs'][0]['computeBudget'] == 1600, 'selected_B1600_profile')
    need(body['mass'] == storage_mass(body, entry), 'official_storage_mass_commitment')
    need(entry['blockDaaScore'] == 0, 'supplied_synthetic_DAA0_profile')
    return {'budget': 1600, 'storage_mass': body['mass'],
            'actual_execution_meter_or_relay_fee_qualification': False}


def public_material(case):
    body, _ = validate_case(case)
    payload = hexbytes(body['payload'])
    frame = hexbytes(body['inputs'][0]['signatureScript'])
    need(len(payload) >= 528 and len(frame) >= 196, 'public_proof_material_width')
    return payload[:528], frame[68:196]


def inspect(policy, case, head, role, verifier, require_live=False):
    """Record independent crypto/public/profile outcomes; infrastructure raises."""
    try:
        auth, proof = public_material(case)
    except Invalid as error:
        return {'accepted': False, 'cryptographic': None, 'public_error': error.code,
                'profile_error': None, 'successor': None, 'effects': None}
    crypto = verifier(role, auth, proof)
    successor, effects, public_error, profile_error = None, None, None, None
    try:
        successor, effects = policy.apply(case, head, role, require_live)
    except Invalid as error:
        public_error = error.code
    try:
        profile(case)
    except Invalid as error:
        profile_error = error.code
    accepted = crypto['verified'] is True and public_error is None and profile_error is None
    return {'accepted': accepted, 'cryptographic': crypto, 'public_error': public_error,
            'profile_error': profile_error, 'successor': successor, 'effects': effects}
