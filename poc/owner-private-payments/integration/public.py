"""Public-only KPX7 session/body assembly; no proof or chain-acceptance oracle."""
import importlib.util
from pathlib import Path
import re
import struct
import sys

from trees import PublicState, sha


def load_wire():
    name = 'kpx7_integration_verification_wire'
    if name not in sys.modules:
        source = Path(__file__).resolve().parents[1] / 'verification/wire.py'
        spec = importlib.util.spec_from_file_location(name, source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


wire = load_wire()
DOMAIN = wire.DOMAIN
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
CLASSIFICATION = 'UNFUNDED_SUPPLIED_CONTEXTS_NOT_ACCEPTED'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def hx(value, size):
    need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * size) + '}', value),
         'canonical-public-hex')
    return bytes.fromhex(value)


def roster_digest(roster):
    need(type(roster) is list and len(roster) == 3 and len(set(roster)) == 3,
         'three-public-participants')
    return sha(b'KPX7RO01', *(hx(value, 32) for value in roster))


def genesis(cms, reserve):
    need(type(reserve) is int and wire.NOTE_FLOOR <= reserve <= wire.MAX_VALUE,
         'genesis-public-reserve-range')
    state = PublicState(cms)
    return {'schema': 'kpx7-public-genesis/v1', 'classification': CLASSIFICATION,
            'domain_hex32': DOMAIN.hex(), 'reserve_sompi': reserve,
            'initial_cm_hex32': [cm.hex() for cm in cms],
            'state_hex112': state.state(DOMAIN).hex(),
            'membership_path_hex512': [state.cm.path(i).hex() for i in range(3)],
            'accepted_backing_or_currentness': False}


def parse_genesis(value):
    need(type(value) is dict and set(value) == {'schema', 'classification', 'domain_hex32',
         'reserve_sompi', 'initial_cm_hex32', 'state_hex112', 'membership_path_hex512',
         'accepted_backing_or_currentness'} and value['schema'] == 'kpx7-public-genesis/v1'
         and value['classification'] == CLASSIFICATION and value['domain_hex32'] == DOMAIN.hex()
         and value['accepted_backing_or_currentness'] is False, 'exact-unfunded-public-genesis')
    expected = genesis([hx(cm, 32) for cm in value['initial_cm_hex32']], value['reserve_sompi'])
    need(value == expected, 'independently-reproduced-genesis-roots-and-paths')
    return value


def mixed_rows(value, session_sha):
    need(type(value) is dict and set(value) == {'schema', 'session_sha256', 'rows_hex',
         'delta_decimal', 'tuple_bytes', 'row_count', 'scope'}
         and value['schema'] == 'kpx7-mixed-complete-outputs/v1'
         and value['session_sha256'] == session_sha and value['tuple_bytes'] == 520
         and value['row_count'] == 6 and value['scope'] ==
         'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION', 'actual-common-MPC-result-shape')
    need(type(value['rows_hex']) is list and len(value['rows_hex']) == 6,
         'six-complete-mixed-rows')
    rows = [hx(row, 520) for row in value['rows_hex']]
    decimal = value['delta_decimal']
    need(type(decimal) is str and re.fullmatch('0|[1-9][0-9]*', decimal), 'canonical-aggregate-decimal')
    delta = int(decimal)
    need(0 <= delta < Q, 'canonical-BabyJubjub-aggregate')
    need(len(set(rows)) == 6 and len({row[:32] for row in rows}) == 6 and
         all(sha(row[96:360]) == row[360:392] for row in rows), 'mixed-components-and-cipher-hashes')
    return rows, delta.to_bytes(32, 'little')


def premix_context(initial, owners, profile_sha, point, fee, native_tail):
    initial = parse_genesis(initial)
    hx(profile_sha, 32); hx(point, 36)
    tail = bytes.fromhex(native_tail)
    need(type(native_tail) is str and native_tail == tail.hex() and
         0 < len(tail) <= 65535 - 114, 'selected-native-template-tail')
    need(type(fee) is int and 1 <= fee < initial['reserve_sompi'], 'approved-global-fee')
    shares = [fee // 3, fee // 3, fee - 2 * (fee // 3)]
    need(len(owners) == 3 and all(type(row['admission_sompi']) is int and
         row['admission_sompi'] - share >= 2 * wire.NOTE_FLOOR
         for row, share in zip(owners, shares)), 'each-owner-can-fund-two-bounded-outputs')
    return {'schema': 'kpx7-wallet-premix-context/v1', 'domain_hex32': DOMAIN.hex(),
            'component_profile_sha256': profile_sha, 'prior_state_hex112': initial['state_hex112'],
            'previous_outpoint_hex36': point, 'reserve_sompi': initial['reserve_sompi'],
            'fee_sompi': fee, 'fee_shares_sompi': shares,
            'initial_cms_hex32': initial['initial_cm_hex32'], 'native_tail_hex': native_tail}


def body_core(genesis_value, inputs, rows, delta, session_sha, roster, point, fee):
    value = parse_genesis(genesis_value)
    need(type(inputs) is list and len(inputs) == 3 and all(type(row) is tuple and len(row) == 2
         and type(row[0]) is bytes and len(row[0]) == 32 and type(row[1]) is bytes
         and len(row[1]) == 64 for row in inputs), 'three-public-NF-CV-records')
    need(type(rows) is list and len(rows) == 6 and all(type(row) is bytes and len(row) == 520
         for row in rows), 'six-complete-mixed-output-records')
    need(type(delta) is bytes and len(delta) == 32 and int.from_bytes(delta, 'little') < Q,
         'canonical-global-Delta')
    need(type(point) is bytes and len(point) == 36 and point[:32] != bytes(32), 'public-supplied-point')
    reserve = value['reserve_sompi']
    need(type(fee) is int and 1 <= fee <= wire.MAX_VALUE and reserve - fee >= wire.NOTE_FLOOR,
         'exact-positive-fee-and-continuing-reserve')
    state = PublicState([hx(cm, 32) for cm in value['initial_cm_hex32']])
    before = state.state(DOMAIN)
    nf_witnesses = [state.insert(nf) for nf, _ in inputs]
    cm_paths = [state.append(row[:32]) for row in rows]
    after = state.state(DOMAIN)
    body = (b'KPX7PB01' + struct.pack('<4H', 1, 3, 6, 0) + DOMAIN + hx(session_sha, 32)
            + roster_digest(roster) + point + before + reserve.to_bytes(8, 'little')
            + after + (reserve - fee).to_bytes(8, 'little') + fee.to_bytes(8, 'little')
            + bytes(8) + delta + b''.join(nf + cv for nf, cv in inputs)
            + b''.join(rows) + b''.join(nf_witnesses) + b''.join(cm_paths) + bytes(384))
    wire.parse_body(body)
    return body


def project(body, input_spk, output_spk):
    parsed = wire.parse_body(body)
    need(type(input_spk) is bytes and len(input_spk) == 37 and
         type(output_spk) is bytes and len(output_spk) == 37, 'exact-public-native-SPKs')
    prefix = (b'KPX7FX01' + struct.pack('<2H', 1, 1) + parsed.point + bytes([255]) * 8
              + parsed.old_reserve.to_bytes(8, 'little') + struct.pack('<H', 37) + input_spk
              + struct.pack('<H', 1) + parsed.new_reserve.to_bytes(8, 'little')
              + struct.pack('<H', 37) + output_spk + bytes(37)
              + wire.BODY_LEN.to_bytes(4, 'little'))
    need(len(prefix) == wire.PREFIX_LEN, 'exact-native-prefix-width')
    projection = prefix + body
    wire.validate_public(projection)
    return projection


def attach_spend_proofs(projection, proofs):
    before = wire.validate_public(projection)
    need(type(proofs) is list and len(proofs) == 3 and
         all(type(proof) is bytes and len(proof) == 128 for proof in proofs), 'three-public-Spend-proofs')
    result = projection[:-384] + b''.join(proofs)
    after = wire.validate_public(result)
    need(before['effects_digest_hex32'] == after['effects_digest_hex32'],
         'Spend-proof-attachment-does-not-change-authorized-effects')
    return result
