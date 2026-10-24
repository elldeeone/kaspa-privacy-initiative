"""KPX7 fixed complete-row transport; no curve or proof implementation."""
import hashlib
import json
import re

Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
DOMAIN = 'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480'
ROW_BYTES, LIMB_BYTES, LIMBS, ROWS, PARTIES = 520, 31, 17, 6, 3
INPUT_DIGITS, INPUT_FIELDS, INPUT_BYTES = 76, 35, 2695
TAG = 'KPX7'


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def hex32(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'canonical-hex32')
    return value


def scalar(value):
    need(type(value) is int and 0 <= value < Q, 'canonical-babyjubjub-scalar')
    return value


def pack_row(raw):
    need(type(raw) is bytes and len(raw) == ROW_BYTES, 'complete-output-row-length')
    padded = raw + bytes(LIMBS * LIMB_BYTES - ROW_BYTES)
    return [int.from_bytes(padded[i:i + LIMB_BYTES], 'little')
            for i in range(0, len(padded), LIMB_BYTES)]


def unpack_row(values):
    need(type(values) is list and len(values) == LIMBS, 'complete-row-limb-count')
    need(all(type(x) is int and 0 <= x < 1 << (8 * LIMB_BYTES) for x in values),
         'canonical-row-limb')
    raw = b''.join(x.to_bytes(LIMB_BYTES, 'little') for x in values)
    need(raw[ROW_BYTES:] == bytes(len(raw) - ROW_BYTES), 'nonzero-row-padding')
    return raw[:ROW_BYTES]


def owner_input(rows, beta):
    """Called inside one owner worker only, never by a public coordinator."""
    need(type(rows) is list and len(rows) == 2, 'two-complete-owner-outputs')
    values = [v for row in rows for v in pack_row(row)] + [scalar(beta)]
    return ''.join(f'{v:0{INPUT_DIGITS}d}\n' for v in values).encode()


def session(raw, program_sha):
    value = parse_json(raw)
    keys = {'schema', 'session_id', 'domain_hex', 'prior_state_digest',
            'circuit_profile_sha256', 'public_effects_context_sha256', 'roster',
            'program_source_sha256', 'tuple_bytes', 'outputs_per_party', 'mpc_prime'}
    need(type(value) is dict and set(value) == keys, 'exact-session-fields')
    need(value['schema'] == 'kpx8-private-construction-session/v1', 'session-schema')
    for key in ('session_id', 'domain_hex', 'prior_state_digest', 'circuit_profile_sha256',
                'public_effects_context_sha256', 'program_source_sha256'):
        hex32(value[key])
    need(value['program_source_sha256'] == program_sha, 'session-program-source')
    need(value['domain_hex'] == DOMAIN, 'exact-adr0064-domain')
    need(type(value['roster']) is list and len(value['roster']) == PARTIES and
         len(set(hex32(x) for x in value['roster'])) == PARTIES, 'three-distinct-participants')
    need(type(value['tuple_bytes']) is int and value['tuple_bytes'] == ROW_BYTES and
         type(value['outputs_per_party']) is int and value['outputs_per_party'] == 2 and
         value['mpc_prime'] == str(Q), 'fixed-session-shape-and-field')
    return value, sha(canonical_json(value))


def engine_output(raw, session_sha):
    """Extract only checked public outputs after successful engine completion."""
    need(type(raw) is bytes and b'insecure' not in raw.lower(), 'stock-insecure-warning')
    text = raw.decode('ascii')
    sessions = re.findall(r'KPX7_SESSION ([0-9a-f]{64})', text)
    need(sessions == [hex32(session_sha)], 'exact-completed-session')
    matches = re.findall(r'KPX7_ROW ([0-5]) ([^\r\n]+)(?:\r?\n|$)', text)
    need([int(i) for i, _ in matches] == list(range(ROWS)), 'exact-six-public-rows')
    rows = []
    for _, values in matches:
        decimal = values.split()
        need(len(decimal) == LIMBS and
             all(v == '0' or (v[0] != '0' and v.isdecimal()) for v in decimal),
             'canonical-row-decimal')
        rows.append(unpack_row([int(v) for v in decimal]))
    deltas = re.findall(r'KPX7_DELTA ([^\r\n]+)(?:\r?\n|$)', text)
    need(len(deltas) == 1 and re.fullmatch(r'0|-?[1-9][0-9]*', deltas[0]),
         'one-canonical-signed-engine-aggregate')
    signed = int(deltas[0])
    # Stock PRINTREGPLAIN uses signed_output (Instruction.hpp:1648).
    # Its unique representative is decoded once at this field boundary;
    # public JSON remains canonical [0,Q). Never reduce private input aliases.
    need(-(Q // 2) <= signed <= Q // 2, 'exact-signed-field-representative')
    delta = scalar(signed if signed >= 0 else signed + Q)
    return {'schema': 'kpx8-mixed-complete-outputs/v1', 'session_sha256': session_sha,
            'rows_hex': [row.hex() for row in rows], 'delta_decimal': str(delta),
            'tuple_bytes': ROW_BYTES, 'row_count': ROWS,
            'scope': 'CHECKED_MPC_OUTPUTS_NOT_FINANCIAL_AUTHORIZATION'}
