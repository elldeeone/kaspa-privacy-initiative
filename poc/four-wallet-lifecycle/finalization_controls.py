"""Pure public mutations for unchanged-proof actual-W binding controls.

No IO, normalization, proof verification or VM execution occurs here. A
nonzero canonical proof slot is only a shape check: the caller must separately
authenticate and verify its genuine receipt. Normalize every returned case
with the selected official normalizer before native Full execution.
"""
from copy import deepcopy

MAX_SOMPI = 2_870_000_000_000_000_000
PAYOUT_SOMPI = 10_000_000
NOTE_FLOOR = 60_000_000
PAYLOAD_HEADER = b'KPX5VP01\x01\x00\x02\x00'
PAYLOAD_BYTES = 8108
CF_OFFSET = 12 + 2912
CHILD_PROOF_OFFSET = 12 + 3920
PAYOUT_SPK = ('00002079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac')
KINDS = ('ciphertext', 'child-proof', 'input-reserve', 'current-point', 'extra-payout')
LABELS = {
    'ciphertext': 'changed-CF-genuine-outer-proof-unchanged',
    'child-proof': 'changed-child-proof-genuine-outer-proof-unchanged',
    'input-reserve': 'changed-input-reserve-genuine-outer-proof-unchanged',
    'current-point': 'changed-current-point-genuine-outer-proof-unchanged',
    'extra-payout': 'unauthorized-extra-payout-genuine-outer-proof-unchanged',
}


def need(value, category):
    if not value:
        raise ValueError(category)


def fields(value, names, category):
    need(type(value) is dict and set(value) == set(names), category)


def uint(value, bits):
    need(type(value) is int and 0 <= value < 1 << bits, 'control-integer-range')
    return value


def hexbytes(value, size=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(char in '0123456789abcdef' for char in value), 'control-canonical-hex')
    raw = bytes.fromhex(value)
    need(size is None or len(raw) == size, 'control-byte-width')
    return raw


def baseline(case):
    """Supported supplied-context case shape, never financial authority."""
    fields(case, ('transaction', 'entries'), 'control-case-fields')
    body = case['transaction']
    fields(body, ('version', 'id', 'inputs', 'outputs', 'lockTime', 'subnetworkId',
                  'gas', 'payload', 'mass'), 'control-body-fields')
    need(type(body['version']) is int and body['version'] == 1
         and uint(body['lockTime'], 64) == uint(body['gas'], 64) == 0
         and hexbytes(body['subnetworkId'], 20) == bytes(20), 'control-native-header')
    hexbytes(body['id'], 32); uint(body['mass'], 64)
    need(type(body['inputs']) is list and len(body['inputs']) == 1
         and type(body['outputs']) is list and len(body['outputs']) == 1
         and type(case['entries']) is list and len(case['entries']) == 1,
         'control-one-input-one-reserve-output')
    inp, out, entry = body['inputs'][0], body['outputs'][0], case['entries'][0]
    fields(inp, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'), 'control-input-fields')
    fields(inp['previousOutpoint'], ('transactionId', 'index'), 'control-point-fields')
    hexbytes(inp['previousOutpoint']['transactionId'], 32)
    uint(inp['previousOutpoint']['index'], 32); uint(inp['computeBudget'], 16)
    need(uint(inp['sequence'], 64) == (1 << 64)-1, 'control-final-sequence')
    fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'),
           'control-context-fields')
    fields(out, ('value', 'scriptPublicKey', 'covenant'), 'control-output-fields')
    amount, remaining = uint(entry['amount'], 64), uint(out['value'], 64)
    need(0 < remaining < amount < MAX_SOMPI and remaining > PAYOUT_SOMPI + NOTE_FLOOR
         and out['covenant'] is None and entry['isCoinbase'] is False
         and entry['covenantId'] is None, 'control-reserve-and-context-range')
    uint(entry['blockDaaScore'], 64)
    for value in (entry['scriptPublicKey'], out['scriptPublicKey']):
        spk = hexbytes(value, 37)
        need(spk[:4] == b'\x00\x00\xaa\x20' and spk[-1:] == b'\x87', 'control-W-P2SH-output')
    payload = hexbytes(body['payload'], PAYLOAD_BYTES)
    need(payload.startswith(PAYLOAD_HEADER), 'control-two-record-payload')
    frame = hexbytes(inp['signatureScript'])
    need(len(frame) >= 313 and frame[:68] == b'\x41' + bytes(65) + b'\x4c\x80'
         and frame[196:197] == b'\x4d'
         and int.from_bytes(frame[197:199], 'little') == len(frame)-199
         and frame[199:201] == b'\x4c\x70' and frame[201:209] == b'KPX2ST01',
         'control-canonical-actual-W-proof-frame')
    proof = frame[68:196]
    need(len(proof) == 128 and proof != bytes(128), 'control-nonzero-outer-proof128-required')
    return body, entry, payload, frame


def mutate(case, kind):
    """Deep-copy one public binding; preserve the complete genuine-proof frame."""
    body, entry, payload, frame = baseline(case)
    need(type(kind) is str and kind in KINDS, 'control-known-mutation-kind')
    changed = deepcopy(case)
    target = changed['transaction']
    if kind in ('ciphertext', 'child-proof'):
        altered = bytearray(payload)
        altered[CF_OFFSET if kind == 'ciphertext' else CHILD_PROOF_OFFSET] ^= 1
        target['payload'] = altered.hex()
    elif kind == 'input-reserve':
        # Change the supplied native reserve only; point and outputs stay fixed.
        changed['entries'][0]['amount'] = entry['amount'] + 1
    elif kind == 'current-point':
        point = target['inputs'][0]['previousOutpoint']
        txid = bytearray(hexbytes(point['transactionId'], 32)); txid[0] ^= 1
        point['transactionId'] = txid.hex()
    else:
        # Split the existing reserve output. Sum(outputs), input amount and
        # actual fee remain unchanged; the added ordinary output is non-dust.
        target['outputs'][0]['value'] -= PAYOUT_SOMPI
        target['outputs'].append({'value': PAYOUT_SOMPI, 'scriptPublicKey': PAYOUT_SPK,
                                  'covenant': None})
        need(sum(row['value'] for row in target['outputs']) == body['outputs'][0]['value'],
             'control-payout-preserves-native-total-and-fee')
    need(target['inputs'][0]['signatureScript'] == frame.hex(), 'control-whole-outer-proof-frame-unchanged')
    # ID and mass are deliberately not recomputed here. The caller must use the
    # selected official normalizer on every variant before native Full.
    return changed


def binding_cases(case):
    """Exactly five negative cases; execute the original separately as positive."""
    baseline(case)
    return tuple((LABELS[kind], mutate(case, kind)) for kind in KINDS)
