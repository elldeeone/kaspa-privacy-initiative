"""Fixed-size private retention of the existing full owner-local JSON record.

Only isolated owner roles encode/decode. No private-content hash is exported.
This is structural validation; existing owner_aux checks the financial witness.
"""
import re
import privacy_codec as codec

MAGIC = b'KPB_OWNER_REC_V2'
FRAME_BYTES = 32_768
HEADER_BYTES = 32
LEAF = 'OWNER-LOCAL-RECORD-V2.bin'
SCHEMA = 'kpb-private-original-owner-record/v1'
# Existing BN254 Fr and BabyJubjub scalar bounds, unchanged by this file codec.
P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
HEX = lambda n: ('hex', n)
DEC = lambda limit: ('decimal', limit)
ARRAY = lambda n, item: ('array', n, item)
RECORD = {
    'schema': ('literal', SCHEMA), 'owner_component': ('owner',),
    'input': {'note_hex168': HEX(168), 'nk_hex32': HEX(32), 'position': ('uint', 32),
        'path_hex32': ARRAY(16, HEX(32)), 'cv_hex64': HEX(64), 'blind_hex32': HEX(32),
        'ak_hex64': HEX(64), 'nf_hex32': HEX(32)},
    'fee_sompi': ('uint', 64), 'nonce_hex32': HEX(32),
    'outputs': ARRAY(2, {'tuple_hex520': HEX(520), 'note_hex168': HEX(168), 'blind_hex32': HEX(32)}),
    'private_delta_hex32': HEX(32), 'intent_hex1460': HEX(1460),
    'signature': {'owner_key_hex64': HEX(64), 'R8': ARRAY(2, DEC(P)), 'S': DEC(Q)},
    'signature_inputs': {'digestLimbs': ARRAY(2, DEC(P)),
        'ownerKeyBytes': ARRAY(64, DEC(256)), 'sigR8': ARRAY(2, DEC(P)), 'sigS': DEC(Q),
        'preimageA': ARRAY(2, DEC(P)), 'preimageR8': ARRAY(2, DEC(P))},
}


def _validate(value, shape):
    if type(shape) is dict:
        codec.fields(value, shape)
        for name, child in shape.items():
            _validate(value[name], child)
        return
    kind = shape[0]
    if kind == 'array':
        codec.need(type(value) is list and len(value) == shape[1], 'owner-record-array')
        for item in value:
            _validate(item, shape[2])
    elif kind == 'hex':
        codec.need(type(value) is str and re.fullmatch('[0-9a-f]{' + str(2 * shape[1]) + '}', value),
                   'owner-record-hex')
    elif kind == 'decimal':
        codec.need(type(value) is str and re.fullmatch('0|[1-9][0-9]*', value)
                   and len(value) <= len(str(shape[1] - 1)) and int(value) < shape[1],
                   'owner-record-decimal')
    elif kind == 'uint':
        codec.need(type(value) is int and 0 <= value < (1 << shape[1]), 'owner-record-uint')
    elif kind == 'owner':
        codec.need(type(value) is int and value in (0, 1, 2), 'owner-record-owner')
    else:
        codec.need(kind == 'literal' and type(value) is str and value == shape[1], 'owner-record-schema')


def _maximum(shape):
    """Public field-width upper bound, without inspecting any private record."""
    if type(shape) is dict:
        return {name: _maximum(child) for name, child in shape.items()}
    kind = shape[0]
    if kind == 'array':
        return [_maximum(shape[2]) for _ in range(shape[1])]
    if kind == 'hex':
        return 'f' * (2 * shape[1])
    if kind == 'decimal':
        return str(shape[1] - 1)
    if kind == 'uint':
        return (1 << shape[1]) - 1
    if kind == 'owner':
        return 2
    return shape[1]


MAX_JSON_BYTES = len(codec.encoded(_maximum(RECORD)))
assert len(MAGIC) == 16 and MAX_JSON_BYTES <= FRAME_BYTES - HEADER_BYTES


def encode(record, owner):
    _validate(owner, ('owner',))
    _validate(record, RECORD)
    codec.need(record['owner_component'] == owner, 'owner-record-selected-owner')
    payload = codec.encoded(record)
    codec.need(0 < len(payload) <= MAX_JSON_BYTES, 'owner-record-public-schema-bound')
    return (MAGIC + owner.to_bytes(8, 'little') + len(payload).to_bytes(8, 'little')
            + payload + bytes(FRAME_BYTES - HEADER_BYTES - len(payload)))


def decode(raw, owner):
    try:
        _validate(owner, ('owner',))
        codec.need(type(raw) is bytes and len(raw) == FRAME_BYTES and raw[:16] == MAGIC,
                   'owner-record-frame')
        codec.need(int.from_bytes(raw[16:24], 'little') == owner, 'owner-record-frame-owner')
        size = int.from_bytes(raw[24:32], 'little')
        codec.need(0 < size <= MAX_JSON_BYTES, 'owner-record-frame-size')
        codec.need(raw[HEADER_BYTES + size:] == bytes(FRAME_BYTES - HEADER_BYTES - size),
                   'owner-record-zero-padding')
        payload = raw[HEADER_BYTES:HEADER_BYTES + size]
        record = codec.parse(payload)
        _validate(record, RECORD)
        codec.need(record['owner_component'] == owner and codec.encoded(record) == payload,
                   'owner-record-canonical-private-payload')
        return record
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise ValueError('owner-record-format') from None
