"""Candidate public intent bytes for P1 review; never a proof/credit verifier."""
import hashlib
import re

TAG = b'KPI/private-payment/intent/v1'
IDS = ('G_hash', 'D', 'network_genesis', 'pool_id', 'lane_id', 'statement_id',
       'proof_suite_id', 'wallet_program_or_vk_hash')
FIELDS = (*IDS, 'operation_kind', 'append_mode', 'expiry_order_bound', 'anchor',
          'nf', 'cmx_new', 'ephemeral_key', 'ciphertext', 'deposit_reference',
          'deposit_principal', 'exit_script', 'exit_principal', 'fee_script', 'private_fee_sompi')


def require(ok, reason):
    if not ok: raise ValueError(reason)


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'exact fields required')


def uint(value, bits):
    require(type(value) is int and 0 <= value < 1 << bits, f'unsigned u{bits} required')
    return value.to_bytes(bits // 8, 'little')


def raw(value, size):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{' + str(size * 2) + '}', value), 'canonical hex/length required')
    return bytes.fromhex(value)


def script(value):
    if value is None: return b'\x00'
    keys(value, ('version', 'script'))
    text = value['script']
    require(type(text) is str and len(text) % 2 == 0, 'script hex required')
    body = raw(text, len(text) // 2)
    require(1 <= len(body) <= 10000, 'script length outside candidate profile')
    return b'\x01' + uint(value['version'], 16) + uint(len(body), 32) + body


def encode(intent):
    keys(intent, FIELDS)
    out = bytearray(TAG)
    for name in IDS: out += raw(intent[name], 20 if name == 'lane_id' else 32)
    kind, mode = intent['operation_kind'], intent['append_mode']
    require(type(kind) is int and kind in (0, 1, 2), 'unknown operation kind')
    require(type(mode) is int and mode in (0, 1), 'unknown append mode')
    out += uint(kind, 8) + uint(mode, 8)
    expiry = intent['expiry_order_bound']
    out += b'\x00' if expiry is None else b'\x01' + uint(expiry, 64)
    out += raw(intent['anchor'], 32)
    for name, size in (('nf', 32), ('cmx_new', 32), ('ephemeral_key', 32), ('ciphertext', 580)):
        values = intent[name]
        require(type(values) is list and len(values) == 2, 'exactly two slots required')
        for value in values: out += raw(value, size)
    deposit = intent['deposit_reference']
    if deposit is None: out += b'\x00'
    else:
        keys(deposit, ('transaction_id', 'index', 'descriptor_hash', 'recovery_public_key'))
        out += b'\x01' + raw(deposit['transaction_id'], 32) + uint(deposit['index'], 32)
        out += raw(deposit['descriptor_hash'], 32) + raw(deposit['recovery_public_key'], 32)
    principal, exited, fee = (intent[name] for name in ('deposit_principal', 'exit_principal', 'private_fee_sompi'))
    out += uint(principal, 64) + script(intent['exit_script']) + uint(exited, 64)
    out += script(intent['fee_script']) + uint(fee, 64)
    require((intent['fee_script'] is not None) == (fee > 0), 'fee script/presence mismatch')
    if kind == 0:
        require(deposit is not None and principal > 0 and intent['exit_script'] is None and exited == fee == mode == 0,
                'invalid CREDIT fields')
    elif kind == 1:
        require(deposit is None and principal == 0 and intent['exit_script'] is None and exited == mode == 0,
                'invalid TRANSFER fields')
    else:
        require(deposit is None and principal == 0 and intent['exit_script'] is not None and exited > 0,
                'invalid EXIT fields')
    return bytes(out)


class Reader:
    def __init__(self, data): self.data, self.at = data, 0

    def take(self, size):
        require(size <= len(self.data) - self.at, 'truncated intent')
        value = self.data[self.at:self.at + size]; self.at += size
        return value

    def number(self, bits): return int.from_bytes(self.take(bits // 8), 'little')

    def optional(self, read):
        flag = self.number(8)
        require(flag in (0, 1), 'noncanonical option flag')
        return None if flag == 0 else read()

    def script(self):
        def read():
            version, length = self.number(16), self.number(32)
            require(1 <= length <= 10000, 'script length outside candidate profile')
            return {'version': version, 'script': self.take(length).hex()}
        return self.optional(read)


def decode(data):
    require(type(data) is bytes, 'intent bytes required')
    r = Reader(data)
    require(r.take(len(TAG)) == TAG, 'wrong intent tag')
    intent = {name: r.take(20 if name == 'lane_id' else 32).hex() for name in IDS}
    intent['operation_kind'], intent['append_mode'] = r.number(8), r.number(8)
    intent['expiry_order_bound'] = r.optional(lambda: r.number(64))
    intent['anchor'] = r.take(32).hex()
    for name, size in (('nf', 32), ('cmx_new', 32), ('ephemeral_key', 32), ('ciphertext', 580)):
        intent[name] = [r.take(size).hex(), r.take(size).hex()]
    intent['deposit_reference'] = r.optional(lambda: {
        'transaction_id': r.take(32).hex(), 'index': r.number(32),
        'descriptor_hash': r.take(32).hex(), 'recovery_public_key': r.take(32).hex()})
    intent['deposit_principal'] = r.number(64)
    intent['exit_script'] = r.script(); intent['exit_principal'] = r.number(64)
    intent['fee_script'] = r.script(); intent['private_fee_sompi'] = r.number(64)
    require(r.at == len(data), 'trailing intent data')
    require(encode(intent) == data, 'noncanonical intent')
    return intent


def digest(intent): return hashlib.sha256(encode(intent)).hexdigest()
