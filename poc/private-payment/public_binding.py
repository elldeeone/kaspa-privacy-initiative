"""Expected public authorization/journal bytes. No proof or native authority."""
import hashlib
import wire_format as wire

AUTH_TAG = b'KPI/private-payment/authorization/v1'
JOURNAL_TAG = b'KPI/private-payment/wallet-journal/v1'


def authorization_bytes(kind, signature):
    wire.require(type(kind) is int and kind in (0, 1, 2), 'unknown kind')
    if kind == 0:
        return b'\1' + wire.raw(signature, 64)
    wire.require(signature is None, 'TRANSFER/EXIT authorization must be absent')
    return b'\0'


def parse_authorization(kind, data):
    wire.require(type(data) is bytes, 'authorization bytes required')
    signature = data[1:].hex() if data and data[0] == 1 else None
    wire.require(authorization_bytes(kind, signature) == data, 'noncanonical authorization')
    return signature


def authorization_digest(kind, data):
    parse_authorization(kind, data)
    return hashlib.sha256(AUTH_TAG + data).digest()


def expected_journal(intent, authorization):
    encoded = wire.encode(intent)
    ids = b''.join(wire.raw(intent[name], 32) for name in
                   ('G_hash', 'statement_id', 'proof_suite_id', 'wallet_program_or_vk_hash'))
    return (JOURNAL_TAG + ids + hashlib.sha256(encoded).digest()
            + authorization_digest(intent['operation_kind'], authorization))
