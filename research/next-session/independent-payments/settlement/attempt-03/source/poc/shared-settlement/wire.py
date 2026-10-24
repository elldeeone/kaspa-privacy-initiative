"""Strict public transcript wire subset; no note witness or execution API.

The selected v1 ID primitive is keyed BLAKE3, not the older transaction hash's
keyed BLAKE2b. ID calculation therefore delegates to the independently selected
public Rust normalizer adapter. Its executable authentication is separate from
the caller's authority/currentness premise; no transcript selects the code.
"""
import copy
import hashlib
from pathlib import Path
import sys

MAX = 2_870_000_000_000_000_000
STORAGE_PARAMETER = 1_000_000_000_000
ROOT = Path(__file__).resolve().parents[2]


class Invalid(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise Invalid(code)


def uint(value, bits):
    need(type(value) is int and 0 <= value < 1 << bits, 'uint-range')
    return value


def hexbytes(value, width=None):
    need(type(value) is str and len(value) % 2 == 0
         and all(char in '0123456789abcdef' for char in value), 'canonical-hex')
    raw = bytes.fromhex(value)
    need(width is None or len(raw) == width, 'byte-width')
    return raw


def h(*parts):
    need(all(type(part) is bytes for part in parts), 'hash-bytes')
    return hashlib.sha256(b''.join(parts)).digest()


def _fields(value, expected, code):
    need(type(value) is dict and set(value) == expected, code)


def _spk(value):
    raw = hexbytes(value)
    need(len(raw) >= 2, 'SPK-version-width')
    return raw


def _body(body):
    _fields(body, {'version', 'id', 'inputs', 'outputs', 'lockTime',
        'subnetworkId', 'gas', 'payload', 'mass'}, 'body-fields')
    need(type(body['version']) is int and body['version'] == 1, 'version1-only')
    hexbytes(body['id'], 32)
    uint(body['lockTime'], 64)
    hexbytes(body['subnetworkId'], 20)
    uint(body['gas'], 64)
    uint(body['mass'], 64)
    hexbytes(body['payload'])
    need(type(body['inputs']) is list and len(body['inputs']) == 1, 'one-private-input')
    row = body['inputs'][0]
    _fields(row, {'previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'}, 'input-fields')
    _fields(row['previousOutpoint'], {'transactionId', 'index'}, 'outpoint-fields')
    hexbytes(row['previousOutpoint']['transactionId'], 32)
    uint(row['previousOutpoint']['index'], 32)
    uint(row['sequence'], 64)
    uint(row['computeBudget'], 16)
    # Parsing must not hide a still-valid ordinary proof behind rejection of a
    # mutated public ScriptSig header/tail. The semantic policy owns that frame.
    hexbytes(row['signatureScript'])
    need(type(body['outputs']) is list and 1 <= len(body['outputs']) <= 2,
         'private-output-count')
    for output in body['outputs']:
        _fields(output, {'value', 'scriptPublicKey', 'covenant'}, 'output-fields')
        uint(output['value'], 64)
        need(0 < output['value'] <= MAX and output['covenant'] is None, 'output-amount-or-covenant')
        _spk(output['scriptPublicKey'])
    return body


def _entry(entry):
    _fields(entry, {'amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'}, 'context-fields')
    uint(entry['amount'], 64)
    need(0 < entry['amount'] <= MAX and entry['isCoinbase'] is False
         and entry['covenantId'] is None, 'context-amount-or-flags')
    uint(entry['blockDaaScore'], 64)
    _spk(entry['scriptPublicKey'])
    return entry


def validate_case(case):
    """Validate the supported JSON subset, not proof/state/chain correctness.

    The JSON reader must separately reject duplicate keys. Native amount,
    state/outpoint bindings, role/domain, meter sufficiency, locktime/subnetwork
    profile and economic currentness belong to the caller's explicit checks.
    """
    _fields(case, {'transaction', 'entries'}, 'case-fields')
    need(type(case['entries']) is list and len(case['entries']) == 1, 'one-native-context')
    return _body(case['transaction']), _entry(case['entries'][0])


def transaction_id(body, entry):
    """Exact v1 ID from the selected real checker, excluding Sig/mass/budget.

    Upstream hashing/tx.rs207–235 and hashes/src/hashers.rs39–43,120–154 at
    01b532e8 use keyed BLAKE3 with zero-padded32-byte domain keys. No local
    BLAKE2b substitution or handwritten BLAKE3 implementation is permitted.
    """
    validate_case({'transaction': body, 'entries': [entry]})
    adapter = ROOT / 'poc/shared-settlement-verifier'
    if str(adapter) not in sys.path:
        sys.path.insert(0, str(adapter))
    import public_native
    need(Path(public_native.__file__).resolve() == adapter / 'public_native.py',
         'selected-id-adapter-path')
    result = public_native.normalize(copy.deepcopy({'transaction': body, 'entries': [entry]}))
    need(result['native_VM_executed'] is False and result['operation'] == 'control-normalize-freeze',
         'ID-normalization-only')
    actual = _body(result['transaction'])
    expected = copy.deepcopy(body)
    expected['id'], expected['mass'] = actual['id'], actual['mass']
    need(actual == expected, 'normalizer-changed-body')
    return actual['id']


def p2sh(redeem):
    need(type(redeem) is bytes, 'redeem-bytes')
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def storage_mass(body, entry):
    """Exact KIP9 one-input/plurality1 subset with integer floors.

    Pinned mass/mod.rs388–508: plurality=ceil((63+scriptBytes)/100) for these
    covenant-free UTXOs. One plurality1 input selects the relaxed formula,
    max(0,sum(C//outputAmount)-C//inputAmount), C=1e12. Larger pluralities are
    explicitly unsupported rather than priced with this narrower equation.
    """
    _body(body)
    _entry(entry)
    for script in [entry['scriptPublicKey'], *(row['scriptPublicKey'] for row in body['outputs'])]:
        raw = _spk(script)
        need((63 + len(raw) - 2 + 99) // 100 == 1, 'unsupported-storage-plurality')
    mass = max(0, sum(STORAGE_PARAMETER // row['value'] for row in body['outputs'])
               - STORAGE_PARAMETER // entry['amount'])
    uint(mass, 64)
    return mass
