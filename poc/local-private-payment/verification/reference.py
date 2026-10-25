"""Independent synthetic public-byte reference; never a financial fixture.

Builds bytes directly from the frozen layout and complete public trees. CV and
proof byte strings intentionally have no claimed cryptographic validity.
"""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
_name = 'kpxa_independent_public_trees'
_spec = importlib.util.spec_from_file_location(_name, HERE.parent / 'integration/trees.py')
_trees = importlib.util.module_from_spec(_spec)
sys.modules[_name] = _trees
_spec.loader.exec_module(_trees)
PublicState = _trees.PublicState
DOMAIN = bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c')


def digest(data):
    return hashlib.sha256(data).digest()


def spk(state, tail):
    script_hash = hashlib.blake2b(b'\x4c\x70' + state + tail, digest_size=32).digest()
    return b'\0\0\xaa\x20' + script_hash + b'\x87'


def output(label):
    cm = digest(b'PUBLIC_SYNTHETIC_CM/' + label)
    cv = digest(b'PUBLIC_SYNTHETIC_CV/X/' + label) + digest(b'PUBLIC_SYNTHETIC_CV/Y/' + label)
    cf = (digest(b'PUBLIC_SYNTHETIC_CF/' + label) * 9)[:264]
    proof = digest(b'NOT_A_G16_PROOF/' + label) * 4
    return cm + cv + cf + digest(cf) + proof


def payment_fixture():
    initial = PublicState([digest(b'PUBLIC_SYNTHETIC_GENESIS_CM')])
    following = initial.copy()
    nf = digest(b'PUBLIC_SYNTHETIC_ORIGINAL_NF')
    witness = following.insert(nf)
    rows = [output(b'output-a'), output(b'output-b')]
    paths = [following.append(row[:32]) for row in rows]
    action, point = digest(b'PUBLIC_SYNTHETIC_ACTION'), digest(b'PUBLIC_SYNTHETIC_TXID') + struct.pack('<I', 0)
    old_reserve, fee, delta = 1_000_000_000, 1_000_000, (123).to_bytes(32, 'little')
    old, new, tail = initial.state(), following.state(), b'PUBLIC_SYNTHETIC_IMMUTABLE_TAIL'
    cv = digest(b'PUBLIC_SYNTHETIC_INPUT_CV/X') + digest(b'PUBLIC_SYNTHETIC_INPUT_CV/Y')
    core = (b'KPXAPB01' + struct.pack('<4H', 1, 1, 2, 0) + DOMAIN + action + bytes(32) + point
            + old + struct.pack('<Q', old_reserve) + new + struct.pack('<QQQ', old_reserve - fee, fee, 0)
            + delta + nf + cv + b''.join(rows) + witness + b''.join(paths))
    body = core + digest(b'NOT_A_SPEND_G16_PROOF') * 4
    prefix = (b'KPXAFX01' + struct.pack('<HH', 1, 1) + point + struct.pack('<Q', (1 << 64) - 1)
              + struct.pack('<QH', old_reserve, 37) + spk(old, tail) + struct.pack('<H', 1)
              + struct.pack('<QH', old_reserve - fee, 37) + spk(new, tail) + bytes(37)
              + struct.pack('<I', len(body)))
    return {'scope': 'SYNTHETIC_PUBLIC_BYTES_NO_VALID_PROOFS_OR_ACCEPTED_BACKING',
            'initial': initial, 'following': following, 'tail': tail, 'action_id': action,
            'point': point, 'old_state': old, 'new_state': new, 'old_reserve': old_reserve,
            'new_reserve': old_reserve - fee, 'fee': fee, 'delta': delta, 'nf': nf, 'cv': cv,
            'outputs': rows, 'nf_witness': witness, 'cm_paths': paths, 'core': core,
            'body': body, 'prefix': prefix, 'projection': prefix + body}


def exit_fixture(terminal=False):
    base = payment_fixture()
    initial, following = base['following'], base['following'].copy()
    nf = digest(b'PUBLIC_SYNTHETIC_EXIT_NF')
    witness = following.insert(nf)
    old, new = initial.state(), following.state()
    reserve, fee = base['new_reserve'], base['fee']
    remaining = 0 if terminal else 200_000_000
    payout = reserve - remaining - fee
    payout_spk = b'\0\0\x20' + digest(b'PUBLIC_SYNTHETIC_DESTINATION') + b'\xac'
    action = digest(b'PUBLIC_SYNTHETIC_EXIT_ACTION/' + bytes([terminal]))
    point = digest(b'PUBLIC_SYNTHETIC_POST_PAYMENT_TXID') + bytes(4)
    body = (b'KPXAXB01' + struct.pack('<4H', 1, 1, 0, 1) + DOMAIN + action + bytes(32) + point
            + old + struct.pack('<Q', reserve) + new + struct.pack('<QQQ', remaining, fee, payout)
            + payout_spk + nf + witness)
    outputs = ([(remaining, spk(new, base['tail']))] if remaining else []) + [(payout, payout_spk)]
    prefix = (b'KPXAFX01' + struct.pack('<HH', 1, 1) + point + struct.pack('<Q', (1 << 64) - 1)
              + struct.pack('<QH', reserve, 37) + spk(old, base['tail']) + struct.pack('<H', len(outputs)))
    for amount, script in outputs:
        prefix += struct.pack('<QH', amount, len(script)) + script + b'\0'
    prefix += bytes(36) + struct.pack('<I', len(body))
    return {'initial': initial, 'following': following, 'old_state': old, 'new_state': new,
            'old_reserve': reserve, 'new_reserve': remaining, 'fee': fee, 'payout': payout,
            'action_id': action, 'point': point, 'tail': base['tail'], 'payout_spk': payout_spk,
            'nf': nf, 'nf_witness': witness, 'body': body, 'prefix': prefix, 'projection': prefix + body}


if __name__ == '__main__':
    import argparse
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for name, fixture in [('payment', payment_fixture()), ('exit-continuing', exit_fixture()),
                          ('exit-terminal', exit_fixture(True))]:
        for part in ('body', 'projection'):
            (args.out / (name + '.' + part + '.bin')).write_bytes(fixture[part])
    (args.out / 'scope.json').write_text(json.dumps({
        'schema': 'kpxa-synthetic-public-byte-reference/v1',
        'scope': 'NO_VALID_COMPONENT_PROOFS_NO_NATIVE_ACCEPTANCE_NO_BACKING',
        'domain_hex32': DOMAIN.hex()}, indent=2) + '\n')
