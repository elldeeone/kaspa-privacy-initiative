#!/usr/bin/env python3
"""Actual public G16 positives/negatives; no proving/native execution or PK reads."""
from pathlib import Path
import argparse
import json
import tempfile

from public_g16 import CheckerUnavailable, digest, verify

ROOT = Path(__file__).resolve().parents[2]
OLD = ROOT / 'research/next-session/compact-batch/prover'
FIXTURES = {
    'wide-parent': ('wide32', 'public-canary-proofs-01/wide32/proof',
        '863e318e1b6302ae7818684f6fed0e89f52f467fd104daede07ad540aa24fc0e'),
    'compact-successor': ('compact2', 'public-competition-proofs-01/compact2/proof',
        'b1bb0082c47b6ca6a388db9f91a6ac392b20db7579b79af03eeeab96abb89a17'),
    'wide-alternative': ('wide32', 'public-competition-proofs-01/wide32/proof',
        '4746f8dd6f8305f02ac6fae10a31e1cff3eec1054e42c37ec468c5e8156724c2'),
    'private-valid-native-NF-invalid': ('compact2', 'public-competition-proofs-01/compact-after-reveal/proof',
        '2d66836c08d8828e7f11133afa155d6e251c5ab60e4562b986cfb447678f51bc'),
}


def run():
    rows, loaded = [], {}
    for name, (role, path, auth_sha) in FIXTURES.items():
        directory = OLD / path
        auth = (directory / 'authorization528.bin').read_bytes()
        proof = (directory / 'proof128.bin').read_bytes()
        assert digest(auth) == auth_sha
        loaded[name] = (role, auth, proof)
        result = verify(role, auth, proof)
        assert result['verified'] and result['rust_verifier_executed']
        rows.append({'case': name, 'expected_verified': True, 'result': result})
    role, auth, proof = loaded['compact-successor']
    changed = bytearray(auth)
    changed[196:204] = (int.from_bytes(auth[196:204], 'little') + 1).to_bytes(8, 'little')
    changed[476:484] = (int.from_bytes(auth[476:484], 'little') - 1).to_bytes(8, 'little')
    # Public reserve conservation still holds. The original cryptographic
    # authorization must fail when exact fee/reserve effects are altered.
    assert int.from_bytes(changed[188:196], 'little') == sum(
        int.from_bytes(changed[a:a+8], 'little') for a in (196, 476, 484))
    broken = bytearray(proof)
    broken[-1] ^= 1
    for name, selected, a, p, rust in [
        ('coherent-fee-reserve-auth-mutation', role, bytes(changed), proof, True),
        ('proof-mutation', role, auth, bytes(broken), True),
        ('foreign-role-proof-transplant', role, auth, loaded['wide-alternative'][2], True),
        ('wrong-trusted-role-for-wide-auth', 'compact2', loaded['wide-parent'][1], loaded['wide-parent'][2], True),
        ('trailing-public-authorization', role, auth + b'\x00', proof, False),
        ('trailing-public-proof', role, auth, proof + b'\x00', False),
    ]:
        result = verify(selected, a, p)
        assert result['verified'] is False and result['rust_verifier_executed'] is rust
        rows.append({'case': name, 'expected_verified': False, 'result': result})
    with tempfile.TemporaryDirectory(prefix='PUBLIC-DO-NOT-FUND-checker-') as name:
        invalid = Path(name) / 'wrong-checker'
        invalid.write_bytes(b'PUBLIC_WRONG_CHECKER_DO_NOT_EXECUTE')
        try:
            verify(role, auth, proof, invalid)
        except CheckerUnavailable:
            rows.append({'case': 'wrong-checker-bytes-never-proof-invalid',
                         'checker_unavailable': True, 'expected_verified': None})
        else:
            raise AssertionError('wrong checker accepted')
    return {'schema': 'kpx5-public-g16-controls/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_DATA',
        'all_expected_outcomes': True, 'cases': rows,
        'actual_Rust_verifier_calls': sum(row.get('result', {}).get('rust_verifier_executed', False) for row in rows),
        'new_proof_setup_native_network_PK_or_owner_witness_reads': False,
        'native_settlement_combination_or_currentness_qualification': False,
        'source_sha256': {'adapter': digest((Path(__file__).parent/'public_g16.py').read_bytes()),
                          'controls': digest(Path(__file__).read_bytes())}}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    assert not args.output.exists()
    args.output.mkdir(parents=True, mode=0o700)
    result = run()
    (args.output / 'RESULTS.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    print(json.dumps({'all_expected_outcomes': True, 'cases': len(result['cases']),
                      'actual_Rust_verifier_calls': result['actual_Rust_verifier_calls']}))
