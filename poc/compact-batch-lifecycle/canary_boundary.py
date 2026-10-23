#!/usr/bin/env python3
"""Valid private proof with a wrong next CM root must fail native tree checks."""
import argparse
import copy
import json
from pathlib import Path

from actions import Candidate
from native_runtime import DOMAIN, ROOT, Runtime, public_case, save
from primitives import fixed, h, insert_nf, need, parse, singleton
from synthetic import box, fixture

LABEL = 'relation-controls/PUBLIC_SYNTHETIC_DO_NOT_FUND/compact'
CASE = Path('/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-direct-cases-01/13-compact-next-CM-root-is-native-obligation.json')
PHASE = ROOT / 'research/next-session/compact-batch'


def run(proof_directory, output):
    need(not output.absolute().is_relative_to(ROOT) and not output.exists(), 'fresh-public-boundary-output')
    witness, _ = fixture(LABEL, 2)
    original_auth = bytes.fromhex(witness['auth_hex528'])
    auth = bytearray(original_auth)
    auth[404] ^= 1
    witness['auth_hex528'] = auth.hex()
    need(parse(CASE.read_bytes()) == witness, 'exact-original-private-SAT-public-boundary-case')
    auth = bytes(auth)
    need([i for i, (before, changed) in enumerate(zip(original_auth, auth)) if before != changed] == [404],
         'only-selected-next-CM-root-byte-mutated')
    note = bytes.fromhex(witness['inputs'][0]['note_hex168'])
    before = singleton(DOMAIN, note, box(LABEL + '/initial', 0))
    after, first = insert_nf(before, auth[204:236])
    after, second = insert_nf(after, auth[236:268])
    notes = tuple(bytes.fromhex(row['note_hex168']) for row in witness['outputs'])
    ciphers = [box(LABEL, i) for i in range(2)]
    after, _, path = after.append(DOMAIN, notes, ciphers)
    need(after.state(DOMAIN) == original_auth[364:476]
         and after.state(DOMAIN) != auth[364:476] and before.state(DOMAIN) == auth[76:188],
         'only-native-next-CM-root-is-wrong')
    chosen = Candidate('compact2', 2, auth, tuple(witness['inputs']), notes, b''.join(ciphers),
        b''.join(h(b'KPX1NOT\0', DOMAIN, raw) for raw in notes), first + second,
        b''.join(path), after, 1000, 0, 130_000_000)
    proof = fixed((proof_directory / 'proof128.bin').read_bytes(), 128)
    report = parse((proof_directory / 'report.json').read_bytes())
    compact = (PHASE / 'prover/setup-compact2-01/result/verification-key.bin').read_bytes()
    wide = (PHASE / 'prover/setup-wide32-01/result/verification-key.bin').read_bytes()
    need((proof_directory / 'authorization528.bin').read_bytes() == auth
         and (proof_directory / 'verification-key.bin').read_bytes() == compact
         and report['genuine_Groth16_verified'] is True
         and report['role'] == 'compact2' and report['proof_sha256'] == h(proof).hex(),
         'genuine-private-SAT-proof-for-exact-bad-public-state')
    runtime = Runtime()
    point = {'transactionId': auth[40:72].hex(), 'index': int.from_bytes(auth[72:76], 'little')}
    body, entries = runtime.body(chosen, point, int.from_bytes(auth[188:196], 'little'), compact, wide, proof)
    output.mkdir(parents=True, mode=0o700)
    body, metrics = runtime.normalize(body, entries, output / 'normalized')
    runtime.sdk(body, entries)
    case_path = output / 'selected-case.json'
    save(case_path, public_case(body, entries))
    runtime.native.run(['validate-transaction', case_path, output / 'native'])
    native = parse((output / 'native/native-validation.json').read_bytes())
    engines = native['per_input_ScriptEngine']
    need(native['isolation'] == 'PASS' and native['Full']['accepted'] is False
         and native['Full']['typed_error'] == 'SignatureInvalid(VerifyError)'
         and native['all_input_engines_accepted'] is False and len(engines) == 1
         and engines[0]['accepted'] is False and engines[0]['typed_error'] == 'VerifyError'
         and engines[0]['units'] < 14_000_000, 'genuine-proof-wrong-tree-not-rejected-before-G16')
    result = {'schema': 'kpx4-public-genuine-proof-native-tree-boundary/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_ACTUAL_MAIN_PRIVATE_DATA',
        'private_relation_satisfied_and_genuine_proof_verified': True,
        'only_changed_authorization_byte_from_valid_base': 404,
        'native_Full_and_engine_reject': True, 'rejection_before_G16': True,
        'typed_error': native['Full']['typed_error'], 'engine_units': engines[0]['units'],
        'native_validation_calls': 1, 'proof_sha256': h(proof).hex(),
        'authorization_sha256': h(auth).hex(), 'transaction_id': body['id'],
        'fee_sompi': 1000, 'reference_rate100_fee_passes': False,
        'statement': 'A private proof alone does not authenticate a public CM update; the retained native subtree checks reject it.',
        'no_seed_or_main_private_data_or_PK_or_network_read': True}
    save(output / 'RESULTS.json', result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.proof_directory, args.output)
