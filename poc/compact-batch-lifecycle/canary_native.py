#!/usr/bin/env python3
"""One genuine public canary proof → one exact official native Full call.

These original shape fixtures have fee1000, below relay-rate100 requirements.
That known economic failure is retained. They test matched circuit/native wire
interoperability, not live readiness, paid inclusion, delivery or the fee target.
No actual private main material is opened. Nominal canary secrets are public.
"""
import argparse
import hashlib
import json
from pathlib import Path

from actions import Candidate
from native_runtime import DOMAIN, ROOT, Runtime, public_case, save
from primitives import fixed, h, insert_nf, need, parse, singleton
from synthetic import box, fixture

LABELS = {'compact-continuing': 2, 'compact-terminal': 0, 'wide32': 32}
CANARIES = Path('/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-canaries-01')
PHASE = ROOT / 'research/next-session/compact-batch'


def candidate(label):
    mode = LABELS[label]
    expected, _ = fixture(label, mode)
    witness = parse((CANARIES / (label + '.json')).read_bytes())
    need(witness == expected, 'exact-original-public-canary')
    auth = bytes.fromhex(witness['auth_hex528'])
    source = bytes.fromhex(witness['inputs'][0]['note_hex168'])
    before = singleton(DOMAIN, source, box(label + '/initial', 0))
    after, first = insert_nf(before, auth[204:236])
    after, second = insert_nf(after, auth[236:268])
    notes = tuple(bytes.fromhex(row['note_hex168']) for row in witness['outputs'])
    if mode:
        ciphers = [box(label, i) for i in range(mode)]
        after, _, path = after.append(DOMAIN, notes, ciphers)
        cm_list = b''.join(h(b'KPX1NOT\0', DOMAIN, note) for note in notes)
        ciphertexts, boundary = b''.join(ciphers), b''.join(path)
    else:
        cm_list, ciphertexts, boundary = b'', bytes(528), b''
    need(auth[76:188] == before.state(DOMAIN) and auth[364:476] == after.state(DOMAIN),
         'public-canary-derived-state')
    return Candidate('wide32' if mode == 32 else 'compact2', mode, auth,
        tuple(witness['inputs']), notes, ciphertexts, cm_list, first + second, boundary, after,
        int.from_bytes(auth[196:204], 'little'), int.from_bytes(auth[484:492], 'little'),
        int.from_bytes(auth[476:484], 'little'))


def run(label, proof_directory, output):
    need(label in LABELS and not output.absolute().is_relative_to(ROOT) and not output.exists(),
         'fresh-public-canary-native-output-outside-Git')
    output.mkdir(parents=True, mode=0o700)
    chosen = candidate(label)
    compact = (PHASE / 'prover/setup-compact2-01/result/verification-key.bin').read_bytes()
    wide = (PHASE / 'prover/setup-wide32-01/result/verification-key.bin').read_bytes()
    proof = fixed((proof_directory / 'proof128.bin').read_bytes(), 128)
    need((proof_directory / 'authorization528.bin').read_bytes() == chosen.auth
         and (proof_directory / 'verification-key.bin').read_bytes()
             == (wide if chosen.role == 'wide32' else compact), 'exact-public-proof-statement-and-role')
    point = {'transactionId': chosen.auth[40:72].hex(),
             'index': int.from_bytes(chosen.auth[72:76], 'little')}
    reserve = int.from_bytes(chosen.auth[188:196], 'little')
    runtime = Runtime()
    body, entries = runtime.body(chosen, point, reserve, compact, wide, proof)
    body, metrics = runtime.normalize(body, entries, output / 'normalized')
    runtime.sdk(body, entries)
    report, actual = runtime.validate(body, entries, output / 'full')
    need(metrics == actual, 'public-canary-official-mass-conformance')
    result = {'schema': 'kpx4-public-canary-genuine-native-result/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_GENUINE_PROOF_INTEROP_NOT_FEE_OR_DELIVERY_QUALIFICATION',
        'case': label, 'role': chosen.role, 'mode': chosen.mode,
        'genuine_Groth16_proof': True, 'native_Full_and_all_engines_accepted': True,
        'native_validation_calls': 1, 'official_SDK_roundtrip': True,
        'actual_common_redeem_bytes': len(bytes.fromhex(body['inputs'][0]['signatureScript'])) - 199,
        'payload_bytes': len(chosen.payload()), 'proof_sha256': h(proof).hex(),
        'authorization_sha256': h(chosen.auth).hex(), 'transaction_id': body['id'],
        'metrics': metrics, 'fee_sompi': chosen.fee,
        'reference_rate100_required_sompi': 100 * metrics['mining_mass'],
        'reference_rate100_fee_passes': chosen.fee >= 100 * metrics['mining_mass'],
        'original_underpaid_shape_fixture_retained': True,
        'no_actual_private_main_or_backup_or_PK_read': True,
        'accepted_chain_live_readiness_or_privacy_claimed': False}
    save(output / 'case.json', public_case(body, entries))
    save(output / 'RESULTS.json', result)
    print(json.dumps({k: v for k, v in result.items() if k != 'metrics'}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', choices=LABELS, required=True)
    parser.add_argument('--proof-directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    run(args.case, args.proof_directory, args.output)
