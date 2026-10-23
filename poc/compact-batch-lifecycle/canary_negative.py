#!/usr/bin/env python3
"""Two genuine foreign-role proof transplants; no new proof, seed, PK or RPC."""
import argparse
import copy
import json
from pathlib import Path

from history import contexts
from native_runtime import ROOT, Runtime, public_case, save
from primitives import fixed, h, need, parse

PHASE = ROOT / 'research/next-session/compact-batch'
POSITIVE = Path('/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-public-canary-native-01')
EXPECTED = 'ZkIntegrity("Groth16 verification failed")'


def run(output):
    need(not output.absolute().is_relative_to(ROOT) and not output.exists(), 'fresh-public-negative-output')
    output.mkdir(parents=True, mode=0o700)
    runtime = Runtime()
    results = []
    for target, foreign in [('compact-continuing', 'wide32'), ('wide32', 'compact-continuing')]:
        case = parse((POSITIVE / target / 'case.json').read_bytes())
        body = copy.deepcopy(case['transaction'])
        proof = fixed((PHASE / 'prover/public-canary-proofs-01' / foreign / 'proof/proof128.bin').read_bytes(), 128)
        signature = bytearray.fromhex(body['inputs'][0]['signatureScript'])
        signature[68:196] = proof
        body['inputs'][0]['signatureScript'] = signature.hex()
        entries = contexts(case)
        target_out = output / target
        body, metrics = runtime.normalize(body, entries, target_out / 'normalized')
        runtime.sdk(body, entries)
        input_case = target_out / 'selected-case.json'
        save(input_case, public_case(body, entries))
        runtime.native.run(['validate-transaction', input_case, target_out / 'native'])
        report = parse((target_out / 'native/native-validation.json').read_bytes())
        engines = report['per_input_ScriptEngine']
        need(report['isolation'] == 'PASS' and report['Full']['accepted'] is False
             and report['Full']['typed_error'] == 'SignatureInvalid(' + EXPECTED + ')'
             and report['all_input_engines_accepted'] is False and len(engines) == 1
             and engines[0]['accepted'] is False and engines[0]['typed_error'] == EXPECTED
             and engines[0]['units'] >= 14_750_000, 'foreign-role-proof-not-rejected-at-G16')
        results.append({'target_public_case': target, 'foreign_public_proof': foreign,
            'foreign_proof_sha256': h(proof).hex(), 'actual_final_G16_rejection': True,
            'typed_error': report['Full']['typed_error'], 'engine_units': engines[0]['units'],
            'actual_native_validation_calls': 1, 'transaction_id': body['id'],
            'fee_sompi': metrics['actual_fee_sompi'],
            'scope': 'Foreign-role plus foreign-statement transplant; not an isolated raw wrong-VK-only experiment'})
    summary = {'schema': 'kpx4-public-foreign-role-native-controls/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND_NO_MAIN_PRIVATE_DATA',
        'case_count': 2, 'new_proofs_or_PK_or_backup_reads': 0, 'actual_native_validation_calls': 2,
        'all_expected_final_G16_rejections': True, 'results': results,
        'accepted_backing_live_readiness_or_fee_privacy_qualification': False}
    save(output / 'RESULTS.json', summary)
    print(json.dumps(summary, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
