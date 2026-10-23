#!/usr/bin/env python3
"""One offline replay of freshly fetched public records, plus one crypto control."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import time

from native_validation import NativeValidator
from replay import replay

NATIVE_SHA256 = "73fb41c66c374da91200f06ae442f5bd8beb3c7954c71fae954b12bec9b1c1cf"


def write(path, value):
    with path.open('x') as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write('\n')


def main():
    descriptor_path, fetch_path, binary, output = map(Path, sys.argv[1:5])
    output.mkdir(parents=True, exist_ok=False)
    descriptor = json.loads(descriptor_path.read_bytes())
    fetched = json.loads(fetch_path.read_bytes())
    validator = NativeValidator(binary, NATIVE_SHA256, output / 'native')
    began = time.monotonic()
    result = replay(descriptor, fetched, validator)
    elapsed = time.monotonic() - began
    positive_count = len(validator.reports)
    assert positive_count == len(result['operations']) and result['local_native_validation']
    write(output / 'replayed.json', result)
    original = next(row for row in fetched['transactions']
                    if bytes.fromhex(row['transaction']['payload'])[:8] == b'KPX2AU01')
    changed = deepcopy(original['transaction'])
    payload = bytearray.fromhex(changed['payload'])
    original_proof = bytes.fromhex(changed['inputs'][0]['signatureScript'])[68:196]
    original_auth_hash = hashlib.sha256(payload[:484]).hexdigest()
    payload[484] ^= 1
    payload[332:364] = hashlib.sha256(payload[484:1012]).digest()
    changed['payload'] = payload.hex()
    assert bytes.fromhex(changed['inputs'][0]['signatureScript'])[68:196] == original_proof
    assert hashlib.sha256(payload[:484]).hexdigest() != original_auth_hash
    accepted = validator(changed, original['accepted_input_contexts'])
    native = json.loads(Path(validator.reports[-1]['native_report_path']).read_bytes())
    reached_g16 = any('Groth16 verification failed' in row.get('typed_error', '')
                     for row in native['per_input_ScriptEngine'])
    assert accepted is False and reached_g16
    report = {'classification': 'ACTUAL_FRESH_NETWORK_DATA_PUBLIC_REPLAY_WITH_LOCAL_NATIVE_VALIDATION',
        'source_fetch_sha256': hashlib.sha256(fetch_path.read_bytes()).hexdigest(),
        'descriptor_file_sha256': hashlib.sha256(descriptor_path.read_bytes()).hexdigest(),
        'descriptor_sha256': result['descriptor_sha256'], 'replay_wall_seconds': elapsed,
        'complete': result['completeness']['complete'], 'terminal': result['completeness']['terminal'],
        'pool_operations': len(result['operations']), 'cm_records': len(result['deliveries']),
        'physical_nf_records': len(result['nullifiers']), 'end_reserve_sompi': result['head']['reserve_sompi'],
        'historical_payouts': result['payouts'],
        'native_validations': validator.reports[:positive_count],
        'wrong_transcript_control': {'accepted': False, 'same_original_curve_proof': True,
            'public_cipher_hash_recomputed': True, 'reached_Groth16_verification': reached_g16,
            'report': validator.reports[-1]},
        'operator_archive_snapshots_profile_seed_pk_prover_read': False,
        'private_key_or_funding_or_broadcast_operation': False,
        'sdk_transaction_ids_recomputed_by_fetcher': result['sdk_transaction_id_validation'],
        'acceptance_trust': 'SELECTED_VALIDATING_NODE_AND_PUBLIC_CHAIN_DATA',
        'local_full_validates_supplied_contexts_not_chain_inclusion': True,
        'independent_consensus_or_durable_DA_proved': False,
        'fresh_unspent_note_exit_demonstrated': False}
    write(output / 'RESULT.json', report)
    print(json.dumps({key: report[key] for key in ('classification', 'complete', 'terminal',
                                                 'pool_operations', 'replay_wall_seconds')}))


if __name__ == '__main__':
    main()
