#!/usr/bin/env python3
"""Public scalar fixture: three ordinary signatures, not a funded lifecycle."""
import argparse
from pathlib import Path

from gn3 import EntrySelection, approval_digest, record
from gn3_common import digest, encoded, write_new
from gn3_entry import combine, prepare_genesis
from gn3_runtime import Runtime


DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')
TRIAL = 'ed13029e-a021-4746-8d4f-0ff0756c6b2c'


def run(output):
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    runtime = Runtime()
    selection = EntrySelection('11' * 32, DOMAIN, b'\x51')
    keys = [bytes([i]) * 32 for i in (1, 2, 3)]  # Published test scalars only.
    records, sources = [], []
    for i, key in enumerate(keys):
        value = 2_000_000_000
        note = (bytes([11 + i]) * 32 + bytes([21 + i]) * 32 + value.to_bytes(8, 'little')
                + bytes([31 + i]) * 32 + bytes([41 + i]) * 32 + bytes([51 + i]) * 32)
        records.append(record(note, bytes([61 + i]) * 264, DOMAIN))
        public = runtime.address(runtime.crypto.xonly(key))
        sources.append({'outpoint': {'transactionId': bytes([71 + i]).hex() * 32, 'index': i},
            'entry': {'amount': value + 1_000_000_000,
                'scriptPublicKey': public['script_public_key'], 'blockDaaScore': i,
                'isCoinbase': False, 'covenantId': None}})
    case, quote = prepare_genesis(selection, TRIAL, records, sources, runtime, output / 'proposal')
    approvals = []
    for index, key in enumerate(keys):
        signature = runtime.signature(case, index, key)
        approvals.append({'schema': 'kpx8-GN3-owner-approval/v1',
            'financial_profile_sha256': selection.profile_sha256, 'trial_id': TRIAL,
            'input_index': index, 'signature_script_hex66': signature.hex(),
            'unsigned_case_approval_sha256': approval_digest(case, selection, TRIAL, 100),
            'own_initial_public_record_sha256': digest(records[index]),
            'own_receipt_rederived': True,  # Public synthetic fixture; no wallet claim.
            'quote': {'fee_rate_sompi_per_mass': 100,
                'mining_mass': quote['metrics']['mining_mass'],
                'storage_mass': quote['metrics']['storage_mass'],
                'total_entry_fee_sompi': quote['derived_entry']['fee_sompi'],
                'owner_entry_fee_sompi': quote['derived_entry']['contributions'][index]['entry_fee_sompi']}})
    selected, result = combine(selection, TRIAL, case, approvals, runtime, output / 'combined')
    failures = []
    for index in range(3):
        wrong = list(approvals)
        wrong[index] = dict(wrong[(index + 1) % 3])
        try:
            combine(selection, TRIAL, case, wrong, runtime, output / f'missing-owner-{index}')
        except ValueError:
            failures.append('omitted-or-duplicated-signer-' + str(index))
        else:
            raise ValueError('omitted-signer-accepted')
    import copy
    for index in range(3):
        damaged = copy.deepcopy(selected)
        damaged['transaction']['inputs'][index]['signatureScript'] = '41' + '00' * 64 + '01'
        try:
            runtime.validate(damaged, output / f'damaged-signature-{index}')
        except ValueError:
            failures.append('invalid-native-signature-' + str(index))
        else:
            raise ValueError('damaged-signature-accepted')
    summary = {'schema': 'kpx8-GN3-public-signature-controls/v1',
        'scope': 'PUBLIC_SYNTHETIC_THREE_ORDINARY_SIGNATURES_DUMMY_OP_TRUE_RESERVE_TAIL',
        'native_full_ordinary_inputs_passed': True, 'ordinary_signatures': 3,
        'rejected_controls': failures, 'financial_profile_or_actual_pool_proven': False,
        'wallet_seed_or_original_backup_read': False, 'network_or_broadcast': False,
        'metrics': result['metrics']}
    write_new(output / 'RESULTS.json', encoded(summary) + b'\n')
    return summary


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    print(encoded(run(parser.parse_args().output)).decode())
