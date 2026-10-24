#!/usr/bin/env python3
"""PUBLIC UNSAFE ordinary signatures only: dummy OP_TRUE tail, never fund.

No real W program, financial selection, proof, PK, private actor file or RPC is
used. Funding creation does not execute its output. Public scalars1/2 and fake
source outpoints calibrate ordinary input signatures, IDs, fees and budgets.
"""
import argparse
import copy
from pathlib import Path
from types import SimpleNamespace
from gn2 import record, validate_genesis
from gn2_common import GENESIS, ROOT, digest, encoded, need, outside, parse, public_bytes, reference, write_new
from gn2_entry import prepare_genesis
from gn2_runtime import Runtime
from gn2_selection import entry_selection, load_identity

TRIAL = '6010c7dd-c83d-4a73-9a76-fc89cc40a193'
NOTICE = 'PUBLIC_UNSAFE_ORDINARY_INPUT_ONLY_NOT_ACTUAL_W_DO_NOT_FUND'


def native(runtime, case, output):
    normalized, _ = runtime.normalize(case, output / 'normalized')
    source = output / 'case.json'
    write_new(source, encoded(normalized) + b'\n')
    runtime.executables['native-validator'].run(['validate-transaction', source, output / 'native'])
    return normalized, parse((output / 'native/native-validation.json').read_bytes())


def run(output):
    output = outside(output)
    need(not output.exists(), 'fresh-public-input-control-output')
    output.mkdir(parents=True, mode=0o700)
    path = ROOT / 'research/next-session/four-wallet-testnet/PROFILE-IDENTITY.json'
    identity_sha = digest(public_bytes(path))
    identity = load_identity(path, identity_sha)
    domain = bytes.fromhex(identity['child_domain_hex32'])
    profile = SimpleNamespace(profile_sha256=digest(NOTICE.encode()), domain=domain,
        w_tail=b'\x51', financial_profile_id=identity['financial_profile_id'])
    runtime, recipient = Runtime(), reference('recipient')
    owners, sources = [], []
    keys = [(i + 1).to_bytes(32, 'big') for i in range(2)]  # Explicit public control constants.
    for i, role in enumerate(('A', 'C')):
        seed = bytes.fromhex(digest(('PUBLIC_GN2_SEED_' + role).encode()))
        wallet = recipient.Receiver(seed, domain, runtime.crypto)
        receipt = recipient.Receipt.for_invoice(wallet.invoice(0), 2_000_000_000,
            bytes.fromhex(digest(('PUBLIC_GN2_RHO_' + role).encode())))
        cipher = runtime.crypto.seal(wallet.invoice(0).delivery_pk, receipt.encode())
        address = runtime.address(runtime.crypto.xonly(keys[i]))
        owners.append({'schema': 'kpx6-owner-initial-public/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': GENESIS, 'financial_profile_id': identity['financial_profile_id'],
            'profile_identity_sha256': identity_sha, 'domain_hex32': domain.hex(), 'trial_id': TRIAL,
            'role': role, 'invoices_hex208': {str(n): wallet.invoice(n).encode().hex() for n in (0, 1)},
            'funding': address, 'initial_record_hex496': record(receipt.note_bytes(), cipher, domain).hex()})
        sources.append({'outpoint': {'transactionId': digest(('NONEXISTENT_PUBLIC_SOURCE_' + role).encode()), 'index': 0},
            'entry': {'amount': 3_000_000_000, 'scriptPublicKey': address['script_public_key'],
                'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}})
    case, quote = prepare_genesis(profile, TRIAL, owners, sources, runtime, output / 'proposal', 100)
    signed = copy.deepcopy(case)
    for i in range(2):
        signed['transaction']['inputs'][i]['signatureScript'] = runtime.signature(case, i, keys[i]).hex()
    validate_genesis(signed, entry_selection(profile), TRIAL,
        required_fee=quote['metrics']['actual_fee_sompi'], signed=True)
    runtime.roundtrip(signed)
    positive, metrics = runtime.validate(signed, output / 'two-ordinary-signatures')
    candidates = []
    row = copy.deepcopy(signed); row['transaction']['inputs'].reverse(); row['entries'].reverse()
    candidates.append(('reordered-source-inputs', row))
    row = copy.deepcopy(signed); row['transaction']['inputs'][1]['signatureScript'] = row['transaction']['inputs'][0]['signatureScript']
    candidates.append(('other-owner-signature', row))
    row = copy.deepcopy(signed); raw = bytearray.fromhex(row['transaction']['payload']); raw[72] ^= 1
    row['transaction']['payload'] = raw.hex(); candidates.append(('changed-signed-trial', row))
    row = copy.deepcopy(signed); row['transaction']['outputs'][1]['value'] -= 1; row['transaction']['outputs'][2]['value'] += 1
    candidates.append(('coherent-fee-redistribution', row))
    row = copy.deepcopy(signed); row['entries'][1]['amount'] += 1
    candidates.append(('wrong-own-source-context', row))
    rejections = []
    for name, candidate in candidates:
        _, report = native(runtime, candidate, output / name)
        need(report['Full']['accepted'] is False and report['all_input_engines_accepted'] is False,
             'ordinary-ALL-mutation-was-accepted')
        rejections.append({'name': name, 'Full': report['Full'], 'engines': report['per_input_ScriptEngine']})
    budget = copy.deepcopy(signed); budget['transaction']['inputs'][0]['computeBudget'] = 11
    budget_case, report = native(runtime, budget, output / 'budget-not-sighash-covered')
    need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True,
         'v1-budget-coverage-calibration')
    refused = False
    try:validate_genesis(budget_case, entry_selection(profile), TRIAL, signed=True)
    except ValueError:refused = True
    need(refused, 'GN2-application-must-independently-reject-wrong-budget')
    result = {'schema': 'kpx6-public-ordinary-GN2-control/v1', 'classification': NOTICE,
        'actual_W_or_financial_profile_validity': False, 'accepted_backing_or_currentness': False,
        'two_genuine_ordinary_ALL_signatures_Full_and_all_engines': True,
        'negative_controls': rejections, 'negative_control_count': len(rejections),
        'v1_budget_mutation_native_accepts_but_application_refuses': True,
        'source_sompi': 6_000_000_000, 'note_reserve_sompi': 4_000_000_000,
        'entry_fee_sompi': metrics['actual_fee_sompi'],
        'ordinary_change_sompi': sum(r['value'] for r in signed['transaction']['outputs'][1:]),
        'setup_PK_proof_private_actor_reads_network_or_broadcast': False}
    need(result['source_sompi'] == result['note_reserve_sompi'] + result['entry_fee_sompi']
         + result['ordinary_change_sompi'], 'public-entry-accounting')
    write_new(output / 'selected-case.json', encoded(signed) + b'\n')
    write_new(output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    result = run(parser.parse_args().output)
    print(encoded({'status': 'PASS', 'classification': NOTICE,
        'negative_controls': result['negative_control_count'], 'entry_fee_sompi': result['entry_fee_sompi']}).decode())
