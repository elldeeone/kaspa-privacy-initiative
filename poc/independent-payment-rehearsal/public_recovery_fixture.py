#!/usr/bin/env python3
"""Build an intentionally public, unfunded GN-only recovery canary.

The seed and ordinary source scalar are public constants. Never fund any
address, outpoint or note produced here. Supplied UTXOs are synthetic. This
reuses the selected existing GN/receiver/native code; it creates no new proof
relation, accepted backing, current state or spend authorization.
"""
import argparse
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'poc/compact-batch-lifecycle'
sys.path.insert(0, str(BASE))

import history
from native_runtime import DOMAIN, GENESIS, Runtime, encoded, p2sh, public_case, save, tx
from primitives import h, need
import receiver

NOTICE = 'PUBLIC_UNSAFE_DO_NOT_FUND_SYNTHETIC_GN_RECOVERY_ONLY'
SEED = h(b'KPI/PUBLIC-UNSAFE-RECOVERY-CANARY/SEED/v1')
FUNDING_SCALAR = bytes(31) + b'\x01'


def build(output):
    # Path.absolute() preserves '..'; reject it before any output creation.
    need('..' not in Path(output).parts, 'canonical-canary-output-path')
    output = receiver.no_symlinks(output)
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-canary-outside-Git')
    output.mkdir(parents=True, mode=0o700)
    phase = ROOT / 'research/next-session/compact-batch'
    compact = (phase / 'prover/setup-compact2-01/result/verification-key.bin').read_bytes()
    wide = (phase / 'prover/setup-wide32-01/result/verification-key.bin').read_bytes()
    manifest_paths = [phase / f'prover/parameters-{role}-01/public-parameters.json'
                      for role in ('compact2', 'wide32')]
    # The externally selected predecessor package fixes these public role keys.
    need(h(compact).hex() == 'bf033abd75237c3f04f4b8ca19ef93c115b192d04eb8360b8d5060ccdb9bed78'
         and h(wide).hex() == 'a1be8ead145bd5fa65702f7eb3d2246dea307138f2915e5847a03813d70373fb',
         'selected-public-role-VKs')
    hashes = [h(path.read_bytes()).hex() for path in manifest_paths]
    need(hashes == ['f27a806928b5c2409d4e4c5428a75deabef6ecf9601b60889667e90363f26043',
                    'b1f0e93bf153c423c669524318efe276917a902d4e9e6b250fba564face94149'],
         'selected-public-role-manifests')
    runtime, crypto, v2 = Runtime(), receiver.Crypto(), receiver.module()
    wallet = v2.Receiver(SEED, DOMAIN, crypto)
    invoice = wallet.invoice(0)
    reserve = 1_000_000_000
    receipt = v2.Receipt.for_invoice(invoice, reserve,
                  h(b'KPI/PUBLIC-UNSAFE-RECOVERY-CANARY/RHO/v1'))
    ciphertext = crypto.seal(invoice.delivery_pk, receipt.encode())
    snapshot, redeem, payload = runtime.genesis(receipt.note_bytes(), ciphertext, compact, wide)
    source_spk = '000020' + crypto.xonly(FUNDING_SCALAR).hex() + 'ac'
    source = {'transactionId': h(b'KPI/SYNTHETIC-NONEXISTENT-PUBLIC-RECOVERY-SOURCE/v1',
                                  DOMAIN).hex(), 'index': 0}
    fee = 1
    # Quote convergence is ordinary deterministic codec work, not a trial
    # timeout or an economic shortcut; the actual final signed body is requoted.
    attempt = 0
    while True:
        context = {'amount_sompi': str(reserve + fee), 'script_public_key': source_spk,
                   'block_daa_score': '0', 'is_coinbase': False, 'covenant_id': None}
        body = tx(source, [(reserve, p2sh(redeem))], payload, bytes(66), 10)
        body, metrics = runtime.normalize(body, [context], output / f'quote-{attempt:04d}')
        required = 100 * metrics['mining_mass']
        if required == fee:
            break
        fee, attempt = required, attempt + 1
    body = runtime.sdk(body, [context], FUNDING_SCALAR)
    body, metrics = runtime.normalize(body, [context], output / 'signed-normalized')
    need(metrics['actual_fee_sompi'] == fee == 100 * metrics['mining_mass'],
         'exact-signed-public-canary-reference-fee')
    runtime.sdk(body, [context])
    report, checked_metrics = runtime.validate(body, [context], output / 'native-full')
    need(checked_metrics == metrics, 'signed-public-canary-mass-match')
    descriptor = {'schema': 'kpx4-compact-batch-descriptor/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': GENESIS, 'domain_hex32': DOMAIN.hex(),
        'founding_outpoint': {'transactionId': body['id'], 'index': 0},
        'birth_start_hash': '00' * 32, 'initial_redeem_hex': redeem.hex(),
        'compact_vk_hex328': compact.hex(), 'wide_vk_hex328': wide.hex(),
        'immutable_policy_sha256': h(redeem[114:]).hex(),
        'compact_public_params_manifest_sha256': hashes[0],
        'wide_public_params_manifest_sha256': hashes[1]}
    descriptor_hash = h(encoded(descriptor)).hex()
    selected, _, _ = history.descriptor(encoded(descriptor), descriptor_hash)
    history.validate_genesis(body, context, selected, runtime, compact, wide)
    public_history = {'schema': 'kpx4-compact-batch-history/v1',
        'classification': 'SYNTHETIC_NATIVE_VALID_CONTEXTS_NOT_ACCEPTED',
        'descriptor_sha256': descriptor_hash, 'records': [public_case(body, [context])]}
    backup = {'schema': 'kpx4-compact-batch-seed-backup/v1', 'network_id': 'testnet-10',
              'genesis_hash_hex': GENESIS, 'domain_hex32': DOMAIN.hex(), 'seed_hex32': SEED.hex()}
    for name, value in [('descriptor.json', descriptor), ('history.json', public_history),
                        ('PUBLIC-UNSAFE-SEED.json', backup)]:
        save(output / name, value)
    manifest = json.loads(manifest_paths[0].read_bytes())
    save(output / 'compact-client-selection.json', {
        'schema': 'kpx4-compact-batch-owner-selection/v1', 'role': 'compact2',
        'domain_hex32': DOMAIN.hex(), 'descriptor_sha256': descriptor_hash,
        'parameter_manifest_sha256': hashes[0], 'vk_sha256': h(compact).hex(),
        'compiled_build_identity_sha256': manifest['compiled_build_identity_sha256'],
        'prover_sha256': '1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d'})
    # Execute the same full public replay and decrypt/rederive checks that a
    # cold recognition client will execute. No PK, main backup or main history.
    replayed = history.replay(encoded(public_history), selected, descriptor_hash,
                              runtime, output / 'recognition-replay')
    own_seed = receiver.backup(output / 'PUBLIC-UNSAFE-SEED.json', DOMAIN)
    own_wallet = v2.Receiver(own_seed, DOMAIN, crypto)
    recovery = receiver.recover(own_wallet, replayed['snapshot'], snapshot.state(DOMAIN))
    need(len(recovery.owned) == 1 and recovery.owned[0].position == 0
         and not recovery.owned[0].spent and recovery.owned[0].owner_action_available
         and recovery.owned[0].receipt.value_sompi == reserve, 'public-canary-own-recognition')
    result = {'schema': 'kpi-public-recovery-canary/v1', 'classification': NOTICE,
        'descriptor_sha256': descriptor_hash, 'history_sha256': h(encoded(public_history) + b'\n').hex(),
        'public_seed_is_deliberately_known': True, 'software_original_backup_count': 1,
        'recognized_note_count': 1, 'recognized_value_sompi': reserve,
        'genesis_native_Full_all_engines': report['Full']['accepted'] is True,
        'fresh_replay_native_Full_all_engines': all(x['native_Full_all_engines']
                                                   for x in replayed['native_reports']),
        'reference_fee_rate': 100, 'ordinary_entry_fee_sompi': fee,
        'proving_parameters_or_private_main_material_read': False,
        'new_proof_or_private_exit_created': False,
        'network_or_broadcast_performed': False,
        'accepted_chain_backing_or_currentness_verified': False,
        'accepted_spend_authorized': False}
    save(output / 'RESULTS.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output), sort_keys=True))
