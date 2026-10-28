#!/usr/bin/env python3
"""Real Output proof/delivery/seed-restoration control with public unfunded seeds.

Reuse the selected new Output parameters. This does not create a pool, accept
backing/history, run a private batch, or broadcast any transaction.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

import output_producer
import wallet_profile as wallet

HERE = Path(__file__).resolve().parent
NODE = Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
CRYPTO = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
JS_ROOT = Path('/var/tmp/kpi-signature-predicate-tools-20261026-01')
LEAF_MAP = Path('/run/user/1000/kpi-nativeauthspend-resume-20261028-03/JS-INSTALLED-LEAF-MAP.json')
LEAF_MAP_SHA = '00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'profile', 'profile-sha256', 'binary', 'binary-sha256',
                 'manifest', 'manifest-sha256', 'proving-key'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    destination = Path(args.output).absolute()
    need(not destination.exists(), 'fresh-output-recovery-identity')
    destination.mkdir(parents=True, mode=0o700)

    def save(name, body):
        with (destination / name).open('xb') as handle:
            handle.write(body)

    try:
        read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        profile = json.loads(read(Path(args.profile).absolute(), args.profile_sha256))
        need(profile['status'] == 'UNFUNDED_COMPONENT_IDENTITY_NO_FINANCIAL_READINESS',
             'unfunded-component-selection')
        descriptor = profile['profile_descriptor']
        identity = hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        need(identity == profile['profile_id_hex32'], 'profile-identity')
        selected = wallet.Profile(bytes.fromhex(descriptor['domain_hex32']), bytes.fromhex(identity))
        sources = []
        for name in ('run_output_recovery.py', 'output_producer.py', 'wallet_profile.py', 'owner_authority.mjs'):
            raw = read(HERE / name)
            sources.append({'path': str(HERE / name), 'sha256': hashlib.sha256(raw).hexdigest()})
        save('SELECTION.json', encoded({'schema': 'kpb-output-recovery-component-selection/v1',
             'source_members': sources, 'profile_sha256': args.profile_sha256,
             'binary_sha256': args.binary_sha256, 'manifest_sha256': args.manifest_sha256,
             'public_unfunded_seed_vectors': ['00..1f', '20..3f'],
             'fresh_parameters_created': False, 'financial_or_privacy_trial': False}))
        modules = wallet.authenticate_js(LEAF_MAP, LEAF_MAP_SHA, JS_ROOT)
        crypto = wallet.Crypto(CRYPTO)
        prover = output_producer.OutputProver(selected, args.binary, args.binary_sha256,
                  args.manifest, args.manifest_sha256, args.proving_key, read_public=read)
        seed = bytes(range(32))  # Deliberately public, never a funded wallet.
        with wallet.Authority(NODE, modules) as authority:
            receiver = wallet.Receiver(seed, selected, crypto, authority)
            created = [prover.create(crypto, receiver.invoice(index), value)
                       for index, value in ((7, 200_000_000), (8, 300_000_000))]
            rows = [item.row for item in created]
            original_nfs = [receiver.nullifier(item.receipt, position)
                            for position, item in enumerate(created)]
        # The original owner authority process is gone. Restoration consumes
        # only original public test seed, profile/software/parameters and rows.
        del created, receiver
        root = wallet.legacy.Tree(wallet.legacy.CM_DEPTH, [row[:32] for row in rows],
                                  wallet.legacy.CM_NODE, wallet.legacy.CM_EMPTY).root
        checks = {}
        with wallet.Authority(NODE, modules) as authority:
            restored = wallet.Receiver(seed, selected, crypto, authority)
            recovered = prover.recover_owned(restored, rows, root, [])
            need(len(recovered) == 2 and [claim.nf for claim in recovered] == original_nfs,
                 'genuine-output-seed-restoration')
            need(all(claim.kind == 'unclassified' for claim in recovered), 'no-private-partition-inference')
            checks['original_seed_restores_both_real_outputs'] = True
            checks['stable_nullifiers_without_creator_blinds'] = True
            checks['roles_remain_unclassified'] = True
            wrong = wallet.Receiver(bytes(range(32, 64)), selected, crypto, authority)
            try:
                prover.recover_owned(wrong, rows, root, [])
                raise ValueError('wrong-seed-accepted')
            except wallet.Invalid:
                checks['wrong_seed_rejected'] = True
            changed = bytearray(rows[0]); changed[96] ^= 1
            try:
                prover.verify(bytes(changed))
                raise ValueError('changed-CF-accepted')
            except wallet.Invalid:
                checks['changed_ciphertext_rejected'] = True
            changed[360:392] = hashlib.sha256(changed[96:360]).digest()
            need(prover.verify(bytes(changed)) is False, 'coherent-CF-hash-proof-substitution')
            checks['coherently_rehashed_ciphertext_rejected_by_real_proof'] = True
            changed = bytearray(rows[0]); changed[-1] ^= 1
            try:
                rejected = prover.verify(bytes(changed)) is False
            except wallet.Invalid:
                rejected = True
            need(rejected, 'changed-proof-accepted')
            checks['changed_proof_rejected'] = True
            for category, candidate_rows, candidate_root in (
                    ('duplicate_commitment_rejected', [rows[0], rows[0]], root),
                    ('wrong_CM_root_rejected', rows, bytes([99]) * 32)):
                try:
                    prover.recover_owned(restored, candidate_rows, candidate_root, [])
                    raise ValueError(category + '-failed')
                except wallet.Invalid:
                    checks[category] = True
        public_rows = b''.join(rows)
        save('PUBLIC-OUTPUTS.bin', public_rows)
        result = {'schema': 'kpb-genuine-output-recovery-component-result/v1',
                  'profile_id_hex32': identity, 'domain_hex32': selected.domain.hex(),
                  'actual_output_proofs': len(rows), 'public_output_bytes': len(public_rows),
                  'public_outputs_sha256': hashlib.sha256(public_rows).hexdigest(),
                  'output_parameter_manifest_sha256': args.manifest_sha256,
                  'fresh_setup_performed': False, 'checks': checks,
                  'actual_private_wallet_originals_used': False,
                  'accepted_history_backing_native_settlement_or_privacy_established': False}
        save('RESULT.json', encoded(result))
        print(json.dumps({'status': 'GENUINE_OUTPUT_RECOVERY_COMPONENT_COMPLETED',
                          'actual_output_proofs': len(rows), 'checks_passed': len(checks),
                          'result_sha256': hashlib.sha256(encoded(result)).hexdigest(),
                          'native_or_privacy_readiness': False}))
    except BaseException as error:
        save('FIRST-FAILURE.json', encoded({'type': type(error).__name__, 'category': str(error)}))
        raise


if __name__ == '__main__':
    main()
