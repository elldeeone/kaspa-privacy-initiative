#!/usr/bin/env python3
"""Three separate owner-local fixture processes; no funded keys or MPC claim.

The controller reads only public preparation/finalization receipts. Notes,
NKs, CV blindings, intents, signatures and normalized witnesses stay in each
owner directory. Public test seeds are fixed source vectors and must never be
funded. Actual funding needs fresh private Originals and actual accepted heads.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import secrets
import stat
import subprocess
import sys

import component_run
import exit_wire
import output_producer
import wallet_profile as wallet
from run_output_recovery import NODE, CRYPTO, JS_ROOT, LEAF_MAP, LEAF_MAP_SHA

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_kpb_restricted_intent', HERE.parent / 'private_batch/intent.py')
intent_codec = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = intent_codec
spec.loader.exec_module(intent_codec)


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def save(path, value, mode=0o400):
    raw = value if type(value) is bytes else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return hashlib.sha256(raw).hexdigest()


def profile_from(config):
    return wallet.Profile(bytes.fromhex(config['profile']['domain_hex32']),
                          bytes.fromhex(config['profile']['profile_id_hex32']))


def prover_from(config, read):
    return output_producer.OutputProver(profile_from(config), config['binary'], config['binary_sha256'],
        config['manifest'], config['manifest_sha256'], config['proving_key'], read_public=read)


def owner_auxiliary(config, directory, read):
    binary = Path(config['owner_aux_binary'])
    info = binary.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o500, 'owner-aux-admitted-binary-metadata')
    read(binary, config['owner_aux_sha256'])
    argv = component_run.Run.isolation(None) + [
        '--ro-bind', str(binary), '/public/owner-aux', '--bind', str(directory), '/work',
        '--chdir', '/work', '/public/owner-aux', '/work/OWNER-AUX-REQUEST.json',
        '/work/OWNER-PRIVATE-INPUT-V2.bin', '/work/PUBLIC-OWNER-AUX.json']
    run_private(argv)
    receipt = json.loads((directory / 'PUBLIC-OWNER-AUX.json').read_bytes())
    need(receipt['schema'] == 'kpi-owner-local-aux-public-receipt/v2'
         and receipt['ordered_private_values'] == 2_635_409
         and receipt['owner_file_encoding'] == 'KPB_OWNER_FR32V2'
         and receipt['owner_file_bytes'] == 84_333_120
         and receipt['native_edges'] == 66 and receipt['native_auxiliary'] == 2_625_295
         and receipt['signature_rows'] == 10_065 and receipt['signature_rows_checked'] is True
         and receipt['signature_matrix_sha256'] == component_run.MATRIX_SHA
         and receipt['signature_mapping_sha256'] == component_run.MAP_SHA
         and receipt['combined_dealer'] is False and receipt['proof_or_mpc_claim'] is False,
         'actual-single-owner-auxiliary-public-receipt')
    return receipt


def run_private(argv, value=None):
    result = subprocess.run(list(map(str, argv)), input=None if value is None else encoded(value),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'RAYON_NUM_THREADS': '2'})
    need(result.returncode == 0, 'owner-private-tool-refused')
    return result.stdout


def normalize_signature(directory, inputs, modules, read):
    artifacts = {name: read(component_run.BUILD / name, pin) for name, pin in component_run.PINS.items()}
    freeze = HERE.parent.parents[1] / 'research/next-session/local-private-payment/source-checkpoint-2026-10-27/native-authority/SOURCE-FREEZE-02.json'
    members = json.loads(read(freeze, '9bded95d08ec2a372bd89b89d83b630155b1e095da7909b2696e423962320b71'))
    members = {row['path']: row['sha256'] for row in members['files']}
    for name in ('harness/worker.mjs', 'source-bridge/signature-component-adapter-selected.mjs'):
        read(component_run.AUTH / name, members[name])
    save(directory / 'SIGNATURE-INPUT.json', inputs)
    cpp = component_run.BUILD / 'cpp0/private_authorization_cpp'
    argv = component_run.Run.isolation(None) + [
        '--ro-bind', str(cpp / 'private_authorization'), '/generator/private_authorization',
        '--ro-bind', str(cpp / 'private_authorization.dat'), '/generator/private_authorization.dat',
        '--bind', str(directory), '/work', '--chdir', '/work',
        '/generator/private_authorization', '/work/SIGNATURE-INPUT.json', '/work/SIGNATURE.wtns']
    run_private(argv)
    request = {'mode': 'witness',
        'ordinaryR1csHex': artifacts['ordinary/private_authorization.r1cs'].hex(),
        'cpp0R1csHex': artifacts['cpp0/private_authorization.r1cs'].hex(),
        'symHex': artifacts['ordinary/private_authorization.sym'].hex(),
        'wtnsHex': (directory / 'SIGNATURE.wtns').read_bytes().hex(),
        'frozen': {'mappingSha256': component_run.MAP_SHA, 'normalizedMatrixSha256': component_run.MATRIX_SHA}}
    argv = component_run.Run.isolation(None) + [
        '--ro-bind', str(NODE), '/runtime/node', '--ro-bind', str(modules), '/src/node_modules',
        '--ro-bind', str(component_run.AUTH / 'harness/worker.mjs'), '/src/harness/worker.mjs',
        '--ro-bind', str(component_run.AUTH / 'source-bridge/signature-component-adapter-selected.mjs'),
        '/src/source-bridge/signature-component-adapter-selected.mjs',
        '/runtime/node', '/src/harness/worker.mjs']
    value = json.loads(run_private(argv, request))
    need(value['matrix']['sha256'] == component_run.MATRIX_SHA
         and value['mapping']['sha256'] == component_run.MAP_SHA, 'actual-selected-signature-matrix-map')
    matrix, mapping, witness = (bytes.fromhex(value[name]['hex']) for name in ('matrix', 'mapping', 'witness'))
    need(hashlib.sha256(matrix).hexdigest() == component_run.MATRIX_SHA
         and hashlib.sha256(mapping).hexdigest() == component_run.MAP_SHA
         and hashlib.sha256(witness).hexdigest() == value['witness']['sha256'],
         'actual-signature-artifact-bytes')
    save(directory / 'SIGNATURE-MATRIX.json', matrix)
    save(directory / 'SIGNATURE-MAP.json', mapping)
    save(directory / 'SIGNATURE-WITNESS.json', witness)
    return hashlib.sha256(witness).hexdigest()


def worker(config, directory, slot, stage):
    need(type(slot) is int and slot in (0, 1, 2), 'owner-slot')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    for member in config['source_members']:
        read(Path(member['path']), member['sha256'])
    modules = wallet.authenticate_js(LEAF_MAP, LEAF_MAP_SHA, JS_ROOT)
    crypto = wallet.Crypto(CRYPTO)
    profile = profile_from(config)
    # Deliberately public synthetic seed recipe; not an Original loader.
    seed = bytes(range(slot * 32, slot * 32 + 32))
    with wallet.Authority(NODE, modules) as authority:
        receiver = wallet.Receiver(seed, profile, crypto, authority)
        if stage == 'prepare':
            prover = prover_from(config, read)
            initial = wallet.Receipt.for_invoice(receiver.invoice(0), 2_000_000_000, os.urandom(32))
            initial_cf = crypto.seal(receiver.invoice(0).delivery_pk, initial.encode())
            rin = secrets.randbelow(output_producer.Q).to_bytes(32, 'little')
            input_statement = prover._call('derive-output', b'', {
                'note_hex168': initial.note_bytes().hex(), 'blinding_hex32': rin.hex(),
                'cf_hash_hex32': hashlib.sha256(initial_cf).hexdigest()})
            input_statement = bytes.fromhex(input_statement['statement_hex168'])
            # The public recipient invoice is requested from another public
            # fixture seed, never a private Original or the other's openings.
            recipient_slot = (slot + 1) % 3
            recipient = wallet.Receiver(bytes(range(recipient_slot * 32, recipient_slot * 32 + 32)),
                                        profile, crypto, authority)
            fee = config['rehearsal']['provisional_unfunded_round1_owner_fees_sompi'][slot]
            payment = config['rehearsal']['workload']['round1_payment_sompi'][slot]
            change = 2_000_000_000 - payment - fee
            created = [prover.create(crypto, recipient.invoice(1), payment),
                       prover.create(crypto, receiver.invoice(2), change)]
            private = {'input_receipt_hex216': initial.encode().hex(), 'input_blind_hex32': rin.hex(),
                'input_cv_hex64': input_statement[72:136].hex(), 'fee_sompi': fee,
                'nonce_hex32': os.urandom(32).hex(),
                'outputs': [{'tuple_hex520': item.row.hex(), 'note_hex168': item.receipt.note_bytes().hex(),
                             'blind_hex32': item.blind.hex()} for item in created]}
            save(directory / 'OWNED-PREPARED.json', private)
            save(directory / 'PUBLIC-PREPARED.json', {'schema': 'kpb-owner-component-prepared/v1',
                'owner_slot': slot, 'initial_cm_hex32': initial.commitment().hex(),
                'initial_ciphertext_hex264': initial_cf.hex(), 'actual_output_proofs': 2,
                'public_output_tuples_hex520': [item.row.hex() for item in created],
                'seed_exported': False, 'financial_or_privacy_readiness': False})
            return

        # This worker reads its own private files only. The controller never
        # reads these bodies, private witnesses, NKs or CV blindings.
        owned = json.loads((directory / 'OWNED-PREPARED.json').read_bytes())
        public = json.loads((directory.parent.parent / 'PUBLIC-GENESIS-HEAD.json').read_bytes())
        rows = [bytes.fromhex(row) for row in public['public_output_tuples_hex520']]
        recovered = prover_from(config, read).recover_owned(receiver, rows,
            bytes.fromhex(public['component_output_cm_root_hex32']), set())
        need(len(recovered) == 2 and all(item.kind == 'unclassified' and not item.spent for item in recovered),
             'original-seed-recovery-of-complete-actual-outputs')
        context = exit_wire.HeadContext.parse(bytes.fromhex(public['context_hex276']))
        initial = wallet.Receipt.parse(bytes.fromhex(owned['input_receipt_hex216']))
        keys = receiver.keys(0)
        need(initial.invoice(keys.invoice.delivery_pk) == keys.invoice, 'owner-initial-descriptor')
        path = public['initial_cm_paths_hex32'][slot]
        nf = receiver.nullifier(initial, slot)
        intent = intent_codec.RestrictedIntent(context.chain, context.pool, context.profile, context.domain,
            context.service, context.point, context.cm_root, context.nf_root, context.cm_count,
            context.nf_count, context.reserve, nf, bytes.fromhex(owned['input_cv_hex64']),
            owned['fee_sompi'], bytes.fromhex(owned['nonce_hex32']),
            tuple(bytes.fromhex(item['tuple_hex520']) for item in owned['outputs']))
        raw_intent = intent.encode()
        signature = authority.sign(keys.signing_seed, raw_intent)
        need(authority.verify(raw_intent, signature), 'actual-restricted-intent-signature')
        inputs = authority.signature_inputs(raw_intent, signature)
        private_delta = (int.from_bytes(bytes.fromhex(owned['input_blind_hex32']), 'little')
            - sum(int.from_bytes(bytes.fromhex(item['blind_hex32']), 'little')
                  for item in owned['outputs'])) % output_producer.Q
        record = {'schema': 'kpb-public-unfunded-owner-record/v1', 'input': {
            'note_hex168': initial.note_bytes().hex(), 'nk_hex32': keys.nf_secret.hex(), 'position': slot,
            'path_hex32': path, 'cv_hex64': owned['input_cv_hex64'],
            'blind_hex32': owned['input_blind_hex32'], 'ak_hex64': keys.owner_key.hex(),
            'nf_hex32': nf.hex()}, 'fee_sompi': owned['fee_sompi'],
            'nonce_hex32': owned['nonce_hex32'], 'outputs': owned['outputs'],
            'private_delta_hex32': private_delta.to_bytes(32, 'little').hex(),
            'intent_hex1460': raw_intent.hex(),
            'signature': {key: signature[key] for key in ('owner_key_hex64', 'R8', 'S')},
            'signature_inputs': inputs}
        save(directory / 'OWNER-LOCAL-RECORD.json', record)
        witness_sha = normalize_signature(directory, inputs, modules, read)
        request = {'schema': 'kpi-owner-local-aux-request/v1', 'owner_component': slot,
            'context_hex': public['context_hex276'], 'owner_record_path': 'OWNER-LOCAL-RECORD.json',
            'signature_matrix_path': 'SIGNATURE-MATRIX.json', 'signature_witness_path': 'SIGNATURE-WITNESS.json',
            'expected_matrix_sha256': component_run.MATRIX_SHA,
            'expected_mapping_sha256': component_run.MAP_SHA, 'expected_witness_sha256': witness_sha}
        save(directory / 'OWNER-AUX-REQUEST.json', request)
        auxiliary = owner_auxiliary(config, directory, read)
        need(auxiliary['owner_component'] == slot
             and auxiliary['context_sha256'] == hashlib.sha256(context.encode()).hexdigest(),
             'single-owner-auxiliary-selected-context')
        save(directory / 'PUBLIC-FINALIZED.json', {'schema': 'kpb-owner-component-finalized/v1',
            'owner_slot': slot, 'actual_restricted_intent_signature': True,
            'actual_signature_normalization': True, 'actual_output_proofs': 2,
            'complete_output_original_seed_recoveries': len(recovered),
            'recovered_output_roles': 'unclassified',
            'owner_local_auxiliary_values': auxiliary['ordered_private_values'],
            'owner_local_auxiliary_generated': True,
            'private_record_or_auxiliary_published': False, 'seed_exported': False})


def launch_workers(config_path, output, stage):
    active = []
    for slot in range(3):
        directory = output / 'owners' / str(slot)
        if stage == 'prepare':
            directory.mkdir(parents=True, mode=0o700)
        stdout = (directory / (stage + '.controller.stdout')).open('xb')
        stderr = (directory / (stage + '.controller.stderr')).open('xb')
        argv = [sys.executable, str(Path(__file__).resolve()), '--worker', stage,
                '--config', str(config_path), '--owner-slot', str(slot), '--output', str(directory)]
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'})
        active.append((process, stdout, stderr))
    codes = []
    for process, stdout, stderr in active:
        codes.append(process.wait())
        stdout.close(); stderr.close()
    need(codes == [0, 0, 0], 'owner-' + stage + '-process-refused')


def controller(args):
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    output = Path(args.output).absolute()
    need(not output.exists(), 'fresh-unfunded-batch-component-identity')
    output.mkdir(parents=True, mode=0o700)
    profile = json.loads(read(Path(args.profile).absolute(), args.profile_sha256))
    rehearsal = json.loads(read(Path(args.rehearsal).absolute(), args.rehearsal_sha256))
    need(profile['status'] == 'UNFUNDED_COMPONENT_IDENTITY_NO_FINANCIAL_READINESS'
        and rehearsal['classification'] == 'PUBLIC_SYNTHETIC_HEAD_NO_ACCEPTED_DEPOSIT_OR_BACKING'
        and rehearsal['profile_descriptor_sha256'] == args.profile_sha256,
        'exact-unfunded-component-descriptors')
    descriptor = profile['profile_descriptor']
    need(hashlib.sha256(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
         == profile['profile_id_hex32'], 'canonical-profile-descriptor-identity')
    need(all(rehearsal[name] == descriptor[name] for name in
             ('domain_hex32', 'chain_genesis_hex32', 'service_policy_hex32'))
         and rehearsal['profile_id_hex32'] == profile['profile_id_hex32'], 'one-selected-rehearsal-profile')
    need(rehearsal['initial_note_values_sompi'] == [2_000_000_000] * 3
         and rehearsal['initial_cm_positions'] == [0, 1, 2]
         and rehearsal['initial_cm_count'] == 3 and rehearsal['initial_nf_count'] == 1
         and rehearsal['initial_reserve_sompi'] == 6_000_000_000
         and rehearsal['workload']['round1_payment_sompi'] == [500_000_000] * 3
         and rehearsal['workload']['round1_recipient_offset'] == 1
         and rehearsal['provisional_unfunded_round1_owner_fees_sompi'] == [7_000_000] * 3
         and rehearsal['provisional_fees_are_native_measured'] is False, 'fixed-matched-unfunded-workload')
    config = {'profile': {'domain_hex32': descriptor['domain_hex32'], 'profile_id_hex32': profile['profile_id_hex32']},
        'rehearsal': rehearsal, 'binary': str(Path(args.binary).absolute()), 'binary_sha256': args.binary_sha256,
        'manifest': str(Path(args.manifest).absolute()), 'manifest_sha256': args.manifest_sha256,
        'proving_key': str(Path(args.proving_key).absolute()),
        'owner_aux_binary': str(Path(args.owner_aux_binary).absolute()), 'owner_aux_sha256': args.owner_aux_sha256}
    read(Path(config['owner_aux_binary']), config['owner_aux_sha256'])
    sources = []
    paths = [HERE / name for name in ('prepare_unfunded_batch.py', 'output_producer.py',
        'wallet_profile.py', 'owner_authority.mjs', 'component_run.py', 'exit_wire.py', 'run_output_recovery.py')]
    paths += [HERE.parent / 'private_batch/intent.py', HERE.parent / 'integration/trees.py',
              HERE.parent / 'verification/wire.py', HERE.parents[1] / 'future-recipient/v2/recipient.py']
    for path in paths:
        raw = read(path)
        sources.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()})
    freeze = HERE.parent.parents[1] / 'research/next-session/local-private-payment/source-checkpoint-2026-10-27/native-authority/SOURCE-FREEZE-02.json'
    frozen = json.loads(read(freeze, '9bded95d08ec2a372bd89b89d83b630155b1e095da7909b2696e423962320b71'))
    frozen = {row['path']: row['sha256'] for row in frozen['files']}
    for name in ('harness/worker.mjs', 'source-bridge/signature-component-adapter-selected.mjs'):
        path = component_run.AUTH / name
        read(path, frozen[name])
        sources.append({'path': str(path), 'sha256': frozen[name]})
    config['source_members'] = sources
    save(output / 'CONFIG.json', config)
    save(output / 'SELECTION.json', {'schema': 'kpb-three-owner-unfunded-component-selection/v1',
        'source_members': sources, 'profile_sha256': args.profile_sha256,
        'rehearsal_sha256': args.rehearsal_sha256, 'public_seed_vectors': ['00..1f', '20..3f', '40..5f'],
        'owner_aux_binary_sha256': args.owner_aux_sha256,
        'actual_originals_or_funding': False, 'private_batch_or_privacy_measurement': False,
        'provisional_fees_native_calibrated': False, 'fresh_setup': False})
    launch_workers(output / 'CONFIG.json', output, 'prepare')
    public = [json.loads((output / 'owners' / str(slot) / 'PUBLIC-PREPARED.json').read_bytes())
              for slot in range(3)]
    tree_spec = importlib.util.spec_from_file_location('_kpb_unfunded_public_trees', HERE.parent / 'integration/trees.py')
    trees = importlib.util.module_from_spec(tree_spec); sys.modules[tree_spec.name] = trees
    tree_spec.loader.exec_module(trees)
    state = trees.PublicState([bytes.fromhex(row['initial_cm_hex32']) for row in public])
    rows = sorted(bytes.fromhex(row) for owner in public for row in owner['public_output_tuples_hex520'])
    need(len(rows) == 6 and len({row[:32] for row in rows}) == 6, 'six-distinct-complete-output-tuples')
    output_state = trees.PublicState([row[:32] for row in rows])
    point = rehearsal['placeholder_reserve_outpoint']
    context = exit_wire.HeadContext(bytes.fromhex(rehearsal['chain_genesis_hex32']),
        bytes.fromhex(rehearsal['pool_lineage_hex32']), bytes.fromhex(rehearsal['profile_id_hex32']),
        bytes.fromhex(rehearsal['domain_hex32']), bytes.fromhex(rehearsal['service_policy_hex32']),
        bytes.fromhex(point['transaction_id_hex32']) + point['index'].to_bytes(4, 'little'),
        state.cm.root(), state.nf.root(), 3, 1, 6_000_000_000)
    public_head = {'schema': 'kpb-public-unfunded-genesis-head/v1',
        'classification': 'PUBLIC_SYNTHETIC_HEAD_NO_ACCEPTED_DEPOSIT_OR_BACKING',
        'context_hex276': context.encode().hex(), 'state_hex112': context.state().hex(),
        'initial_deliveries': [{'position': slot, 'cm_hex32': row['initial_cm_hex32'],
             'ciphertext_hex264': row['initial_ciphertext_hex264']} for slot, row in enumerate(public)],
        'initial_cm_paths_hex32': [[state.cm.path(slot)[at:at + 32].hex() for at in range(0, 512, 32)]
                                 for slot in range(3)],
        'public_output_tuples_hex520': [row.hex() for row in rows],
        'component_output_cm_root_hex32': output_state.cm.root().hex(),
        'initial_genesis_or_backing_verified': False, 'initial_funding_output_proofs_claimed': False,
        'provisional_owner_fees_sompi': rehearsal['provisional_unfunded_round1_owner_fees_sompi']}
    save(output / 'PUBLIC-GENESIS-HEAD.json', public_head)
    launch_workers(output / 'CONFIG.json', output, 'finalize')
    summaries = [json.loads((output / 'owners' / str(slot) / 'PUBLIC-FINALIZED.json').read_bytes())
                 for slot in range(3)]
    need(all(row['actual_restricted_intent_signature'] and row['actual_signature_normalization']
             and row['actual_output_proofs'] == 2 and row['seed_exported'] is False for row in summaries),
         'all-three-owner-components-required')
    result = {'schema': 'kpb-three-owner-unfunded-components-result/v1',
        'classification': 'PUBLIC_SYNTHETIC_HEAD_NO_ACCEPTED_DEPOSIT_OR_BACKING',
        'actual_output_proofs': 6, 'actual_restricted_intent_signatures': 3,
        'actual_signature_normalizations': 3, 'public_head': str(output / 'PUBLIC-GENESIS-HEAD.json'),
        'owner_local_auxiliaries': sum(row['owner_local_auxiliary_generated'] for row in summaries),
        'owner_local_ordered_values_each': [row['owner_local_auxiliary_values'] for row in summaries],
        'complete_output_original_seed_recoveries': sum(row['complete_output_original_seed_recoveries'] for row in summaries),
        'recovered_output_roles': 'unclassified',
        'public_head_sha256': hashlib.sha256(encoded(public_head)).hexdigest(),
        'owner_directories': [str(output / 'owners' / str(slot)) for slot in range(3)],
        'controller_read_owner_private_records_or_auxiliaries': False,
        'fresh_setup': False, 'native_fees_calibrated': False,
        'funding_accepted_history_native_batch_or_privacy_qualification': False}
    save(output / 'RESULT.json', result)
    print(json.dumps({'status': 'THREE_OWNER_REAL_COMPONENTS_COMPLETED',
                      'actual_output_proofs': 6, 'actual_restricted_intent_signatures': 3,
                      'result_sha256': hashlib.sha256(encoded(result)).hexdigest()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', choices=('prepare', 'finalize'))
    parser.add_argument('--config'); parser.add_argument('--owner-slot', type=int)
    parser.add_argument('--output', required=True)
    for name in ('profile', 'profile-sha256', 'rehearsal', 'rehearsal-sha256',
                 'binary', 'binary-sha256', 'manifest', 'manifest-sha256', 'proving-key'):
        parser.add_argument('--' + name)
    parser.add_argument('--owner-aux-binary'); parser.add_argument('--owner-aux-sha256')
    args = parser.parse_args()
    try:
        if args.worker:
            worker(json.loads(Path(args.config).read_bytes()), Path(args.output).absolute(), args.owner_slot, args.worker)
        else:
            controller(args)
    except BaseException as error:
        target = Path(args.output)
        if target.exists() and not (target / 'PUBLIC-FAILURE.json').exists():
            save(target / 'PUBLIC-FAILURE.json', {'schema': 'kpb-owner-fixture-failure/v1',
                 'type': type(error).__name__, 'category': str(error) if isinstance(error, (ValueError, wallet.Invalid)) else 'worker-failure'})
        raise


if __name__ == '__main__':
    main()
