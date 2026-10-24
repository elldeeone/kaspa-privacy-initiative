#!/usr/bin/env python3
"""Unfunded one-backup signer integration with an explicitly fake W profile.

No PK, W proof, node query, funding or broadcast. The structurally selected tail
is not a real W program and must never receive money. Owners remain isolated;
the coordinator reads only their public initialization records.
"""
import argparse
import copy
from pathlib import Path
import subprocess

from gn2_common import CLEAN, HERE, ROOT, digest, encoded, need, outside, parse, public_bytes, write_new
from gn2_entry import combine, prepare_genesis
from gn2_runtime import GENERIC, Runtime
from gn2_selection import decode_profile, profile_loader
from gn2 import validate_genesis
from gn2_selection import entry_selection

NOTICE = 'UNFUNDED_STRUCTURAL_PROFILE_ONLY_NOT_ACTUAL_W_NEVER_FUND'


def structural_profile():
    canonical = profile_loader()
    vk = bytes(range(256)) + bytes(range(72))
    child = b'UNFUNDED_STRUCTURAL_PROFILE_ONLY' + vk + bytes(328) + b'END'
    image, h = bytes.fromhex('11' * 32), digest(NOTICE.encode())
    tail = (b'\x75\x20' + bytes.fromhex(canonical.WRAPPER) + b'\x75\x20'
        + bytes.fromhex(digest(child)) + b'\x75\x20' + image + b'\x75\x08KPX5WS01\x75\x51')
    executables = {name: {'basename': name, 'bytes': 1, 'sha256': h}
                   for name in canonical.EXECUTABLES}
    for name, (path, sha) in GENERIC.items():
        executables[name] = {'basename': name, 'bytes': path.stat().st_size, 'sha256': sha}
    return {'schema': canonical.SCHEMA, 'financial_profile_id': canonical.PROFILE_ID,
        'classification': canonical.CLASSIFICATION, 'network_id': canonical.NETWORK,
        'genesis_hash_hex': canonical.GENESIS, 'child_domain_hex32': canonical.DOMAIN,
        'wrapper_domain_hex32': canonical.WRAPPER,
        'compact': {'role': 'compact2', 'output_arity': 2, 'parameter_manifest_sha256': h,
            'vk_hex328': vk.hex(), 'vk_sha256': digest(vk), 'pk_sha256': h,
            'pk_bytes': 1, 'compiled_build_identity_sha256': h},
        'settlement': {'child_profile_sha256': h, 'child_template_tail_hex': child.hex(),
            'child_template_tail_sha256': digest(child), 'image_id_hex32': image.hex(),
            'program_sha256': h, 'child_count': 2, 'child_mode': 2, 'journal_bytes': 424,
            'payload_bytes': 8108, 'aggregate_budget': 1600},
        'W': {'immutable_tail_hex': tail.hex(), 'immutable_tail_sha256': digest(tail)},
        'private': {'budget': 1500, 'complete_input_bound_units': 14_957_286,
                    'bound_result_sha256': h}, 'executables': executables}


def run(args):
    output = outside(args.output)
    need(not output.exists(), 'fresh-isolated-worker-control-output')
    output.mkdir(parents=True, mode=0o700)
    owners = [parse(public_bytes(Path(p) / 'owner-init.json')) for p in (args.owner_A, args.owner_C)]
    trial = owners[0]['trial_id']
    need(owners[1]['trial_id'] == trial, 'same-selected-control-trial')
    raw = encoded(structural_profile()) + b'\n'
    pin = digest(raw)
    path = output / 'FAKE-STRUCTURAL-PROFILE-DO-NOT-FUND.json'
    write_new(path, raw, 0o400)
    profile, runtime = decode_profile(raw, pin), Runtime()
    sources = [{'outpoint': {'transactionId': digest(('NONEXISTENT_ISOLATED_SOURCE_' + str(i)).encode()), 'index': 0},
        'entry': {'amount': 3_000_000_000, 'scriptPublicKey': value['funding']['script_public_key'],
            'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}} for i, value in enumerate(owners)]
    case, quote = prepare_genesis(profile, trial, owners, sources, runtime, output / 'proposal', 100)
    approvals = []
    for i, owner in enumerate((args.owner_A, args.owner_C)):
        result = subprocess.run(['/usr/bin/python3', '-B', str(HERE / 'run_signer.py'), '--owner', str(owner),
            '--profile', str(path), '--profile-sha256', pin, '--case', str(output / 'proposal/proposed-case.json'),
            '--trial-id', trial, '--output', str(output / ('owner-' + str(i)))],
            capture_output=True, text=True, env=dict(CLEAN))
        need(result.returncode == 0, 'isolated-original-backup-worker-control-refused')
        approvals.append(parse(public_bytes(output / ('owner-' + str(i)) / 'client/run/APPROVAL.json')))
    signed, checked = combine(profile, trial, case, approvals, runtime, output / 'combined', 100)
    # A coordinator can coherently change ciphertext+its public hash without
    # changing the note/CM/state. Public consistency alone must not authorize
    # replacing the original owner's chosen recoverable receipt.
    changed = copy.deepcopy(case)
    payload = bytearray.fromhex(changed['transaction']['payload'])
    payload[288] ^= 1
    payload[552:584] = bytes.fromhex(digest(payload[288:552]))
    changed['transaction']['payload'] = payload.hex()
    changed, _ = runtime.normalize(changed, output / 'coherent-CF-substitution-normalized')
    validate_genesis(changed, entry_selection(profile), trial)
    changed_path = output / 'coherent-CF-substitution.json'
    write_new(changed_path, encoded(changed) + b'\n')
    rejected = subprocess.run(['/usr/bin/python3', '-B', str(HERE / 'run_signer.py'),
        '--owner', str(args.owner_A), '--profile', str(path), '--profile-sha256', pin,
        '--case', str(changed_path), '--trial-id', trial,
        '--output', str(output / 'coherent-CF-substitution-owner')],
        capture_output=True, text=True, env=dict(CLEAN))
    need(rejected.returncode != 0 and not (output / 'coherent-CF-substitution-owner/client/run/APPROVAL.json').exists(),
         'coherent-replacement-must-not-reach-an-owner-signature')
    result = {'schema': 'kpx6-isolated-one-backup-GN2-signers/v1', 'classification': NOTICE,
        'actual_W_private_proof_financial_profile_or_chain_backing': False,
        'two_own_original_compound_backup_namespaces': True,
        'each_own_initial_receipt_recovered_before_own_ALL_signature': True,
        'two_signature_only_exports_combined_and_Native_Full_all_engines_pass': True,
        'public_consistent_CF_substitution_refused_by_immutable_own_record_guard': True,
        'entry_fee_sompi': checked['metrics']['actual_fee_sompi'],
        'coordinator_original_backup_contents_or_funding_keys_read': False,
        'PK_or_proof_generation_worker_used': False, 'funding_or_broadcast_performed': False}
    write_new(output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-A', type=Path, required=True)
    parser.add_argument('--owner-C', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    print(encoded(run(parser.parse_args())).decode())
