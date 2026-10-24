#!/usr/bin/env python3
"""Bind the reviewed fresh public assets into one externally selected profile.

Public PK metadata is read; the PK itself and all owner backups are not read.
No proof, native VM, signing, network request or funding is performed. Callers
must independently review the exact new W source bound before final selection.
"""
from pathlib import Path
import argparse
import hashlib
import json

import selection

HERE = Path(__file__).resolve().parent
GENERIC = {
    'native-validator': (Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator'),
        '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'),
    'node': (Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'),
        'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'),
    'crypto': (Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto'),
        '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'),
}


def need(value, code):
    if not value:
        raise ValueError(code)


def checked_path(path):
    path = Path(path)
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-public-asset-path')
    return path


def sha(path):
    with checked_path(path).open('rb') as file:
        return hashlib.file_digest(file, 'sha256').hexdigest()


def document(path, expected):
    path = checked_path(path)
    raw = path.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == expected, 'selected-public-document-digest')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=selection.unique)


def executable(path, expected, basename):
    path = checked_path(path)
    need(path.is_file() and sha(path) == expected, 'selected-public-executable-digest')
    return {'basename': basename, 'bytes': path.stat().st_size, 'sha256': expected}


def finish(args):
    output, report = checked_path(args.output), checked_path(args.report)
    need(not output.exists() and output.parent.is_dir()
         and not report.exists() and report.parent.is_dir(), 'fresh-public-selection-output')
    compact = document(args.manifest, args.manifest_sha256)
    child_raw = (HERE / 'proof/child-profile.json').read_bytes()
    child = json.loads(child_raw, object_pairs_hook=selection.unique)
    outer = json.loads((HERE / 'proof/outer-selection.json').read_bytes(),
                       object_pairs_hook=selection.unique)
    emission = document(args.emission, args.emission_sha256)
    bound = document(args.bound, args.bound_sha256)
    for key, expected in (('trial_id', selection.PROFILE_ID), ('domain_hex32', selection.DOMAIN),
        ('network_id', selection.NETWORK), ('genesis_hash_hex', selection.GENESIS),
        ('role', 'compact2'), ('output_arity', 2)):
        need(compact[key] == expected, 'selected-compact-instance')
    need(child['selected'] is True and outer['selected'] is True
         and child['classification'] == outer['classification'] == selection.CLASSIFICATION
         and child['trial_id'] == outer['financial_profile_id'] == selection.PROFILE_ID
         and child['child_domain_hex32'] == selection.DOMAIN
         and child['wrapper_domain_hex32'] == selection.WRAPPER
         and child['child_vk_hex328'] == compact['vk_hex328']
         and child['child_vk_sha256'] == compact['vk_sha256']
         and child['child_parameter_manifest_sha256'] == args.manifest_sha256
         and child['unused_wide_virtual_key_policy'] == 'UNSELECTED_WIDE_VIRTUAL_ONLY'
         and child['owner_witness_or_funding_authority'] is False
         and outer['funding_or_chain_currentness_authority'] is False, 'selected-child-and-outer')
    need(emission['template_kind'] == 'ACTUAL_R0_W'
         and emission['outer_image_hex32'] == outer['image_id_hex32']
         and emission['child_vk_sha256'] == compact['vk_sha256']
         and emission['child_profile_source_sha256'] == hashlib.sha256(child_raw).hexdigest(),
         'actual-W-emission-binding')
    program = bytes.fromhex(emission['redeem_hex'])
    need(program[:2] == b'\x4c\x70' and program[10:42].hex() == selection.DOMAIN
         and len(program) == emission['redeem_bytes']
         and hashlib.sha256(program).hexdigest() == emission['redeem_sha256'], 'actual-W-bytes')
    tail = program[114:]
    need(bound['program_sha256'] == emission['redeem_sha256']
         and bound['program_bytes'] == len(program)
         and bound['immutable_tail_after_state112_sha256'] == hashlib.sha256(tail).hexdigest()
         and bound['budget_candidate'] == 1500 and bound['source_bound_fits_candidate'] is True
         and bound['complete_input_script_units_upper_bound'] <= 15_009_999,
         'new-exact-W-reviewed-bound')
    execs = {role: executable(path, expected, role) for role, (path, expected) in GENERIC.items()}
    execs['prover'] = executable(args.prover, args.prover_sha256, 'prover')
    execs['w-codec'] = executable(args.codec, args.codec_sha256, 'w-codec')
    profile = {'schema': selection.SCHEMA, 'financial_profile_id': selection.PROFILE_ID,
        'classification': selection.CLASSIFICATION, 'network_id': selection.NETWORK,
        'genesis_hash_hex': selection.GENESIS, 'child_domain_hex32': selection.DOMAIN,
        'wrapper_domain_hex32': selection.WRAPPER,
        'compact': {'role': 'compact2', 'output_arity': 2,
            'parameter_manifest_sha256': args.manifest_sha256,
            'vk_hex328': compact['vk_hex328'], 'vk_sha256': compact['vk_sha256'],
            'pk_sha256': compact['pk_sha256'], 'pk_bytes': compact['pk_bytes'],
            'compiled_build_identity_sha256': compact['compiled_build_identity_sha256']},
        'settlement': {'child_profile_sha256': hashlib.sha256(child_raw).hexdigest(),
            'child_template_tail_hex': child['child_template_tail_hex'],
            'child_template_tail_sha256': hashlib.sha256(bytes.fromhex(child['child_template_tail_hex'])).hexdigest(),
            'image_id_hex32': outer['image_id_hex32'], 'program_sha256': outer['program_sha256'],
            'child_count': 2, 'child_mode': 2, 'journal_bytes': 424,
            'payload_bytes': 8108, 'aggregate_budget': 1600},
        'W': {'immutable_tail_hex': tail.hex(), 'immutable_tail_sha256': hashlib.sha256(tail).hexdigest()},
        'private': {'budget': 1500,
            'complete_input_bound_units': bound['complete_input_script_units_upper_bound'],
            'bound_result_sha256': args.bound_sha256}, 'executables': execs}
    raw = json.dumps(profile, sort_keys=True, separators=(',', ':')).encode() + b'\n'
    pin = hashlib.sha256(raw).hexdigest()
    selection.load(raw, pin)
    with output.open('xb') as file:
        file.write(raw)
    result = {'schema': 'kpx6-financial-final-public-selection/v1',
        'financial_profile_id': selection.PROFILE_ID, 'financial_profile_sha256': pin,
        'child_profile_sha256': hashlib.sha256(child_raw).hexdigest(),
        'parameter_manifest_sha256': args.manifest_sha256, 'bound_result_sha256': args.bound_sha256,
        'guest_image_id_hex32': outer['image_id_hex32'], 'W_immutable_tail_sha256': profile['W']['immutable_tail_sha256'],
        'structural_immutable_profile_loader_passed': True,
        'new_financial_PK_bytes_owner_seed_native_VM_or_proof_network_or_funding_used': False,
        'source_review_budget_review_and_complete_local_rehearsal_remain_external_required_gates': True}
    with report.open('x') as file:
        json.dump(result, file, sort_keys=True, indent=2)
        file.write('\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'emission', 'bound', 'prover', 'codec', 'output', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('manifest-sha256', 'emission-sha256', 'bound-sha256', 'prover-sha256', 'codec-sha256'):
        parser.add_argument('--' + name, required=True)
    print(json.dumps(finish(parser.parse_args()), sort_keys=True))
