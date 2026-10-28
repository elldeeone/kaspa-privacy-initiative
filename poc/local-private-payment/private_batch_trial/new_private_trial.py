#!/usr/bin/env python3
"""One command creates three isolated new-profile Originals and genuine Outputs.

No controller read/hash of private seeds, notes, plans, logs or witnesses.
The command is unfunded and network-off; full financial/R0/native settlement
and independently frozen observer/truth boundaries remain separate work.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import time
import uuid

import output_producer
import private_worker
import wallet_profile as wallet

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/private-batch-20261028')
PUBLIC = Path('/var/tmp/kpi-private-batch-bootstrap-20261028')
PROFILE = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/PROFILE-DESCRIPTOR.json'
PROFILE_SHA = 'd07d66d7668b94df7a003ed7cd289f2805f46a96206824e8af4279b632d76546'
BINARY = ROOT / '.local/private-batch-auth-exit-execution/admission-01/auth-exit'
BINARY_SHA = '930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6'
PARAMETERS = ROOT / '.local/private-batch-component-parameters/output-01'
MANIFEST_SHA = '1e24b8d3e22692b7445822d533b28f8ab7a09ddc4050c6e785941717e3e6fc82'
NODE = Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
CRYPTO = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
JS_ROOT = Path('/var/tmp/kpi-signature-predicate-tools-20261026-01')
LEAF_MAP = Path('/run/user/1000/kpi-nativeauthspend-resume-20261028-03/JS-INSTALLED-LEAF-MAP.json')
LEAF_MAP_SHA = '00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


def need(value, category):
    if not value:
        raise ValueError(category)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(path):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical-nonsymlink-path')
    return path


def save(path, value, mode=0o400):
    raw = value if type(value) is bytes else private_worker.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return digest(raw)


def original_metadata(path):
    # Never open, hash, copy or decode an Original in the controller.
    path = checked(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
         'one-original-readonly-leaf-metadata')


def run_owner(slot, operation, trial_private, trial_public, shared, config, read):
    own = trial_private / (('owner-' if operation == 'init' else 'restore-') + str(slot))
    own.mkdir(mode=0o700)
    public = trial_public / (('init-' if operation == 'init' else 'restore-') + str(slot))
    public.mkdir(mode=0o700)
    selected = dict(config)
    additions = []
    if operation == 'restore-probe':
        original = trial_private / ('owner-' + str(slot)) / 'BACKUP.json'
        original_metadata(original)
        initial = trial_public / ('init-' + str(slot)) / 'PUBLIC.json'
        selected['initial_public_sha256'] = digest(read(initial))
        additions = ['--ro-bind', str(original), '/original/BACKUP.json',
                     '--ro-bind', str(initial), '/initial/PUBLIC.json']
    config_path = shared / (operation + '-' + str(slot) + '-CONFIG.json')
    save(config_path, selected)
    marker = shared / (operation + '-' + str(slot) + '-NAMESPACE.json')
    save(marker, {'schema': 'kpb-one-owner-namespace/v1', 'network': 'disabled',
                  'operation': operation, 'owner_slots': 1})
    mounts = []
    for row in config['source_members']:
        mounts += ['--ro-bind', str(shared / ('source-' + str(row['index']))), row['path']]
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        *mounts, '--ro-bind', str(NODE), '/runtime/node', '--ro-bind', str(CRYPTO), '/runtime/crypto',
        '--ro-bind', str(BINARY), '/runtime/prover',
        '--ro-bind', str(JS_ROOT / 'node_modules'), '/runtime/js/node_modules',
        '--ro-bind', str(LEAF_MAP), '/runtime/JS-INSTALLED-LEAF-MAP.json',
        '--ro-bind', str(PARAMETERS / 'MANIFEST.json'), '/parameters/MANIFEST.json',
        '--ro-bind', str(PARAMETERS / 'parameters.pk'), '/parameters/parameters.pk',
        '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker), '/NAMESPACE.json',
        '--bind', str(own), '/owner', '--bind', str(public), '/out', *additions,
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', str(HERE / 'private_worker.py'), operation]
    # The controller sends file descriptors directly to excluded private logs;
    # it never captures, opens for reading, hashes or interprets their bodies.
    with (own / 'WORKER-STDOUT.log').open('xb') as stdout, (own / 'WORKER-STDERR.log').open('xb') as stderr:
        process = subprocess.run(command, env=CLEAN, stdout=stdout, stderr=stderr)
    need(process.returncode == 0, 'isolated-one-owner-' + operation + '-refused')
    value = private_worker.parse(read(public / 'PUBLIC.json'))
    if operation == 'init':
        need(set(value) == {'schema', 'domain_hex32', 'profile_id_hex32', 'output_hex520', 'admission_sompi',
             'funding_spk_hex36', 'original_backup_schema', 'kdf_tag_ascii8', 'public_known_seed_used',
             'funding_or_native_acceptance'}, 'exact-new-owner-public-export')
        need(value['schema'] == 'kpb-fresh-owner-initial-public/v1' and type(value['admission_sompi']) is int
             and value['admission_sompi'] == 2_000_000_000 and value['public_known_seed_used'] is False
             and value['funding_or_native_acceptance'] is False
             and value['domain_hex32'] == config['domain_hex32'] and value['profile_id_hex32'] == config['profile_id_hex32']
             and value['original_backup_schema'] == private_worker.BACKUP_SCHEMA
             and value['kdf_tag_ascii8'] == private_worker.KDF_TAG, 'new-profile20KAS-public-export')
        original_metadata(own / 'BACKUP.json')
    else:
        need(value['schema'] == 'kpb-new-original-recovery-public/v1' and value['seed_only'] is True
             and value['new_profile_and_backup_version_checked'] is True
             and value['actual_output_proof_verified'] is True
             and value['encrypted_note_and_AK_bound_descriptor_recovered'] is True
             and value['private_maps_imported'] is False and value['private_values_or_seed_exported'] is False
             and value['legacy_backup_reinterpretation'] is False, 'new-original-only-recovery-public-export')
    return value


def run(args):
    started = time.monotonic()
    need(re.fullmatch('[a-z][a-z0-9-]{0,63}', args.label), 'canonical-fresh-label')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    profile = private_worker.parse(read(PROFILE, PROFILE_SHA))
    descriptor = profile['profile_descriptor']
    need(profile['status'] == 'UNFUNDED_COMPONENT_IDENTITY_NO_FINANCIAL_READINESS'
         and digest(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode()) == profile['profile_id_hex32']
         and descriptor['wallet_kdf_tag'] == private_worker.KDF_TAG and descriptor['owner_binding_tag'] == 'KPBPOW01'
         and descriptor['network'] == 'kaspa-testnet-10', 'selected-new-AK-bound-research-profile')
    selected_profile = wallet.Profile(bytes.fromhex(descriptor['domain_hex32']), bytes.fromhex(profile['profile_id_hex32']))
    verifier = output_producer.OutputProver(selected_profile, BINARY, BINARY_SHA,
        PARAMETERS / 'MANIFEST.json', MANIFEST_SHA, PARAMETERS / 'parameters.pk', read_public=read)
    read(NODE, wallet.NODE_SHA256); read(CRYPTO, wallet.CRYPTO_SHA256)
    wallet.authenticate_js(LEAF_MAP, LEAF_MAP_SHA, JS_ROOT)
    private = checked(PRIVATE / args.label); public = checked(PUBLIC / args.label)
    need(not private.exists() and not public.exists(), 'fresh-unused-private-batch-trial-label')
    private.mkdir(parents=True, mode=0o700); public.mkdir(parents=True, mode=0o700)
    shared = public / 'selected-public'; shared.mkdir(mode=0o700)
    paths = [HERE / name for name in ('private_worker.py', 'new_private_trial.py', 'wallet_profile.py',
                                      'output_producer.py', 'owner_authority.mjs')]
    paths += [HERE.parents[1] / 'future-recipient/v2/recipient.py']
    sources = []
    for index, path in enumerate(paths):
        raw = read(path)
        save(shared / ('source-' + str(index)), raw)
        sources.append({'index': index, 'path': str(path), 'sha256': digest(raw), 'bytes': len(raw)})
    config = {'domain_hex32': selected_profile.domain.hex(), 'profile_id_hex32': selected_profile.profile_id.hex(),
        'binary_sha256': BINARY_SHA, 'manifest_sha256': MANIFEST_SHA, 'js_leaf_map_sha256': LEAF_MAP_SHA,
        'source_members': sources}
    trial_id = str(uuid.uuid4())
    selection = {'schema': 'kpb-new-private-original-bootstrap-selection/v1', 'label': args.label, 'trial_id': trial_id,
        'network_id': 'testnet-10', 'profile_sha256': PROFILE_SHA, **config,
        'original_backup_schema': private_worker.BACKUP_SCHEMA, 'kdf_tag_ascii8': private_worker.KDF_TAG,
        'selected_node_sha256': wallet.NODE_SHA256, 'selected_crypto_sha256': wallet.CRYPTO_SHA256,
        'immutable_owner_source_copies': True, 'outer_one_owner_network_off_namespaces': True,
        'fresh_private_seeds_generated_inside_owner_namespaces': True,
        'financial_profile_or_privacy_trial_selected': False, 'broadcast_operation_available': False}
    save(public / 'SELECTION.json', selection)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        initial = list(pool.map(lambda slot: run_owner(slot, 'init', private, public, shared, config, read), range(3)))
    rows = [bytes.fromhex(value['output_hex520']) for value in initial]
    need(len({row[:32] for row in rows}) == 3 and len({value['funding_spk_hex36'] for value in initial}) == 3,
         'three-distinct-new-owner-admissions')
    need(all(verifier.verify(row) for row in rows), 'independent-no-PK-mount-public-Output-verification')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(lambda slot: run_owner(slot, 'restore-probe', private, public, shared, config, read), range(3)))
    result = {'schema': 'kpb-fresh-unfunded-private-original-trial/v1', 'trial_id': trial_id, 'label': args.label,
        'network_id': 'testnet-10', 'domain_hex32': selected_profile.domain.hex(),
        'profile_id_hex32': selected_profile.profile_id.hex(), 'original_backup_schema': private_worker.BACKUP_SCHEMA,
        'owner_count': 3, 'genuine_initial_Output_proofs': 3, 'one_Original_only_recovery_probes': 3,
        'independent_public_Output_verification_without_PK_mount': True,
        'initial_public_files': [str(public / ('init-' + str(slot)) / 'PUBLIC.json') for slot in range(3)],
        'recovery_public_files': [str(public / ('restore-' + str(slot)) / 'PUBLIC.json') for slot in range(3)],
        'private_original_parent': str(private), 'controller_read_or_hashed_private_bodies': False,
        'setup_mining_funding_broadcast_or_accepted_backing': False, 'privacy_qualification': False,
        'testnet_readiness': False, 'wall_seconds': time.monotonic() - started}
    save(public / 'TRIAL.json', result)
    return {'status': 'FRESH_PRIVATE_ORIGINALS_AND_GENUINE_OUTPUTS_COMPLETED', 'trial': str(public / 'TRIAL.json'),
            'trial_sha256': digest(private_worker.encoded(result)), 'owner_count': 3,
            'genuine_initial_Output_proofs': 3, 'original_only_recovery_probes': 3}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
    except BaseException as error:
        # No private exception/log body enters the controller response.
        print(json.dumps({'status': 'UNFUNDED_BOOTSTRAP_INCOMPLETE', 'category': type(error).__name__}), flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
