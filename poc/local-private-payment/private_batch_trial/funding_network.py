#!/usr/bin/env python3
"""Finite public network namespace. Default stages; --execute activates RPC.

Node/SDK/native binaries are reused read-only, never copied per worker. Only
public certificates are mounted. No Original, financial witness, signing key,
PK, host home or TLS private-key directory is visible in this namespace.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import uuid

import genesis
import new_private_trial as bootstrap
import private_worker

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
BASE = HERE.parent
SDK = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
SDK_PINS = {'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'}
NATIVE = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
NATIVE_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
WHEEL_MANIFEST = ROOT / '.local/private-batch-ingress-wheel-admission-01/MANIFEST.json'
WHEEL_MANIFEST_SHA = '2cbee37b19b469526e5750b2b2a32817fb9ec53b7328f2bad68b3023ccf3c4fc'
REGISTRY = bootstrap.PRIVATE / 'network-registries'
need, checked, save = bootstrap.need, bootstrap.checked, bootstrap.save
parse, encoded = private_worker.parse, private_worker.encoded


def metadata(path, size=None, executable=False):
    path = checked(path); info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(), 'public-network-owned-leaf')
    need(size is None or info.st_size == size, 'public-network-derived-leaf-size')
    if executable: need(stat.S_IMODE(info.st_mode) == 0o500, 'public-network-selected-executable-mode')
    return path


def sources():
    return [HERE / name for name in ('funding_network.py', 'funding_network.mjs', 'funding_network_common.mjs',
        'funding_network_miner.mjs', 'funding_network_gate.py', 'funding_network_bridge.mjs', 'funding_network_rpc.mjs', 'genesis.py', 'output_verifier.py',
        'new_private_trial.py', 'private_worker.py', 'wallet_profile.py', 'output_producer.py',
        'wallet_history.py', 'exit_wire.py')] + [
        BASE / 'bootstrap/mining_jobs.mjs', BASE / 'chain/acquire.mjs',
        BASE / 'chain/wire.mjs', BASE / 'chain/public.mjs', BASE / 'chain/selection.mjs', BASE / 'chain/json.mjs',
        BASE / 'ingress/bridge.py', BASE / 'ingress/tor_ingress.py',
        BASE / 'integration/trees.py', BASE / 'verification/wire.py',
        HERE.parents[1] / 'future-recipient/v2/recipient.py']


def admitted_wheels(read):
    """Exactly two qualified readonly zipimports; no installed tree or cache."""
    manifest = parse(read(WHEEL_MANIFEST, WHEEL_MANIFEST_SHA))
    need(manifest['schema'] == 'kpb-public-ingress-wheel-admission/v1'
         and manifest['installed_python_dependency_tree_admitted'] is False
         and manifest['copies_or_installation_created'] is False
         and len(manifest['archives']) == 2, 'exact-existing-wheel-admission')
    rows = manifest['archives']
    need(manifest['runtime_pythonpath'] == ':'.join(row['mount'] for row in rows), 'exact-wheel-zipimport-PYTHONPATH')
    for row in rows:
        raw = read(checked(row['path']), row['sha256'])
        need(len(raw) == row['bytes'] and row['mount'].startswith('/deps/') and row['mount'].endswith('.whl'),
             'qualified-public-wheel-leaf')
    return manifest, rows


def validate_identity(value):
    genesis.trial_uuid(value['trial_id'])
    need(value['schema'] == 'kpb-three-owner-funding-identity/v1' and value['network_id'] == 'testnet-10'
         and value['financial_readiness'] is False, 'new-public-funding-identity-only')
    need(tuple(bytes.fromhex(value[name]) for name in ('genesis_hash_hex', 'pool_lineage_hex32', 'profile_id_hex32',
        'domain_hex32', 'service_policy_hex32')) == genesis.EXPECTED_IDENTITY, 'exact-new-funding-five-identities')
    return value


def run(args):
    guard = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    read = guard['read']
    raw_identity = read(checked(args.identity), args.identity_sha256)
    identity = validate_identity(parse(raw_identity))
    if args.operation in ('submit-consolidation', 'reconcile-ordinary'):
        need(args.case_mode == 'consolidation' and args.owner_component in (0, 1, 2), 'exact-own-consolidation-network-mode')
    if args.operation == 'submit-genesis':
        need(args.case_mode == 'genesis' and args.owner_component is None, 'exact-three-owner-GEN3-network-mode')
    if args.operation == 'confirm':
        need((args.case_mode == 'genesis' and args.owner_component is None)
             or (args.case_mode == 'consolidation' and args.owner_component in (0, 1, 2)), 'exact-confirmed-CASE-mode')
    output = checked(args.output)
    need(not output.exists() and not output.is_relative_to(bootstrap.PRIVATE), 'fresh-public-network-result')
    output.mkdir(parents=True, mode=0o700)
    operation_id = str(uuid.uuid4())
    private = checked(bootstrap.PRIVATE / 'network-controllers' / operation_id)
    private.mkdir(parents=True, mode=0o700)
    shared = output / 'selected-public'; shared.mkdir(mode=0o700)
    mounts, selected = [], []
    for index, path in enumerate(sources()):
        raw = read(path); target = shared / ('source-' + str(index)); save(target, raw)
        mounts += ['--ro-bind', str(target), str(path)]
        selected.append({'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)})
    wheel_manifest, wheels = admitted_wheels(read)
    for row in wheels:
        mounts += ['--ro-bind', row['path'], row['mount']]
        selected.append({'path': row['mount'], 'sha256': row['sha256'], 'bytes': row['bytes']})
    read(bootstrap.NODE, bootstrap.wallet.NODE_SHA256); metadata(bootstrap.NODE, executable=True)
    mounts += ['--ro-bind', str(bootstrap.NODE), '/node']
    for name, pin in SDK_PINS.items():
        read(SDK / name, pin); mounts += ['--ro-bind', str(SDK / name), '/sdk/' + name]
    selected_identity = shared / 'IDENTITY.json'; save(selected_identity, raw_identity)
    job = {'schema': 'kpb-public-network-job/v1', 'operation': args.operation, 'operation_id': operation_id,
        'identity_sha256': args.identity_sha256, 'rpc_index': args.rpc_index,
        'source_members': selected, 'owner_component': args.owner_component, 'case_mode': args.case_mode,
        'fee_rate_sompi_per_mass': args.fee_rate_sompi_per_mass}
    if args.operation not in ('anchor', 'collect', 'mine', 'plan-mining'):
        need(args.case and args.case_sha256, 'exact-public-whole-CASE-required')
        target = shared / 'CASE.json'; save(target, read(checked(args.case), args.case_sha256))
        mounts += ['--ro-bind', str(target), '/inputs/CASE.json']
        job['case_sha256'] = args.case_sha256
        read(NATIVE, NATIVE_SHA); metadata(NATIVE, executable=True)
        mounts += ['--ro-bind', str(NATIVE), '/runtime/native-validator']
        if args.case_mode == 'genesis':
            need(args.component_profile and args.tail, 'real-new-GEN3-component-and-tail-required')
            component, tail = shared / 'PROFILE.json', shared / 'IMMUTABLE-TAIL.bin'
            save(component, read(checked(args.component_profile), identity['component_profile_sha256']))
            save(tail, read(checked(args.tail), identity['native_tail_sha256']))
            read(bootstrap.BINARY, bootstrap.BINARY_SHA); metadata(bootstrap.BINARY, executable=True)
            manifest = shared / 'OUTPUT-MANIFEST.json'
            save(manifest, read(bootstrap.PARAMETERS / 'MANIFEST.json', bootstrap.MANIFEST_SHA))
            mounts += ['--ro-bind', str(component), '/component/PROFILE.json', '--ro-bind', str(tail), '/component/IMMUTABLE-TAIL.bin',
                '--ro-bind', str(manifest), '/parameters/OUTPUT-MANIFEST.json', '--ro-bind', str(bootstrap.BINARY), '/runtime/prover']
    if args.operation == 'confirm':
        need(args.anchor and args.anchor_sha256, 'actual-new-birth-anchor-required')
        target = shared / 'ANCHOR.json'; save(target, read(checked(args.anchor), args.anchor_sha256))
        mounts += ['--ro-bind', str(target), '/inputs/ANCHOR.json']; job['anchor_sha256'] = args.anchor_sha256
    marker = shared / 'NAMESPACE.json'
    save(marker, {'schema': 'kpb-public-network-namespace/v1', 'operation': args.operation,
        'network_id': 'testnet-10', 'trial_id': identity['trial_id']})
    job_path = shared / 'NETWORK-JOB.json'; save(job_path, job)
    REGISTRY.mkdir(parents=True, exist_ok=True, mode=0o700)
    checked(REGISTRY)
    registry_parent = os.open(REGISTRY.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(registry_parent)
    finally: os.close(registry_parent)
    journal = private / 'block-journal'; journal.mkdir(mode=0o700)
    node_args = [str(HERE / 'funding_network.mjs'), args.operation]
    if args.operation in ('mine', 'plan-mining'):
        need(args.owner_component in (0, 1, 2), 'one-new-public-mining-owner')
        node_args = [str(HERE / 'funding_network_miner.mjs'), '--mode', 'mine' if args.operation == 'mine' else 'plan',
            '--role', str(args.owner_component), '--rpc-index', str(args.rpc_index), '--wallet-sha256', args.identity_sha256,
            '--workers', str(args.workers), '--target-sompi', str(args.target_sompi)]
        if args.operation == 'mine': node_args.append('--execute')
    command = ['/usr/bin/bwrap', '--unshare-all', '--share-net', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc/ssl/certs', '/etc/ssl/certs', '--ro-bind', '/etc/resolv.conf', '/etc/resolv.conf',
        '--ro-bind', '/etc/hosts', '/etc/hosts', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(selected_identity), '/IDENTITY.json', '--ro-bind', str(selected_identity), '/wallet.json',
        '--ro-bind', str(marker), '/NAMESPACE.json', '--ro-bind', str(job_path), '/NETWORK-JOB.json',
        '--bind', str(REGISTRY), '/registry', '--bind', str(journal), '/journal', '--bind', str(output), '/out',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/node', '--use-openssl-ca', *node_args]
    private_worker.write(private / 'PRIVATE-PLAN.json', {'command': command, 'publish_or_hash': False})
    receipt = {'schema': 'kpb-public-network-launch/v1', 'operation_id': operation_id, 'operation': args.operation,
        'trial_id': identity['trial_id'], 'identity_sha256': args.identity_sha256, 'executed': False,
        'network_invoked': False, 'node_or_SDK_copied': False, 'Node_pin': bootstrap.wallet.NODE_SHA256,
        'SDK_pins': SDK_PINS, 'ingress_wheel_manifest_sha256': WHEEL_MANIFEST_SHA, 'python_source_archives': wheels, 'source_members': selected,
        'Original_key_PK_or_TLS_private_directory_mounted': False, 'automatic_resubmission_permitted': False}
    if args.execute:
        with (private / 'PRIVATE-STDOUT.log').open('xb') as stdout, (private / 'PRIVATE-STDERR.log').open('xb') as stderr:
            result = subprocess.run(command, env=bootstrap.CLEAN, stdout=stdout, stderr=stderr)
        receipt.update(executed=True, network_invoked=True, returncode=result.returncode)
        save(output / 'LAUNCH.json', receipt)
        need(result.returncode == 0, 'public-network-incomplete-query-only-no-resend')
    else:
        save(output / 'LAUNCH.json', receipt)
    return {'status': 'PUBLIC_NETWORK_EXECUTED' if args.execute else 'SOURCE_STAGED_NO_RPC',
            'output': str(output), 'operation_id': operation_id, 'network_invoked': args.execute}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('anchor', 'collect', 'mine', 'plan-mining', 'submit-consolidation', 'reconcile-ordinary', 'submit-genesis', 'confirm'))
    for name in ('identity', 'identity-sha256', 'output'): parser.add_argument('--' + name, required=True)
    for name in ('case', 'case-sha256', 'component-profile', 'tail', 'anchor', 'anchor-sha256'): parser.add_argument('--' + name)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2))
    parser.add_argument('--case-mode', choices=('consolidation', 'genesis'), default='genesis')
    parser.add_argument('--rpc-index', type=int, choices=(0, 1), default=0)
    parser.add_argument('--fee-rate-sompi-per-mass', type=int, default=100)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--target-sompi', type=int, default=3_100_000_000)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.operation in ('submit-consolidation', 'reconcile-ordinary'): args.case_mode = 'consolidation'
    try: print(json.dumps(run(args), sort_keys=True))
    except BaseException:
        raise SystemExit('new public network stage incomplete; retain identity and reconcile read-only')


if __name__ == '__main__': main()
