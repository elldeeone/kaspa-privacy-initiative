#!/usr/bin/env python3
"""Stage a finite public Testnet namespace; direct execution is disabled.

Node/SDK/native binaries are reused read-only, never copied per worker. Only
public certificates are mounted. No Original, financial witness, signing key,
PK, host home or TLS private-key directory is visible in this namespace.

Network execution must eventually be spawned by the selected parent while it
consumes live BatchPrivacyPass and PreNetworkSafety authorities.  A CLI flag,
saved preflight receipt, or staged command is not that authority.
"""
import argparse
import json
import os
from pathlib import Path
import runpy
import stat

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
WHEEL_MANIFEST = ROOT / '.local/private-batch-ingress-wheel-admission-01/MANIFEST.json'
WHEEL_MANIFEST_SHA = '2cbee37b19b469526e5750b2b2a32817fb9ec53b7328f2bad68b3023ccf3c4fc'
need, checked, save = bootstrap.need, bootstrap.checked, bootstrap.save
parse = private_worker.parse


def metadata(path, size=None, executable=False):
    path = checked(path); info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid(), 'public-network-owned-leaf')
    need(size is None or info.st_size == size, 'public-network-derived-leaf-size')
    if executable: need(stat.S_IMODE(info.st_mode) == 0o500, 'public-network-selected-executable-mode')
    return path


def sources():
    return [HERE / name for name in ('funding_network.py', 'funding_network.mjs', 'funding_network_activation.mjs', 'funding_network_common.mjs',
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
    # Refuse before reading the root guard, identity, filesystem state, or
    # constructing any network command.  The future parent-owned activation
    # seam must live outside this public/stageable CLI and carry a live,
    # one-shot capability; serialized evidence cannot enable this function.
    if args.execute:
        need(False, 'parent-live-activation-authority-required')
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
    # This is deliberately not a prepared launch.  In particular it contains
    # no argv, mounts, copied child inputs, registry, journal, controller path,
    # RPC selection, or serialized capability.  The future selected parent
    # must build the namespace in memory while consuming both live authorities.
    receipt = {'schema': 'kpb-public-network-source-only/v1', 'operation': args.operation,
        'trial_id': identity['trial_id'], 'identity_sha256': args.identity_sha256,
        'status': 'CONFIGURED0', 'network_invoked': False,
        'network_activation_configured': False,
        'executable_network_plan_persisted': False, 'child_job_persisted': False,
        'controller_registry_or_journal_created': False,
        'serialized_evidence_is_activation_authority': False,
        'required_live_authorities': ['BatchPrivacyPassAuthority', 'PreNetworkSafetyAuthority'],
        'automatic_resubmission_permitted': False}
    save(output / 'LAUNCH.json', receipt)
    return {'status': 'SOURCE_ONLY_NETWORK_DISABLED', 'output': str(output),
            'network_invoked': False, 'network_activation_configured': False}


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
