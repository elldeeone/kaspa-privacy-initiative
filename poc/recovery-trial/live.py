#!/usr/bin/env python3
"""Prepare an old-KPX2 service-loss trial; no RPC or broadcast interface.

The six-body local rehearsal establishes terminal feasibility only. An operator
may publish its four-body prefix, then separate one-backup clients must discover
the live head and construct new exits. The local exits are never client inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'poc/independent-recovery'), str(ROOT / 'poc/future-testnet')]
import orchestrate
import replay
import trial as identities

PAYMENT = 60_000_000
PREFIX = ('fundingprep', 'founding', 'admit', 'private')


def require(condition, category):
    if not condition:
        raise ValueError(category)


def load(path):
    return json.loads(Path(path).read_bytes())


def node_preflight():
    """Systemd's default PATH lacks the host's Node wrapper; fail before seeds."""
    node = shutil.which('node')
    require(node is not None, 'node-missing-from-service-path')
    result = subprocess.run([node, '--version'], capture_output=True, text=True)
    require(result.returncode == 0 and result.stdout.startswith('v'), 'node-runtime-preflight')
    return node


def checked_source(identity, source):
    """Accept only the NEW identity's funding key, never an old key path."""
    require(type(source) is dict and source.get('source_key') == 'TRIAL_FUNDING_KEY',
            'new-trial-funding-key-required')
    require(source.get('oracle_stage') in
            ('LOCAL_SUPPLIED_CONTEXT', 'TRUSTED_TN10_ACCEPTED_NODE'), 'source-acceptance-boundary')
    replay.hx(source.get('transaction_id'), 32)
    require(type(source.get('index')) is int and 0 <= source['index'] <= 0xffffffff,
            'source-output-index')
    # The old orchestrator consumes integer sompi; reject strings/bools here.
    require(type(source.get('amount_sompi')) is int
            and 0 < source['amount_sompi'] <= replay.MAX, 'source-integer-sompi')
    require(source.get('spk_version') == 0 and type(source.get('spk_version')) is int
            and source.get('spk_hex') == identity['identities']['funding']['spk_hex'],
            'source-fresh-funding-destination')
    require(identity['network_id'] == 'testnet-10'
            and identity['genesis_hash_hex'] == replay.GENESIS, 'source-testnet-only')
    return source


def build_descriptor(identity, founding, admit, vk, birth_start_hash):
    """Derive the exact nine public fields without loading any operator secret."""
    require(identity['network_id'] == 'testnet-10'
            and identity['genesis_hash_hex'] == replay.GENESIS, 'descriptor-testnet-only')
    replay.hx(identity['domain_hex32'], 32)
    replay.hx(birth_start_hash, 32)
    require(type(vk) is bytes and len(vk) == 328, 'descriptor-vk-width')
    replay.hx(founding['id'], 32)
    require(admit['inputs'][0]['previousOutpoint'] ==
            {'transactionId': founding['id'], 'index': 0}, 'descriptor-founding-link')
    _, _, initial = replay.pool_witness(admit)
    descriptor = {'schema': 'kpx2-recovery-descriptor/v1', 'network_id': 'testnet-10',
        'genesis_hash_hex': replay.GENESIS, 'domain_hex32': identity['domain_hex32'],
        'founding_outpoint': {'transactionId': founding['id'], 'index': 0},
        'birth_start_hash': birth_start_hash, 'initial_redeem_hex': initial.hex(),
        'vk_hex328': vk.hex(),
        'immutable_policy_sha256': hashlib.sha256(initial[114:]).hexdigest()}
    replay.descriptor_check(descriptor)
    note, _, cipher, reserve = replay.public_note(replay.hx(founding['payload'], 536),
                                                replay.hx(identity['domain_hex32'], 32), b'KPX2GN01')
    require(initial[2:114] == replay.State(bytes.fromhex(identity['domain_hex32']), note, cipher).encoded(),
            'descriptor-founding-genesis-state')
    require(replay.integer(founding['outputs'][0]['value']) == reserve,
            'descriptor-founding-reserve')
    require(founding['outputs'][0]['scriptPublicKey'] == replay.p2sh(initial),
            'descriptor-founding-script')
    return descriptor


def prefix_plan(ctx):
    """Return only the four local bodies eligible for operator publication."""
    complete = load(ctx.directory / 'LOCAL-COMPLETE.json')
    stopped = load(ctx.directory / 'prover-stopped.json')
    require(complete['trial_id'] == ctx.profile['trial_id']
            and complete['native_Full_operations'] == 6
            and complete['terminal_reserve_sompi'] == 0
            and complete['payment_value_sompi'] == PAYMENT, 'local-terminal-rehearsal')
    require(stopped['trial_id'] == ctx.profile['trial_id']
            and stopped['process_stopped'] is True
            and not orchestrate.server_alive(load(ctx.directory / 'prover-session.json')),
            'prover-must-be-stopped')
    archive = load(ctx.directory / 'local-archive.json')
    operations = archive['operations'][:4]
    require(tuple(row['kind'] for row in operations) == PREFIX, 'operator-prefix-order')
    for row in operations:
        require(orchestrate.sha(row['accepted_body_path']) == row['accepted_body_sha256']
                and orchestrate.sha(row['local_check_path']) == row['local_check_sha256'],
                'operator-prefix-body-changed')
    return {'schema': 'kpx2-unspent-recovery-prefix/v1', 'trial_id': ctx.profile['trial_id'],
        'domain_hex32': ctx.profile['domain_hex32'], 'payment_value_sompi': PAYMENT,
        'operations': operations, 'broadcast': False,
        'precomputed_exits_excluded_from_prefix_and_cold_client_inputs': True,
        'cold_clients_require_network_fetch_and_their_own_backup': True,
        'scope': 'TN10_R1_SELECTED_NODE_RETAINED_DATA_LIVENESS_ONLY'}


def rehearse(directory, source_path, cpus):
    directory = Path(directory).absolute()
    node_preflight()
    identities.outside_git(directory)
    # Refuse a used identity before Context can open any seed or funding key.
    require(not any((directory / name).exists() for name in
            ('prover-session.json', 'LOCAL-COMPLETE.json', 'chain-release.json', 'chain-public')),
            'fresh-session-required')
    # Guard the key selector before Context reads even this new trial's secrets.
    source = checked_source(load(directory / 'public/identity.json'), load(source_path))
    ctx = orchestrate.Context(directory)
    try:
        result = orchestrate.rehearse(ctx, source, PAYMENT, 4, cpus)
    finally:
        if (directory / 'prover-session.json').exists() and not (directory / 'prover-stopped.json').exists():
            orchestrate.stop_prover(ctx)
    plan = prefix_plan(ctx)
    identities.private_write(directory / 'recovery-prefix.json', identities.encoded(plan))
    return {'local_rehearsal': result, 'operator_prefix_plan': str(directory / 'recovery-prefix.json'),
            'operator_bodies': 4, 'cold_owner_exits_built': False, 'broadcast': False}


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    a = sub.add_parser('rehearse')
    a.add_argument('trial', type=Path)
    a.add_argument('--source', required=True, type=Path)
    a.add_argument('--cpus', type=int, default=14)
    a = sub.add_parser('descriptor')
    for name in ('identity', 'founding', 'admit', 'vk', 'output'):
        a.add_argument('--' + name, required=True, type=Path)
    a.add_argument('--birth-start-hash', required=True)
    args = p.parse_args()
    try:
        if args.command == 'rehearse':
            require(args.cpus > 0, 'positive-cpu-count')
            result = rehearse(args.trial, args.source, args.cpus)
        else:
            descriptor = build_descriptor(load(args.identity), load(args.founding), load(args.admit),
                                          args.vk.read_bytes(), args.birth_start_hash)
            identities.outside_git(args.output.absolute())
            identities.private_write(args.output, identities.encoded(descriptor))
            result = {'descriptor_path': str(args.output), 'fields': len(descriptor),
                      'descriptor_sha256': replay.digest(descriptor), 'broadcast': False}
        print(json.dumps(result, sort_keys=True))
    except (ValueError, KeyError, IndexError, TypeError, OSError, subprocess.SubprocessError) as error:
        if args.command == 'rehearse' and args.trial.is_dir():
            failure = args.trial / 'preparation-failure.json'
            if not failure.exists():
                try:
                    identities.outside_git(args.trial.absolute())
                    identities.private_write(failure, identities.encoded({
                        'schema': 'kpx2-unspent-recovery-local-failure/v1',
                        'exception_type': type(error).__name__, 'traceback': traceback.format_exc(),
                        'broadcast': False}))
                except (ValueError, OSError):
                    pass
        print('recovery trial preparation refused: ' + type(error).__name__ +
              '; private failure retained where possible; no broadcast interface exists', file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
