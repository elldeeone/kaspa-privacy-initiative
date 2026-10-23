#!/usr/bin/env python3
"""Submit one reviewed finite TN10 trace once and retain confirmed public evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import recovery_check as recovery

RPC = 'wss://electron-10.kaspa.blue/kaspa/testnet-10/wrpc/borsh'
KINDS = ('fundingprep', 'founding', 'admit', 'private', 'bob-reveal', 'charlie-reveal')
SNAPSHOTS = {1: 'founding', 2: 'before-private', 3: 'after-private', 4: 'after-bob', 5: 'terminal'}
ADAPTER = ROOT / 'poc/future-native-chain/adapter.mjs'


def load(path):
    return json.loads(Path(path).read_bytes())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = (json.dumps(value, separators=(',', ':'), ensure_ascii=False) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as file:
        file.write(raw)
        file.flush()
        os.fsync(file.fileno())
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def save_or_match(path, value):
    if path.exists():
        if load(path) != value:
            raise ValueError('retained artifact differs: ' + path.name)
    else:
        save(path, value)


def call(request):
    result = subprocess.run(['node', str(ADAPTER)], input=json.dumps(request),
                            text=True, capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'adapter stopped')
    return json.loads(result.stdout)


class Trace:
    def __init__(self, trial):
        self.trial = trial.resolve(strict=True)
        if self.trial.stat().st_mode & 0o777 != 0o700:
            raise ValueError('private trial directory permissions')
        self.identity = self.trial / 'public/identity.json'
        self.archive = load(self.trial / 'local-archive.json')
        self.complete = load(self.trial / 'LOCAL-COMPLETE.json')
        self.public = self.trial / 'chain-public'
        self.release = self.trial / 'chain-release.json'
        self.profile = load(self.identity)
        if (self.profile['classification'] != 'PRIVATE_TN10_TEST_KAS_ONLY'
                or self.profile['network_id'] != 'testnet-10'
                or self.profile['genesis_hash_hex'] != recovery.GENESIS
                or self.archive['oracle_stage'] != 'LOCAL_SUPPLIED_CONTEXT'
                or self.archive['trial_id'] != self.profile['trial_id']
                or self.complete['trial_id'] != self.profile['trial_id']
                or self.complete['native_Full_operations'] != 6
                or self.complete['sdk_lossless_roundtrips'] != 6
                or self.complete['genuine_private_proofs'] != 1
                or self.complete['terminal_reserve_sompi'] != 0
                or self.complete['terminal_liability_sompi'] != 0
                or self.complete['preferred_service_prover_pk_absent_for_exit'] is not True
                or [row['kind'] for row in self.archive['operations']] != list(KINDS)):
            raise ValueError('complete fresh TN10 local trace required')
        self.operations = self.archive['operations']

    def base(self, index):
        row = self.operations[index]
        return {'rpc_url': RPC, 'stage': row['kind'], 'profile_path': str(self.identity),
                'body_path': row['accepted_body_path'], 'local_check_path': row['local_check_path']}

    def select_release(self):
        bodies = {}
        binary_hash = None
        for row in self.operations:
            if (digest(row['accepted_body_path']) != row['accepted_body_sha256']
                    or digest(row['local_check_path']) != row['local_check_sha256']
                    or digest(row['native_validation_path']) != row['native_validation_sha256']):
                raise ValueError('local artifact changed')
            check = load(row['local_check_path'])
            validation = load(row['native_validation_path'])
            if (check['profile_sha256'] != digest(self.identity)
                    or check['transaction_id'] != row['txid_raw_hex']
                    or check['body_sha256'] != row['accepted_body_sha256']
                    or validation['Full']['accepted'] is not True
                    or validation['all_input_engines_accepted'] is not True):
                raise ValueError('local authority/Full validation mismatch')
            if binary_hash is not None and binary_hash != check['native_binary_sha256']:
                raise ValueError('mixed native binaries')
            binary_hash = check['native_binary_sha256']
            bodies[row['kind']] = {'transaction_id': row['txid_raw_hex'],
                'body_sha256': row['accepted_body_sha256'], 'local_check_sha256': row['local_check_sha256']}
        value = {'authorization': 'TN10_FRESH_TRIAL_REHEARSAL',
            'trial_directory': str(self.trial), 'profile_sha256': digest(self.identity),
            'network': 'testnet-10', 'genesis': recovery.GENESIS, 'rpc_url': RPC,
            'allowed_stages': list(KINDS), 'adapter_sha256': digest(ADAPTER),
            'native_safe_sha256': digest(ADAPTER.with_name('native_safe.py')),
            'native_binary_sha256': binary_hash, 'bodies': bodies,
            'local_complete_sha256': digest(self.trial / 'LOCAL-COMPLETE.json'),
            'driver_sha256': digest(Path(__file__)),
            'recovery_checker_sha256': digest(HERE / 'recovery_check.py'),
            'recipient_source_sha256': digest(ROOT / 'poc/future-recipient/v2/recipient.py')}
        save(self.release, value)
        return {'release_path': str(self.release), 'release_sha256': digest(self.release)}

    def observe(self, index, start, indices=None):
        request = dict(self.base(index), op='observe', start_hash=start, min_confirmations=20)
        if indices is not None:
            request['expected_unspent_output_indices'] = indices
        return call(request)

    def recovery_archive(self, through, observations):
        phase = self.public / ('phase-' + str(through) + '-' + uuid.uuid4().hex)
        operations = []
        bodies = []
        for index in range(through + 1):
            stage = KINDS[index]
            body = load(self.public / 'bodies' / (stage + '.json'))
            bodies.append(body)
            operations.append({'kind': stage, 'txid_raw_hex': body['id'],
                'accepted_body_path': '../bodies/' + stage + '.json',
                'accepted_body_sha256': digest(self.public / 'bodies' / (stage + '.json')),
                'observation_path': '../observations/' + stage + '.json',
                'observation_sha256': digest(self.public / 'observations' / (stage + '.json'))})
        snapshots = {name: self.archive['snapshots'][name]
                     for index, name in SNAPSHOTS.items() if index <= through}
        snapshot, reserve, _, _ = recovery.finite_trace(bodies, snapshots,
                                                bytes.fromhex(self.profile['domain_hex32']))
        archive = {key: self.archive[key] for key in ('schema', 'trial_id', 'domain_hex32',
                        'network_id', 'genesis_hash_hex', 'expected_payments_sompi')}
        archive.update(oracle_stage=recovery.NETWORK, operations=operations, snapshots=snapshots,
            head={'state_hex112': recovery.state(snapshot, bytes.fromhex(self.profile['domain_hex32'])).hex(),
                  'reserve_sompi': reserve, 'outpoint': recovery.point(bodies[-1], 0) if reserve else None,
                  'accepted_operation_index': through})
        checkpoint = call({'op': 'checkpoint', 'rpc_url': RPC})
        fresh = []
        wanted = [(through, [0])] if reserve else [(4, [1]), (5, [0])]
        for index, outputs in wanted:
            fresh.append(self.observe(index, observations[index]['start_hash'], outputs))
        save(phase / 'archive.json', archive)
        save(phase / 'current.json', {'schema': 'kpx2-tn10-current-view/v1',
            'trial_id': self.profile['trial_id'], 'oracle_stage': recovery.NETWORK,
            'checkpoint': checkpoint, 'observations': fresh})
        return phase

    def check_owner(self, phase, owner):
        self.check_sources(load(self.release))
        identity = self.trial / 'public/recovery-identity.json'
        public_identity = load(identity)
        # Bridge pathname is public runtime metadata; no private profile is read.
        bridge = Path('/home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto')
        expected = public_identity['runtime_pins']['bridge_sha256']
        if digest(bridge) != expected:
            raise ValueError('recovery bridge identity changed')
        request = {'oracle_stage': recovery.NETWORK, 'identity_path': '/identity.json',
            'backup_path': '/backup.json', 'archive_path': '/archive/' + phase.name + '/archive.json',
            'current_observations_path': '/archive/' + phase.name + '/current.json',
            'crypto_path': '/crypto', 'crypto_sha256': expected, 'label': owner}
        command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
            '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--ro-bind', str(ROOT / 'poc'), '/work/poc', '--ro-bind', str(self.public), '/archive',
            '--ro-bind', str(identity), '/identity.json',
            '--ro-bind', str(self.trial / 'backups' / (owner + '.json')), '/backup.json',
            '--ro-bind', str(bridge), '/crypto', '--setenv', 'PATH', '/usr/bin:/bin',
            '/usr/bin/python3', '-B', '/work/poc/future-testnet/recovery_check.py']
        result = subprocess.run(command, input=json.dumps(request), text=True, capture_output=True)
        value = json.loads(result.stdout) if result.stdout else {'passed': False}
        save(phase / (owner + '-recovery.json'), value)
        if result.returncode or value.get('passed') is not True:
            raise ValueError('isolated accepted-record recovery rejected for ' + owner)
        return value

    def check_sources(self, release):
        if (release['driver_sha256'] != digest(Path(__file__))
                or release['recovery_checker_sha256'] != digest(HERE / 'recovery_check.py')
                or release['recipient_source_sha256'] != digest(ROOT / 'poc/future-recipient/v2/recipient.py')
                or release['adapter_sha256'] != digest(ADAPTER)
                or release['native_safe_sha256'] != digest(ADAPTER.with_name('native_safe.py'))):
            raise ValueError('released source changed')

    def run(self):
        release = load(self.release)
        self.check_sources(release)
        if release['local_complete_sha256'] != digest(self.trial / 'LOCAL-COMPLETE.json'):
            raise ValueError('released driver/local result changed')
        observations = []
        for index, stage in enumerate(KINDS):
            saved = self.public / 'observations' / (stage + '.json')
            if saved.exists():
                observations.append(load(saved))
            else:
                intent = self.trial / 'chain' / (stage + '.submission-intent.json')
                if intent.exists():
                    # Resume observation only; the durable adapter marker forbids another send.
                    checkpoint = {'start_hash': load(intent)['start_hash']}
                else:
                    checkpoint = call({'op': 'checkpoint', 'rpc_url': RPC})
                    sent = call(dict(self.base(index), op='submit-once', trial_dir=str(self.trial),
                        release_path=str(self.release), release_sha256=digest(self.release),
                        start_hash=checkpoint['start_hash']))
                    print(json.dumps({'stage': stage, 'submission': sent['status']}), flush=True)
                observed = self.observe(index, checkpoint['start_hash'])
                save_or_match(self.public / 'bodies' / (stage + '.json'), observed['accepted_body'])
                save(saved, observed)
                observations.append(observed)
                print(json.dumps({'stage': stage, 'confirmed': True, 'transaction_id': observed['transaction_id']}), flush=True)
            # Repeat read-only recovery checks on resume; a saved body is not a
            # substitute for a fresh accepted/current view before either exit.
            successor_committed = index < 5 and (
                (self.trial / 'chain' / (KINDS[index + 1] + '.submission-intent.json')).exists()
                or (self.public / 'observations' / (KINDS[index + 1] + '.json')).exists())
            if index == 3 and not successor_committed:
                phase = self.recovery_archive(index, observations)
                self.check_owner(phase, 'bob')
                self.check_owner(phase, 'charlie')
            elif index == 4 and not successor_committed:
                phase = self.recovery_archive(index, observations)
                self.check_owner(phase, 'charlie')
        phase = self.recovery_archive(5, observations)
        checks = {owner: self.check_owner(phase, owner) for owner in ('bob', 'charlie')}
        result = {'schema': 'kpx2-tn10-confirmed-rehearsal/v1', 'trial_id': self.profile['trial_id'],
            'domain_hex32': self.profile['domain_hex32'], 'network': 'testnet-10',
            'confirmed_native_operations': 6, 'confirmed_payouts_sompi': self.complete['payouts_sompi'],
            'terminal_reserve_sompi': 0, 'terminal_liability_sompi': 0, 'recipient_checks': checks,
            'total_fees_sompi': self.complete['total_fees_sompi'],
            'fee_qualification': self.complete['fee_qualification'],
            'trust': 'VALIDATING_NODE_AND_PUBLIC_ARCHIVE_ORACLE',
            'privacy_qualified': False, 'independent_network_recovery_proved': False}
        save_or_match(self.trial / 'CHAIN-COMPLETE.json', result)
        return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['release', 'run'])
    parser.add_argument('trial', type=Path)
    args = parser.parse_args()
    trace = Trace(args.trial)
    result = trace.select_release() if args.command == 'release' else trace.run()
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
