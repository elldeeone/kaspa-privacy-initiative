#!/usr/bin/env python3
"""Trusted bounded stage scheduling for the integrated lifecycle.

Private command plans and diagnostics stay in the reserved private parent.
Public exports are registered before invocation and validated before promotion.
This module has no funding/broadcast method and claims no operator independence.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'construction'))
from backend import fresh, path, write
from codec import canonical_json, parse_json, sha
from driver import authorize_public, ready_public
from ingress import Ingress, PRIVATE
from public import DOMAIN, fields, hx, initial_record, need

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def resource_child(args):
    relative = next(row.split(':', 2)[2] for row in Path('/proc/self/cgroup').read_text().splitlines()
                    if row.startswith('0::'))
    root = Path('/sys/fs/cgroup') / relative.lstrip('/')
    quota, period = (root / 'cpu.max').read_text().split()
    need(quota != 'max' and int(quota) <= args.cpu * int(period), 'own-CPU-cap')
    need(int((root / 'memory.max').read_text()) <= args.memory
         and (root / 'memory.swap.max').read_text().strip() == '0', 'own-memory-and-swap-cap')
    jobs = parse_json(sys.stdin.buffer.read())
    need(type(jobs) is list and 1 <= len(jobs) <= 3, 'bounded-trusted-job-list')
    started = time.monotonic()

    def execute(job):
        fields(job, ('argv', 'stdout', 'stderr'), 'trusted-job-fields')
        need(type(job['argv']) is list and all(type(value) is str for value in job['argv']), 'trusted-fixed-argv')
        with Path(job['stdout']).open('xb') as out, Path(job['stderr']).open('xb') as err:
            return subprocess.run(job['argv'], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                  env=CLEAN).returncode

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        statuses = list(pool.map(execute, jobs))
    counters = {key: (root / key).read_text().strip() for key in
                ('cpu.max', 'memory.max', 'memory.swap.max', 'cpu.stat', 'memory.peak', 'memory.events')}
    write(path(args.metrics), canonical_json({'schema': 'kpx8-lifecycle-resource/v1',
        'wall_seconds': time.monotonic() - started, 'child_count': len(jobs),
        'all_children_succeeded': statuses == [0] * len(jobs), 'observed_own_cgroup': counters}))
    return 0 if statuses == [0] * len(jobs) else 2


def initial_public(raw, party, participant, admission):
    value = parse_json(raw)
    fields(value, ('schema', 'domain_hex32', 'participant_id_hex32', 'initial_position',
                   'admission_sompi', 'initial_record_hex496', 'funding'), 'exact-owner-init-public-fields')
    need(value['schema'] == 'kpx8-owner-initial-public/v1' and value['domain_hex32'] == DOMAIN.hex()
         and value['participant_id_hex32'] == participant
         and type(value['initial_position']) is int and value['initial_position'] == party
         and type(value['admission_sompi']) is int and value['admission_sompi'] == admission,
         'owner-init-exact-selected-identity-admission')
    _, _, note_value = initial_record(hx(value['initial_record_hex496'], 496))
    need(note_value == admission, 'owner-init-authenticated-admission-value')
    fields(value['funding'], ('xonly_hex32', 'script_public_key'), 'owner-init-public-funding-fields')
    key = hx(value['funding']['xonly_hex32'], 32)
    need(value['funding']['script_public_key'] == (b'\0\0\x20' + key + b'\xac').hex(),
         'owner-initial-native-funding-script')
    return value


class StageRunner:
    def __init__(self, private_base, public_base, original_trials, retained_private, source_manifest=None):
        self.private = path(private_base)
        need(self.private.is_relative_to(PRIVATE) and self.private != PRIVATE, 'runtime-within-reserved-private-parent')
        self.public = path(public_base)
        self.old = list(original_trials)
        self.retained = list(retained_private)
        self.ingress = Ingress(self.old, self.retained)
        need(all(not self.public.is_relative_to(root) for root in self.ingress.guard.directories),
             'public-runtime-outside-private')
        self.source_manifest = source_manifest

    def authenticate(self):
        if self.source_manifest is None:
            return
        source = parse_json(self.ingress.read(*self.source_manifest))
        fields(source, ('schema', 'files'), 'source-manifest-fields')
        need(source['schema'] == 'kpx8-lifecycle-source-selection/v1' and type(source['files']) is list,
             'source-selection-schema')
        seen = set()
        guard = self.ingress.refresh()
        for row in source['files']:
            fields(row, ('path', 'sha256', 'bytes'), 'source-selection-member-fields')
            member = path(row['path'])
            need(member not in seen, 'unique-source-selection-member')
            seen.add(member)
            raw = guard.read(member, row['sha256'])
            need(type(row['bytes']) is int and len(raw) == row['bytes'], 'source-selection-member-length')

    def initialize_directories(self):
        need(not self.private.exists() and not self.public.exists(), 'fresh-integrated-runtime')
        self.authenticate()
        self.private.mkdir(parents=True, mode=0o700)
        self.public.mkdir(parents=True, mode=0o700)
        (self.private / 'controller').mkdir(mode=0o700)
        for party in range(3):
            parent = self.private / ('party-%d' % party)
            parent.mkdir(mode=0o700)
            for name in ('owner', 'mpc'):
                (parent / name).mkdir(mode=0o700)
        self.ingress.refresh()

    def stage(self, label, commands, *, cpu=4, memory=4 * 1024**3):
        need(type(label) is str and label.replace('-', '').isalnum(), 'simple-public-stage-label')
        self.authenticate()
        controller = self.private / 'controller'
        jobs = [{'argv': list(map(str, command)), 'stdout': str(controller / (label + '-%d.stdout' % i)),
                 'stderr': str(controller / (label + '-%d.stderr' % i))} for i, command in enumerate(commands)]
        unit = 'kpx8-lifecycle-' + secrets.token_hex(8)
        metrics = self.public / (label + '-resources.json')
        command = ['/usr/bin/systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect', '--unit', unit,
            '-p', 'CPUQuota=%d%%' % (cpu * 100), '-p', 'MemoryMax=%d' % memory,
            '-p', 'MemorySwapMax=0', '/usr/bin/python3', '-B', str(Path(__file__).resolve()),
            '_resource', '--cpu', str(cpu), '--memory', str(memory), '--metrics', str(metrics)]
        env = dict(CLEAN, XDG_RUNTIME_DIR='/run/user/%d' % os.getuid(),
                   DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/%d/bus' % os.getuid())
        child = subprocess.run(command, input=canonical_json(jobs), capture_output=True, env=env)
        write(controller / (label + '-supervisor.stdout'), child.stdout)
        write(controller / (label + '-supervisor.stderr'), child.stderr)
        self.ingress.refresh()
        need(child.returncode == 0, 'selected-phase-incomplete:' + label)

    def wallet_command(self, operation, party, public_output, private_run, extra):
        need(type(party) is int and 0 <= party < 3, 'selected-owner-index')
        parent = self.private / ('party-%d' % party)
        command = ['/usr/bin/python3', '-B', str(HERE.parent / 'wallet/run_owner.py'), operation,
            '--owner-directory', str(parent / 'owner'), '--mpc-directory', str(parent / 'mpc'),
            '--output', str(public_output), '--private-run-directory', str(private_run)]
        for old in self.old:
            command += ['--exclude-old-trial', str(old)]
        for root in self.retained:
            command += ['--exclude-new-private-directory', str(root)]
        if operation == 'prepare':
            for index in range(3):
                command += ['--peer-owner-directory', str(self.private / ('party-%d' % index) / 'owner')]
        return command + list(map(str, extra)) + ['--execute']

    def initialize_owners(self, crypto, admission_sompi):
        self.ingress.read(*crypto)
        participants = [secrets.token_hex(32) for _ in range(3)]
        outputs = [self.public / ('init-%d' % i) for i in range(3)]
        for output in outputs:
            self.ingress.register(output, 'init')
        commands = [self.wallet_command('init', i, outputs[i], self.private / 'controller' / ('init-%d' % i),
            ['--crypto', crypto[0], '--participant-id', participants[i], '--position', i,
             '--admission-sompi', admission_sompi]) for i in range(3)]
        self.stage('init', commands)
        owners = []
        for index, output in enumerate(outputs):
            value, _ = self.ingress.promote(output, self.public / ('OWNER-%d.json' % index),
                lambda raw, kind, index=index: initial_public(raw, index, participants[index], admission_sompi))
            owners.append(value)
        write(self.public / 'OWNERS.json', canonical_json({'schema': 'kpx8-initial-owner-exports/v1',
              'domain_hex32': DOMAIN.hex(), 'owners': owners}))
        return owners

    def driver(self, operation, output, extra):
        command = ['/usr/bin/python3', '-B', str(HERE / 'driver.py'), operation, '--output', str(output)]
        for old in self.old:
            command += ['--exclude-private-root', str(old)]
        for root in self.retained:
            command += ['--exclude-private-directory', str(root)]
        return command + list(map(str, extra))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if len(sys.argv) > 1 and sys.argv[1] == '_resource':
        parser.add_argument('--cpu', type=int, required=True)
        parser.add_argument('--memory', type=int, required=True)
        parser.add_argument('--metrics', required=True)
        return resource_child(parser.parse_args(sys.argv[2:]))
    parser.add_argument('operation', choices=('initialize',))
    parser.add_argument('--private-base', required=True)
    parser.add_argument('--public-base', required=True)
    parser.add_argument('--exclude-private-root', action='append', required=True)
    parser.add_argument('--exclude-private-directory', action='append', required=True)
    parser.add_argument('--source-manifest', nargs=2, required=True)
    parser.add_argument('--crypto', nargs=2, required=True)
    parser.add_argument('--admission-sompi', type=int, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    runner = StageRunner(args.private_base, args.public_base, args.exclude_private_root,
                         args.exclude_private_directory, args.source_manifest)
    runner.authenticate()
    if not args.execute:
        print('{"status":"SOURCE_PREFLIGHT_ONLY","owner_init_count":0}')
        return 0
    runner.initialize_directories()
    runner.initialize_owners(args.crypto, args.admission_sompi)
    print('{"status":"THREE_FRESH_OWNERS_INITIALIZED","financial_or_chain_acceptance":false}')
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
