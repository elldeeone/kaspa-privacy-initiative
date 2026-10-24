#!/usr/bin/env python3
"""Trusted serial cohort supervision. No owner truth or MPC stream is read here."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
import re
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent / 'construction'))
from backend import PublicGuard, fresh, path, write
from codec import canonical_json, parse_json, sha
from driver import initial_public, ready_public, authorize_public
from public import need, wire
from cohort_stats import world_event, summarize

CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
EXPERIMENT = '625f57369497b198d87e57d554e1d4976d4efa47b6b8f9a8ad94e936e7275803'
CONTRACT = '28a3b29edff91634e193d28ed7b4914b1216d84bf6200c210899e967870016c2'
INITIAL_SESSION = '51731a3efdc6543ddeb77310b975587d82e3f3bafb9828f4797dae9be30e7b9c'
STRATEGY = '26e8279d8a4f76660e63a66372d07f51596d33f1638cb83a1426184a8fbda830'
RETAINED = ('/var/tmp/kpi-owner-private-integration-01', '/var/tmp/kpi-owner-private-diagnostics-01')


def safe_reason(error):
    value = str(error) if isinstance(error, ValueError) else ''
    return value if re.fullmatch(r'[A-Za-z0-9:._-]{1,120}', value) else 'unexpected-runtime-failure'


class ConfirmedFalsification(Exception):
    """Trusted evidence classifier only; ordinary child refusal is not this verdict."""
    KINDS = frozenset(('confirmed-invalid-financial-acceptance', 'confirmed-double-spend',
        'confirmed-direct-grouping-disclosure', 'confirmed-premix-disclosure', 'confirmed-map-disclosure'))

    def __init__(self, kind):
        need(kind in self.KINDS, 'explicit-confirmed-falsification-kind')
        super().__init__(kind)


def resource_child(args):
    """Installed cgroup API, own process counters and trusted argv handles only."""
    relative = next(row.split(':', 2)[2] for row in Path('/proc/self/cgroup').read_text().splitlines()
                    if row.startswith('0::'))
    root = Path('/sys/fs/cgroup') / relative.lstrip('/')
    quota, period = (root / 'cpu.max').read_text().split()
    need(quota != 'max' and int(quota) <= args.cpu * int(period), 'own-CPU-cap')
    need(int((root / 'memory.max').read_text()) <= args.memory and
         (root / 'memory.swap.max').read_text().strip() == '0', 'own-memory-and-swap-cap')
    jobs = parse_json(sys.stdin.buffer.read())
    need(type(jobs) is list and 1 <= len(jobs) <= 3, 'bounded-trusted-child-count')
    started = time.monotonic()
    def run(job):
        need(set(job) == {'argv', 'stdout', 'stderr'} and type(job['argv']) is list and
             all(type(s) is str for s in job['argv']), 'trusted-command-handle-shape')
        with Path(job['stdout']).open('xb') as out, Path(job['stderr']).open('xb') as err:
            return subprocess.run(job['argv'], stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                  env=CLEAN).returncode
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        statuses = list(pool.map(run, jobs))
    counters = {key: (root / key).read_text().strip() for key in
                ('cpu.max', 'memory.max', 'memory.swap.max', 'cpu.stat', 'memory.peak', 'memory.events')}
    write(path(args.metrics), canonical_json({'schema': 'kpx7-cohort-resource/v1',
        'wall_seconds': time.monotonic() - started, 'child_count': len(jobs),
        'all_children_succeeded': statuses == [0] * len(jobs), 'observed_own_cgroup': counters}))
    return 0 if statuses == [0] * len(jobs) else 2


class Cohort:
    def __init__(self, args):
        self.args = args
        self.retained = [path(p) for p in args.exclude_retained_private_directory]
        need(all(path(p) in self.retained for p in RETAINED), 'initial-world-and-diagnostics-excluded')
        self.parties, self.controllers = [], []
        self.forbidden = set()
        self.output = path(args.output)
        need(all(not self.output.is_relative_to(d) and not d.is_relative_to(self.output)
                 for d in self.guard().directories), 'cohort-output-disjoint-from-retained-private')
        self.spec = parse_json(self.guard().read(args.spec, args.spec_sha256))
        need(set(self.spec) == {'schema', 'contract', 'world_ids', 'source_manifests', 'source_files',
             'assets', 'engine_root', 'template', 'native_codec', 'verifier_host', 'admission_sompi',
             'excluded_initial_session_sha256', 'experiment_sha256', 'strategy_sha256'}, 'exact-cohort-spec')
        need(self.spec['schema'] == 'kpx7-independent-world-cohort/v1' and
             self.spec['world_ids'] == ['world-%02d' % i for i in range(1, 17)] and
             self.spec['excluded_initial_session_sha256'] == INITIAL_SESSION and
             self.spec['experiment_sha256'] == EXPERIMENT and self.spec['strategy_sha256'] == STRATEGY and
             self.spec['admission_sompi'] == 2_000_000_000, 'frozen-cohort-workload')
        need(self.spec['contract']['sha256'] == CONTRACT, 'frozen-cohort-contract')
        self.pins = {}
        self.authenticate()
        self.seen = {key: set() for key in ('participant_id_hex32', 'initial_cm_hex32', 'nf_hex32', 'session')}
        self.seen['session'].add(INITIAL_SESSION)

    def guard(self, *, producer=False):
        # Only a registered current producer leaf may use the narrow route.
        stable_roots = [*self.retained, *self.parties, *self.controllers[:-1]]
        guard = PublicGuard(self.args.exclude_private_root, stable_roots)
        # Persist all party/retained identities, including private inodes later moved out.
        self.forbidden.update(guard.forbidden)
        if self.controllers:
            full = PublicGuard(self.args.exclude_private_root, [*stable_roots, self.controllers[-1]])
            candidates = set()
            for job in getattr(self, 'approved_jobs', ()):
                need(job.parent == self.controllers[-1], 'registered-current-producer-job')
                leaf = path(job / 'public/PUBLIC.json')
                try:
                    info = leaf.lstat()
                except FileNotFoundError:
                    continue
                identity = (info.st_dev, info.st_ino)
                # This is only a candidate for a typed producer read. An inode
                # previously observed private can NEVER become an exception.
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and identity not in self.forbidden:
                    candidates.add(identity)
            self.forbidden.update(full.forbidden - candidates)
            if not producer:
                guard = full  # Generic ingress excludes the WHOLE current controller.
        guard.forbidden.update(self.forbidden)
        return guard

    def selected(self, selector):
        need(set(selector) == {'path', 'sha256'}, 'exact-public-selector')
        p = Path(selector['path'])
        return p if p.is_absolute() else REPO / p

    def get(self, selector):
        return self.guard().read(self.selected(selector), selector['sha256'])

    def authenticate(self):
        self.get(self.spec['contract'])
        for selected in self.spec['source_manifests']:
            need(set(selected) == {'path', 'sha256', 'member_base'}, 'source-manifest-selection')
            selector = {k: selected[k] for k in ('path', 'sha256')}
            manifest = parse_json(self.get(selector))
            for row in manifest['files'] + manifest.get('immutable_reuse', []):
                relative = Path(selected['member_base']) / row['path']
                need(not relative.is_absolute() and '..' not in relative.parts, 'finite-source-member')
                raw = self.guard().read(REPO / relative, row['sha256'])
                need(len(raw) == row['bytes'], 'source-member-byte-length')
                key = str(relative)
                need(key not in self.pins or self.pins[key] == row['sha256'], 'consistent-source-pin')
                self.pins[key] = row['sha256']
        for selector in self.spec['source_files']:
            self.get(selector); self.pins[selector['path']] = selector['sha256']
        for selector in (self.spec['template'], self.spec['native_codec'], self.spec['verifier_host']):
            self.get(selector)
        self.assets = self.spec['assets']
        for role in ('relation', 'crypto'):
            self.get(self.assets[role])
        self.guard().read(self.assets['component_profile'], self.assets['component_profile_sha256'])
        for role in ('spend', 'output'):
            row = self.assets[role]
            self.guard().read(row['manifest'], row['manifest_sha256'])
            # No controller PK read/hash/copy: only the selected financial launcher authenticates it.
            _, info = self.guard().metadata(row['pk'])
            need(info.st_mode & 0o222 == 0, 'readonly-public-parameter-metadata')
        engine_root = path(self.spec['engine_root'])
        installation = parse_json(self.guard().read(engine_root / 'INSTALLATION.json',
            '5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594'))
        for row in installation['files']:
            relative = Path(row['path'])
            need(not relative.is_absolute() and '..' not in relative.parts, 'finite-existing-engine-member')
            self.guard().metadata(engine_root / 'software' / relative)
        self.template = parse_json(self.get(self.spec['template']))
        need(self.template['compute_budget'] == 1800 and self.template['fee_sompi'] == 19_332_300 and
             self.template['component_profile_sha256'] == self.assets['component_profile_sha256'],
             'unchanged-selected-native-policy')

    def pin(self, relative):
        return self.pins['poc/owner-private-payments/' + relative]

    def produced(self, p):
        # Known producer public files only, all owner/private/controller aliases excluded.
        from operations import created_public
        raw = created_public(self.guard(), p)
        return raw, sha(raw)

    def selector(self, p):
        return [str(p), self.produced(p)[1]]

    def promote(self, job, target, kind, check=None):
        """Narrow typed producer exception, never reads a plan/log/private state leaf."""
        from operations import created_public
        leaf = job / 'public/PUBLIC.json'
        need(job.parent == self.controllers[-1] and leaf.parent.parent == job, 'registered-current-public-leaf')
        need(job in self.approved_jobs, 'only-selected-producer-job')
        value_raw = created_public(self.guard(producer=True), leaf)
        value = parse_json(value_raw)
        if kind == 'init':
            initial_public(value, check)
        elif kind == 'prepare':
            ready_public(value, *check)
        elif kind == 'authorize':
            authorize_public(value, *check)
        elif kind == 'observe':
            need(set(value) == {'schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
                 'strategy_sha256', 'capsule_seal_sha256', 'excluded_known_creator_count',
                 'unknown_creator_target_count', 'candidate_creator_assignments', 'candidate_partitions',
                 'hash_tie_break_used', 'unique_partition_from_constraints', 'scope'}, 'typed-observer-export')
            need(value['schema'] == 'kpx7-colluder-observer-seal/v1', 'typed-observer-schema')
        else:
            need(set(value) == {'schema', 'experiment_sha256', 'session_sha256', 'projection_sha256',
                 'sealed_bundle_sha256', 'coordinator_only', 'one_colluder', 'scope', 'interpretation'},
                 'typed-global-count-export')
            need(value['schema'] == 'kpx7-owner-privacy-global-counts/v1' and
                 set(value['coordinator_only']) == {'eligible_count', 'matched_count', 'label_invariant_groups_matched'}
                 and set(value['one_colluder']) == {'eligible_count', 'matched_count', 'excluded_known_creator_count',
                     'label_invariant_unknown_groups_matched', 'presealed_ambiguity'}, 'typed-global-count-fields')
        write(target, value_raw)
        return value

    def stage(self, label, commands, cpu=4, memory=4 * 1024**3):
        self.last_stage = label
        self.authenticate()  # Same finite source/assets before every phase, no directory-content ingress.
        jobs = [{'argv': command, 'stdout': str(self.controller / (label + '-%d.stdout' % i)),
                 'stderr': str(self.controller / (label + '-%d.stderr' % i))} for i, command in enumerate(commands)]
        unit = 'kpx7-cohort-' + secrets.token_hex(8)
        metrics = self.public / (label + '-resources.json')
        command = ['/usr/bin/systemd-run', '--user', '--quiet', '--wait', '--pipe', '--collect', '--unit', unit,
            '-p', 'CPUQuota=%d%%' % (cpu * 100), '-p', 'MemoryMax=%d' % memory,
            '-p', 'MemorySwapMax=0', '/usr/bin/python3', '-B', str(Path(__file__).resolve()),
            '_resource', '--cpu', str(cpu), '--memory', str(memory), '--metrics', str(metrics)]
        supervisor_env = dict(CLEAN, XDG_RUNTIME_DIR='/run/user/%d' % os.getuid(),
                              DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/%d/bus' % os.getuid())
        result = subprocess.run(command, input=canonical_json(jobs), capture_output=True, env=supervisor_env)
        # This is own child diagnostic output, never an owner record or publication payload.
        write(self.controller / (label + '-supervisor.stdout'), result.stdout)
        write(self.controller / (label + '-supervisor.stderr'), result.stderr)
        self.guard()  # Register new PRIVATE plan/log inodes before any producer export read.
        need(result.returncode == 0, 'selected-phase-incomplete:' + label)

    def driver(self, op, output, extra):
        command = ['/usr/bin/python3', '-B', str(HERE / 'driver.py'), op, '--output', str(output)]
        for p in self.args.exclude_private_root:
            command += ['--exclude-private-root', p]
        for p in self.current:
            command += ['--exclude-owner-private-directory', str(p)]
        return command + list(map(str, extra))

    def one(self, label, op, extra, cpu=4, memory=4 * 1024**3):
        output = self.public / label
        self.stage(label, [self.driver(op, output, extra)], cpu, memory)
        return output

    def score_command(self, op, output, extra):
        command = ['/usr/bin/python3', '-B', str(HERE.parent / 'wallet/run_score.py'), op,
                   '--output', str(output), '--experiment-sha256', EXPERIMENT, '--execute']
        for p in self.args.exclude_private_root:
            command += ['--exclude-old-trial', p]
        for p in self.current:
            command += ['--exclude-new-private-directory', str(p)]
        return command + list(map(str, extra))

    def remember(self, key, values):
        need(len(set(values)) == len(values) and not self.seen[key].intersection(values), 'fresh-public-world-material')
        self.seen[key].update(values)

    def run_world(self, world):
        root = self.output / world; root.mkdir(mode=0o700)
        self.public = root / 'public'; self.public.mkdir(mode=0o700)
        self.controller = root / 'controller-private'; self.controller.mkdir(mode=0o700)
        self.controllers.append(self.controller)
        self.approved_jobs = set()
        self.current = [root / ('party-%d' % i) for i in range(3)]
        for p in self.current:
            p.mkdir(mode=0o700); (p / 'owner').mkdir(mode=0o700); (p / 'mpc').mkdir(mode=0o700)
        self.parties.extend(self.current)
        owner_ids = [secrets.token_hex(32) for _ in range(3)]
        jobs = [self.controller / ('init-%d' % i) for i in range(3)]
        self.approved_jobs.update(jobs)
        self.stage('init', [self.driver('owner-init', jobs[i], ['--party', i, '--participant-id', owner_ids[i],
            '--admission-sompi', self.spec['admission_sompi'], '--crypto', self.assets['crypto']['path'],
            self.assets['crypto']['sha256'], '--wallet-script-sha256', self.pin('wallet/run_owner.py'), '--execute'])
            for i in range(3)])
        init_paths = [self.public / ('init-%d.json' % i) for i in range(3)]
        owners = [self.promote(jobs[i], init_paths[i], 'init', i) for i in range(3)]
        for key in ('participant_id_hex32', 'initial_cm_hex32'):
            self.remember(key, [o[key] for o in owners])
        genesis_args = [v for p in init_paths for v in ['--owner-public', *self.selector(p)]]
        gen = self.one('genesis', 'genesis', genesis_args)
        point = sha(b'KPX7 fresh unfunded cohort point\0' + bytes.fromhex(CONTRACT) + world.encode()) + '00000000'
        context = self.one('context', 'context', ['--genesis', *self.selector(gen / 'GENESIS.json'),
            '--owners', *self.selector(gen / 'OWNERS.json'), '--component-profile-sha256', self.assets['component_profile_sha256'],
            '--point-hex36', point, '--fee-sompi', 19_332_300, '--native-tail-hex', self.template['immutable_tail_hex']])
        sess = self.one('session', 'session', ['--genesis', *self.selector(gen / 'GENESIS.json'),
            '--owners', *self.selector(gen / 'OWNERS.json'), '--component-profile-sha256', self.assets['component_profile_sha256'],
            '--effects-context-sha256', self.selector(context / 'CONTEXT.json')[1],
            '--program-sha256', self.pin('construction/kpx7_mix.mpc')])
        session = self.selector(sess / 'SESSION.json'); sid = session[1]; self.remember('session', [sid])
        assets = self.selector(self.output / 'public/ASSETS.json')
        prepared = self.one('mpc-prepared', 'mpc-prepare', ['--engine-root', self.spec['engine_root'],
            '--session', *session, '--backend-sha256', self.pin('construction/backend.py'),
            '--program-sha256', self.pin('construction/kpx7_mix.mpc'), '--codec-sha256', self.pin('construction/codec.py'),
            '--party-sha256', self.pin('construction/party.py'), '--coordinator-sha256', self.pin('construction/coordinator.py'), '--execute'])
        jobs = [self.controller / ('prepare-%d' % i) for i in range(3)]
        self.approved_jobs.update(jobs)
        self.stage('outputs', [self.driver('owner-prepare', jobs[i], ['--party', i, '--owners', *self.selector(gen / 'OWNERS.json'),
            '--assets', *assets, '--session', *session, '--context', *self.selector(context / 'CONTEXT.json'),
            '--wallet-script-sha256', self.pin('wallet/run_owner.py'), '--execute']) for i in range(3)], 14, 20 * 1024**3)
        ready_paths = [self.public / ('ready-%d.json' % i) for i in range(3)]
        ready = [self.promote(jobs[i], ready_paths[i], 'prepare', (owners[i], sid)) for i in range(3)]
        self.remember('nf_hex32', [r['nf_hex32'] for r in ready])
        mixed = self.one('mpc-mixed', 'mpc-run', ['--prepared-root', prepared,
            '--prepared-sha256', self.selector(prepared / 'PREPARED.json')[1],
            '--backend-sha256', self.pin('construction/backend.py'), '--execute'], 1, 512 * 1024**2)
        relative = self.own_reports()
        args = ['--genesis', *self.selector(gen / 'GENESIS.json'), '--owners', *self.selector(gen / 'OWNERS.json'),
            '--session', *session, '--context', *self.selector(context / 'CONTEXT.json'), '--mixed', *self.selector(mixed / 'MIXED.json')]
        args += [v for p in ready_paths for v in ['--ready', *self.selector(p)]]
        core = self.one('body-core', 'build', args)
        native = ['--native-codec', str(self.selected(self.spec['native_codec'])), self.spec['native_codec']['sha256'],
            '--outer-image-hex32', self.template['outer_image_hex32'], '--component-profile-sha256',
            self.assets['component_profile_sha256'], '--compute-budget', 1800]
        pre = self.one('pre-authorization', 'native-project', ['--body', *self.selector(core / 'BODY.bin'), *native])
        projection = self.selector(pre / 'PROJECTION.bin')
        jobs = [self.controller / ('authorize-%d' % i) for i in range(3)]
        self.approved_jobs.update(jobs)
        self.stage('spends', [self.driver('owner-authorize', jobs[i], ['--party', i, '--assets', *assets,
            '--session', *session, '--projection', *projection, '--own-mpc-result', relative[i],
            '--wallet-script-sha256', self.pin('wallet/run_owner.py'), '--execute']) for i in range(3)], 14, 20 * 1024**3)
        auth_paths = [self.public / ('authorization-%d.json' % i) for i in range(3)]
        raw_projection = self.produced(pre / 'PROJECTION.bin')[0]
        for i in range(3):
            self.promote(jobs[i], auth_paths[i], 'authorize', (raw_projection, i))
        args = ['--projection', *projection] + [v for p in auth_paths for v in ['--spend-public', *self.selector(p)]]
        final = self.one('final-body', 'finalize', args)
        final = self.one('final-projection', 'native-project', ['--body', *self.selector(final / 'BODY.bin'), *native])
        projection = self.selector(final / 'PROJECTION.bin')
        self.one('nine-proof-crosscheck', 'verify', ['--projection', *projection, '--verifier-host',
            str(self.selected(self.spec['verifier_host'])), self.spec['verifier_host']['sha256'],
            '--component-profile-sha256', self.assets['component_profile_sha256'], '--execute'])
        return self.diagnostics(session, projection, self.selector(gen / 'OWNERS.json'), assets)

    def own_reports(self):
        # Metadata-only discovery in fresh owned scratch. Never open/copy/hash these files.
        results = []
        for parent in self.current:
            matches = list((parent / 'mpc').glob('mpc-private-*/OWN-MPC-PROJECTION.json'))
            need(len(matches) == 1, 'one-own-engine-result-in-fresh-world')
            p = path(matches[0]); before = p.lstat()
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                 stat.S_IMODE(before.st_mode) in (0o644, 0o400), 'own-result-metadata-only')
            p.chmod(0o400)
            after = p.lstat()
            need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                 (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'own-result-bytes-metadata-unchanged')
            results.append(str(p.relative_to(parent / 'mpc')))
        return results

    def diagnostics(self, session, projection, registry, assets):
        prediction = {'schema': 'kpx7-public-creator-prediction/v1', 'experiment_sha256': EXPERIMENT,
            'session_sha256': session[1], 'projection_sha256': projection[1], 'strategy_sha256': STRATEGY,
            'guesses_creator_index': [0, 0, 1, 1, 2, 2]}
        pred = self.public / 'PREDICTIONS.json'; write(pred, canonical_json(prediction))
        common = ['--assets', assets[0], '--assets-sha256', assets[1],
                  '--session', session[0], '--session-sha256', session[1],
                  '--projection', projection[0], '--projection-sha256', projection[1]]
        observed = self.controller / 'observer'
        self.approved_jobs.add(observed)
        self.stage('observer', [self.score_command('observe', observed, [*common, '--owner-directory', self.current[0] / 'owner',
            '--registry', registry[0], '--registry-sha256', registry[1]])])
        receipt = self.public / 'OBSERVER.json'; observer = self.promote(observed, receipt, 'observe')
        bundle = {'schema': 'kpx7-owner-privacy-prediction-bundle/v1', 'experiment_sha256': EXPERIMENT,
            'session_sha256': session[1], 'projection_sha256': projection[1], 'coordinator_predictions_sha256': self.selector(pred)[1],
            'colluder_observer_receipt_sha256': self.selector(receipt)[1],
            'colluder_capsule_seal_sha256': observer['capsule_seal_sha256']}
        sealed = self.public / 'BUNDLE.json'; write(sealed, canonical_json(bundle))
        scores = [self.controller / ('score-%d' % i) for i in range(3)]
        self.stage('score', [self.score_command('score', scores[i], [*common, '--owner-directory', self.current[i] / 'owner',
            '--predictions', pred, '--predictions-sha256', self.selector(pred)[1], '--observer-receipt', receipt,
            '--observer-receipt-sha256', self.selector(receipt)[1], '--bundle', sealed, '--bundle-sha256', self.selector(sealed)[1],
            '--capsule', self.current[0] / 'owner/diagnostics/OBSERVER-CAPSULE.bin']) for i in range(3)])
        aggregate = self.controller / 'aggregate'
        self.approved_jobs.add(aggregate)
        args = ['--session-sha256', session[1], '--projection-sha256', projection[1], '--bundle', sealed,
            '--bundle-sha256', self.selector(sealed)[1], '--observer-receipt', receipt,
            '--observer-receipt-sha256', self.selector(receipt)[1]]
        args += [v for p in self.current for v in ['--count-file', p / 'owner/diagnostics/COUNTS.bin']]
        self.stage('aggregate', [self.score_command('aggregate', aggregate, args)])
        counts = self.promote(aggregate, self.public / 'COUNTS.json', 'aggregate')
        return world_event(observer, counts)

    def run(self):
        # Default mode authenticates source/public selectors only. It allocates no world/owner.
        need(not self.output.exists(), 'fresh-cohort-output')
        if not self.args.execute:
            return {'status': 'SOURCE_PREFLIGHT_ONLY', 'registered_world_count': 16, 'owner_init_count': 0}
        fresh(self.output); public = self.output / 'public'; public.mkdir(mode=0o700)
        write(public / 'ASSETS.json', canonical_json(self.assets))
        write(public / 'REGISTRATION.json', canonical_json({'schema': 'kpx7-cohort-registration/v1',
            'world_ids': self.spec['world_ids'], 'contract_sha256': CONTRACT,
            'spec_sha256': self.args.spec_sha256, 'excluded_initial_session_sha256': INITIAL_SESSION}))
        events = []; halted = False
        for world in self.spec['world_ids']:
            attempted = not halted
            try:
                if halted:
                    (self.output / world / 'public').mkdir(parents=True, mode=0o700)
                    event = {'status': 'INCOMPLETE', 'candidate_failed': False, 'S': None, 'K': None,
                             'reason': 'unattempted-after-operational-MPC-stop'}
                else:
                    event = self.run_world(world)
            except ConfirmedFalsification as error:
                # Only an explicit trusted confirmed verdict uses this path;
                # a rejection, missing file or process error is not acceptance of invalid effects.
                event = {'status': 'CANDIDATE_FAIL', 'candidate_failed': True,
                         'S': None, 'K': None, 'reason': str(error)}
            except Exception as error:
                # Retain this exact world/authorization/failure. No retry, replacement or score-based stop.
                event = {'status': 'INCOMPLETE', 'candidate_failed': False, 'S': None, 'K': None,
                         'reason': safe_reason(error)}
                # A failed/unknown owned-container cleanup must not overlap a later proof phase.
                # This is operational stopping, never a score-dependent stop or replacement.
                halted = getattr(self, 'last_stage', None) == 'mpc-mixed'
            event = {'world_id': world, 'attempted': attempted,
                     'classification_pending': event['status'] == 'INCOMPLETE', **event}
            write(self.output / world / 'public/WORLD-RESULT.json', canonical_json(event))
            events.append(event)
            print(json.dumps({'world': world, 'status': event['status']}, sort_keys=True), flush=True)
        result = summarize(events)
        result.update({'contract_sha256': CONTRACT, 'spec_sha256': self.args.spec_sha256,
                       'attempted_worlds': sum(e['attempted'] for e in events),
                       'classification_pending_worlds': sum(e['classification_pending'] for e in events),
                       'candidate_safety_established': False,
                       'native_VM_or_outer_proof_per_world': False, 'privacy_qualified': False})
        write(public / 'COHORT-RESULT.json', canonical_json(result))
        return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    if len(sys.argv) > 1 and sys.argv[1] == '_resource':
        parser.add_argument('--cpu', type=int, required=True); parser.add_argument('--memory', type=int, required=True)
        parser.add_argument('--metrics', required=True)
        return resource_child(parser.parse_args(sys.argv[2:]))
    parser.add_argument('--spec', required=True); parser.add_argument('--spec-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--exclude-private-root', action='append', required=True)
    parser.add_argument('--exclude-retained-private-directory', action='append', required=True)
    parser.add_argument('--execute', action='store_true')
    try:
        print(json.dumps(Cohort(parser.parse_args()).run(), sort_keys=True)); return 0
    except Exception as error:
        parser.exit(2, 'cohort INCOMPLETE: ' + safe_reason(error) + '\n')


if __name__ == '__main__':
    sys.exit(main())
