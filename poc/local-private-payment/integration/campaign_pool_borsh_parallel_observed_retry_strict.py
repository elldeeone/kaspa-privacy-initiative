#!/usr/bin/env python3
"""Observed strict single-retry Parallel-prefix Borsh pool entry; original caller and submitter stay intact."""
import argparse
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys
import time

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
BASE_CALLER = {'path': str(BASE / 'integration/campaign_cached.py'),
    'sha256': '586a8852bff9b5dbfce13d0f16a70546d9f94d39553d9a4bc1df85d6ce655bd8'}
BASE_LAUNCHER = {'path': str(BASE / 'integration/launch_cached_campaign.py'),
    'sha256': '4291fff9733021a0317277be0ad2d3dd75055276dc2274c3f0d075cfa1caf32f'}
WRITER = {'path': str(BASE / 'integration/campaign_writer_fix.py'),
    'sha256': '6ee8400700db857e0f52e0dfb67b6cb100f36d232483bf06cc1e40cc8ad9c3e5'}


def need(ok, category):
    if not ok:
        raise ValueError(category)


def module(row, name, read):
    raw = read(row['path'], row['sha256'])
    value = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    value.__file__ = row['path']
    sys.modules[name] = value
    sys.path.insert(0, str(Path(row['path']).parent))
    exec(compile(raw, row['path'], 'exec'), value.__dict__)
    return value


def fresh_public_reader():
    """Use a fresh, unchanged helper09 for each instance public read.

    Current private path/inode aliases still fail before bytes are read. Only
    historical metadata from earlier reads is not retained here. The private
    reader and every expected public SHA remain unchanged.
    """
    def read(path, expected=None):
        return runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read'](path, expected)
    return read


def protected_head_matches(base, private, profile, expected_handoff):
    """Own-controller comparison only; no values, counts, or hashes are exported."""
    state = base.parse(base.read(private / 'STATE.json', private=True))
    need(state['schema'] == 'kpxa-private-campaign-state/v1'
         and state['head'] == expected_handoff['selectors']
         and type(state['next_action']) is int
         and state['next_action'] == profile['expected_next_action']
         and state['submission_consumed'] is profile['expected_submission_consumed'],
         'protected-current-head-must-match-Root-selected-genuine-handoff')
    if profile['expected_submission_consumed']:
        need(state['qualified_case'] == profile['expected_qualified_case'],
             'same-consumed-public-qualified-case')


def pool_argv(argv, scripts, selected):
    """Only the two explicit host chain seams receive a pool selector."""
    values = list(map(str, argv))
    is_submit = len(values) > 1 and values[1] == scripts['submit']['path']
    is_confirm = len(values) > 2 and values[2] == scripts['confirm']['path']
    if is_submit or is_confirm:
        need('--pool-selection' not in values, 'single-explicit-pool-selector')
        values += ['--pool-selection', selected['path'], '--pool-selection-sha256', selected['sha256']]
    return values


def validate_pool_socket(unit, socket):
    match = re.fullmatch('local-payment-campaign-([0-9]{2,})', unit)
    need(match is not None, 'neutral-numbered-pool-unit')
    socket = Path(socket).absolute()
    need(len(os.fsencode(str(socket))) <= 107, 'unix-socket-path-too-long')
    expected = Path('/var/tmp/kpi-local-private-payment-01') / ('pool-ipc-' + match.group(1)) / 'p.sock'
    need(socket == expected, 'unit-specific-public-only-ipc-directory')
    return socket


def run_after_pool_ready(server, socket, run):
    """Readiness waits precede every base caller financial-consumption branch."""
    while not socket.exists():
        need(server.poll() is None, 'pool-cold-admission-failed-before-financial-consumption')
        time.sleep(0.2)
    s = socket.lstat()
    need(stat.S_ISSOCK(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o600
         and s.st_uid == os.getuid() and server.poll() is None, 'ready-public-offline-pool')
    return run()


def service_prefix(unit):
    return ['/usr/bin/systemd-run', '--user', '--unit', unit, '--property=Restart=no',
            '--property=KillMode=control-group', '--property=LimitNOFILE=65536', '--property=UMask=0077']


def load_profile(path, expected):
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    base = module(BASE_CALLER, '_kpxa_pool_campaign_base', read)
    writer = module(WRITER, '_kpxa_pool_campaign_writer', read)
    launcher = module(BASE_LAUNCHER, '_kpxa_pool_campaign_launcher', read)
    p = base.parse(read(str(path), expected))
    base.fields(p, ('schema', 'scope', 'entry_source', 'base_caller', 'base_launcher', 'writer_source',
        'parent_proposal', 'parent_materialization', 'parent_selection', 'campaign_selection',
        'pool_selection', 'private_directory', 'trial_private_directory', 'output_directory', 'unit',
        'expected_head_handoff', 'expected_next_action', 'expected_submission_consumed',
        'expected_qualified_case'), 'explicit-pool-campaign-profile-fields')
    need(p['schema'] == 'kpxa-pool-campaign-entry/v1' and p['scope'] == 'public-offline-roles-only'
         and p['base_caller'] == BASE_CALLER and p['base_launcher'] == BASE_LAUNCHER
         and p['writer_source'] == WRITER
         and p['entry_source']['path'] == str(Path(__file__).absolute()), 'explicit-old-and-new-source-provenance')
    for name in ('entry_source', 'parent_proposal', 'parent_materialization', 'parent_selection',
                 'campaign_selection', 'pool_selection', 'expected_head_handoff'):
        row = p[name]
        read(row['path'], row['sha256'])
    mat = base.parse(read(p['parent_materialization']['path'], p['parent_materialization']['sha256']))
    need(mat['proposal'] == p['parent_proposal'] and mat['campaign_selection'] == p['parent_selection']
         and mat['caller_source'] == BASE_CALLER, 'original-validated-campaign-parent')
    parent = base.parse(read(p['parent_selection']['path'], p['parent_selection']['sha256']))
    selected = base.parse(read(p['campaign_selection']['path'], p['campaign_selection']['sha256']))
    pool = base.parse(read(p['pool_selection']['path'], p['pool_selection']['sha256']))
    need(pool['schema'] == 'kpxa-public-offline-pool-selection/v1'
         and pool['scope'] == 'local-offline-public-replay-and-preflight-only'
         and pool['parent_runtime'] == parent['cache_policy']['runtime_source']
         and pool['parent_admission'] == parent['cache_policy']['admission'], 'same-frozen-financial-runtime-and-admission')
    members = {row['path']: row for row in pool['source_members']}
    need(members.get(p['entry_source']['path']) == p['entry_source']
         and members.get(BASE_CALLER['path']) == BASE_CALLER and members.get(WRITER['path']) == WRITER
         and members.get(BASE_LAUNCHER['path']) == BASE_LAUNCHER,
         'pool-profile-honestly-records-caller-and-writer')
    for name in ('server', 'client', 'core', 'supervisor', 'admit'):
        need(members.get(pool[name]['path']) == pool[name], 'executed-pool-entry-is-source-selected')
    for row in pool['source_members']:
        read(row['path'], row['sha256'])
    expected_selected = {**parent, 'scripts': dict(parent['scripts'])}
    for name, filename in (('submit', 'submit_pool.mjs'), ('confirm', 'confirm_pool_borsh_parallel_observed_retry_strict.py')):
        path = str(BASE / 'chain' / filename)
        need(path in members, 'selected-pool-chain-seam-present')
        expected_selected['scripts'][name] = members[path]
    need(selected == expected_selected, 'only-two-chain-script-selectors-may-change')
    private = base.checked(p['private_directory'])
    output = base.checked(p['output_directory'])
    need(private == PRIVATE / 'campaign-trial-02'
         and base.checked(p['trial_private_directory']) == PRIVATE / 'local-pay-testnet-02'
         and output == Path('/var/tmp/kpi-local-private-payment-01/campaign/trial-02/run'), 'same-existing-caller-interface')
    need(type(p['unit']) is str and re.fullmatch('[a-z][a-z0-9-]{0,62}', p['unit']), 'neutral-pool-unit-name')
    socket = base.checked(validate_pool_socket(p['unit'], pool['socket']))
    need(not socket.parent.exists(), 'fresh-unit-specific-ipc-directory')
    need(type(p['expected_next_action']) is int and 0 <= p['expected_next_action'] < 15
         and type(p['expected_submission_consumed']) is bool, 'explicit-resume-branch')
    if not p['expected_submission_consumed']:
        need(p['expected_qualified_case'] is None, 'unconsumed-boundary-has-no-qualified-case')
    head = base.parse(read(p['expected_head_handoff']['path'], p['expected_head_handoff']['sha256']))
    need(head['accepted_whole_CASE_equals_expected'] is True
         and head['trial_id'] == selected['trial_id'], 'Root-selected-genuine-current-head')
    return p, base, writer, launcher, pool, head


def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('operation', choices=('launch', 'run'))
    a.add_argument('--profile', type=Path, required=True)
    a.add_argument('--profile-sha256', required=True)
    a.add_argument('--execute', action='store_true')
    args = a.parse_args()
    p, base, writer, launcher, pool, head = load_profile(args.profile, args.profile_sha256)
    private, output = Path(p['private_directory']), Path(p['output_directory'])
    selected = p['campaign_selection']

    class PoolCampaign(base.Campaign):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # Base constructor/source checks stay unchanged. Future public rows
            # use this explicit instance adapter, never a global or fs shim.
            self.public_read = fresh_public_reader()

        def save_public(self, path, value):
            return writer.publish_known_json(path, value)

        def call(self, argv, *, label):
            return super().call(pool_argv(argv, self.selection['scripts'], p['pool_selection']), label=label)

    if args.operation == 'run':
        need(args.execute, 'explicit-pool-execution-release')
        lock = os.open(private / 'CALLER-LOCK', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            protected_head_matches(base, private, p, head)
            caller = PoolCampaign(selected['path'], selected['sha256'], private, output)
            socket = Path(pool['socket'])
            socket.parent.mkdir(mode=0o700)
            parent_info = socket.parent.lstat()
            need(stat.S_IMODE(parent_info.st_mode) == 0o700 and parent_info.st_uid == os.getuid(),
                 'caller-owned-closed-ipc-parent')
            logs = private / ('pool-logs-' + p['unit'])
            logs.mkdir(mode=0o700)
            with (logs / 'stdout').open('xb') as stdout, (logs / 'stderr').open('xb') as stderr:
                server = subprocess.Popen(['/usr/bin/python3', '-B', pool['server']['path'],
                    '--pool-selection', p['pool_selection']['path'], '--pool-selection-sha256', p['pool_selection']['sha256'],
                    '--parent-pid', str(os.getpid())], stdout=stdout, stderr=stderr,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'})
                try:
                    run_after_pool_ready(server, socket, caller.run)
                finally:
                    if server.poll() is None:
                        server.terminate()
                    server.wait()
        finally:
            os.close(lock)
        return
    # Preserve original financial/cold materialization checks for the parent.
    launcher.Producer().launch(p['parent_proposal'], p['parent_materialization'], private, output,
        Path(p['trial_private_directory']), p['unit'], execute=False, resume=True)
    if not args.execute:
        print('PUBLIC_POOL_CAMPAIGN_PREFLIGHT_ONLY')
        return
    probe = subprocess.run(['/usr/bin/systemctl', '--user', 'show', p['unit'] + '.service',
        '--property=LoadState', '--value'], capture_output=True, text=True)
    need(probe.stdout.strip() == 'not-found', 'fresh-pool-unit-required')
    receipt_path = output / ('POOL-RESUME-LAUNCH-' + p['unit'] + '.json')
    need(not receipt_path.exists(), 'fresh-pool-launch-receipt')
    command = [*service_prefix(p['unit']), '--property=WorkingDirectory=' + str(ROOT),
        '--property=StandardOutput=append:' + str(private / 'CONTROLLER.stdout'),
        '--property=StandardError=append:' + str(private / 'CONTROLLER.stderr'),
        '--setenv=PATH=/usr/bin:/bin', '--setenv=LANG=C.UTF-8', '--setenv=TZ=UTC',
        '/usr/bin/python3', '-B', str(Path(__file__).absolute()), 'run', '--profile', str(args.profile),
        '--profile-sha256', args.profile_sha256, '--execute']
    result = subprocess.run(command, capture_output=True)
    need(result.returncode == 0, 'pool-unit-start-refused')
    receipt = {'schema': 'kpxa-pool-campaign-launch/v1', 'unit': p['unit'] + '.service',
        'restart_policy': 'no', 'kill_mode': 'control-group', 'entry_source': p['entry_source'],
        'base_caller': BASE_CALLER, 'writer_source': WRITER, 'pool_selection': p['pool_selection'],
        'profile': {'path': str(args.profile), 'sha256': args.profile_sha256},
        'campaign_selection': selected, 'expected_head_handoff': p['expected_head_handoff'],
        'private_state_head_migrated': False, 'private_contents_read_by_launcher': False,
        'financial_submission_performed_by_launcher': False}
    writer.publish_known_json(receipt_path, receipt)
    print(base.encoded(receipt).decode())


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('pool campaign refused; preserve state and never retry a consumed financial submission')
