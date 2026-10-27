#!/usr/bin/env python3
"""Explicit outer provenance for the known-public writer fix; old checks stay intact."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys

BASE = Path(__file__).absolute().parents[1]
ROOT = BASE.parents[1]
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/local-private-payment-01')
BASE_CALLER = {'path': str(BASE / 'integration/campaign_cached.py'),
    'sha256': '586a8852bff9b5dbfce13d0f16a70546d9f94d39553d9a4bc1df85d6ce655bd8'}
BASE_LAUNCHER = {'path': str(BASE / 'integration/launch_cached_campaign.py'),
    'sha256': '4291fff9733021a0317277be0ad2d3dd75055276dc2274c3f0d075cfa1caf32f'}


def need(ok, category):
    if not ok:
        raise ValueError(category)


def checked(path):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical-path')
    return path


def attributes(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)


def publish_known_json(path, value):
    """Never read back a file containing only these known-public encoded bytes.

    Historical private-inode exclusion sets remain untouched. O_EXCL refuses
    existing files/aliases, and complete writes, fsync and metadata are checked.
    All later financial input reads still go through the original base caller.
    """
    path = checked(path)
    need(not path.is_relative_to(PRIVATE), 'public-write-outside-private-parent')
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.fchmod(fd, 0o400)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            need(type(count) is int and 0 < count <= len(raw) - offset, 'public-write-made-no-progress')
            offset += count
        os.fsync(fd)
        own = os.fstat(fd)
        need(stat.S_ISREG(own.st_mode) and own.st_nlink == 1 and own.st_size == len(raw),
             'complete-known-public-write')
        need(attributes(path.lstat()) == attributes(own), 'known-public-write-path-replaced')
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest()}


def module(row, name, read):
    source = read(row['path'], row['sha256'])
    value = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    value.__file__ = row['path']
    sys.modules[name] = value
    sys.path.insert(0, str(Path(row['path']).parent))
    exec(compile(source, row['path'], 'exec'), value.__dict__)
    return value


def load_profile(path, expected):
    h = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
    read = h['read']
    profile = json.loads(read(str(path), expected))
    need(set(profile) == {'schema', 'fix_scope', 'entry_source', 'base_caller', 'base_launcher',
        'proposal', 'materialization', 'campaign_selection', 'private_directory',
        'trial_private_directory', 'output_directory', 'unit', 'confirmed_boundary'}, 'writer-profile-fields')
    need(profile['schema'] == 'kpxa-known-public-writer-entry/v1'
         and profile['fix_scope'] == 'known-public-json-write-without-readback'
         and profile['base_caller'] == BASE_CALLER and profile['base_launcher'] == BASE_LAUNCHER
         and profile['entry_source']['path'] == str(Path(__file__).absolute()), 'explicit-base-and-new-entry-identity')
    read(profile['entry_source']['path'], profile['entry_source']['sha256'])
    for name in ('base_caller', 'base_launcher', 'proposal', 'materialization', 'campaign_selection'):
        row = profile[name]
        read(row['path'], row['sha256'])
    base = module(BASE_CALLER, '_kpxa_writer_fix_base', read)
    launcher = module(BASE_LAUNCHER, '_kpxa_writer_fix_launcher', read)
    materialized = base.parse(read(profile['materialization']['path'], profile['materialization']['sha256']))
    need(materialized['proposal'] == profile['proposal']
         and materialized['campaign_selection'] == profile['campaign_selection']
         and materialized['caller_source'] == BASE_CALLER,
         'same-old-validated-selection-and-base-caller')
    boundary = profile['confirmed_boundary']
    marker = base.parse(read(boundary['path'], boundary['sha256']))
    need(marker['action'] == 'action-0003'
         and marker['transaction_id'] == '638a30aeb70c7b0b0a1ec464b749dac67c500bd89ca99a33c4d8e67213d0ae14',
         'same-public-confirmed-third-action')
    need(checked(profile['private_directory']) == PRIVATE / 'campaign-trial-02'
         and checked(profile['trial_private_directory']) == PRIVATE / 'local-pay-testnet-02'
         and checked(profile['output_directory']) == Path('/var/tmp/kpi-local-private-payment-01/campaign/trial-02/run')
         and profile['unit'] == 'local-payment-campaign-05', 'same-existing-caller-and-fresh-unit-interface')
    need(not (Path(profile['output_directory']) / 'action-0004').exists(), 'no-fourth-action-started')
    return profile, base, launcher


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation', choices=('launch', 'run'))
    p.add_argument('--profile', type=Path, required=True)
    p.add_argument('--profile-sha256', required=True)
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    profile, base, launcher = load_profile(a.profile, a.profile_sha256)
    selected = profile['campaign_selection']

    class KnownPublicWriter(base.Campaign):
        def save_public(self, path, value):
            return publish_known_json(path, value)

    if a.operation == 'run':
        need(a.execute, 'explicit-execution-release-required')
        caller = KnownPublicWriter(selected['path'], selected['sha256'],
            Path(profile['private_directory']), Path(profile['output_directory']))
        lock = os.open(Path(profile['private_directory']) / 'CALLER-LOCK', os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            caller.run()
        finally:
            os.close(lock)
        return
    # Reuse every existing public frozen-proposal/materialization/cold check.
    producer = launcher.Producer()
    producer.launch(profile['proposal'], profile['materialization'],
        Path(profile['private_directory']), Path(profile['output_directory']),
        Path(profile['trial_private_directory']), profile['unit'], execute=False, resume=True)
    if not a.execute:
        print('KNOWN_PUBLIC_WRITER_PREFLIGHT_ONLY')
        return
    probe = subprocess.run(['/usr/bin/systemctl', '--user', 'show', profile['unit'] + '.service',
        '--property=LoadState', '--value'], capture_output=True, text=True)
    need(probe.stdout.strip() == 'not-found', 'fresh-no-restart-unit-required')
    receipt_path = Path(profile['output_directory']) / ('WRITER-RESUME-LAUNCH-' + profile['unit'] + '.json')
    need(not receipt_path.exists(), 'fresh-public-launch-receipt')
    private = Path(profile['private_directory'])
    command = ['/usr/bin/systemd-run', '--user', '--unit', profile['unit'], '--property=Restart=no',
        '--property=UMask=0077', '--property=WorkingDirectory=' + str(ROOT),
        '--property=StandardOutput=append:' + str(private / 'CONTROLLER.stdout'),
        '--property=StandardError=append:' + str(private / 'CONTROLLER.stderr'),
        '--setenv=PATH=/usr/bin:/bin', '--setenv=LANG=C.UTF-8', '--setenv=TZ=UTC',
        '/usr/bin/python3', '-B', str(Path(__file__).absolute()), 'run', '--profile', str(a.profile),
        '--profile-sha256', a.profile_sha256, '--execute']
    started = subprocess.run(command, capture_output=True)
    need(started.returncode == 0, 'detached-unit-start-refused')
    receipt = {'schema': 'kpxa-known-public-writer-launch/v1', 'unit': profile['unit'] + '.service',
        'restart_policy': 'no', 'entry_source': profile['entry_source'], 'base_caller': BASE_CALLER,
        'profile': {'path': str(a.profile), 'sha256': a.profile_sha256}, 'campaign_selection': selected,
        'same_private_plan_state_and_invoices_retained': True, 'private_contents_read_by_launcher': False,
        'financial_submission_performed_by_launcher': False}
    publish_known_json(receipt_path, receipt)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('writer-fix entry refused; preserve all state and never retry a consumed submission')
