#!/usr/bin/env python3
"""Snapshot and launch one PUBLIC actor-only network-off child producer.

Root owns the resource/heavy execution window. Default only prepares an exact
namespace command. No other backup, seed, private witness, controller or original
operator source directory is mounted. Known-unsafe setup records stay separate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

from reuse import load, ROOT, PINS

HERE = Path(__file__).resolve().parent
OWN = ('reuse.py', 'payment.py', 'public_fixture.py', 'public_child.py')


def main(args):
    c = load()
    p = c.primitives
    controller = c.receiver.no_symlinks(args.controller)
    p.need(not controller.is_relative_to(ROOT) and not controller.exists(), 'fresh-owner-controller-outside-Git')
    controller.mkdir(parents=True, mode=0o700)
    software = controller / 'software'
    software.mkdir(mode=0o700)
    public = controller / 'public-inputs'
    public.mkdir(mode=0o700)
    output = controller / 'client-output'
    output.mkdir(mode=0o700)
    copied = []
    for name in OWN:
        source = c.receiver.no_symlinks(HERE / name)
        raw = source.read_bytes()
        target = software / name
        target.write_bytes(raw)
        target.chmod(0o400)
        copied.append({'logical': '/work/poc/independent-single-payment/' + name,
                       'path': str(target), 'sha256': hashlib.sha256(raw).hexdigest()})
    for name, expected in PINS.items():
        source = c.receiver.no_symlinks(ROOT / 'poc/compact-batch-lifecycle' / (name + '.py'))
        raw = source.read_bytes()
        p.need(hashlib.sha256(raw).hexdigest() == expected, 'exact-reused-helper-before-namespace')
        target = software / ('compat-' + name + '.py')
        target.write_bytes(raw)
        target.chmod(0o400)
        copied.append({'logical': '/work/poc/compact-batch-lifecycle/' + name + '.py',
                       'path': str(target), 'sha256': expected})
    raw = c.receiver.no_symlinks(c.receiver.SOURCE).read_bytes()
    p.need(hashlib.sha256(raw).hexdigest() == c.receiver.SOURCE_SHA, 'selected-V2-source')
    target = software / 'recipient-v2.py'
    target.write_bytes(raw)
    target.chmod(0o400)
    copied.append({'logical': '/work/poc/future-recipient/v2/recipient.py',
                   'path': str(target), 'sha256': c.receiver.SOURCE_SHA})
    for name in ('profile', 'context', 'manifest'):
        raw = c.receiver.no_symlinks(getattr(args, name)).read_bytes()
        target = public / (name + '.json')
        target.write_bytes(raw)
        target.chmod(0o400)
    # These are public objects. Selection/content checks run again inside.
    c.native_runtime.Executable(args.prover, args.prover_sha256)
    pk = c.receiver.no_symlinks(args.pk)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp']
    for row in copied:
        command += ['--ro-bind', row['path'], row['logical']]
    for name in ('profile', 'context', 'manifest'):
        command += ['--ro-bind', str(public / (name + '.json')), '/' + name + '.json']
    for path in (c.receiver.CRYPTO, c.native_runtime.NATIVE):
        command += ['--ro-bind', str(path), str(path)]
    command += ['--ro-bind', str(c.receiver.no_symlinks(args.prover)), '/prover',
        '--ro-bind', str(pk), '/parameters.pk', '--bind', str(output), '/out',
        '--chdir', '/work/poc/independent-single-payment', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC',
        '/usr/bin/python3', '-B', '/work/poc/independent-single-payment/public_child.py',
        '--profile', '/profile.json', '--profile-sha256', args.profile_sha256, 'prove-child',
        '--context', '/context.json', '--context-sha256', args.context_sha256,
        '--manifest', '/manifest.json', '--prover', '/prover', '--prover-sha256', args.prover_sha256,
        '--pk', '/parameters.pk', '--output', '/out/run', '--workers', str(args.workers), '--execute']
    absent = list(args.must_be_absent) + [ROOT, pk, c.receiver.no_symlinks(args.prover), controller]
    for path in absent:
        command += ['--must-be-absent', str(path)]
    plan = {'schema': 'kpx5-public-owner-namespace-plan/v1', 'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND',
        'source_snapshots': copied, 'command': command, 'network_unshared': True,
        'other_owner_backup_private_witness_or_controller_mounted': False,
        'resource_limits_owned_by_root_scheduler': True, 'workers': args.workers}
    c.native_runtime.save(controller / 'NAMESPACE-PLAN.json', plan)
    if not args.execute:
        return {'prepared': True, 'executed': False, 'PK_native_proof_or_actor_seed_read': False}
    start = time.monotonic()
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    (controller / 'PUBLIC-STDOUT.log').write_text(result.stdout)
    (controller / 'PUBLIC-STDERR.log').write_text(result.stderr)
    receipt = {'returncode': result.returncode, 'wall_seconds': time.monotonic() - start,
        'namespace_process_waited': True, 'network_unshared': True,
        'resource_measurement_is_external': True}
    c.native_runtime.save(controller / 'EXECUTION.json', receipt)
    p.need(result.returncode == 0 and (output / 'run/RESULTS.json').is_file(), 'public-owner-namespace-failed')
    return {'prepared': True, 'executed': True, 'wall_seconds': receipt['wall_seconds'],
        'genuine_public_component_written': True, 'actual_wrapper_chain_or_currentness_claimed': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('controller', type=Path)
    for name in ('profile', 'context', 'manifest', 'prover', 'pk'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('profile-sha256', 'context-sha256', 'prover-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--must-be-absent', type=Path, action='append', default=[])
    try:
        print(json.dumps(main(parser.parse_args()), sort_keys=True))
    except (ValueError, KeyError, TypeError, OSError):
        raise SystemExit('public-owner namespace refused') from None

