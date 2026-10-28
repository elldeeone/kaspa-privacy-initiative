#!/usr/bin/env python3
"""Isolated ADR-0074 public R0 stages; no wallet, MPC witness or network input.

Reuse the authenticated legacy full-parent Guard and pinned worker/runtime
helper. New jobs bind a caller-selected fresh domain, component manifest, image,
104-byte journal and 10,685-byte native projection. A dry stage is not execution.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[4]
LEGACY = ROOT / 'poc/local-private-payment/execution/outer.py'
LEGACY_SHA = '02700ec04438c777b98d82c23b1843e3bb7b431bc8d5629c331a074f0f44b53e'
BOOTSTRAP = Path('/var/tmp/kpi-root-guard-helper-09.py')
BOOTSTRAP_SHA = '0f8ff562a4364c1db7729d98d7daf57f75ff5e882936e06e9907a4e936bd82fd'
SCHEMA = 'private-batch-outer-job/v1'
OPS = ('execute', 'prove', 'compress', 'verify', 'native-proof')
PROJECTION_LEN = 10685
BODY_LEN = 10492
PREFIX_LEN = 193


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def private_metadata(roots):
    """Register whole caller-selected parents without opening their contents."""
    need(bool(roots), 'whole-private-parent-exclusions-required')
    directories = tuple(Path(root).absolute() for root in roots)
    need(len(directories) == len(set(directories)), 'distinct-private-exclusions')
    inodes = set()
    for root in directories:
        need('..' not in root.parts and root.is_dir()
             and not any(path.is_symlink() for path in (root, *root.parents)),
             'private-parent-metadata-only')
        need(all(not root.is_relative_to(Path(system)) for system in
                 ('/usr', '/etc/alternatives', '/lib', '/lib64')),
             'private-parent-outside-worker-system-mounts')
        def failed(error):
            raise ValueError('private-metadata-enumeration-failed') from error
        for current, names, files in os.walk(root, followlinks=False, onerror=failed):
            names[:] = [name for name in names if not (Path(current) / name).is_symlink()]
            for name in files:
                info = (Path(current) / name).lstat()
                if stat.S_ISREG(info.st_mode):
                    inodes.add((info.st_dev, info.st_ino))
    return directories, inodes


def fixed_bootstrap(directories, inodes):
    """Authenticate the retained trusted guard code, after fresh-parent metadata.

    The unchanged guard09/helper08 closure is the existing workflow's trusted
    bootstrap. Fresh owner/MAC/TLS parents are added before any selected file
    body is admitted. The legacy Guard later enforces all retained old parents.
    """
    need(not any(path.is_symlink() for path in (BOOTSTRAP, *BOOTSTRAP.parents)),
         'canonical-bootstrap-code')
    need(all(not BOOTSTRAP.is_relative_to(root) for root in directories),
         'bootstrap-inside-fresh-private-parent')
    before = BOOTSTRAP.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and (before.st_dev, before.st_ino) not in inodes, 'bootstrap-private-alias')
    fd = os.open(BOOTSTRAP, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        need(tuple(getattr(before, name) for name in attributes)
             == tuple(getattr(opened, name) for name in attributes), 'bootstrap-open-race')
        raw = source.read()
        after = os.fstat(source.fileno())
    need(tuple(getattr(before, name) for name in attributes)
         == tuple(getattr(after, name) for name in attributes)
         and len(raw) == before.st_size
         and hashlib.sha256(raw).hexdigest() == BOOTSTRAP_SHA,
         'unchanged-trusted-bootstrap-source')
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader('private_batch_bootstrap_guard09', loader=None))
    module.__file__ = str(BOOTSTRAP)
    exec(compile(raw, str(BOOTSTRAP), 'exec'), module.__dict__)
    base = module.m.GUARD
    base.directories = tuple(dict.fromkeys((*base.directories, *directories)))
    base.inodes.update(inodes)
    return module


def legacy(roots):
    directories, inodes = private_metadata(roots)
    bootstrap = fixed_bootstrap(directories, inodes)
    # All fresh exclusions are active in guard09 before this selected source
    # body read. No unverified legacy Python code is executed.
    raw = bootstrap.read(LEGACY, LEGACY_SHA)
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader('private_batch_legacy_outer', loader=None))
    module.__file__ = str(LEGACY)
    exec(compile(raw, str(LEGACY), 'exec'), module.__dict__)
    return module


def digest32(module, value, reason):
    module.external_pin(value)
    need(value != '00' * 32, reason)
    return value


def selected(guard, base, module, path, pin, op):
    need(op in OPS, 'known-outer-operation')
    job = module.parse(base.read(guard, path, module.external_pin(pin)))
    need(type(job) is dict and set(job) == {'schema', 'domain_hex32',
         'component_profile_sha256', 'image_id_hex32', 'files'}, 'exact-outer-selection-fields')
    need(job['schema'] == SCHEMA, 'private-batch-outer-schema')
    digest32(module, job['domain_hex32'], 'fresh-domain-required')
    digest32(module, job['component_profile_sha256'], 'selected-component-identity')
    digest32(module, job['image_id_hex32'], 'selected-image-identity')
    names = {'host', 'program', 'journal', 'projection' if op in ('execute', 'prove') else 'receipt'}
    need(type(job['files']) is dict and set(job['files']) == names, 'exact-stage-file-selectors')
    for row in job['files'].values():
        need(type(row) is dict and set(row) == {'path', 'sha256'}
             and type(row['path']) is str, 'exact-public-file-selector')
        module.external_pin(row['sha256'])
        guard.metadata(row['path'])
    return job


def check_journal(job, journal):
    need(len(journal) == 104 and journal[:8] == b'KPBAJR01'
         and journal[8:40].hex() == job['domain_hex32']
         and journal[40:72].hex() == job['component_profile_sha256'],
         'selected-private-batch-journal104')


def stage(guard, base, module, job, op, output, threads=2):
    need(op in OPS, 'known-outer-operation')
    need(type(threads) is int and threads >= 1, 'positive-resource-thread-selection')
    gpu = op in ('prove', 'compress')
    worker = module.TOOLS / ('r0vm-cuda' if gpu else 'r0vm')
    worker_pin = module.WORKER_SHA if gpu else module.CPU_WORKER_SHA
    # No runtime body is opened until every selected member passed metadata
    # checks against all whole old/fresh parents and their regular-file inodes.
    for row in job['files'].values():
        guard.metadata(row['path'])
    guard.metadata(worker)
    if op == 'compress':
        for name in module.COMPRESSION:
            guard.metadata(module.EXTENSION / name)
    output = module.fresh(base.output_path(guard, output))
    command = module.bubble()
    rows = dict(job['files'])
    rows['worker'] = {'path': str(worker), 'sha256': worker_pin}
    for name, row in rows.items():
        target = output / name
        module.staged(row['path'], target, row['sha256'], name in ('host', 'worker'))
        command += ['--ro-bind', str(target), '/' + name]
    journal = base.read(guard, output / 'journal', rows['journal']['sha256'])
    check_journal(job, journal)
    if op in ('execute', 'prove'):
        projection = base.read(guard, output / 'projection', rows['projection']['sha256'])
        need(len(projection) == PROJECTION_LEN and projection[:8] == b'KPBAFX01'
             and projection[PREFIX_LEN:PREFIX_LEN + 8] == b'KPBAEF01'
             and projection[PREFIX_LEN + 104:PREFIX_LEN + 136].hex() == job['domain_hex32']
             and int.from_bytes(projection[189:193], 'little') == BODY_LEN
             and journal[72:] == hashlib.sha256(projection).digest(),
             'selected-projection10685-journal-join')
        invocation = ['/host', op, '/program', '/projection', '/out/result']
    else:
        invocation = ['/host', op, '/receipt']
        if op == 'compress':
            invocation += [rows['receipt']['sha256']]
        invocation += ['/journal', '/out/result']
    client = output / 'public-output'
    client.mkdir()
    scratch = output / 'scratch'
    scratch.mkdir()
    for directory in ('home', 'cache', 'work', 'risc0/extensions'):
        (scratch / directory).mkdir(parents=True, exist_ok=True)
    command += ['--bind', str(client), '/out', '--bind', str(scratch), '/scratch']
    compression = []
    if op == 'compress':
        for name, pin in module.COMPRESSION.items():
            path, info = base.stream_selected(guard, module.EXTENSION / name, pin)
            command += ['--ro-bind', str(path),
                        '/scratch/risc0/extensions/v0.1.0-risc0-groth16/' + name]
            compression.append({'path': str(path), 'sha256': pin,
                                'attributes': list(base.attributes(info))})
    if gpu:
        devices = sorted(Path('/dev').glob('nvidia*'))
        need(bool(devices), 'selected-GPU-device-present')
        for device in devices:
            command += ['--dev-bind', str(device), str(device)]
    command += ['--setenv', 'HOME', '/scratch/home', '--setenv', 'XDG_CACHE_HOME', '/scratch/cache',
        '--setenv', 'RISC0_HOME', '/scratch/risc0', '--setenv', 'RISC0_WORK_DIR', '/scratch/work',
        '--setenv', 'RISC0_PROVER', 'ipc', '--setenv', 'RISC0_SERVER_PATH', '/worker',
        '--setenv', 'RAYON_NUM_THREADS', str(threads), '--setenv', 'OMP_NUM_THREADS', str(threads),
        '--setenv', 'CUDA_VISIBLE_DEVICES', '0',
        '--setenv', 'LD_LIBRARY_PATH', '/usr/lib/x86_64-linux-gnu',
        '--setenv', 'GITHUB_TOKEN', '', '--chdir', '/scratch', *invocation]
    plan = {'schema': 'private-batch-outer-stage/v1', 'op': op,
            'domain_hex32': job['domain_hex32'], 'component_profile_sha256': job['component_profile_sha256'],
            'image_id_hex32': job['image_id_hex32'], 'files': rows,
            'journal_sha256': rows['journal']['sha256'], 'command': command,
            'compression_assets': compression, 'GPU_selected': gpu,
            'network_namespace': 'UNSHARED', 'wallet_or_PK_or_host_home_mounted': False,
            'worker_started': False, 'selected_threads': threads, 'native_or_chain_acceptance': False,
            'bootstrap_guard_sha256': BOOTSTRAP_SHA, 'legacy_outer_sha256': LEGACY_SHA,
            'runtime_helper_sha256': base.HELPER_SHA}
    module.save(output / 'STAGE.json', plan)
    return output, command, plan


def execute(guard, base, module, output, command, plan):
    for name, row in plan['files'].items():
        base.read(guard, output / name, row['sha256'])
    for row in plan['compression_assets']:
        _, info = guard.metadata(row['path'])
        need(list(base.attributes(info)) == row['attributes'], 'compression-changed-before-worker')
    resources = module.call(command, output, monitor_gpu=plan['GPU_selected'])
    result = output / 'public-output' / 'result'
    report = module.parse(base.read(guard, result / 'report.json'))
    need(type(report) is dict, 'returned-report-object')
    # Every new host operation reports both joins. No legacy verify/compress
    # exception may accept a missing image or journal identity.
    need(report.get('journal_sha256') == plan['journal_sha256'], 'returned-report-selected-journal')
    need(report.get('image_id_hex32') == plan['image_id_hex32'], 'returned-report-selected-image')
    positive = {'execute': 'genuine_seven_G16_public_guest_execution_passed',
                'prove': 'genuine_seven_G16_succinct_receipt_verified',
                'compress': 'same_claim_genuine_Groth16_compression_verified',
                'verify': 'genuine_new_image_receipt_verified',
                'native-proof': 'genuine_new_image_Groth16_receipt_verified'}
    need(report.get(positive[plan['op']]) is True, 'selected-operation-success-report')
    expected = base.read(guard, output / 'journal', plan['journal_sha256'])
    check_journal(plan, expected)
    if plan['op'] != 'verify':
        produced = base.read(guard, result / 'journal.bin', plan['journal_sha256'])
        need(len(produced) == 104 and produced == expected, 'returned-exact-journal-bytes')
    for row in plan['compression_assets']:
        _, info = guard.metadata(row['path'])
        need(list(base.attributes(info)) == row['attributes'], 'compression-changed-during-worker')
    outcome = {'schema': 'private-batch-outer-result/v1', 'op': plan['op'],
               'worker_completed': True, 'exact_external_journal_matched': True,
               'image_id_hex32': plan['image_id_hex32'],
               'component_profile_sha256': plan['component_profile_sha256'],
               'worker_image_report_compared': True, 'worker_journal_report_compared': True,
               'resources': resources, 'worker_report': report, 'native_or_chain_acceptance': False}
    module.save(output / 'RESULT.json', outcome)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=OPS)
    parser.add_argument('--selection', required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--threads', type=int, default=2)
    parser.add_argument('--exclude-private-directory', action='append', required=True)
    parser.add_argument('--execute', action='store_true', help='launch only this selected stage')
    args = parser.parse_args()
    base = legacy(args.exclude_private_directory)
    guard = base.Guard(args.exclude_private_directory)
    module = base.helper(guard)
    job = selected(guard, base, module, args.selection, args.selection_sha256, args.op)
    output, command, plan = stage(guard, base, module, job, args.op, args.output, args.threads)
    if args.execute:
        execute(guard, base, module, output, command, plan)
    print(__import__('json').dumps({'output': str(output), 'op': args.op,
                                  'worker_started': args.execute}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError):
        print('selected-private-batch-public-outer-stage-refused', file=sys.stderr)
        raise SystemExit(2)
