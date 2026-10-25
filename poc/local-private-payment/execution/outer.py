#!/usr/bin/env python3
"""Selected public-only local 1/2 R0 stages; isolated workers have no wallet or network."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / 'poc/four-wallet-profile/outer_run.py'
HELPER_SHA = 'da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
SCHEMA = 'local-private-payment-outer-job/v1'
OPS = ('execute', 'prove', 'compress', 'verify', 'native-proof')


RETAINED_PRIVATE_ROOTS = ('/var/tmp/kpi-four-wallet-local-rehearsal-01/owners/A', '/var/tmp/kpi-four-wallet-local-rehearsal-01/owners/B', '/var/tmp/kpi-four-wallet-local-rehearsal-01/owners/C', '/var/tmp/kpi-four-wallet-local-rehearsal-01/owners/D', '/var/tmp/kpi-four-wallet-live-01/owners/A', '/var/tmp/kpi-four-wallet-live-01/owners/B', '/var/tmp/kpi-four-wallet-live-01/owners/C', '/var/tmp/kpi-four-wallet-live-01/owners/D', '/var/tmp/kpi-owner-private-integration-01/party-0', '/var/tmp/kpi-owner-private-integration-01/party-1', '/var/tmp/kpi-owner-private-integration-01/party-2', '/var/tmp/kpi-owner-private-integration-01/controller-private', '/var/tmp/kpi-owner-private-diagnostics-01/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-01/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-01/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-01/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-01/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-02/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-02/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-02/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-02/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-03/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-03/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-03/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-03/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-04/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-04/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-04/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-04/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-05/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-05/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-05/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-05/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-06/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-06/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-06/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-06/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-07/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-07/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-07/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-07/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-08/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-08/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-08/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-08/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-09/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-09/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-09/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-09/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-10/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-10/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-10/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-10/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-11/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-11/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-11/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-11/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-12/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-12/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-12/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-12/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-13/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-13/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-13/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-13/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-14/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-14/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-14/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-14/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-15/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-15/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-15/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-15/controller-private', '/var/tmp/kpi-owner-private-cohort-01/world-16/party-0', '/var/tmp/kpi-owner-private-cohort-01/world-16/party-1', '/var/tmp/kpi-owner-private-cohort-01/world-16/party-2', '/var/tmp/kpi-owner-private-cohort-01/world-16/controller-private', '/var/tmp/kpi-owner-private-cohort-controller-01', '/var/tmp/kpi-owner-private-publication-runtime-01', '/var/tmp/kpi-owner-private-publication-runtime-02', '/var/tmp/kpi-owner-private-lifecycle-01/private')
MANDATORY_PRIVATE_PARENT = Path("/var/tmp/kpi-owner-private-lifecycle-01/private")

def required_private_roots():
    """Whole retained parents; paths inspected by metadata only at selection."""
    roots = tuple(Path(p) for p in RETAINED_PRIVATE_ROOTS)
    return tuple(p for p in roots if p == MANDATORY_PRIVATE_PARENT or p.exists())

def need(condition, reason):
    if not condition:
        raise ValueError(reason)

class Guard:
    def __init__(self, roots, *, required=None):
        need(bool(roots), 'all-private-parent-exclusions-required')
        self.directories = tuple(Path(p).absolute() for p in roots)
        need(len(self.directories) == len(set(self.directories)), 'distinct-private-exclusions')
        required = required_private_roots() if required is None else tuple(required)
        need(all(any(p.is_relative_to(root) for root in self.directories) for p in required),
             'whole-lifecycle-and-all-retained-private-exclusions-required')
        self.inodes = set()
        for p in self.directories:
            need('..' not in p.parts and p.is_dir()
                 and not any(q.is_symlink() for q in (p, *p.parents)),
                 'private-parent-metadata-only')
            need(all(not p.is_relative_to(Path(system)) for system in
                     ('/usr', '/etc/alternatives', '/lib', '/lib64')),
                 'private-parent-outside-worker-system-mounts')
        self.refresh()

    def refresh(self):
        for root in self.directories:
            need(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)),
                 'private-exclusion-disappeared-or-symlinked')
            def failed(error):
                raise ValueError('private-metadata-enumeration-failed') from error
            for current, directories, files in os.walk(root, followlinks=False, onerror=failed):
                directories[:] = [n for n in directories if not (Path(current) / n).is_symlink()]
                for name in files:
                    info = (Path(current) / name).lstat()
                    if stat.S_ISREG(info.st_mode):
                        self.inodes.add((info.st_dev, info.st_ino))

    def metadata(self, path):
        self.refresh()
        p = Path(path).absolute()
        need('..' not in p.parts and not any(q.is_symlink() for q in (p, *p.parents)),
             'canonical-public-path')
        need(all(not p.is_relative_to(root) for root in self.directories),
             'public-selector-inside-private-parent')
        info = p.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
             and (info.st_dev, info.st_ino) not in self.inodes, 'public-private-alias-or-not-regular')
        return p, info

def attributes(info):
    return tuple(getattr(info, k) for k in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink'))


def read(guard, path, expected=None):
    p, before = guard.metadata(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        need(attributes(opened) == attributes(before)
             and (opened.st_dev, opened.st_ino) not in guard.inodes, 'public-open-race')
        raw = source.read()
        after = os.fstat(source.fileno())
    need(attributes(before) == attributes(after) and len(raw) == before.st_size,
         'public-read-mutation')
    need(expected is None or hashlib.sha256(raw).hexdigest() == expected,
         'external-public-selector-hash')
    return raw

def helper(guard):
    raw = read(guard, HELPER, HELPER_SHA)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader('selected_outer', loader=None))
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), module.__dict__)
    module.GUARD = guard
    # Keep the selected helper functions unchanged, while routing their dynamic
    # public read boundary through this profile's stronger full-parent guard.
    module.read = lambda path, expected=None: read(guard, path, expected)
    return module


def selected(guard, module, path, pin, op):
    job = module.parse(read(guard, path, module.external_pin(pin)))
    need(type(job) is dict and set(job) == {'schema', 'domain_hex32',
         'component_profile_sha256', 'image_id_hex32', 'files'}, 'exact-outer-selection-fields')
    need(job['schema'] == SCHEMA and job['domain_hex32'] == DOMAIN, 'new-domain-outer-selection')
    module.external_pin(job['component_profile_sha256'])
    module.external_pin(job['image_id_hex32'])
    names = {'host', 'program', 'journal', 'projection' if op in ('execute', 'prove') else 'receipt'}
    need(type(job['files']) is dict and set(job['files']) == names, 'exact-stage-file-selectors')
    for row in job['files'].values():
        need(type(row) is dict and set(row) == {'path', 'sha256'}
             and type(row['path']) is str, 'exact-public-file-selector')
        module.external_pin(row['sha256'])
        guard.metadata(row['path'])
    return job


def stream_selected(guard, path, expected):
    """Authenticate complete multi-GB public compression assets, never truncate."""
    p, before = guard.metadata(path)
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    count = 0
    digest = hashlib.sha256()
    with os.fdopen(fd, 'rb') as source:
        need(attributes(os.fstat(source.fileno())) == attributes(before),
             'compression-open-race')
        for chunk in iter(lambda: source.read(8 * 1024 * 1024), b''):
            count += len(chunk)
            digest.update(chunk)
        need(attributes(os.fstat(source.fileno())) == attributes(before)
             and attributes(p.lstat()) == attributes(before) and count == before.st_size,
             'compression-stream-mutation')
    need(digest.hexdigest() == expected, 'whole-selected-compression-asset-hash')
    return p, before


def output_path(guard, path):
    p = Path(path).absolute()
    need('..' not in p.parts and not any(q.is_symlink() for q in (p, *p.parents)),
         'canonical-fresh-output')
    need(all(not p.is_relative_to(root) for root in guard.directories),
         'output-inside-private-exclusion')
    return p


def stage(guard, module, job, op, output, threads=2):
    need(type(threads) is int and threads >= 1, 'positive-resource-thread-selection')
    gpu = op in ('prove', 'compress')
    worker = module.TOOLS / ('r0vm-cuda' if gpu else 'r0vm')
    worker_pin = module.WORKER_SHA if gpu else module.CPU_WORKER_SHA
    # Preflight every member before reading any selected runtime file. The
    # selection/helper themselves are already externally pinned public inputs.
    for row in job['files'].values():
        guard.metadata(row['path'])
    guard.metadata(worker)
    if op == 'compress':
        for name in module.COMPRESSION:
            guard.metadata(module.EXTENSION / name)
    output = module.fresh(output_path(guard, output))
    command = module.bubble()
    rows = dict(job['files'])
    rows['worker'] = {'path': str(worker), 'sha256': worker_pin}
    for name, row in rows.items():
        destination = output / name
        module.staged(row['path'], destination, row['sha256'], name in ('host', 'worker'))
        command += ['--ro-bind', str(destination), '/' + name]
    journal = read(guard, output / 'journal', rows['journal']['sha256'])
    need(len(journal) == 104 and journal[:8] == b'KPXAJR01'
         and journal[8:40].hex() == DOMAIN
         and journal[40:72].hex() == job['component_profile_sha256'], 'selected-journal104-identity')
    if op in ('execute', 'prove'):
        projection = read(guard, output / 'projection', rows['projection']['sha256'])
        need(len(projection) == 4077 and journal[72:] == hashlib.sha256(projection).digest(),
             'selected-projection4077-journal-join')
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
            path, info = stream_selected(guard, module.EXTENSION / name, pin)
            command += ['--ro-bind', str(path),
                        '/scratch/risc0/extensions/v0.1.0-risc0-groth16/' + name]
            compression.append({'path': str(path), 'sha256': pin,
                                'attributes': list(attributes(info))})
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
    plan = {'schema': 'local-private-payment-outer-stage/v1', 'op': op,
            'domain_hex32': DOMAIN, 'component_profile_sha256': job['component_profile_sha256'],
            'image_id_hex32': job['image_id_hex32'], 'files': rows,
            'journal_sha256': rows['journal']['sha256'], 'command': command,
            'compression_assets': compression, 'GPU_selected': gpu,
            'network_namespace': 'UNSHARED', 'wallet_or_PK_or_host_home_mounted': False,
            'worker_started': False, 'selected_threads': threads, 'native_or_chain_acceptance': False}
    module.save(output / 'STAGE.json', plan)
    return output, command, plan


def execute(guard, module, output, command, plan):
    # Reauthenticate the staged files at the last boundary before process start;
    # a dry-run plan does not authorize later replacement bytes.
    for name, row in plan['files'].items():
        read(guard, output / name, row['sha256'])
    for row in plan['compression_assets']:
        _, info = guard.metadata(row['path'])
        need(list(attributes(info)) == row['attributes'], 'compression-changed-before-worker')
    resources = module.call(command, output, monitor_gpu=plan['GPU_selected'])
    result = output / 'public-output' / 'result'
    report = module.parse(read(guard, result / 'report.json'))
    need(type(report) is dict, 'returned-report-object')
    journal_reported = 'journal_sha256' in report
    need((plan['op'] == 'compress' and not journal_reported)
         or report.get('journal_sha256') == plan['journal_sha256'],
         'returned-report-selected-journal')
    if 'image_id_hex32' in report:
        need(report['image_id_hex32'] == plan['image_id_hex32'], 'returned-report-selected-image')
    else:
        need(plan['op'] == 'verify', 'returned-report-missing-image')
    positive = {'execute': 'genuine_three_G16_public_guest_execution_passed',
                'prove': 'genuine_three_G16_succinct_receipt_verified',
                'compress': 'same_claim_genuine_Groth16_compression_verified',
                'verify': 'genuine_new_image_receipt_verified',
                'native-proof': 'genuine_new_image_Groth16_receipt_verified'}
    need(report.get(positive[plan['op']]) is True, 'selected-operation-success-report')
    if plan['op'] != 'verify':
        produced = read(guard, result / 'journal.bin', plan['journal_sha256'])
        expected = read(guard, output / 'journal', plan['journal_sha256'])
        need(len(produced) == 104 and produced == expected, 'returned-exact-journal-bytes')
    for row in plan['compression_assets']:
        _, info = guard.metadata(row['path'])
        need(list(attributes(info)) == row['attributes'], 'compression-changed-during-worker')
    outcome = {'schema': 'local-private-payment-outer-result/v1', 'op': plan['op'],
               'worker_completed': True, 'exact_external_journal_matched': True,
               'image_id_hex32': plan['image_id_hex32'],
               'component_profile_sha256': plan['component_profile_sha256'],
               'worker_image_report_compared': 'image_id_hex32' in report,
               'worker_journal_report_compared': journal_reported,
               'resources': resources, 'worker_report': report,
               'native_or_chain_acceptance': False}
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
    guard = Guard(args.exclude_private_directory)
    module = helper(guard)
    job = selected(guard, module, args.selection, args.selection_sha256, args.op)
    output, command, plan = stage(guard, module, job, args.op, args.output, args.threads)
    if args.execute:
        execute(guard, module, output, command, plan)
    print(json.dumps({'output': str(output), 'op': args.op, 'worker_started': args.execute},
                     sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, TypeError, KeyError):
        print('selected-public-outer-stage-refused', file=sys.stderr)
        raise SystemExit(2)
