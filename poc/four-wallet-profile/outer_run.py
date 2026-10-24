#!/usr/bin/env python3
"""Public-only ADR60 outer rehearsal; supplied contexts confer no chain authority.

The preparation worker sees selected public software, GN2/history and two public
G16 records. R0 workers see only the public projection/journal/receipt. No PK,
wallet backup, witness, signer or broadcast interface exists here. Root schedules
CPU/GPU jobs separately; this module never launches a background unit.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
INVENTORY_SHA = '798c246f5769ade14b27d0fb119077600e4cfcacc9c375dc8076041e58e2236b'
BASE = Path('/home/luke/projects/kpi-intensive-2026-10-22')
ASSETS = BASE / 'four-wallet-profile-build-01/selected-runtime'
HOST_SHA = 'efddfb276afcdd0eec4ae8a071bbfb1e02a8f6189db4424efeccd64d6def27e1'
PROGRAM_SHA = '227bbfa4f7c40ab07081e9e13393e5339f3d24b2d92fe1d9039ccceedafc890d'
CODEC_SHA = '3cc966dab7af0fb0e015f52fc281c7c4f70a41975afdc9afd15e3fd1dd090939'
WORKER_SHA = '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'
CPU_WORKER_SHA = '2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6'
TOOLS = BASE / 'proof-target/tools'
EXTENSION = BASE / ('observer/artifacts/groth16-compression-preparation/'
                    'risc0-home/extensions/v0.1.0-risc0-groth16')
COMPRESSION = {
    'stark_verify_final.zkey': 'f525bfbcadcd01339a243db59213f213a357adbaaff7b4203c9c57ce25e91d5c',
    'fuzzed_msm_results.bin': '5c31207007ab5489bddf60594434c161739baca4cde6786f493ffa44aaebcc43',
    'preprocessed_coeffs.bin': '424368948ad64d7cdd6632fc9efa9b1a52f45ea8b5bf1d568682a7eaa91efbb0',
    'stark_verify_graph.bin': '51020d6fd9ded9627ed08044fb428bca46ee2bfcc90f5819469601564050315f',
}
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
GUARD = None


def need(value, label):
    if not value:
        raise ValueError(label)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def checked(value):
    path = Path(value).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-nonsymlink-public-path')
    return path


class PublicGuard:
    """Metadata only: reject every declared original owner file/whole directory."""
    def __init__(self, roots, *, closed_namespace=False):
        need(closed_namespace or roots, 'explicit-all-original-private-root-selectors')
        self.inodes, directories = set(), []
        for root in roots:
            root = checked(root)
            for role in ('A', 'B', 'C', 'D'):
                directory = checked(root / 'owners' / role)
                need(directory.is_dir(), 'original-owner-directory-metadata')
                path = checked(directory / 'backup.json'); info = path.stat()
                need(stat.S_ISREG(info.st_mode), 'original-backup-regular-metadata-only')
                self.inodes.add((info.st_dev, info.st_ino)); directories.append(directory)
        self.directories = tuple(directories)

    def metadata(self, path):
        path = checked(path)
        need(all(not path.is_relative_to(directory) for directory in self.directories),
             'public-candidate-inside-original-owner-directory')
        info = path.stat()
        need(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in self.inodes,
             'public-file-aliases-original-backup-or-is-not-regular')
        return path, info


def read(path, expected=None):
    need(GUARD is not None, 'public-metadata-guard-before-first-read')
    path, before = GUARD.metadata(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as file:
        opened = os.fstat(file.fileno())
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
             and (opened.st_dev, opened.st_ino) not in GUARD.inodes,
             'public-file-swapped-before-read')
        raw = file.read(); after = os.fstat(file.fileno())
    attributes = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(tuple(getattr(before, key) for key in attributes) ==
         tuple(getattr(after, key) for key in attributes) and len(raw) == before.st_size,
         'public-file-mutated-during-read')
    need(expected is None or digest(raw) == expected, 'externally-selected-public-bytes')
    return raw


def external_pin(value):
    need(type(value) is str and len(value) == 64
         and all(char in '0123456789abcdef' for char in value), 'explicit-external-SHA256-pin')
    return value


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-JSON-key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def save(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as file:
        file.write(value if type(value) is bytes else
                   (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode())


def fresh(path):
    path = checked(path)
    need(not path.exists() and not path.is_relative_to(ROOT), 'fresh-output-outside-project')
    probe = path.parent
    while not probe.exists():
        probe = probe.parent
    test = subprocess.run(['/usr/bin/git', '-C', str(probe), 'rev-parse', '--is-inside-work-tree'],
                          capture_output=True, env=CLEAN)
    need(test.returncode != 0 or test.stdout.strip() != b'true', 'output-outside-any-Git')
    path.mkdir(parents=True, mode=0o700)
    return path


def bubble():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8',
        '--setenv', 'TZ', 'UTC', '--setenv', 'PYTHONDONTWRITEBYTECODE', '1']


def staged(source, destination, expected, executable=False):
    save(destination, read(source, expected)); destination.chmod(0o500 if executable else 0o400)


def call(command, output, *, monitor_gpu=False):
    """Keep failures and actual owned process/device counters, including cleanup."""
    began = time.monotonic(); samples = []; peak = 0; observed = set()
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   env=CLEAN)
        while True:
            if monitor_gpu:
                # Walk descendants of this exact worker, not device-global use.
                parents = {}
                for entry in Path('/proc').iterdir():
                    if entry.name.isdigit():
                        try:
                            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
                            parents[int(entry.name)] = int(fields[1])
                        except (OSError, ValueError, IndexError):
                            pass
                owned = {process.pid}
                for _ in range(len(parents) + 1):
                    more = {pid for pid, parent in parents.items() if parent in owned}
                    if more <= owned:
                        break
                    owned |= more
                gpu = subprocess.run(['/usr/bin/nvidia-smi',
                    '--query-compute-apps=pid,used_gpu_memory', '--format=csv,noheader,nounits'],
                    capture_output=True, text=True, env=CLEAN)
                rows = []
                if gpu.returncode == 0:
                    for line in gpu.stdout.splitlines():
                        parts = [part.strip() for part in line.split(',')]
                        if len(parts) == 2 and all(part.isdigit() for part in parts):
                            pid, mib = map(int, parts)
                            if pid in owned:
                                observed.add(pid); rows.append({'pid': pid, 'used_MiB': mib})
                    peak = max(peak, sum(row['used_MiB'] for row in rows))
                samples.append({'seconds': time.monotonic() - began, 'owned_gpu_processes': rows})
            status = process.poll()
            if status is not None:
                break
            time.sleep(0.5)
    cgroup = None
    try:
        relative = next(line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                        if line.startswith('0::'))
        base = Path('/sys/fs/cgroup') / relative.lstrip('/')
        cgroup = {name: (base / name).read_text().strip()
                  for name in ('cpu.stat', 'memory.peak', 'memory.swap.peak') if (base / name).exists()}
    except (OSError, StopIteration):
        pass
    report = {'returncode': status, 'wall_seconds': time.monotonic() - began,
              'cgroup_counters': cgroup, 'owned_GPU_peak_MiB': peak if monitor_gpu else None,
              'observed_owned_GPU_PIDs': sorted(observed), 'GPU_samples': samples,
              'worker_exit_observed': True, 'background_units_created': False}
    save(output / 'PROCESS-RESOURCES.json', report)
    need(status == 0, 'public-worker-failed-see-retained-stderr')
    return report


def prepare(args):
    inventory = parse(read(Path(args.software_root) / 'SOFTWARE-BUNDLE.json', INVENTORY_SHA))
    need(inventory['schema'] == 'kpx4-public-software-bundle/v1', 'selected-public-inventory')
    # Check every listed member and explicit public argument's metadata before
    # the first member is read/copied; even a late fourth-owner alias is refused.
    for row in inventory['files']:
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'inventory-relative-path')
        GUARD.metadata(Path(args.software_root) / relative)
    for path in (args.history, args.prefix, ROOT / 'poc/four-wallet-profile/financial-profile.json',
                 ASSETS / 'w-codec', ASSETS / 'r0-host', __file__):
        GUARD.metadata(path)
    output = fresh(args.output); software = output / 'software'; software.mkdir()
    command = bubble()
    for row in inventory['files']:
        relative = Path(row['path'])
        need(not relative.is_absolute() and '..' not in relative.parts, 'inventory-relative-path')
        target = software / relative
        executable = row['kind'] == 'selected-executable'
        staged(Path(args.software_root) / relative, target, row['sha256'], executable)
        need(target.stat().st_size == row['bytes'], 'selected-member-length')
        if relative.parts[0] == 'runtime-source':
            destination = '/work/' + str(Path(*relative.parts[1:]))
        elif relative.parts[0] == 'runtime':
            destination = '/' + str(relative)
        elif relative.parts[0] == 'runtime-sdk':
            destination = '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/' + relative.name
        else:
            continue
        command += ['--ro-bind', str(target), destination]
    for name, source, expected in (
        ('history.json', args.history, args.history_sha256),
        ('prefix.json', args.prefix, args.prefix_sha256),
        ('financial.json', ROOT / 'poc/four-wallet-profile/financial-profile.json', PROFILE_SHA),
        ('w-codec', ASSETS / 'w-codec', CODEC_SHA),
        ('r0-host', ASSETS / 'r0-host', HOST_SHA),
        ('outer_run.py', Path(__file__), digest(read(__file__)))):
        target = output / name
        staged(source, target, expected, name in ('w-codec', 'r0-host'))
        destination = '/work/poc/four-wallet-profile/outer_run.py' if name == 'outer_run.py' else '/' + name
        command += ['--ro-bind', str(target), destination]
    client = output / 'public-output'; client.mkdir()
    command += ['--bind', str(client), '/out', '--chdir', '/work/poc/four-wallet-lifecycle',
        '--setenv', 'KPX6_PUBLIC_OUTER_CLOSED', '1',
        '/usr/bin/python3', '-B', '/work/poc/four-wallet-profile/outer_run.py', '_prepare',
        '--history-sha256', args.history_sha256, '--prefix-sha256', args.prefix_sha256]
    call(command, output)
    return output


def prepare_worker(args):
    # The launcher mounted every byte from one externally selected inventory.
    # Its SDK3 is mounted at the historical helper's fixed logical path, keeping
    # mutable host cache, repo, owner backups and parameters outside namespace.
    sys.path.insert(0, '/work/poc/four-wallet-lifecycle')
    from contracts import financial
    from compat import core, public
    from runtime import Runtime
    from local_source import replay_local
    from preparation import virtual_prefix
    from source import actual_daa
    profile = financial(read('/financial.json', PROFILE_SHA), PROFILE_SHA)
    runtime = Runtime(profile, '/runtime'); c = core(); pub = public(); v = pub.virtual
    output = Path('/out')
    prefix = parse(read('/prefix.json', args.prefix_sha256))
    need(type(prefix) is dict and set(prefix) == {'schema', 'financial_profile_sha256', 'record_hex4048'}
         and prefix['schema'] == 'kpx6-four-wallet-proposed-prefix/v1'
         and prefix['financial_profile_sha256'] == PROFILE_SHA
         and type(prefix['record_hex4048']) is list and len(prefix['record_hex4048']) == 2,
         'selected-exact-two-public-record-prefix')
    records = [pub.wire.hexbytes(value, 4048) for value in prefix['record_hex4048']]
    base = replay_local(read('/history.json', args.history_sha256), args.history_sha256,
                        profile, runtime, output / 'base-replay')
    after = virtual_prefix(runtime, base, records, output / 'proposed-prefix')
    state, successor = base['snapshot'].state(profile.domain), after['snapshot'].state(profile.domain)
    daa = actual_daa(base, runtime)
    frame = v.push(bytes(65)) + v.push(bytes(128)) + v.push(runtime.emit(state))
    body = c.native_runtime.tx(base['point'], [(after['reserve'], c.native_runtime.p2sh(runtime.emit(successor)))],
                               v.encode_payload(records), frame, profile.aggregate_budget)
    contexts = [dict(base['head_context'])]
    candidate = c.native_runtime.public_case(body, contexts)
    candidate, checked_contexts, metrics = runtime.normalize_case(candidate, output / 'outer-normalize')
    need(contexts == checked_contexts and int(contexts[0]['block_daa_score']) == daa,
         'actual-supplied-context-DAA-preserved')
    runtime.sdk(candidate['transaction'], contexts)
    projection = v.financial_projection(candidate)
    journal = v.encode_journal(profile.wrapper_domain, profile.domain, base['point'], state,
        base['reserve'], successor, after['reserve'], base['reserve'] - after['reserve'], records, projection)
    result = subprocess.run(['/w-codec'], input=json.dumps({'operation': 'body', 'case': candidate}),
        capture_output=True, text=True, env=CLEAN)
    need(result.returncode == 0 and not result.stderr, 'selected-native-body-codec')
    native = parse(result.stdout)
    need(native['template_kind'] == 'ACTUAL_R0_W' and native['outer_image_hex32'] == profile.image_id.hex()
         and native['financial_projection_hex'] == projection.hex()
         and native['journal_hex424'] == journal.hex()
         and native['native_VM_executed'] is False
         and native['receipt_or_child_G16_verified'] is False
         and native['journal_sha256'] == digest(journal)
         and native['financial_projection_sha256'] == digest(projection),
         'independent-new-profile-native-Python-body-and-journal-join')
    need(len(projection) == 8301 and len(journal) == 424
         and metrics['actual_fee_sompi'] == base['reserve'] - after['reserve']
         and metrics['actual_fee_sompi'] == 100 * metrics['mining_mass'], 'actual-fee-body-quote')
    save(output / 'validation-case.json', candidate); save(output / 'contexts.json', contexts)
    save(output / 'projection.bin', projection); save(output / 'journal.bin', journal)
    save(output / 'native-body.json', native); save(output / 'metrics.json', metrics)
    host = subprocess.run(['/r0-host', 'host-check', str(output / 'projection.bin'),
        str(output / 'journal.bin'), str(output / 'host-check')], capture_output=True, env=CLEAN)
    save(output / 'host-check.stdout', host.stdout); save(output / 'host-check.stderr', host.stderr)
    need(host.returncode == 0, 'independent-selected-host-public-predicate')
    save(output / 'PREPARATION.json', {'schema': 'kpx6-four-wallet-public-outer-preparation/v1',
        'financial_profile_sha256': PROFILE_SHA, 'history_sha256': args.history_sha256,
        'prefix_sha256': args.prefix_sha256, 'projection_sha256': digest(projection),
        'journal_sha256': digest(journal), 'transaction_id': candidate['transaction']['id'],
        'actual_DAA': daa, 'fee_sompi': metrics['actual_fee_sompi'],
        'new_reserve_sompi': after['reserve'], 'independent_inner_G16_NF_CM_replay': True,
        'host_predicate_and_independent_native_codec_match': True,
        'classification': 'UNFUNDED_SUPPLIED_GN2_CONTEXTS_NOT_ACCEPTED',
        'accepted_chain_currentness_or_broadcast': False, 'outer_receipt_or_native_Full': False})


def r0(args):
    # Selected readonly host/program/worker bytes are copied into fresh owned
    # staging. A receipt never selects its verifier, image, program or assets.
    gpu = args.op in ('prove', 'compress')
    public_paths = [ASSETS / 'r0-host', ASSETS / 'guest.program.bin',
                    TOOLS / ('r0vm-cuda' if gpu else 'r0vm'), args.journal,
                    args.projection if args.op in ('execute', 'prove') else args.receipt]
    if args.op == 'compress':
        public_paths += [EXTENSION / name for name in COMPRESSION]
    for path in public_paths:
        GUARD.metadata(path)
    output = fresh(args.output)
    command = bubble()
    for name, source, expected, executable in (
        ('host', ASSETS / 'r0-host', HOST_SHA, True),
        ('program', ASSETS / 'guest.program.bin', PROGRAM_SHA, False),
        ('worker', TOOLS / ('r0vm-cuda' if gpu else 'r0vm'),
         WORKER_SHA if gpu else CPU_WORKER_SHA, True),
        ('journal', args.journal, args.journal_sha256, False)):
        target = output / name; staged(source, target, expected, executable)
        command += ['--ro-bind', str(target), '/' + name]
    need(len(read(output / 'journal')) == 424, 'public-journal424')
    if args.op in ('execute', 'prove'):
        staged(args.projection, output / 'projection', args.projection_sha256)
        need(len(read(output / 'projection')) == 8301, 'public-projection8301')
        command += ['--ro-bind', str(output / 'projection'), '/projection']
        invocation = ['/host', args.op, '/program', '/projection', '/journal', '/out/result']
    else:
        staged(args.receipt, output / 'receipt', args.receipt_sha256)
        command += ['--ro-bind', str(output / 'receipt'), '/receipt']
        invocation = ['/host', args.op, '/receipt']
        if args.op == 'compress':
            invocation += [args.receipt_sha256]
        invocation += ['/journal', '/out/result']
    client = output / 'public-output'; client.mkdir()
    scratch = output / 'scratch'; scratch.mkdir()
    for directory in ('home', 'cache', 'work', 'risc0/extensions'):
        (scratch / directory).mkdir(parents=True, exist_ok=True)
    command += ['--bind', str(client), '/out', '--bind', str(scratch), '/scratch']
    if args.op == 'compress':
        assets = output / 'compression-assets'; assets.mkdir()
        for name, expected in COMPRESSION.items():
            # Multi-GB established public assets: authenticate whole bytes,
            # readonly bind originals; no regeneration or owner data involved.
            path = checked(EXTENSION / name)
            path, before = GUARD.metadata(path)
            hasher = hashlib.sha256()
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as file:
                opened = os.fstat(file.fileno())
                need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                     and (opened.st_dev, opened.st_ino) not in GUARD.inodes,
                     'compression-file-swapped-before-read')
                for chunk in iter(lambda: file.read(8 * 1024 * 1024), b''):
                    hasher.update(chunk)
            need(hasher.hexdigest() == expected, 'official-compression-member-identity')
            command += ['--ro-bind', str(path), '/scratch/risc0/extensions/v0.1.0-risc0-groth16/' + name]
    # Device files are the sole extra capability on GPU-selected prove/compress.
    if gpu:
        devices = sorted(Path('/dev').glob('nvidia*'))
        need(devices, 'selected-GPU-device-present')
        for device in devices:
            command += ['--dev-bind', str(device), str(device)]
    command += ['--setenv', 'HOME', '/scratch/home', '--setenv', 'XDG_CACHE_HOME', '/scratch/cache',
        '--setenv', 'RISC0_HOME', '/scratch/risc0', '--setenv', 'RISC0_WORK_DIR', '/scratch/work',
        '--setenv', 'RISC0_PROVER', 'ipc', '--setenv', 'RISC0_SERVER_PATH', '/worker',
        '--setenv', 'RAYON_NUM_THREADS', '14', '--setenv', 'OMP_NUM_THREADS', '14',
        '--setenv', 'CUDA_VISIBLE_DEVICES', '0',
        '--setenv', 'LD_LIBRARY_PATH', '/usr/lib/x86_64-linux-gnu',
        '--setenv', 'GITHUB_TOKEN', '', '--chdir', '/scratch', *invocation]
    # RISC0_DEV_MODE is absent from the cleared namespace, including value "0".
    call(command, output, monitor_gpu=gpu)
    return output


def main():
    global GUARD
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op', choices=('prepare', '_prepare', 'execute', 'prove', 'compress', 'verify', 'native-proof'))
    for name in ('output', 'history', 'history-sha256', 'prefix', 'prefix-sha256',
                 'projection', 'projection-sha256', 'journal', 'journal-sha256',
                 'receipt', 'receipt-sha256'):
        parser.add_argument('--' + name)
    parser.add_argument('--software-root', default=str(BASE / 'four-wallet-owner-runtime-01'))
    parser.add_argument('--exclude-private-root', action='append', default=[],
                        help='metadata-only trial root, repeated for ALL original A/B/C/D backups')
    args = parser.parse_args()
    required = {'prepare': ('output', 'history', 'history_sha256', 'prefix', 'prefix_sha256'),
                '_prepare': ('history_sha256', 'prefix_sha256'),
                'execute': ('output', 'projection', 'projection_sha256', 'journal', 'journal_sha256'),
                'prove': ('output', 'projection', 'projection_sha256', 'journal', 'journal_sha256'),
                'compress': ('output', 'receipt', 'receipt_sha256', 'journal', 'journal_sha256'),
                'verify': ('output', 'receipt', 'receipt_sha256', 'journal', 'journal_sha256'),
                'native-proof': ('output', 'receipt', 'receipt_sha256', 'journal', 'journal_sha256')}
    for name in required[args.op]:
        need(getattr(args, name) is not None, 'required-explicit-public-argument-' + name)
        if name.endswith('_sha256'):
            external_pin(getattr(args, name))
    if args.op == '_prepare':
        need(os.environ.get('KPX6_PUBLIC_OUTER_CLOSED') == '1', 'closed-public-worker-namespace')
        GUARD = PublicGuard((), closed_namespace=True)
    else:
        GUARD = PublicGuard(args.exclude_private_root)
    if args.op == '_prepare':
        prepare_worker(args)
    elif args.op == 'prepare':
        print(prepare(args))
    else:
        print(r0(args))


if __name__ == '__main__':
    main()
