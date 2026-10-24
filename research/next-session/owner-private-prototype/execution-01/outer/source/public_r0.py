#!/usr/bin/python3
"""Public-only new-profile R0 staging. No owner, PK or network capability."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

TOOLS = Path('/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools')
EXTENSION = Path('/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home/extensions/v0.1.0-risc0-groth16')
CPU_SHA = '2acdf550f9aca4d05b74072463e4ed307c3824309c754a5cb5f93aa84f3390e6'
CUDA_SHA = '3f22b68b6d32904fe766e14e62ce011febdc946dd98d015747f40ce5fb5fffc7'
COMPRESSION = {
    'stark_verify_final.zkey': 'f525bfbcadcd01339a243db59213f213a357adbaaff7b4203c9c57ce25e91d5c',
    'fuzzed_msm_results.bin': '5c31207007ab5489bddf60594434c161739baca4cde6786f493ffa44aaebcc43',
    'preprocessed_coeffs.bin': '424368948ad64d7cdd6632fc9efa9b1a52f45ea8b5bf1d568682a7eaa91efbb0',
    'stark_verify_graph.bin': '51020d6fd9ded9627ed08044fb428bca46ee2bfcc90f5819469601564050315f',
}
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(value, label):
    if not value:
        raise ValueError(label)


def attrs(info):
    return tuple(getattr(info, k) for k in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def canonical(value):
    p = Path(value).absolute()
    need('..' not in p.parts and not any(x.is_symlink() for x in (p, *p.parents)), 'canonical-nonsymlink-path')
    return p


def strict(raw):
    def pairs(rows):
        result = {}
        for k, v in rows:
            need(k not in result, 'duplicate-public-json-field')
            result[k] = v
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))


class Guard:
    def __init__(self, directories, originals):
        self.directories = tuple(canonical(p) for p in directories)
        need(len(self.directories) >= 11 and len(set(self.directories)) == len(self.directories), 'all-eight-old-and-three-new-private-parents')
        self.inodes = set()
        originals = tuple(canonical(p) for p in originals)
        need(len(originals) >= 11 and len(set(originals)) == len(originals), 'all-original-private-file-selectors')
        for original in originals:
            need(any(original.is_relative_to(d) for d in self.directories), 'original-within-blocked-parent')
            info = original.lstat()
            need(stat.S_ISREG(info.st_mode), 'original-private-file-present')
            self.inodes.add((info.st_dev, info.st_ino))
        # Metadata only. Never follow private TLS/program symlinks or open a leaf.
        def walk(p):
            info = p.lstat()
            if stat.S_ISREG(info.st_mode):
                self.inodes.add((info.st_dev, info.st_ino))
            elif stat.S_ISDIR(info.st_mode):
                for entry in os.scandir(p):
                    walk(Path(entry.path))
        for directory in self.directories:
            need(directory.is_dir(), 'selected-complete-private-parent')
            walk(directory)

    def metadata(self, value):
        p = canonical(value)
        need(all(not p.is_relative_to(d) for d in self.directories), 'private-directory-refusal')
        s = p.lstat()
        need(stat.S_ISREG(s.st_mode) and (s.st_dev, s.st_ino) not in self.inodes, 'private-inode-or-nonregular-refusal')
        return p, s

    def read(self, value, expected, destination=None, executable=False):
        p, before = self.metadata(value)
        need(type(expected) is str and len(expected) == 64 and all(c in '0123456789abcdef' for c in expected), 'external-sha256')
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        target, digest, size = None, hashlib.sha256(), 0
        try:
            with os.fdopen(fd, 'rb') as source:
                opened = os.fstat(source.fileno())
                need(attrs(opened) == attrs(before) and (opened.st_dev, opened.st_ino) not in self.inodes, 'opened-inode-before-first-byte')
                if destination is not None:
                    target = destination.open('xb')
                chunks = [] if destination is None else None
                while data := source.read(8 * 1024 * 1024):
                    digest.update(data); size += len(data)
                    if target is not None:
                        target.write(data)
                    else:
                        chunks.append(data)
                need(attrs(os.fstat(source.fileno())) == attrs(before), 'stable-source-after-read')
        finally:
            if target is not None:
                target.close()
        need(size == before.st_size and digest.hexdigest() == expected, 'whole-selected-public-bytes')
        if destination is not None:
            destination.chmod(0o500 if executable else 0o400)
            return None
        return b''.join(chunks)

    def hash_only(self, value, expected):
        p, before = self.metadata(value)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        digest, size = hashlib.sha256(), 0
        with os.fdopen(fd, 'rb') as source:
            need(attrs(os.fstat(source.fileno())) == attrs(before), 'asset-opened-inode-before-read')
            for data in iter(lambda: source.read(8 * 1024 * 1024), b''):
                size += len(data); digest.update(data)
            need(attrs(os.fstat(source.fileno())) == attrs(before), 'stable-asset-after-read')
        need(size == before.st_size and digest.hexdigest() == expected, 'whole-official-compression-asset')
        return p


def run(args):
    guard = Guard(args.exclude_private_dir, args.exclude_private_file)
    selected = strict(guard.read(args.selection, args.selection_sha256))
    need(set(selected) == {'schema', 'classification', 'image_hex32', 'component_profile_sha256', 'files', 'CPU_guest_gate_passed'}, 'selection-fields')
    need(selected['schema'] == 'kpx7-public-R0-selection/v1' and selected['classification'] == 'UNFUNDED_RESEARCH_ONLY_ADR0063' and selected['CPU_guest_gate_passed'] is True, 'new-profile-CPU-gate-selection')
    for key in ('image_hex32', 'component_profile_sha256'):
        h = selected[key]
        need(type(h) is str and len(h) == 64 and all(c in '0123456789abcdef' for c in h), 'selected-image-and-profile-identities')
    need(set(selected['files']) == {'host', 'program', 'projection', 'journal'}, 'selected-public-files')
    gpu = args.op in ('prove', 'compress')
    rows = [(name, row['path'], row['sha256'], name == 'host') for name, row in selected['files'].items()]
    rows.append(('worker', TOOLS / ('r0vm-cuda' if gpu else 'r0vm'), CUDA_SHA if gpu else CPU_SHA, True))
    if args.op != 'prove':
        need(args.receipt is not None and args.receipt_sha256 is not None, 'exact-public-receipt-selection')
        rows.append(('receipt', args.receipt, args.receipt_sha256, False))
    for _, p, _, _ in rows:
        guard.metadata(p)
    if args.op == 'compress':
        for name in COMPRESSION:
            guard.metadata(EXTENSION / name)
    output = canonical(args.output)
    need(not output.exists() and all(not output.is_relative_to(d) for d in guard.directories), 'fresh-nonprivate-output')
    output.mkdir(parents=True, mode=0o700)
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--ro-bind', '/etc/alternatives', '/etc/alternatives',
        '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--setenv', 'PATH', '/usr/bin:/bin',
        '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']
    for name, p, pin, executable in rows:
        target = output / name
        guard.read(p, pin, target, executable)
        command += ['--ro-bind', str(target), '/' + name]
    need((output / 'journal').stat().st_size == 104, 'new-journal104-only')
    if args.op == 'prove':
        invocation = ['/host', 'prove', '/program', '/projection', '/out/result']
    else:
        invocation = ['/host', args.op, '/receipt']
        if args.op == 'compress':
            invocation.append(args.receipt_sha256)
        invocation += ['/journal', '/out/result']
    client, scratch = output / 'public-output', output / 'scratch'
    client.mkdir(); scratch.mkdir()
    for name in ('home', 'cache', 'work', 'risc0/extensions'):
        (scratch / name).mkdir(parents=True, exist_ok=True)
    command += ['--bind', str(client), '/out', '--bind', str(scratch), '/scratch']
    if args.op == 'compress':
        for name, pin in COMPRESSION.items():
            p = guard.hash_only(EXTENSION / name, pin)
            command += ['--ro-bind', str(p), '/scratch/risc0/extensions/v0.1.0-risc0-groth16/' + name]
    if gpu:
        devices = sorted(Path('/dev').glob('nvidia*')); need(devices, 'GPU-device-required')
        for device in devices:
            command += ['--dev-bind', str(device), str(device)]
    command += ['--setenv', 'HOME', '/scratch/home', '--setenv', 'XDG_CACHE_HOME', '/scratch/cache',
        '--setenv', 'RISC0_HOME', '/scratch/risc0', '--setenv', 'RISC0_WORK_DIR', '/scratch/work',
        '--setenv', 'RISC0_PROVER', 'ipc', '--setenv', 'RISC0_SERVER_PATH', '/worker',
        '--setenv', 'RAYON_NUM_THREADS', '14', '--setenv', 'OMP_NUM_THREADS', '14',
        '--setenv', 'CUDA_VISIBLE_DEVICES', '0', '--setenv', 'LD_LIBRARY_PATH', '/usr/lib/x86_64-linux-gnu',
        '--setenv', 'GITHUB_TOKEN', '', '--chdir', '/scratch', *invocation]
    # RISC0_DEV_MODE and all cloud/prover overrides remain ABSENT.
    with (output / 'stdout.log').open('xb') as stdout, (output / 'stderr.log').open('xb') as stderr:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=dict(CLEAN))
    need(result.returncode == 0, 'new-public-R0-stage-failed-see-retained-evidence')
    print(str(client / 'result'))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('op', choices=('prove', 'compress', 'verify', 'native-proof'))
    p.add_argument('--selection', type=Path, required=True)
    p.add_argument('--selection-sha256', required=True)
    p.add_argument('--exclude-private-dir', type=Path, action='append', required=True)
    p.add_argument('--exclude-private-file', type=Path, action='append', required=True)
    p.add_argument('--receipt', type=Path)
    p.add_argument('--receipt-sha256')
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args())
