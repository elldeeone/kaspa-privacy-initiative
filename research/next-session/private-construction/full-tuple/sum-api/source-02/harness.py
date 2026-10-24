#!/usr/bin/env python3
"""Stage authenticated public ADR0062 software; execute only an explicit phase."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
ARCHIVE = Path('/var/tmp/kpi-sum-mpspdz-distribution-source-01/mp-spdz-0.4.4.tar.xz')
ARCHIVE_SHA = '73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760'
ENGINE_SHA = '47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(value, reason):
    if not value: raise ValueError(reason)


def checked(value):
    path = Path(value).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-nonsymlink-path')
    return path


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-JSON-key'); value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-JSON')))


def sha(raw): return hashlib.sha256(raw).hexdigest()


class PublicGuard:
    def __init__(self, roots):
        need(roots, 'all-original-private-root-selectors-required')
        self.inodes, self.directories = set(), []
        for root in roots:
            for role in 'ABCD':
                directory = checked(Path(root) / 'owners' / role)
                path = checked(directory / 'backup.json'); info = path.stat()
                need(directory.is_dir() and stat.S_ISREG(info.st_mode), 'private-metadata-only')
                self.inodes.add((info.st_dev, info.st_ino)); self.directories.append(directory)

    def metadata(self, path):
        path = checked(path); info = path.stat()
        need(all(not path.is_relative_to(d) for d in self.directories)
             and stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) not in self.inodes,
             'public-input-aliases-original-private-file-or-directory')
        return path, info

    def read(self, path, expected):
        path, before = self.metadata(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            opened = os.fstat(f.fileno())
            need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                 and (opened.st_dev, opened.st_ino) not in self.inodes, 'opened-public-inode-swapped')
            raw = f.read(); after = os.fstat(f.fileno())
        keys = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        need(tuple(getattr(before,k) for k in keys) == tuple(getattr(after,k) for k in keys)
             and len(raw) == before.st_size and sha(raw) == expected, 'selected-stable-public-bytes')
        return raw


def relative(name):
    path = Path(name)
    need(type(name) is str and not path.is_absolute() and '..' not in path.parts
         and str(path) == name and name != '.', 'canonical-relative-member')
    return path


def fresh(value):
    path = checked(value)
    need(not path.exists() and not path.is_relative_to(PROJECT), 'fresh-output-outside-project')
    parent = path.parent
    while not parent.exists(): parent = parent.parent
    probe = subprocess.run(['/usr/bin/git','-C',str(parent),'rev-parse','--is-inside-work-tree'],
        capture_output=True, env=CLEAN)
    need(probe.returncode != 0 or probe.stdout.strip() != b'true', 'output-outside-any-Git')
    path.mkdir(parents=True, mode=0o700); return path


def write(path, raw, mode=0o400):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as f: f.write(raw)
    path.chmod(mode)


def stage(args, guard):
    manifest = parse(guard.read(HERE / 'SOURCE.json', args.inventory_sha256))
    need(manifest['schema'] == 'kpx6-private-sum-source/v1', 'fixed-source-inventory')
    rows = manifest['files']
    need(len({r['path'] for r in rows}) == len(rows), 'unique-source-members')
    for row in rows: guard.metadata(HERE / relative(row['path']))
    guard.metadata(ARCHIVE)
    source = {r['path']: guard.read(HERE / r['path'], r['sha256']) for r in rows}
    selected = parse(source['DISTRIBUTION-MEMBERS.json'])['files']
    need(len({r['path'] for r in selected}) == len(selected), 'unique-distribution-members')
    archive = guard.read(ARCHIVE, ARCHIVE_SHA)
    need(len(archive) == 78428724, 'official-distribution-length')
    output = fresh(args.output); software = output / 'software'; software.mkdir()
    inventory = []
    for name, raw in source.items():
        write(software / name, raw); inventory.append({'path': name, 'bytes':len(raw),'sha256':sha(raw)})
    import io
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:xz') as bundle:
        for row in selected:
            name = str(relative(row['path'])); entry = bundle.getmember('mp-spdz-0.4.4/' + name)
            need(entry.isfile() and not entry.issym() and not entry.islnk(), 'regular-selected-archive-member')
            raw = bundle.extractfile(entry).read()
            need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'selected-archive-member-bytes')
            target = 'mascot-party.x' if name == 'bin/Linux-adx/mascot-party.x' else name
            write(software / target, raw, 0o500 if target == 'mascot-party.x' else 0o400)
            inventory.append({'path':target,'bytes':len(raw),'sha256':sha(raw)})
    need(sha((software/'mascot-party.x').read_bytes()) == ENGINE_SHA, 'selected-official-engine')
    raw = (json.dumps({'schema':'kpx6-private-sum-public-installation/v1',
        'source_inventory_sha256':args.inventory_sha256,'distribution_sha256':ARCHIVE_SHA,
        'files':sorted(inventory,key=lambda r:r['path'])}, sort_keys=True, indent=2)+'\n').encode()
    write(output/'INSTALLATION.json',raw)
    print(json.dumps({'installation_sha256':sha(raw),'member_count':len(inventory),
        'downloaded_code_executed':False}))


def launch(args, guard):
    root = checked(args.software_root)
    installed = parse(guard.read(root/'INSTALLATION.json', args.inventory_sha256))
    need(installed['schema'] == 'kpx6-private-sum-public-installation/v1', 'fixed-public-installation')
    for row in installed['files']: guard.metadata(root/'software'/relative(row['path']))
    for row in installed['files']:
        path = root/'software'/row['path']; raw=guard.read(path,row['sha256'])
        need(len(raw)==row['bytes'] and path.stat().st_mode & 0o222 == 0, 'readonly-selected-software')
    output = fresh(args.output)
    command = ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
        '--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
        '--ro-bind',str(root/'software'),'/software','--bind',str(output),'/out',
        '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--setenv','TZ','UTC']
    if args.op == 'run':
        compiled = checked(args.compiled_root)
        raw = guard.read(compiled/'COMPILED.json',args.compiled_sha256)
        data = parse(raw)
        for row in data['files']: guard.metadata(compiled/'compiler/Programs'/relative(row['path']))
        for row in data['files']:
            need(len(guard.read(compiled/'compiler/Programs'/row['path'], row['sha256']))==row['bytes'],
                'actual-compiled-member-bytes')
        command += ['--ro-bind',str(compiled/'compiler/Programs'),'/programs',
                    '--ro-bind',str(compiled/'COMPILED.json'),'/compiled.json']
    if args.op == 'build-consumer':
        cache = Path('/home/luke/projects/kpi-intensive-2026-10-22/private-construction-build-01/cargo-home')
        need({p.name for p in cache.iterdir()} <= {'git','registry','.package-cache',
             '.package-cache-mutate','.global-cache'},'existing-public-only-cache-no-config-or-credentials')
        # This previously selected, locked public dependency cache contains no
        # wallet material. Only operational Cargo cache locks may change.
        command += ['--ro-bind','/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu','/toolchain',
                    '--bind',str(cache),'/cargo','--ro-bind','/etc/alternatives','/etc/alternatives']
    if args.op == 'consumer':
        binary=checked(args.consumer_binary)
        guard.read(binary,args.consumer_sha256)
        guard.read(args.sum_results,args.sum_results_sha256)
        command += ['--ro-bind',str(binary),'/consumer',
                    '--ro-bind',str(checked(args.sum_results)),'/sum-results.json']
    command += ['--chdir','/software','/usr/bin/python3','-B','/software/worker.py',args.op]
    with (output/'stdout.log').open('xb') as stdout, (output/'stderr.log').open('xb') as stderr:
        result = subprocess.run(command,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=CLEAN)
    counters = None
    try:
        relative_cgroup = next(line.split(':',2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
                               if line.startswith('0::'))
        directory = Path('/sys/fs/cgroup')/relative_cgroup.lstrip('/')
        counters = {name:(directory/name).read_text().strip() for name in
                    ('cpu.stat','memory.peak','memory.swap.peak','memory.events') if (directory/name).exists()}
    except (OSError,StopIteration): pass
    write(output/'PHASE.json',(json.dumps({'schema':'kpx6-private-sum-phase/v1','op':args.op,
        'returncode':result.returncode,'installation_sha256':args.inventory_sha256,
        'host_network_home_wallet_parameters_or_credentials_mounted':False,
        'owned_unit_cgroup_counters':counters,'background_units_created':False,
        'downloaded_engine_executed':args.op=='run',
        'downloaded_compiler_executed':args.op=='compile'},sort_keys=True)+'\n').encode())
    need(result.returncode==0,'phase-failed-see-retained-stderr')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('op',choices=('stage','calibrate','compile','run','build-consumer','consumer'))
    parser.add_argument('--output',required=True)
    parser.add_argument('--inventory-sha256',required=True)
    parser.add_argument('--software-root')
    parser.add_argument('--compiled-root')
    parser.add_argument('--compiled-sha256')
    parser.add_argument('--consumer-binary')
    parser.add_argument('--consumer-sha256')
    parser.add_argument('--sum-results')
    parser.add_argument('--sum-results-sha256')
    parser.add_argument('--exclude-private-root',action='append',required=True)
    args=parser.parse_args(); guard=PublicGuard(args.exclude_private_root)
    if args.op=='stage':stage(args,guard)
    else:launch(args,guard)


if __name__=='__main__': main()
