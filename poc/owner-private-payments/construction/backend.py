#!/usr/bin/env python3
"""Bounded public compiler/controller for stock complete-row MASCOT construction."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time
import uuid

from codec import INPUT_BYTES, Q, canonical_json, hex32, need, parse_json, session, sha

HERE = Path(__file__).resolve().parent
IMAGE = 'sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea'
ENGINE_SHA = '47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e'
ENGINE_INVENTORY_SHA = '5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
LABEL = 'kpx7.construction.owned'


def path(value):
    p = Path(value).absolute()
    need('..' not in p.parts and all(not q.is_symlink() for q in (p, *p.parents)),
         'canonical-nonsymlink-path')
    return p


class PublicGuard:
    """Metadata exclusion before public bytes; no original private file opens."""
    def __init__(self, roots, owner_roots=()):
        need(len(roots) == 2 and len(set(path(root) for root in roots)) == 2,
             'exact-two-distinct-original-trial-exclusions-required')
        self.forbidden, self.originals, self.directories = set(), set(), []
        for root in roots:
            for role in 'ABCD':
                directory = path(Path(root) / 'owners' / role)
                p = path(directory / 'backup.json'); s = p.stat()
                need(directory.is_dir() and stat.S_ISREG(s.st_mode), 'original-metadata-only')
                self.directories.append(directory); self.forbidden.add((s.st_dev, s.st_ino))
                self.originals.add((s.st_dev, s.st_ino))
        need(len(self.originals) == 8, 'eight-distinct-original-private-inodes-required')
        self.owner_directories = [path(root) for root in owner_roots]
        need(len(set(self.owner_directories)) == len(self.owner_directories), 'distinct-owner-private-roots')
        for directory in self.owner_directories:
            need(all(not directory.is_relative_to(old) and not old.is_relative_to(directory)
                     for old in self.directories), 'new-owner-private-roots-must-not-overlap-old-owners')
            need(directory.is_dir(), 'owner-private-root-metadata')
            self.directories.append(directory)
            # Metadata only: cover all current new secret files and complete
            # directories before first public ingress. Never read a leaf.
            for current, dirs, files in os.walk(directory, followlinks=False):
                for name in dirs + files:
                    # Prior owned TLS rehash creates private cert symlinks.
                    # Observe only link metadata; never follow a private
                    # target. Public ingress still rejects every symlink.
                    member = Path(current) / name; s = member.lstat()
                    if stat.S_ISREG(s.st_mode):
                        self.forbidden.add((s.st_dev, s.st_ino))

    def metadata(self, value):
        p = path(value); s = p.stat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and (s.st_dev, s.st_ino) not in self.forbidden and
             all(not p.is_relative_to(d) for d in self.directories), 'public-aliases-original-private')
        return p, s

    def own_input_metadata(self, value, party):
        p = path(value); s = p.stat()
        need(len(self.owner_directories) == 3 and p.name == f'Input-P{party}-0' and
             p.is_relative_to(self.owner_directories[party]) and stat.S_ISREG(s.st_mode) and
             (s.st_dev, s.st_ino) not in self.originals and s.st_nlink == 1 and
             s.st_mode & 0o777 == 0o400 and s.st_size == INPUT_BYTES,
             'exact-one-own-fixed-size-synthetic-input-handle')
        return p, s

    def read(self, value, expected):
        p, before = self.metadata(value)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            opened = os.fstat(source.fileno())
            need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino) and
                 (opened.st_dev, opened.st_ino) not in self.forbidden, 'public-swapped-before-read')
            raw = source.read(); after = os.fstat(source.fileno())
        attrs = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, k) == getattr(after, k) for k in attrs) and
             len(raw) == before.st_size and sha(raw) == hex32(expected), 'stable-selected-public-bytes')
        return raw


def relative(value):
    need(type(value) is str, 'relative-path-string')
    p = Path(value)
    need(not p.is_absolute() and '..' not in p.parts and str(p) == value and value != '.',
         'canonical-relative-member')
    return p


def write(p, raw, mode=0o400):
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open('xb') as out:
        out.write(raw)
    p.chmod(mode)


def fresh(value):
    p = path(value)
    need(not p.exists(), 'fresh-output-required')
    parent = p.parent
    while not parent.exists():
        parent = parent.parent
    test = subprocess.run(['/usr/bin/git', '-C', str(parent), 'rev-parse', '--is-inside-work-tree'],
                          capture_output=True, env=CLEAN)
    need(test.returncode != 0 or test.stdout.strip() != b'true', 'runtime-output-outside-git')
    p.mkdir(parents=True, mode=0o700)
    return p


def bubble():
    return ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
            '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'TZ', 'UTC']


def prepare(args, guard):
    root = path(args.engine_root)
    raw = guard.read(root / 'INSTALLATION.json', ENGINE_INVENTORY_SHA)
    inventory = parse_json(raw)
    need(inventory['schema'] == 'kpx6-private-sum-public-installation/v1' and
         inventory['distribution_sha256'] ==
         '73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760',
         'selected-existing-public-engine-installation')
    selected = [r for r in inventory['files'] if r['path'].startswith(('Compiler/', 'compiler-dependency/'))
                or r['path'] in ('compile.py', 'mascot-party.x')]
    need(len({r['path'] for r in selected}) == len(selected), 'unique-engine-members')
    for r in selected:
        guard.metadata(root / 'software' / relative(r['path']))
    for name in ('codec.py', 'party.py', 'coordinator.py', 'kpx7_mix.mpc'):
        guard.metadata(HERE / name)
    guard.metadata(args.session)
    program = guard.read(HERE / 'kpx7_mix.mpc', args.program_sha256)
    specification = guard.read(args.session, args.session_sha256)
    _, session_sha = session(specification, sha(program))
    output = fresh(args.output); software = output / 'software'; software.mkdir()
    files = []
    for r in selected:
        source = root / 'software' / r['path']
        content = guard.read(source, r['sha256'])
        need(len(content) == r['bytes'] and source.stat().st_mode & 0o222 == 0,
             'readonly-selected-engine-member')
        write(software / r['path'], content, 0o500 if r['path'] == 'mascot-party.x' else 0o400)
    need(sha((software / 'mascot-party.x').read_bytes()) == ENGINE_SHA, 'stock-engine-pin')
    for name, pin in (('codec.py', args.codec_sha256), ('party.py', args.party_sha256),
                      ('coordinator.py', args.coordinator_sha256)):
        write(software / name, guard.read(HERE / name, pin))
    write(software / 'kpx7_mix.mpc', program)
    write(output / 'SESSION.json', canonical_json(parse_json(specification)))
    work = output / 'compiler'; (work / 'Programs/Source').mkdir(parents=True)
    write(work / 'Programs/Source/kpx7_mix.mpc', program)
    command = bubble() + ['--ro-bind', str(software), '/software', '--bind', str(work), '/work',
                         '--chdir', '/work', '--setenv', 'PYTHONPATH', '/software/compiler-dependency',
                         '/usr/bin/python3', '-B', '/software/compile.py', '-F', '249', '-P', str(Q),
                         'kpx7_mix', session_sha]
    with (output / 'compiler.stdout').open('xb') as out, (output / 'compiler.stderr').open('xb') as err:
        result = subprocess.run(command, stdout=out, stderr=err, env=CLEAN, stdin=subprocess.DEVNULL)
    need(result.returncode == 0, 'stock-compiler-failed-see-public-output')
    programs = output / 'programs'
    for kind in ('Schedules', 'Bytecode'):
        for source in sorted((work / 'Programs' / kind).rglob('*')):
            if source.is_file():
                write(programs / source.relative_to(work / 'Programs'), source.read_bytes())
    schedule = programs / 'Schedules' / ('kpx7_mix-' + session_sha + '.sch')
    need(str(Q) in schedule.read_text(), 'compiled-schedule-exact-babyjubjub-prime')
    for directory in (software, programs):
        for p in sorted(directory.rglob('*')):
            if p.is_file():
                content = p.read_bytes()
                files.append({'path': str(p.relative_to(output)), 'bytes': len(content), 'sha256': sha(content)})
    write(output / 'PREPARED.json', canonical_json({
        'schema': 'kpx7-mascot-complete-row-prepared/v1', 'session_sha256': session_sha,
        'session_file_sha256': sha((output / 'SESSION.json').read_bytes()), 'prime_decimal': str(Q),
        'program_source_sha256': sha(program), 'image': IMAGE, 'engine_sha256': ENGINE_SHA,
        'files': files, 'scope': 'PUBLIC_COMPILE_ONLY_NO_OWNER_INPUT_OR_ENGINE_EXECUTION'}))
    print(json.dumps({'prepared_sha256': sha((output / 'PREPARED.json').read_bytes()),
                      'session_sha256': session_sha, 'file_count': len(files), 'engine_executed': False}))


def load_prepared(args, guard):
    root = path(args.prepared_root)
    value = parse_json(guard.read(root / 'PREPARED.json', args.prepared_sha256))
    need(value['schema'] == 'kpx7-mascot-complete-row-prepared/v1' and value['prime_decimal'] == str(Q)
         and value['image'] == IMAGE and value['engine_sha256'] == ENGINE_SHA, 'selected-prepared-program')
    need(len({r['path'] for r in value['files']}) == len(value['files']), 'unique-prepared-members')
    for r in value['files']:
        p = relative(r['path'])
        need(p.parts[0] in ('software', 'programs'), 'fixed-prepared-member-kind')
        guard.metadata(root / p)
    for r in value['files']:
        p = root / r['path']; content = guard.read(p, r['sha256'])
        need(len(content) == r['bytes'] and p.stat().st_mode & 0o222 == 0, 'readonly-prepared-member')
    raw = guard.read(root / 'SESSION.json', value['session_file_sha256'])
    _, sid = session(raw, value['program_source_sha256'])
    need(sid == value['session_sha256'], 'prepared-session-join')
    return root, value


class Docker:
    def __init__(self, output, token):
        self.output, self.token = output, token
        for name in ('home', 'docker-config'):
            (output / name).mkdir()
        self.env = dict(CLEAN, HOME=str(output / 'home'), DOCKER_CONFIG=str(output / 'docker-config'),
                        DOCKER_HOST='unix:///var/run/docker.sock')
        self.names = []
        self.samples = []

    def cli(self, *args, check=True):
        result = subprocess.run(['/usr/bin/docker', *args], capture_output=True, env=self.env)
        if check:
            need(result.returncode == 0, 'owned-docker-operation-failed')
        return result

    def info(self, name):
        need(name in self.names, 'only-current-owned-container')
        value = parse_json(self.cli('inspect', '--format', '{{json .}}', name).stdout)
        need(value['Config']['Image'] == IMAGE and
             value['Config']['Labels'].get(LABEL) == self.token, 'owned-container-identity')
        return value

    def base(self, name, network, anchor=False):
        self.names.append(name)
        memory, cpu = ('32m', '0.1') if anchor else ('1g', '0.9')
        return ['/usr/bin/docker', 'run', '--pull=never', '--name', name,
                '--label', LABEL + '=' + self.token, '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true', '--user', f'{os.getuid()}:{os.getgid()}',
                '--cpus', cpu, '--memory', memory, '--memory-swap', memory, '--pids-limit', '256',
                '--network', network, '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m,mode=1777',
                '--mount', 'type=bind,src=/usr,dst=/usr,readonly']

    def cleanup(self):
        receipts, errors = [], []
        for name in self.names:
            result = self.cli('container', 'ls', '--all', '--filter', 'name=^/' + name + '$',
                              '--format', '{{.Names}}', check=False)
            if result.returncode != 0:
                errors.append('state-query-failed'); continue
            if not result.stdout.strip():
                continue
            try:
                value = self.info(name)
                receipts.append({'name': name, 'container_id': value['Id'],
                                 'state': {k: value['State'][k] for k in
                                           ('Status', 'Running', 'Pid', 'ExitCode', 'OOMKilled', 'Dead')},
                                 'limits': {k: value['HostConfig'][k] for k in
                                            ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit')}})
                self.cli('rm', '--force', name)
                test = self.cli('container', 'ls', '--all', '--filter', 'name=^/' + name + '$',
                                '--format', '{{.Names}}')
                need(not test.stdout.strip(), 'owned-container-removal-not-confirmed')
            except Exception:
                errors.append('identity-or-cleanup-failed')
        write(self.output / 'CLEANUP.json', canonical_json({'owned': receipts, 'errors': errors,
                                                          'resource_samples': self.samples,
                                                          'samples_are_not_complete_lifetime_totals': True,
                                                          'unrelated_images_or_containers_changed': False}))
        need(not errors, 'owned-cleanup-incomplete')

    def sample(self):
        for name in self.names:
            try:
                probe = self.cli('inspect', '--format', '{{.Id}}', name, check=False)
                if probe.returncode != 0:
                    continue
                value = self.info(name); pid = value['State']['Pid']
                if not pid:
                    continue
                group = next(line.split(':', 2)[2]
                             for line in Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                             if line.startswith('0::'))
                need(value['Id'] in group, 'current-owned-container-cgroup')
                directory = Path('/sys/fs/cgroup') / group.lstrip('/')
                fields = {key: (directory / key).read_text().strip() for key in
                          ('cpu.stat', 'memory.peak', 'memory.swap.peak', 'memory.events')
                          if (directory / key).exists()}
                self.samples.append({'container_id': value['Id'], 'observed': fields,
                                     'monotonic': time.monotonic()})
            except (OSError, StopIteration):
                pass


def controller_limits():
    relative_group = next(s.split(':', 2)[2] for s in Path('/proc/self/cgroup').read_text().splitlines()
                          if s.startswith('0::'))
    directory = Path('/sys/fs/cgroup') / relative_group.lstrip('/')
    quota, period = (directory / 'cpu.max').read_text().split()
    memory = (directory / 'memory.max').read_text().strip()
    need(quota != 'max' and int(quota) <= int(period) and memory != 'max' and
         int(memory) <= 512 * 1024 * 1024, 'controller-at-most-one-cpu-512mib')


def run(args, guard):
    need(args.execute, 'explicit-engine-execution-required')
    controller_limits()
    root, prepared = load_prepared(args, guard)
    sid = prepared['session_sha256']
    # Metadata only. The public controller NEVER reads an owner input file.
    inputs = []
    for party, directory in enumerate(args.owner_input_directory):
        p, s = guard.own_input_metadata(path(directory) / f'Input-P{party}-0', party)
        need(s.st_nlink == 1 and s.st_mode & 0o777 == 0o400, 'own-readonly-private-input-handle')
        inputs.append((p, s))
    need(len({(s.st_dev, s.st_ino) for _, s in inputs}) == 3, 'distinct-private-input-handles')
    output = fresh(args.output); token = str(uuid.uuid4()); docker = Docker(output, token)
    need(parse_json(docker.cli('image', 'inspect', IMAGE, '--format', '{{json .Id}}').stdout) == IMAGE,
         'exact-existing-image-no-pull')
    certs = output / 'certificates'; certs.mkdir()
    private = []
    # Fresh transport material only. Never tuple/proof/beta material here.
    for party in range(3):
        # Internal engine diagnostics remain beside this one owner's opaque
        # input, outside the public output tree. Never copy them to collector.
        directory = inputs[party][0].parent / ('mpc-private-' + token)
        need(not directory.exists(), 'fresh-own-private-engine-scratch')
        directory.mkdir(mode=0o700)
        cert, key = certs / f'P{party}.pem', directory / f'P{party}.key'
        result = subprocess.run(['/usr/bin/openssl', 'req', '-config', '/dev/null', '-newkey', 'rsa:2048',
                                 '-nodes', '-x509', '-days', '1', '-out', str(cert), '-keyout', str(key),
                                 '-subj', f'/CN=P{party}'], capture_output=True, env=CLEAN)
        need(result.returncode == 0, 'fresh-party-transport-setup')
        key.chmod(0o400); private.append(directory)
    for directory in private:
        for cert in certs.iterdir():
            write(directory / cert.name, cert.read_bytes())
        result = subprocess.run(['/usr/bin/openssl', 'rehash', str(directory)], capture_output=True, env=CLEAN)
        need(result.returncode == 0, 'public-peer-certificate-setup')
    names = ['kpx7-' + token + '-anchor'] + ['kpx7-' + token + '-p' + str(i) for i in range(3)]
    processes, streams, receipts = [], [], []
    started = time.monotonic()
    try:
        anchor = docker.base(names[0], 'none', anchor=True) + ['--detach', '--entrypoint', '/usr/bin/env',
                    IMAGE, '-i', 'PATH=/usr/bin:/bin', '/usr/bin/sleep', 'infinity']
        need(subprocess.run(anchor, capture_output=True, env=docker.env).returncode == 0,
             'isolated-loopback-anchor-start')
        for party, (source, before) in enumerate(inputs):
            _, now = guard.own_input_metadata(source, party)
            need((now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) ==
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                 'private-input-handle-changed-before-mount')
            command = docker.base(names[party + 1], 'container:' + names[0]) + [
                '--mount', f'type=bind,src={source},dst=/input/Input-P{party}-0,readonly',
                '--mount', f'type=bind,src={private[party]},dst=/work/Player-Data',
                '--mount', f'type=bind,src={private[party] / ("P" + str(party) + ".key")},dst=/work/Player-Data/P{party}.key,readonly',
                '--mount', f'type=bind,src={root / "programs"},dst=/work/Programs,readonly',
                '--mount', f'type=bind,src={root / "software/mascot-party.x"},dst=/engine,readonly',
                '--mount', f'type=bind,src={root / "software/party.py"},dst=/software/party.py,readonly',
                '--mount', f'type=bind,src={root / "software/codec.py"},dst=/software/codec.py,readonly',
                '--workdir', '/work', '--entrypoint', '/usr/bin/env', IMAGE, '-i',
                'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'TZ=UTC', '/usr/bin/python3', '-B',
                '/software/party.py', str(party), sid, str(before.st_dev), str(before.st_ino)]
            out, err = (output / f'public-party-{party}.json').open('xb'), (output / f'public-party-{party}.stderr').open('xb')
            streams.extend((out, err))
            processes.append(subprocess.Popen(command, stdout=out, stderr=err,
                                               stdin=subprocess.DEVNULL, env=docker.env))
        # Generous operational cap produces INCOMPLETE only; no subset result.
        last_sample = 0
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None, 0) for p in processes):
                raise ValueError('party-failed-no-subset-result')
            need(time.monotonic() - started < 1800, 'operational-incomplete-no-partial-result')
            if time.monotonic() - last_sample >= 1:
                docker.sample(); last_sample = time.monotonic()
            time.sleep(0.1)
        need([p.returncode for p in processes] == [0, 0, 0], 'three-successful-party-exits')
        for stream in streams:
            stream.close()
        receipts = [(output / f'public-party-{i}.json').read_bytes() for i in range(3)]
        need(receipts[0] == receipts[1] == receipts[2], 'all-party-public-output-equality')
        value = parse_json(receipts[0])
        need(value['schema'] == 'kpx7-mixed-complete-outputs/v1' and value['session_sha256'] == sid,
             'public-result-session')
        # The host is a trusted process launcher, not the malicious observer.
        # The observer is a separate least-privilege coordinator process with
        # this public-only stdin packet and no Docker/owner path mounts/API.
        observer = output / 'coordinator-public'; observer.mkdir()
        packet = canonical_json({'schema': 'kpx7-coordinator-public-ipc/v1',
                 'session': parse_json((root / 'SESSION.json').read_bytes()),
                 'session_sha256': sid, 'prepared_sha256': args.prepared_sha256,
                 'party_projections': [parse_json(raw) for raw in receipts]})
        write(output / 'COORDINATOR-PUBLIC-IPC.json', packet)
        command = bubble() + [
            '--ro-bind', str(root / 'software/codec.py'), '/app/codec.py',
            '--ro-bind', str(root / 'software/coordinator.py'), '/app/coordinator.py',
            '--bind', str(observer), '/out', '--chdir', '/app',
            '/usr/bin/python3', '-B', '/app/coordinator.py']
        result = subprocess.run(command, input=packet, capture_output=True, env=CLEAN)
        write(output / 'coordinator.stdout', result.stdout)
        write(output / 'coordinator.stderr', result.stderr)
        need(result.returncode == 0, 'public-only-coordinator-failed')
        need(guard.read(observer / 'MIXED.json', sha(receipts[0])) == receipts[0],
             'coordinator-output-must-match-own-engines')
        write(output / 'MIXED.json', receipts[0])
    finally:
        try:
            docker.cleanup()
        finally:
            for p in processes:
                if p.poll() is None:
                    try:
                        p.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        p.kill(); p.wait()
            for stream in streams:
                stream.close()
    write(output / 'RESULTS.json', canonical_json({'schema': 'kpx7-complete-row-mascot-result/v1',
          'status': 'COMPLETE', 'session_sha256': sid, 'prepared_sha256': args.prepared_sha256,
          'mixed_sha256': sha(receipts[0]), 'row_count': 6, 'tuple_bytes': 520,
          'party_success_count': 3, 'wall_seconds': time.monotonic() - started,
          'host_owner_input_read_count': 0, 'all_owned_containers_removed': True,
          'financial_authorization_or_privacy_qualification': False}))
    print(json.dumps({'status': 'COMPLETE', 'mixed_sha256': sha(receipts[0]), 'row_count': 6}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('op', choices=('prepare', 'run'))
    parser.add_argument('--exclude-private-root', action='append', required=True)
    parser.add_argument('--exclude-owner-private-directory', action='append', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--engine-root'); parser.add_argument('--session'); parser.add_argument('--session-sha256')
    parser.add_argument('--program-sha256'); parser.add_argument('--codec-sha256'); parser.add_argument('--party-sha256')
    parser.add_argument('--coordinator-sha256')
    parser.add_argument('--prepared-root'); parser.add_argument('--prepared-sha256')
    parser.add_argument('--owner-input-directory', nargs=3); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    need(len(args.exclude_owner_private_directory) == 3, 'three-new-owner-private-exclusions')
    guard = PublicGuard(args.exclude_private_root, args.exclude_owner_private_directory)
    if args.op == 'prepare':
        need(not args.execute, 'prepare-is-public-compiler-only')
        prepare(args, guard)
    else:
        need(args.owner_input_directory is not None, 'three-opaque-owner-input-handles')
        run(args, guard)


if __name__ == '__main__':
    main()
