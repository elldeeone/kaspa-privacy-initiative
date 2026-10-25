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

from codec import PHASE_BYTES, Q, canonical_json, hex32, need, parse_json, session, sha, validate_admission, validate_authorizations

HERE = Path(__file__).resolve().parent
IMAGE = 'sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea'
ENGINE_SHA = '47d9ae6f52003825946a4abb6cf9dc62f62a4e2fc2c19a5e3ee6f59a6889b07e'
ENGINE_INVENTORY_SHA = '5d0def4ae617f6365fccb5f243922088faaf7a6148aa0938c3a3f9520c4ff594'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
LABEL = 'kpx9.admission.owned'
LOCAL_SOURCES = ('codec.py', 'party.py', 'coordinator.py', 'kpx9_admission.mpc')
COMMON_SCHEMA = 'kpx9-mascot-readonly-public-software/v1'
PREPARED_V1 = 'kpx9-two-phase-admission-prepared/v1'
PREPARED_V2 = 'kpx9-two-phase-admission-prepared/v2'


def path(value):
    p = Path(value).absolute()
    need('..' not in p.parts and all(not q.is_symlink() for q in (p, *p.parents)),
         'canonical-nonsymlink-path')
    return p


class PublicGuard:
    """Metadata exclusion before public bytes; no original private file opens."""
    def __init__(self, roots, owner_roots=(), retained_roots=()):
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
        # The whole integrated runtime's private parent was reserved before
        # any wallet/controller material existed. Retained old experiment
        # private parents are likewise metadata-only exclusions, independent
        # of the three current input owners used by own_input_metadata().
        for value in retained_roots:
            directory = path(value)
            need(directory.is_dir(), 'retained-private-parent-metadata')
            if directory not in self.directories:
                self.directories.append(directory)
            for current, dirs, files in os.walk(directory, followlinks=False):
                for name in dirs + files:
                    member = Path(current) / name
                    info = member.lstat()
                    if stat.S_ISREG(info.st_mode):
                        self.forbidden.add((info.st_dev, info.st_ino))

    def metadata(self, value):
        p = path(value); s = p.stat()
        need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1 and (s.st_dev, s.st_ino) not in self.forbidden and
             all(not p.is_relative_to(d) for d in self.directories), 'public-aliases-original-private')
        return p, s

    def own_input_metadata(self, value, party, phase):
        p = path(value); s = p.stat()
        need(len(self.owner_directories) == 3 and p.name == f'Input-P{party}-0' and
             p.is_relative_to(self.owner_directories[party]) and stat.S_ISREG(s.st_mode) and
             (s.st_dev, s.st_ino) not in self.originals and s.st_nlink == 1 and
             s.st_mode & 0o777 == 0o400 and s.st_size == PHASE_BYTES[phase],
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


def program_name(sid, phase, effects):
    hex32(sid); hex32(effects)
    need(phase in PHASE_BYTES, 'selected-admission-phase')
    return 'kpx9_admission-' + sid + '-' + phase + '-' + effects


def source_pins(args):
    values = {'codec.py': args.codec_sha256, 'party.py': args.party_sha256,
              'coordinator.py': args.coordinator_sha256, 'kpx9_admission.mpc': args.program_sha256}
    for value in values.values():
        hex32(value)
    return values


def installation(guard, root):
    raw = guard.read(root / 'INSTALLATION.json', ENGINE_INVENTORY_SHA)
    inventory = parse_json(raw)
    need(inventory['schema'] == 'kpx6-private-sum-public-installation/v1' and
         inventory['distribution_sha256'] ==
         '73d6473526101b4433999fc4f7521fdfdc53ddf018e5f64480518d6293f62760',
         'selected-existing-public-engine-installation')
    selected = [r for r in inventory['files'] if r['path'].startswith(('Compiler/', 'compiler-dependency/'))
                or r['path'] in ('compile.py', 'mascot-party.x')]
    need(len({r['path'] for r in selected}) == len(selected) and
         {'compile.py', 'mascot-party.x'} <= {r['path'] for r in selected}, 'unique-complete-engine-members')
    return raw, selected


def public_fresh(value, guard):
    result = path(value)
    need(all(not result.is_relative_to(directory) for directory in guard.directories),
         'public-software-or-program-output-outside-private')
    return fresh(result)


def create_software(args, guard, *, freeze_root=True):
    """One explicit immutable public software closure, never owner inputs."""
    root = path(args.engine_root)
    inventory_raw, selected = installation(guard, root)
    pins = source_pins(args)
    for row in selected:
        guard.metadata(root / 'software' / relative(row['path']))
    for name in LOCAL_SOURCES:
        guard.metadata(HERE / name)
    output = public_fresh(args.output, guard)
    software = output / 'software'; software.mkdir()
    files = []
    for row in selected:
        source = root / 'software' / relative(row['path'])
        content = guard.read(source, row['sha256'])
        need(type(row['bytes']) is int and len(content) == row['bytes'] and
             source.stat().st_mode & 0o222 == 0, 'readonly-selected-engine-member')
        write(software / row['path'], content, 0o500 if row['path'] == 'mascot-party.x' else 0o400)
        files.append({'path': 'software/' + row['path'], 'bytes': len(content), 'sha256': sha(content)})
    for name, expected in pins.items():
        content = guard.read(HERE / name, expected)
        write(software / name, content)
        files.append({'path': 'software/' + name, 'bytes': len(content), 'sha256': sha(content)})
    need(guard.read(software / 'mascot-party.x', ENGINE_SHA), 'stock-engine-pin')
    write(output / 'INSTALLATION.json', inventory_raw)
    manifest = {'schema': COMMON_SCHEMA, 'prime_decimal': str(Q), 'image': IMAGE,
        'engine_sha256': ENGINE_SHA, 'installation_sha256': ENGINE_INVENTORY_SHA,
        'local_source_sha256': pins, 'files': sorted(files, key=lambda row: row['path']),
        'scope': 'READONLY_PUBLIC_SOFTWARE_NO_SESSION_OWNER_INPUT_OR_ENGINE_EXECUTION'}
    raw = canonical_json(manifest); write(output / 'COMMON.json', raw)
    for directory in sorted((p for p in software.rglob('*') if p.is_dir()), reverse=True):
        directory.chmod(0o500)
    software.chmod(0o500)
    if freeze_root:
        output.chmod(0o500)
    return output, manifest, sha(raw)


def prepare_software(args, guard):
    output, manifest, expected = create_software(args, guard)
    print(json.dumps({'software_root': str(output), 'software_manifest_sha256': expected,
                      'file_count': len(manifest['files']), 'engine_executed': False}))


def load_software(root, expected, guard):
    root = path(root)
    software = root / 'software'
    value = parse_json(guard.read(root / 'COMMON.json', expected))
    need(type(value) is dict and set(value) == {'schema', 'prime_decimal', 'image', 'engine_sha256',
         'installation_sha256', 'local_source_sha256', 'files', 'scope'} and
         value['schema'] == COMMON_SCHEMA and value['prime_decimal'] == str(Q) and
         value['image'] == IMAGE and value['engine_sha256'] == ENGINE_SHA and
         value['installation_sha256'] == ENGINE_INVENTORY_SHA and
         value['scope'] == 'READONLY_PUBLIC_SOFTWARE_NO_SESSION_OWNER_INPUT_OR_ENGINE_EXECUTION',
         'exact-selected-common-software')
    _, stock = installation(guard, root)
    pins = value['local_source_sha256']
    need(type(pins) is dict and set(pins) == set(LOCAL_SOURCES), 'exact-shared-local-source-pins')
    for expected_source in pins.values():
        hex32(expected_source)
    required = {'software/' + row['path']: row for row in stock}
    required.update({'software/' + name: {'sha256': expected_source} for name, expected_source in pins.items()})
    need(type(value['files']) is list and len(value['files']) == len(required) and
         {row['path'] for row in value['files']} == set(required), 'complete-exact-common-software-inventory')
    need({member.name for member in root.iterdir()} == {'COMMON.json', 'INSTALLATION.json', 'software'},
         'no-extra-common-root-members')
    actual = set()
    for current, directories, names in os.walk(software, followlinks=False):
        need(all(not (Path(current) / name).is_symlink() for name in directories),
             'no-common-directory-alias')
        for name in names:
            member = Path(current) / name
            guard.metadata(member)
            actual.add(str(member.relative_to(root)))
    need(actual == set(required), 'no-unlisted-common-software-files')
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             type(row['bytes']) is int and row['bytes'] >= 0, 'exact-common-file-fields')
        member = root / relative(row['path'])
        guard.metadata(member)
        need(row['sha256'] == required[row['path']]['sha256'] and
             ('bytes' not in required[row['path']] or row['bytes'] == required[row['path']]['bytes']),
             'shared-member-origin-pin')
    for row in value['files']:
        member = root / row['path']; content = guard.read(member, row['sha256'])
        need(len(content) == row['bytes'] and member.stat().st_mode & 0o222 == 0,
             'readonly-common-member')
    guard.read(software / 'mascot-party.x', ENGINE_SHA)
    return root / 'software', value


def prepare(args, guard):
    guard.metadata(args.session)
    specification = guard.read(args.session, args.session_sha256)
    pins = source_pins(args)
    shared = getattr(args, 'software_root', None)
    if shared is not None:
        need(getattr(args, 'software_sha256', None) is not None, 'selected-shared-software-pin-required')
        software, common = load_software(shared, args.software_sha256, guard)
        need(common['local_source_sha256'] == pins, 'shared-source-and-selected-phase-source-join')
        program = guard.read(software / 'kpx9_admission.mpc', args.program_sha256)
        output = public_fresh(args.output, guard)
    else:
        need(getattr(args, 'software_sha256', None) is None, 'shared-root-and-pin-together')
        output, common, _ = create_software(args, guard, freeze_root=False)
        software = output / 'software'
        program = guard.read(software / 'kpx9_admission.mpc', args.program_sha256)
    _, session_sha = session(specification, sha(program))
    write(output / 'SESSION.json', canonical_json(parse_json(specification)))
    work = output / 'compiler'; work.mkdir()
    programs = output / 'programs'; (programs / 'Source').mkdir(parents=True)
    write(programs / 'Source/kpx9_admission.mpc', program)
    # Compile directly into the selected per-session program directory. No
    # duplicate compiler/dependency/engine tree or bytecode copy is necessary.
    command = bubble() + ['--ro-bind', str(software), '/software', '--bind', str(work), '/work',
                         '--bind', str(programs), '/work/Programs', '--chdir', '/work',
                         '--setenv', 'PYTHONPATH', '/software/compiler-dependency',
                         '/usr/bin/python3', '-B', '/software/compile.py', '-F', '249', '-P', str(Q),
                         'kpx9_admission', session_sha, args.phase, args.effects_digest]
    with (output / 'compiler.stdout').open('xb') as out, (output / 'compiler.stderr').open('xb') as err:
        result = subprocess.run(command, stdout=out, stderr=err, env=CLEAN, stdin=subprocess.DEVNULL)
    need(result.returncode == 0, 'stock-compiler-failed-see-public-output')
    schedule = programs / 'Schedules' / (program_name(session_sha, args.phase, args.effects_digest) + '.sch')
    need(str(Q) in schedule.read_text(), 'compiled-schedule-exact-babyjubjub-prime')
    files = [] if shared is not None else list(common['files'])
    for member in sorted(programs.rglob('*')):
        if member.is_file():
            need(not member.is_symlink(), 'compiled-members-not-symlinks')
            content = member.read_bytes(); member.chmod(0o400)
            files.append({'path': str(member.relative_to(output)), 'bytes': len(content), 'sha256': sha(content)})
    value = {'schema': PREPARED_V2 if shared is not None else PREPARED_V1,
        'session_sha256': session_sha, 'session_file_sha256': sha((output / 'SESSION.json').read_bytes()),
        'prime_decimal': str(Q), 'program_source_sha256': sha(program), 'image': IMAGE, 'engine_sha256': ENGINE_SHA,
        'phase': args.phase, 'effects_digest_hex32': args.effects_digest,
        'program_name': program_name(session_sha, args.phase, args.effects_digest),
        'files': files, 'scope': 'PUBLIC_COMPILE_ONLY_NO_OWNER_INPUT_OR_ENGINE_EXECUTION'}
    if shared is not None:
        value['shared_software'] = {'root': str(path(shared)), 'manifest_sha256': args.software_sha256}
    write(output / 'PREPARED.json', canonical_json(value))
    print(json.dumps({'prepared_sha256': sha((output / 'PREPARED.json').read_bytes()),
                      'session_sha256': session_sha, 'file_count': len(files), 'engine_executed': False,
                      'shared_readonly_software': shared is not None}))


def prepared_software(root, value):
    return (path(value['shared_software']['root']) if value['schema'] == PREPARED_V2 else root) / 'software'


def load_prepared(args, guard):
    root = path(args.prepared_root)
    value = parse_json(guard.read(root / 'PREPARED.json', args.prepared_sha256))
    fields = {'schema', 'session_sha256', 'session_file_sha256', 'prime_decimal', 'program_source_sha256',
              'image', 'engine_sha256', 'phase', 'effects_digest_hex32', 'program_name', 'files', 'scope'}
    need(type(value) is dict and value.get('schema') in (PREPARED_V1, PREPARED_V2), 'prepared-schema')
    shared = value['schema'] == PREPARED_V2
    need(set(value) == fields | ({'shared_software'} if shared else set()) and
         value['prime_decimal'] == str(Q) and value['image'] == IMAGE and value['engine_sha256'] == ENGINE_SHA and
         value['scope'] == 'PUBLIC_COMPILE_ONLY_NO_OWNER_INPUT_OR_ENGINE_EXECUTION', 'exact-prepared-fields')
    if shared:
        selector = value['shared_software']
        need(type(selector) is dict and set(selector) == {'root', 'manifest_sha256'}, 'selected-shared-software-fields')
        _, common = load_software(selector['root'], selector['manifest_sha256'], guard)
        need(common['local_source_sha256']['kpx9_admission.mpc'] == value['program_source_sha256'],
             'prepared-and-common-program-source')
    need(type(value['files']) is list and len({r['path'] for r in value['files']}) == len(value['files']),
         'unique-prepared-members')
    for row in value['files']:
        need(type(row) is dict and set(row) == {'path', 'bytes', 'sha256'} and
             type(row['bytes']) is int and row['bytes'] >= 0, 'prepared-member-fields')
        member = relative(row['path'])
        need(member.parts[0] in (('programs',) if shared else ('software', 'programs')),
             'fixed-prepared-member-kind')
        guard.metadata(root / member)
    for row in value['files']:
        member = root / row['path']; content = guard.read(member, row['sha256'])
        need(len(content) == row['bytes'] and member.stat().st_mode & 0o222 == 0, 'readonly-prepared-member')
    raw = guard.read(root / 'SESSION.json', value['session_file_sha256'])
    _, sid = session(raw, value['program_source_sha256'])
    need(sid == value['session_sha256'], 'prepared-session-join')
    need(value['phase'] == args.phase and value['effects_digest_hex32'] == args.effects_digest
         and value['program_name'] == program_name(sid, args.phase, args.effects_digest),
         'prepared-phase-effects-and-program-name')
    software = prepared_software(root, value)
    guard.read(software / 'kpx9_admission.mpc', value['program_source_sha256'])
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
        memory, cpu = ('128m', '0.1') if anchor else ('4g', '2')
        return ['/usr/bin/docker', 'run', '--pull=never', '--name', name,
                '--label', LABEL + '=' + self.token, '--read-only', '--cap-drop=ALL',
                '--security-opt=no-new-privileges:true', '--user', f'{os.getuid()}:{os.getgid()}',
                '--cpus', cpu, '--memory', memory, '--memory-swap', memory, '--pids-limit', '1024',
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
                                     'monotonic_milliseconds': int(time.monotonic() * 1000)})
            except (OSError, StopIteration):
                pass


def run(args, guard):
    need(args.execute, 'explicit-engine-execution-required')
    root, prepared = load_prepared(args, guard)
    software = prepared_software(root, prepared)
    sid = prepared['session_sha256']
    phase, effects = prepared['phase'], prepared['effects_digest_hex32']
    # Metadata only. The public controller NEVER reads an owner input file.
    inputs = []
    for party, directory in enumerate(args.owner_input_directory):
        p, s = guard.own_input_metadata(path(directory) / f'Input-P{party}-0', party, phase)
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
    names = ['kpx9-' + token + '-anchor'] + ['kpx9-' + token + '-p' + str(i) for i in range(3)]
    processes, streams, receipts = [], [], []
    started = time.monotonic()
    try:
        anchor = docker.base(names[0], 'none', anchor=True) + ['--detach', '--entrypoint', '/usr/bin/env',
                    IMAGE, '-i', 'PATH=/usr/bin:/bin', '/usr/bin/sleep', 'infinity']
        need(subprocess.run(anchor, capture_output=True, env=docker.env).returncode == 0,
             'isolated-loopback-anchor-start')
        for party, (source, before) in enumerate(inputs):
            _, now = guard.own_input_metadata(source, party, phase)
            need((now.st_dev, now.st_ino, now.st_size, now.st_mtime_ns, now.st_ctime_ns) ==
                 (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                 'private-input-handle-changed-before-mount')
            command = docker.base(names[party + 1], 'container:' + names[0]) + [
                '--mount', f'type=bind,src={source},dst=/input/Input-P{party}-0,readonly',
                '--mount', f'type=bind,src={private[party]},dst=/work/Player-Data',
                '--mount', f'type=bind,src={private[party] / ("P" + str(party) + ".key")},dst=/work/Player-Data/P{party}.key,readonly',
                '--mount', f'type=bind,src={root / "programs"},dst=/work/Programs,readonly',
                '--mount', f'type=bind,src={software / "mascot-party.x"},dst=/engine,readonly',
                '--mount', f'type=bind,src={software / "party.py"},dst=/software/party.py,readonly',
                '--mount', f'type=bind,src={software / "codec.py"},dst=/software/codec.py,readonly',
                '--workdir', '/work', '--entrypoint', '/usr/bin/env', IMAGE, '-i',
                'PATH=/usr/bin:/bin', 'LANG=C.UTF-8', 'TZ=UTC', '/usr/bin/python3', '-B',
                '/software/party.py', str(party), sid, phase, effects, str(before.st_dev), str(before.st_ino)]
            out, err = (output / f'public-party-{party}.json').open('xb'), (output / f'public-party-{party}.stderr').open('xb')
            streams.extend((out, err))
            processes.append(subprocess.Popen(command, stdout=out, stderr=err,
                                               stdin=subprocess.DEVNULL, env=docker.env))
        # Dependency/party failure aborts. Elapsed time alone never accepts or aborts a trial.
        last_sample = 0
        while any(p.poll() is None for p in processes):
            if any(p.poll() not in (None, 0) for p in processes):
                raise ValueError('party-failed-no-subset-result')
            if time.monotonic() - last_sample >= 1:
                docker.sample(); last_sample = time.monotonic()
            time.sleep(0.1)
        need([p.returncode for p in processes] == [0, 0, 0], 'three-successful-party-exits')
        for stream in streams:
            stream.close()
        receipts = [(output / f'public-party-{i}.json').read_bytes() for i in range(3)]
        need(receipts[0] == receipts[1] == receipts[2], 'all-party-public-output-equality')
        value = parse_json(receipts[0])
        (validate_admission(value, sid) if phase == 'admit' else
         validate_authorizations(value, sid, effects))
        # The host is a trusted process launcher, not the malicious observer.
        # The observer is a separate least-privilege coordinator process with
        # this public-only stdin packet and no Docker/owner path mounts/API.
        observer = output / 'coordinator-public'; observer.mkdir()
        packet = canonical_json({'schema': 'kpx9-coordinator-public-ipc/v1',
                 'session': parse_json((root / 'SESSION.json').read_bytes()),
                 'session_sha256': sid, 'prepared_sha256': args.prepared_sha256,
                 'phase': phase, 'effects_digest_hex32': effects, 'party_projections': [parse_json(raw) for raw in receipts]})
        write(output / 'COORDINATOR-PUBLIC-IPC.json', packet)
        command = bubble() + [
            '--ro-bind', str(software / 'codec.py'), '/app/codec.py',
            '--ro-bind', str(software / 'coordinator.py'), '/app/coordinator.py',
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
    write(output / 'RESULTS.json', canonical_json({'schema': 'kpx9-two-phase-mascot-result/v1',
          'status': 'COMPLETE', 'session_sha256': sid, 'prepared_sha256': args.prepared_sha256,
          'mixed_sha256': sha(receipts[0]), 'phase': phase, 'effects_digest_hex32': effects,
          'party_success_count': 3, 'wall_milliseconds': int((time.monotonic() - started) * 1000),
          'host_owner_input_read_count': 0, 'all_owned_containers_removed': True,
          'financial_authorization_or_privacy_qualification': False}))
    print(json.dumps({'status': 'COMPLETE', 'mixed_sha256': sha(receipts[0]), 'phase': phase}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('op', choices=('prepare-software', 'prepare', 'run'))
    parser.add_argument('--exclude-private-root', action='append', required=True)
    parser.add_argument('--exclude-owner-private-directory', action='append', default=[])
    parser.add_argument('--exclude-retained-private-directory', action='append', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--phase', choices=('admit', 'authorize'))
    parser.add_argument('--effects-digest')
    parser.add_argument('--engine-root'); parser.add_argument('--session'); parser.add_argument('--session-sha256')
    parser.add_argument('--program-sha256'); parser.add_argument('--codec-sha256'); parser.add_argument('--party-sha256')
    parser.add_argument('--coordinator-sha256')
    parser.add_argument('--software-root'); parser.add_argument('--software-sha256')
    parser.add_argument('--prepared-root'); parser.add_argument('--prepared-sha256')
    parser.add_argument('--owner-input-directory', nargs=3); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if args.op != 'prepare-software':
        need(args.phase in PHASE_BYTES, 'selected-admission-phase')
        hex32(args.effects_digest)
        need(args.phase != 'admit' or args.effects_digest == '0' * 64, 'admission-precedes-effects')
    need(len(args.exclude_owner_private_directory) in (0, 3) if args.op == 'prepare-software' else
         len(args.exclude_owner_private_directory) == 3, 'three-new-owner-private-exclusions')
    need(path('/var/tmp/kpi-owner-private-lifecycle-01/private') in
         [path(value) for value in args.exclude_retained_private_directory],
         'whole-integrated-private-parent-exclusion-required')
    guard = PublicGuard(args.exclude_private_root, args.exclude_owner_private_directory,
                        args.exclude_retained_private_directory)
    if args.op == 'prepare-software':
        need(not args.execute, 'software-preparation-does-not-run-engine')
        prepare_software(args, guard)
    elif args.op == 'prepare':
        need(not args.execute, 'prepare-is-public-compiler-only')
        prepare(args, guard)
    else:
        need(args.owner_input_directory is not None, 'three-opaque-owner-input-handles')
        run(args, guard)


if __name__ == '__main__':
    main()
