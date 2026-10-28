#!/usr/bin/env python3
"""Selected PUBLIC-only onion-path probe. No wallet, proof or broadcast role.

The host entry and guard helper must be admitted by the selected caller first.
Installed Python stdlib is an explicit OS trust boundary, not an archive claim.
"""
import argparse
import collections
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
HERE = ROOT / '.local/private-exit-submission-proposal-01/prototype'
PRIVATE_PARENT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
GUARD = ROOT / 'poc/local-private-payment/private_batch_trial/payout_linkage_guard.py'
GUARD_SHA = 'ce86998d7ddfe404cc1c194cda064d369ca1bd78c8df674e43b2381da1d3a4b1'
TOOLS = HERE.parent / 'RUNTIME-ADMISSION-01.json'
TOOLS_SHA = '00a542151ec26f3ce5c6bf7118c2d52c869dd4d32c6700d196d7f54f805adc62'
ELF = HERE.parent / 'RUNTIME-ELF-CLOSURE-02.json'
ELF_SHA = '37de32f92ea7bbe130e122fca73cd7e69a99f02b737cbb2a00231306e883fe4c'
STDLIB = Path('/usr/lib/python3.14')
TOR = Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/bundle/tor/tor')
OLD_STATE = Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/tor-state')
ONION = re.compile(r'[a-z2-7]{56}\.onion')


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def identity(info):
    return tuple(getattr(info, field) for field in
        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_mode'))


def tor_role(kind, socks_port, receiver_port):
    """Only this role sees its own newly generated Tor state and raw notices."""
    os.umask(0o077)
    argv = ['/tools/tor', '--defaults-torrc', '/dev/null', '-f', '/dev/null',
        '--RunAsDaemon', '0', '--DataDirectory', '/state/data', '--ControlPort', '0',
        '--SocksPort', ('127.0.0.1:%d IsolateSOCKSAuth' % socks_port) if kind == 'client' else '0',
        '--Log', 'notice stdout', '--ClientOnly', '1']
    if kind == 'service':
        argv += ['--HiddenServiceDir', '/state/hidden', '--HiddenServiceVersion', '3',
                 '--HiddenServicePort', '80 127.0.0.1:%d' % receiver_port]
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        close_fds=True, env={'PATH': '/usr/bin', 'HOME': '/state', 'LANG': 'C.UTF-8',
                            'LD_LIBRARY_PATH': '/tools:/usr/lib/x86_64-linux-gnu'})
    def stopped(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stopped)
    def notices():
        previous = None
        for line in iter(child.stdout.readline, b''):
            match = re.search(rb'Bootstrapped ([0-9]{1,3})%', line)
            if match and 0 <= int(match[1]) <= 100 and int(match[1]) != previous:
                previous = int(match[1])
                emit({'schema': 'kpb-probe-tor-progress/v1', 'role': kind,
                      'percent': previous, 'monotonic_ns': time.monotonic_ns()})
        # Raw notices are neither retained, hashed nor sent to the host.
    thread = threading.Thread(target=notices, daemon=True)
    thread.start()
    exported = False
    try:
        while child.poll() is None:
            path = Path('/state/hidden/hostname')
            if kind == 'service' and not exported and path.exists():
                before = path.lstat()
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 128
                     and not path.parent.is_symlink(), 'public-hostname-metadata')
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as source:
                    opened = os.fstat(source.fileno()); raw = source.read(129)
                    after = os.fstat(source.fileno())
                need(identity(before) == identity(opened) == identity(after), 'public-hostname-race')
                hostname = raw.decode('ascii').removesuffix('\n')
                need(ONION.fullmatch(hostname) is not None, 'public-v3-hostname')
                emit({'schema': 'kpb-probe-public-onion/v1', 'role': kind,
                      'hostname': hostname, 'monotonic_ns': time.monotonic_ns()})
                exported = True
            time.sleep(0.1)
        emit({'schema': 'kpb-probe-tor-exit/v1', 'role': kind,
              'returncode': child.returncode, 'monotonic_ns': time.monotonic_ns()})
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait()
        thread.join()


def receiver_role(host, port):
    sys.path.insert(0, '/app')
    import receiver
    observer = receiver.Observer('/observations/arrivals')
    server = receiver.ObservedHTTPServer(('127.0.0.1', port), observer, host)
    server.daemon_threads = False
    def stopped(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stopped)
    emit({'schema': 'kpb-probe-listener/v1', 'port': server.server_address[1],
          'monotonic_ns': time.monotonic_ns()})
    try:
        server.serve_forever()
    finally:
        server.server_close()
        emit({'schema': 'kpb-probe-listener-summary/v1', 'accepted': observer.sequence,
              'completed': len(list(Path('/observations/arrivals').glob('arrival-*.json'))),
              'monotonic_ns': time.monotonic_ns()})


def guard_loader():
    # Initial host entry/helper source admission belongs to the selected caller.
    spec = importlib.util.spec_from_file_location('_probe_guard', GUARD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    guard = module.load_guard()
    module.add_exclusions(guard, (OLD_STATE,))
    guard['read'](GUARD, GUARD_SHA)
    return guard


def host(plan_path, plan_sha):
    sys.dont_write_bytecode = True
    guard = guard_loader(); read = guard['read']; metadata = guard['m'].GUARD.metadata
    plan_raw = read(Path(plan_path).absolute(), plan_sha); plan = json.loads(plan_raw)
    need(set(plan) == {'schema', 'classification', 'trial_id', 'source_members', 'runtime_tools',
        'runtime_elf', 'public_input', 'public_output', 'private_state', 'startup_grace_seconds',
        'installed_stdlib_trust', 'execution_selected'}, 'exact-probe-plan')
    need(plan['schema'] == 'kpb-owner-origin-public-onion-probe/v1'
         and plan['classification'] == 'PUBLIC_FIXTURE_TRANSPORT_ONLY_NO_ANONYMITY_OR_FINANCIAL_AUTHORITY'
         and plan['execution_selected'] is True and str(uuid.UUID(plan['trial_id'])) == plan['trial_id']
         and plan['startup_grace_seconds'] == 60
         and plan['installed_stdlib_trust'] == 'ROOT_OWNED_INSTALLED_STDLIB_METADATA_ONLY_NOT_ARCHIVE_AUTHENTICATED',
         'selected-public-probe-only')
    need(plan['runtime_tools'] == {'path': str(TOOLS), 'sha256': TOOLS_SHA}
         and plan['runtime_elf'] == {'path': str(ELF), 'sha256': ELF_SHA}, 'selected-observed-runtime-receipts')
    selected = {}
    for row in plan['source_members']:
        need(set(row) == {'path', 'sha256'} and Path(row['path']).parent == HERE, 'exact-selected-probe-source')
        selected[Path(row['path']).name] = (row, read(Path(row['path']), row['sha256']))
    need(set(selected) == {'run_probe.py', 'receiver.py', 'transport.py', 'packet.py'}, 'complete-probe-source')
    public = Path(plan['public_output']); private = Path(plan['private_state'])
    need(public == HERE.parent / 'runs' / plan['trial_id']
         and private == PRIVATE_PARENT / 'diagnostics' / ('owner-origin-probe-' + plan['trial_id'])
         and not public.exists() and not private.exists(), 'fresh-fixed-role-roots')
    need(any(PRIVATE_PARENT == p or PRIVATE_PARENT.is_relative_to(p) for p in guard['m'].GUARD.directories),
         'private-parent-already-guard-protected')
    for path in (public, private):
        need(not any(p.is_symlink() for p in (path, *path.parents)), 'no-role-root-alias')
    public.mkdir(mode=0o700, parents=True)
    (public / 'observations').mkdir(mode=0o700)
    def save(name, value):
        with (public / name).open('xb') as output:
            output.write(value if type(value) is bytes else encoded(value)); output.flush(); os.fsync(output.fileno())
    save('PLAN.json', plan_raw)
    tools = json.loads(read(TOOLS, TOOLS_SHA)); elf = json.loads(read(ELF, ELF_SHA))
    rows = {r['path']: r for r in [*tools['files'], *elf['files']]}
    descriptors = {}; app_fds = {}; setup_fds = []; processes = []; events = []; messages = queue.Queue(); latest = {}; stopped_roles = set(); masked_packages = []
    def event(kind, **values):
        events.append({'kind': kind, 'monotonic_ns': time.monotonic_ns(), **values})
    def admit_runtime(path, row):
        canonical, info = metadata(Path(path))
        expected = tuple(row[k] for k in ('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns', 'nlink', 'uid', 'mode'))
        need(identity(info) == expected, 'unchanged-selected-runtime-metadata')
        fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        need(identity(os.fstat(fd)) == expected, 'selected-runtime-open-identity')
        descriptors[path] = fd
    def public_memfd(raw):
        fd = os.memfd_create('kpb-probe-public', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(fd), 'wb') as output:
                output.write(raw); output.flush()
            os.fchmod(fd, 0o400)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                        | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd); raise
    def namespace(*, state=None, observations=False, input_fd=None, network=False):
        argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
            '--clearenv', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--dir', '/app',
            '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib/x86_64-linux-gnu', '/lib64',
            '--ro-bind', str(STDLIB), str(STDLIB)]
        if network:
            argv += ['--share-net']
        for path in masked_packages:
            argv += ['--tmpfs', str(path), '--remount-ro', str(path)]
        for path, fd in descriptors.items():
            argv += ['--ro-bind', '/proc/self/fd/' + str(fd), path]
        for path, record in elf['aliases'].items():
            if record['link_text'] is not None:
                argv += ['--symlink', record['link_text'], path]
        for name, fd in app_fds.items():
            # A fresh open description is required: --ro-bind-data consumes its
            # offset, whereas dup() would share it across concurrent launches.
            source = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
            setup_fds.append(source)
            argv += ['--perms', '0400', '--ro-bind-data', str(source), '/app/' + name]
        marker_source = os.open('/proc/self/fd/' + str(marker_fd), os.O_RDONLY | os.O_CLOEXEC)
        setup_fds.append(marker_source)
        argv += ['--perms', '0400', '--ro-bind-data', str(marker_source), '/NO-ORIGINAL-PUBLIC-TRANSPORT',
                 '--ro-bind', '/proc/self/fd/' + str(descriptors[str(TOR)]), '/tools/tor']
        for name in ('libevent-2.1.so.7', 'libssl.so.3', 'libcrypto.so.3'):
            argv += ['--ro-bind', '/proc/self/fd/' + str(descriptors[str(TOR.parent / name)]), '/tools/' + name]
        argv += ['--setenv', 'PATH', '/usr/bin', '--setenv', 'LANG', 'C.UTF-8', '--setenv', 'HOME', '/tmp']
        if state is not None:
            argv += ['--bind', str(private / state), '/state']
        if observations:
            argv += ['--bind', str(public / 'observations'), '/observations']
        if input_fd is not None:
            argv += ['--dir', '/input', '--perms', '0400', '--ro-bind-data', str(input_fd), '/input/frame']
        return argv
    python = ['/usr/bin/python3.14', '-I', '-S', '-B']
    def public_fds():
        return tuple(descriptors.values()) + tuple(app_fds.values()) + tuple(setup_fds) + (marker_fd,)
    def launch(role, argv, extra_fds=()):
        started = time.monotonic_ns()
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, close_fds=True, pass_fds=public_fds() + tuple(extra_fds),
            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        processes.append((role, process)); event('launch', role=role, pid=process.pid, started_ns=started, argv=argv)
        def receive():
            for raw in iter(process.stdout.readline, b''):
                try:
                    value = json.loads(raw)
                    messages.put((role, value))
                except (ValueError, UnicodeError):
                    messages.put((role, {'schema': 'kpb-probe-invalid-public-status/v1'}))
        threading.Thread(target=receive, daemon=True).start()
        return process
    def status_ok(role, value):
        if type(value) is not dict:
            return False
        schema = value.get('schema')
        fields = {
            'kpb-probe-tor-progress/v1': {'schema','role','percent','monotonic_ns'},
            'kpb-probe-public-onion/v1': {'schema','role','hostname','monotonic_ns'},
            'kpb-probe-tor-exit/v1': {'schema','role','returncode','monotonic_ns'},
            'kpb-probe-listener/v1': {'schema','port','monotonic_ns'},
            'kpb-probe-listener-summary/v1': {'schema','accepted','completed','monotonic_ns'},
            'kpb-exit-transport-status/v1': {'schema','transport_receipt','financial_or_chain_acceptance'},
        }
        if schema not in fields or set(value) != fields[schema]:
            return False
        if 'monotonic_ns' in value and (type(value['monotonic_ns']) is not int or value['monotonic_ns'] < 0):
            return False
        if schema.startswith('kpb-probe-tor-') or schema == 'kpb-probe-public-onion/v1':
            if value['role'] != role or role not in ('service','client'):
                return False
        if schema == 'kpb-probe-tor-progress/v1':
            return type(value['percent']) is int and 0 <= value['percent'] <= 100
        if schema == 'kpb-probe-public-onion/v1':
            return role == 'service' and type(value['hostname']) is str and ONION.fullmatch(value['hostname']) is not None
        if schema == 'kpb-probe-listener/v1':
            return role == 'receiver' and type(value['port']) is int and 0 < value['port'] < 65536
        if schema == 'kpb-probe-listener-summary/v1':
            return role == 'receiver' and all(type(value[k]) is int and value[k] >= 0 for k in ('accepted','completed'))
        if schema == 'kpb-probe-tor-exit/v1':
            return type(value['returncode']) is int
        if schema == 'kpb-exit-transport-status/v1':
            return role.startswith('transport-') and value['transport_receipt'] is True and value['financial_or_chain_acceptance'] is False
        return True
    def wait_for(predicate):
        while True:
            for (role, _schema), value in latest.items():
                if predicate(role, value):
                    return value
            try:
                role, value = messages.get(timeout=0.25)
                need(status_ok(role, value), 'typed-public-role-status')
                event('role-status', role=role, value=value)
                latest[(role, value['schema'])] = value
                if predicate(role, value):
                    return value
            except queue.Empty:
                pass
            need(all(p.poll() is None for r, p in processes if r in ('receiver', 'service', 'client') and r not in stopped_roles),
                 'probe-dependency-exited')
    def stop(role, process):
        if role in stopped_roles:
            return
        stopped_roles.add(role)
        if process.poll() is None:
            process.terminate()
        process.wait(); event('role-exit', role=role, returncode=process.returncode)
    result = {'schema': 'kpb-public-onion-probe-result/v1', 'trial_id': plan['trial_id'],
        'classification': plan['classification'], 'financial_validation': 'NOT_RUN',
        'broadcast': False, 'anonymity_qualified': False, 'original_mounted': False}
    marker_fd = None
    try:
        for path, row in rows.items():
            admit_runtime(path, row)
        for ancestor in (Path('/usr/bin/bwrap'), *Path('/usr/bin/bwrap').parents):
            info = ancestor.lstat()
            need(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                 'root-owned-namespace-tool-and-ancestors')
        for path, record in elf['aliases'].items():
            link = Path(path)
            if record['link_text'] is not None:
                need(link.is_symlink() and os.readlink(link) == record['link_text']
                     and str(link.resolve(strict=True)) == record['target'], 'unchanged-runtime-alias')
        need(STDLIB.is_dir() and not any(p.is_symlink() for p in (STDLIB, *STDLIB.parents)), 'installed-stdlib-root')
        stdlib_count = 0; stdlib_aliases = []
        for directory, dirs, files in os.walk(STDLIB, followlinks=False):
            for name in [*dirs, *files]:
                path = Path(directory) / name; info = path.lstat()
                need(info.st_uid == 0
                     and (info.st_dev, info.st_ino) not in guard['m'].GUARD.inodes,
                     'installed-stdlib-owned-public-metadata')
                if name in ('site-packages', 'dist-packages'):
                    need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, 'package-mask-directory')
                    masked_packages.append(path)
                    dirs.remove(name)
                    continue
                if stat.S_ISLNK(info.st_mode):
                    target = path.resolve(strict=True)
                    need(not target.is_dir(), 'no-stdlib-directory-alias')
                    _, target_info = metadata(target)
                    need(target_info.st_uid == 0 and not target_info.st_mode & 0o022, 'stdlib-alias-public-target')
                    stdlib_aliases.append({'path': str(path), 'link_text': os.readlink(path),
                                          'target': str(target), 'target_mounted': target.is_relative_to(STDLIB)
                                            or str(target) in descriptors})
                    continue
                need(not info.st_mode & 0o022, 'installed-stdlib-not-writable-to-others')
                need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), 'regular-installed-stdlib')
                stdlib_count += 1
        event('runtime-admission', kind_of_admission='EXACT_ROOT_RECEIPT_METADATA_REUSE_NO_NEW_BODY_HASH',
              elf_leaves=len(rows), installed_stdlib_metadata_entries=stdlib_count, stdlib_aliases=stdlib_aliases,
              package_directories_shadowed_empty=[str(path) for path in masked_packages])
        for name, (_row, body) in selected.items():
            app_fds[name] = public_memfd(body)
        marker_fd = public_memfd(b'')
        # One complete network-off runtime pass; no generated Tor state exists yet.
        checks = [
            ('tor-version', namespace() + ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
                '--library-path', '/tools:/usr/lib/x86_64-linux-gnu', '/tools/tor', '--version']),
            ('tor-config', namespace() + ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
                '--library-path', '/tools:/usr/lib/x86_64-linux-gnu', '/tools/tor',
                '--defaults-torrc', '/dev/null', '-f', '/dev/null', '--verify-config',
                '--DataDirectory', '/tmp/config-check', '--SocksPort', '0', '--ControlPort', '0']),
            ('curl-version', namespace() + ['/usr/bin/curl', '-q', '--version']),
            ('python-import-frame', namespace() + python + ['-c',
                "import sys;sys.path.insert(0,'/app');import packet,receiver,transport;"
                "from pathlib import Path;assert not list(Path('/usr/lib/python3.14/dist-packages').iterdir());"
                "p=b'KPBXFX01'+bytes(1844-8);assert packet.decode(packet.encode(p,bytes(128))).projection==p;"
                "s=receiver.ObservedHTTPServer(('127.0.0.1',0),receiver.Observer('/tmp/observations'),'preflight');s.server_close();"
                "print('KPB_PUBLIC_IMPORT_FRAME_OK')"]),
        ]
        for label, argv in checks:
            done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL, close_fds=True, pass_fds=public_fds(), env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
            need(done.returncode == 0, 'network-off-runtime-preflight-' + label)
            event('runtime-preflight', check=label, returncode=done.returncode,
                  public_stdout_sha256=hashlib.sha256(done.stdout).hexdigest())
        # Exercise the real pipe setup and independent source offsets before
        # generating state. These commands cannot reach any network or wallet.
        incoming, outgoing = os.pipe2(os.O_CLOEXEC)
        try:
            os.write(outgoing, b'KPB_PUBLIC_PIPE_SMOKE'); os.close(outgoing); outgoing = None
            command = namespace(input_fd=incoming) + python + ['-c',
                "from pathlib import Path;assert Path('/input/frame').read_bytes()==b'KPB_PUBLIC_PIPE_SMOKE';"
                "print('KPB_PUBLIC_PIPE_OK')"]
            done = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=public_fds() + (incoming,), env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
            need(done.returncode == 0 and done.stdout == b'KPB_PUBLIC_PIPE_OK\n', 'network-off-pipe-setup-smoke')
            event('runtime-preflight', check='pipe-setup', returncode=0)
        finally:
            os.close(incoming)
            if outgoing is not None:
                os.close(outgoing)
        parallel = [namespace() + python + ['-c',
            "import sys;sys.path.insert(0,'/app');import packet,receiver,transport;print('KPB_PUBLIC_SOURCE_OK')"]
            for _ in range(2)]
        results = [None, None]
        def public_source_check(index):
            results[index] = subprocess.run(parallel[index], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=public_fds(), env={'PATH':'/usr/bin','LANG':'C.UTF-8'})
        threads = [threading.Thread(target=public_source_check, args=(index,)) for index in range(2)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        need(all(done is not None and done.returncode == 0 and done.stdout == b'KPB_PUBLIC_SOURCE_OK\n'
                 for done in results), 'network-off-concurrent-source-offset-smoke')
        event('runtime-preflight', check='independent-concurrent-source-offsets', copies=2, returncode=0)
        save('NAMESPACE-PREFLIGHT.json', {'all_checks_passed': True, 'private_state_root_created': False,
            'network': 'UNSHARED', 'checks': [label for label, _argv in checks]
                + ['pipe-setup', 'independent-concurrent-source-offsets']})
        row = plan['public_input']; raw_input = read(Path(row['path']), row['sha256']); inputs = json.loads(raw_input)
        need(inputs['schema'] == 'kpb-public-exit-fixture-selection/v1'
             and inputs['classification'] == 'PUBLIC_SYNTHETIC_UNFUNDED_OFFLINE_KNOWN_SEED_HYPOTHETICAL_CASES'
             and type(inputs['fixtures']) is list and len(inputs['fixtures']) == 3,
             'three-fixed-public-fixtures')
        spec = importlib.util.spec_from_file_location('packet', HERE / 'packet.py')
        packet = importlib.util.module_from_spec(spec); sys.modules['packet'] = packet
        exec(compile(selected['packet.py'][1], str(HERE / 'packet.py'), 'exec'), packet.__dict__)
        frames = []
        for item in inputs['fixtures']:
            frames.append(packet.encode(bytes.fromhex(item['projection_hex']), bytes.fromhex(item['proof_hex128'])))
        def port():
            with socket.socket() as reserve:
                reserve.bind(('127.0.0.1', 0)); return reserve.getsockname()[1]
        socks, receiver_port = port(), port()
        need(socks != receiver_port, 'distinct-fresh-listener-ports')
        private.mkdir(mode=0o700, parents=True)
        need(stat.S_IMODE(private.lstat().st_mode) == 0o700 and private.lstat().st_uid == os.getuid(),
             'fresh-private-state-owner-and-mode')
        for name in ('service', 'client'):
            (private / name).mkdir(mode=0o700)
        # Service hostname is generated before client submission; bootstrap events
        # remain metadata only. The 60-second grace is probe startup, not an Exit rule.
        service = launch('service', namespace(state='service', network=True) + python +
            ['/app/run_probe.py', '--role', 'service', '--receiver-port', str(receiver_port)])
        hostname = wait_for(lambda r, v: r == 'service' and v.get('schema') == 'kpb-probe-public-onion/v1')['hostname']
        need(ONION.fullmatch(hostname) is not None, 'strict-public-onion-export')
        receiver = launch('receiver', namespace(observations=True, network=True) + python +
            ['/app/run_probe.py', '--role', 'receiver', '--common-host', hostname,
             '--receiver-port', str(receiver_port)])
        listener = wait_for(lambda r, v: r == 'receiver' and v.get('schema') == 'kpb-probe-listener/v1')
        need(listener['port'] == receiver_port, 'exact-selected-receiver-listener')
        launch('client', namespace(state='client', network=True) + python +
            ['/app/run_probe.py', '--role', 'client', '--socks-port', str(socks)])
        for role in ('service', 'client'):
            wait_for(lambda r, v: r == role and v.get('schema') == 'kpb-probe-tor-progress/v1'
                     and v.get('percent') == 100)
        # Startup grace is a declared public probe warm-up, never a withdrawal rule.
        deadline = time.monotonic() + plan['startup_grace_seconds']
        while time.monotonic() < deadline:
            time.sleep(0.25)
            need(all(p.poll() is None for _r, p in processes), 'dependency-during-startup-grace')
        senders = []
        for index, frame in enumerate(frames):
            incoming, outgoing = os.pipe2(os.O_CLOEXEC)
            event('pipe-created', client=index, read_fd=incoming, write_fd=outgoing,
                  pipe_inode=os.fstat(incoming).st_ino)
            argv = namespace(input_fd=incoming, network=True) + python + ['-c',
                "import sys,runpy,os;sys.path.insert(0,'/app');fd=os.open('/input/frame',os.O_RDONLY);sys.argv=" + repr([
                '/app/transport.py', '--frame-fd', 'INPUT_FD', '--onion-endpoint', 'http://' + hostname + '/exit',
                '--socks', '127.0.0.1:' + str(socks), '--selected-curl', '/usr/bin/curl']) +
                ";sys.argv[2]=str(fd);runpy.run_path('/app/transport.py',run_name='__main__')"]
            try:
                sender = launch('transport-' + str(index), argv, (incoming,)); senders.append(sender)
                event('pipe-write-start', client=index)
                remaining = memoryview(frame)
                while remaining:
                    written = os.write(outgoing, remaining); need(written > 0, 'frame-pipe-write')
                    remaining = remaining[written:]
                event('pipe-write-complete', client=index, bytes=len(frame))
            finally:
                os.close(incoming); os.close(outgoing)
        for sender in senders:
            sender.wait(); need(sender.returncode == 0, 'one-shot-onion-transport-failed')
        for index in range(len(senders)):
            wait_for(lambda r, v: r == 'transport-' + str(index)
                     and v.get('schema') == 'kpb-exit-transport-status/v1')
        # Close our Tor streams, then drain every accepted receiver handler before
        # interpreting its records. Arrival order is never completion order.
        for role, process in reversed(processes):
            if role in ('service', 'client'):
                stop(role, process)
        stop('receiver', receiver)
        summary = wait_for(lambda r, v: r == 'receiver' and v.get('schema') == 'kpb-probe-listener-summary/v1')
        need(summary['accepted'] == summary['completed'] == 3, 'complete-three-arrival-observations')
        # Only public observations are read. They are never finance capabilities.
        observed = []
        for path in sorted((public / 'observations/arrivals').glob('arrival-*.json')):
            item = json.loads(read(path)); observed.append(item)
        expected = collections.Counter((i['projection_hex'], i['proof_hex128']) for i in inputs['fixtures'])
        actual = collections.Counter((i.get('projection_hex'), i.get('proof_hex128')) for i in observed)
        frame_hashes = collections.Counter(hashlib.sha256(frame).hexdigest() for frame in frames)
        need(len(observed) == 3 and actual == expected
             and collections.Counter(i.get('frame_sha256') for i in observed) == frame_hashes
             and all(i.get('framing') == 'PASS'
             and i.get('financial_validation') == 'NOT_RUN' and i.get('broadcast') is False for i in observed),
             'exact-three-received-public-fixtures')
        save('RECEIVED.json', {'schema': 'kpb-public-onion-received-fixtures/v1',
            'fixture_selection_sha256': row['sha256'], 'arrivals': observed, 'receiver_summary': summary,
            'expected_frame_sha256': sorted(frame_hashes.elements()),
            'financial_validation': 'NOT_RUN', 'broadcast': False})
        result.update(status='PUBLIC_ONION_FRAME_BYTES_MATCHED', received=3,
            fixture_selection_sha256=row['sha256'], public_onion_hostname=hostname,
            network_boundary='SHARED_HOST_NETWORK_SELECTED_TOR_SOCKS_CLIENT_NO_ORIGINALS')
    except BaseException as error:
        result['status'] = 'REFUSED_OR_FAILED'; result['category'] = type(error).__name__
    finally:
        for role, process in reversed(processes):
            stop(role, process)
        for fd in descriptors.values():
            os.close(fd)
        for fd in app_fds.values():
            os.close(fd)
        for fd in setup_fds:
            os.close(fd)
        if marker_fd is not None:
            os.close(marker_fd)
        save('EVENTS.json', events); save('RESULT.json', result)
    emit({'schema': 'kpb-public-onion-probe-status/v1', 'status': result.get('status'),
          'financial_or_anonymity_qualification': False})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan'); parser.add_argument('--plan-sha256')
    parser.add_argument('--role', choices=('service', 'client', 'receiver'))
    parser.add_argument('--socks-port', type=int, default=0)
    parser.add_argument('--receiver-port', type=int, default=0)
    parser.add_argument('--common-host')
    args = parser.parse_args()
    if args.role in ('service', 'client'):
        tor_role(args.role, args.socks_port, args.receiver_port)
    elif args.role == 'receiver':
        receiver_role(args.common_host, args.receiver_port)
    else:
        need(args.plan and args.plan_sha256, 'selected-plan-required')
        host(args.plan, args.plan_sha256)


if __name__ == '__main__':
    main()
