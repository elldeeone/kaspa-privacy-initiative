#!/usr/bin/env python3
"""Metadata-only optional owner stdout -> transport stdin functionality launcher.

The selected caller must admit this entry and the stdlib-only shared guard first.
The controller never opens/hashes a candidate or reads a frame, receiver body,
decoded candidate, or receiver digest. Only the selected network-off owner role
opens its one prepared candidate. A fresh Tor receiver/state is used; the old
direct release and current study remain unchanged. No privacy/finance claim.
"""
import argparse
import ast
import collections
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import socket
import stat
import subprocess
import sys
import threading
import time
import types
import uuid

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE = ROOT / '.local/private-exit-submission-proposal-01'
PROTO = BASE / 'prototype'
PRIVATE_PARENT = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
GUARD = ROOT / 'poc/local-private-payment/private_batch_trial/payout_linkage_guard.py'
GUARD_SHA = 'ce86998d7ddfe404cc1c194cda064d369ca1bd78c8df674e43b2381da1d3a4b1'
TOOLS = BASE / 'RUNTIME-ADMISSION-01.json'
TOOLS_SHA = '00a542151ec26f3ce5c6bf7118c2d52c869dd4d32c6700d196d7f54f805adc62'
ELF = BASE / 'RUNTIME-ELF-CLOSURE-02.json'
ELF_SHA = '37de32f92ea7bbe130e122fca73cd7e69a99f02b737cbb2a00231306e883fe4c'
ROLE_SELECTION = BASE / 'OWNER-PIPE-SOURCE-SELECTION.json'
ROLE_SELECTION_SHA = '05d77baf6917aa5ac7a326ccee0e9b7877eddf4558f7046d3b3060282132e1f0'
PROBE = PROTO / 'run_probe.py'
PROBE_SHA = '0582a871c6f03a1d512618cede051c6b36bae37acae4a26be25b11534fcd9dec'
RECEIVER_SHA = '0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac'
PACKET_SHA = '7c0ad5f630a94a1481384c8726d98ebcfbab7ff1f6ba5395b3d8da9fafda38a6'
TRANSPORT_SHA = '88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4'
PREPARED = ROOT / '.local/private-payout-linkage-02/original-paired-03/prepared-B/RESULT.json'
PREPARED_SHA = '5291be322ccbb198f14903b7778fc4a54c45a543f2cf3f55df01273c32ecb4e1'
HISTORY = ROOT / '.local/private-payout-linkage-02/original-paired-03/COMPONENT-HISTORY-B.json'
HISTORY_SHA = '0e8d8d12fc30760716751baa445d90c3c41fe9530a426676e4322910762b37fd'
TAIL = ROOT / '.local/private-batch-public-native-final-parameters-01/IMMUTABLE-TAIL.bin'
TAIL_SHA = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
CANDIDATE = PRIVATE_PARENT / 'private-batch-20261028/new-profile-original-01/operations/original-paired-03-b-proof/owner-0/EXIT-CANDIDATE.json'
TRIAL_ID = 'e3778888-54bc-4bc7-bb5d-f1a969e072ec'
OPERATION_ID = '00714017-3aac-4efd-bc43-7456ea978a61'
SCOPE = 'UNFUNDED_SUPPLIED_CONTEXT'
CLASSIFICATION = 'FUNCTIONALITY_ONLY_REUSED_ALREADY_EXPORTED_CANDIDATE_NO_PRIVACY_OR_FINANCE'


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def save(path, value):
    raw = value if type(value) is bytes else encoded(value)
    with Path(path).open('xb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())


def identity(info):
    return tuple(getattr(info, name) for name in
        ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_mode'))


def guard_loader():
    # Initial entry/helper admission is the selected caller's obligation.
    spec = importlib.util.spec_from_file_location('_owner_pipe_guard', GUARD)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    guard = module.load_guard()
    guard['read'](GUARD, GUARD_SHA)
    module.add_exclusions(guard, (Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/tor-state'),))
    return guard


def candidate_metadata(prepared):
    """Only metadata; never an O_RDONLY open, digest, or private body read."""
    need(prepared['schema'] == 'kpb-original-lifecycle-controller-result/v1'
         and prepared['scope'] == SCOPE and prepared['operation'] == 'exit'
         and prepared['bootstrap_trial_id'] == TRIAL_ID and prepared['operation_id'] == OPERATION_ID
         and prepared['controller_read_or_hashed_private_bodies'] is False,
         'exact-already-generated-owner-preparation')
    owners = [row for row in prepared['owners'] if row['owner_component'] == 0]
    need(len(owners) == 1 and Path(owners[0]['private_output_directory']) == CANDIDATE.parent,
         'derived-own-private-candidate-path')
    status = owners[0]['status']
    need(status['schema'] == 'kpb-original-lifecycle-operation/v1' and status['scope'] == SCOPE
         and status['operation'] == 'exit' and status['actual_AuthExit_proof'] is True
         and status['original_only_recovered_claim'] is True and status['candidate_exported'] is False
         and status['private_original_or_witness_exported'] is False
         and status['accepted_backing_or_native_settlement'] is False, 'unchanged-prepared-owner-status')
    need(not any(path.is_symlink() for path in (CANDIDATE, *CANDIDATE.parents)), 'no-private-candidate-path-alias')
    info = CANDIDATE.lstat()
    need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
         and info.st_uid == os.getuid() == 1000 and info.st_gid == 1000 and info.st_nlink == 1
         and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            == (64512, 70796949, 4431, 1793190280510541019, 1793190280510541019),
         'exact-previously-admitted-private-candidate-metadata')
    return info


def selected_helpers(raw, environment):
    """Reuse the selected probe's four actual namespace helpers unchanged."""
    host = next(node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == 'host')
    names = {'admit_runtime', 'public_memfd', 'namespace', 'public_fds'}
    nodes = [node for node in host.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in nodes} == names, 'selected-namespace-helper-closure')
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), str(PROBE), 'exec'), environment)
    return environment


def isolated_transport_entry(python, arguments):
    # Keep stdin0 occupied while immutable transport closes its duplicated reader.
    # Otherwise payload memfd0 can be replaced by curl's DEVNULL stdin mapping.
    script = ("import os,sys,runpy,json;sys.path.insert(0,'/app');sys.argv="
              + repr(['/app/transport.py', *arguments]) + ";"
              + "n=sys.argv.index('--frame-fd')+1 if '--frame-fd' in sys.argv else None;"
              + "r=os.dup(0) if n is not None and sys.argv[n]=='0' else None;"
              + "assert r is None or r>=3;"
              + "sys.argv.__setitem__(n,str(r)) if r is not None else None;"
              + "print(json.dumps({'schema':'kpb-owner-transport-input-fd/v1','inherited_fd':0,'reader_fd':r},sort_keys=True),flush=True) if r is not None else None;"
              + "runpy.run_path('/app/transport.py',run_name='__main__')")
    return [*python, '-c', script]

PUBLIC_TRANSPORT_FD_CONTROL = "import sys,socket,threading,subprocess,json\nsys.path.insert(0,'/app')\nimport packet\nframe=packet.encode(b'KPBXFX01'+bytes(1836),bytes(128),padding=bytes(2114))\ndef exact(conn,n):\n    result=b''\n    while len(result)<n:\n        part=conn.recv(n-len(result))\n        assert part\n        result+=part\n    return result\ndef serve(listener,record):\n    try:\n        with listener:\n            conn,_=listener.accept()\n            with conn:\n                conn.settimeout(120)\n                greeting=exact(conn,2)\n                assert greeting[0]==5 and 2 in exact(conn,greeting[1])\n                conn.sendall(b'\\x05\\x02')\n                auth=exact(conn,2)\n                assert auth[0]==1\n                exact(conn,auth[1])\n                exact(conn,exact(conn,1)[0])\n                conn.sendall(b'\\x01\\x00')\n                request=exact(conn,4)\n                assert request[:3]==b'\\x05\\x01\\x00'\n                if request[3]==3: exact(conn,exact(conn,1)[0])\n                elif request[3]==1: exact(conn,4)\n                elif request[3]==4: exact(conn,16)\n                else: raise ValueError('SOCKS address type')\n                exact(conn,2)\n                conn.sendall(b'\\x05\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\x00\\x50')\n                headers=bytearray()\n                while not headers.endswith(b'\\r\\n\\r\\n'):\n                    headers.extend(exact(conn,1))\n                    assert len(headers)<65536\n                lengths=[int(row.split(b':',1)[1]) for row in bytes(headers).split(b'\\r\\n') if row.lower().startswith(b'content-length:')]\n                assert len(lengths)==1\n                remaining=lengths[0];total=0\n                while remaining:\n                    part=conn.recv(min(65536,remaining))\n                    assert part\n                    total+=len(part);remaining-=len(part)\n                status=202 if total==4096 else 400\n                conn.sendall(('HTTP/1.0 '+str(status)+' Result\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n').encode())\n                record.update(received_bytes=total,http_status=status)\n    except BaseException as error:\n        record.update(error_category=type(error).__name__)\nresults=[]\nfor script in scripts:\n    listener=socket.socket()\n    listener.bind(('127.0.0.1',0));listener.listen(1)\n    port=listener.getsockname()[1]\n    record={}\n    thread=threading.Thread(target=serve,args=(listener,record),daemon=True);thread.start()\n    script=script.replace('127.0.0.1:9','127.0.0.1:'+str(port))\n    done=subprocess.run([sys.executable,'-I','-S','-B','-c',script],input=frame,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)\n    thread.join(120)\n    statuses=[json.loads(line) for line in done.stdout.splitlines()]\n    results.append({'returncode':done.returncode,'received_bytes':record.get('received_bytes'),'http_status':record.get('http_status'),'statuses':statuses})\nassert results[0]['returncode']==1 and results[0]['received_bytes']==0 and results[0]['http_status']==400\nassert results[1]['returncode']==0 and results[1]['received_bytes']==4096 and results[1]['http_status']==202\nassert len(results[1]['statuses'])==2 and results[1]['statuses'][0]['schema']=='kpb-owner-transport-input-fd/v1'\nassert results[1]['statuses'][1].get('transport_receipt') is True\nprint(json.dumps({'schema':'kpb-public-selected-curl-stdin-fd-control/v1','network':'UNSHARED_LOOPBACK_ONLY','private_input':False,'results':results},sort_keys=True))\n"


def admit_stdlib(guard, descriptors, masked_packages):
    stdlib = Path('/usr/lib/python3.14'); metadata = guard['m'].GUARD.metadata
    need(stdlib.is_dir() and not any(path.is_symlink() for path in (stdlib, *stdlib.parents)), 'installed-stdlib-root')
    aliases = []; count = 0
    for directory, dirs, files in os.walk(stdlib, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(directory) / name; info = path.lstat()
            need(info.st_uid == 0 and (info.st_dev, info.st_ino) not in guard['m'].GUARD.inodes,
                 'root-owned-public-stdlib-metadata')
            if name in ('site-packages', 'dist-packages'):
                need(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022, 'masked-package-root')
                masked_packages.append(path); dirs.remove(name); continue
            if stat.S_ISLNK(info.st_mode):
                target = path.resolve(strict=True); need(not target.is_dir(), 'no-stdlib-directory-alias')
                _, target_info = metadata(target)
                need(target_info.st_uid == 0 and not target_info.st_mode & 0o022, 'public-stdlib-alias-target')
                aliases.append({'path': str(path), 'target': str(target), 'link_text': os.readlink(path),
                    'target_mounted': target.is_relative_to(stdlib) or str(target) in descriptors})
            else:
                need(not info.st_mode & 0o022 and (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)),
                     'installed-stdlib-owned-regular-tree'); count += 1
    return {'installed_stdlib_metadata_entries': count, 'aliases': aliases,
            'masked_package_directories': [str(path) for path in masked_packages]}


def stage(args):
    guard = guard_loader(); read = guard['read']
    role = json.loads(read(ROLE_SELECTION, ROLE_SELECTION_SHA))
    read(PROBE, PROBE_SHA); read(HISTORY, HISTORY_SHA); read(TAIL, TAIL_SHA)
    prepared = json.loads(read(PREPARED, PREPARED_SHA)); info = candidate_metadata(prepared)
    trial = str(uuid.uuid4())
    plan = {'schema': 'kpb-owner-stdio-onion-functionality-plan/v1', 'classification': CLASSIFICATION,
        'trial_id': trial, 'scope': SCOPE, 'mode': args.mode,
        'role_selection': {'path': str(ROLE_SELECTION), 'sha256': ROLE_SELECTION_SHA},
        'source_members': [
            {'path': str(Path(__file__).absolute()), 'sha256': hashlib.sha256(read(Path(__file__).absolute())).hexdigest()},
            {'path': str(PROBE), 'sha256': PROBE_SHA},
            {'path': str(PROTO / 'receiver.py'), 'sha256': RECEIVER_SHA},
            {'path': str(PROTO / 'packet.py'), 'sha256': PACKET_SHA},
            {'path': str(PROTO / 'transport.py'), 'sha256': TRANSPORT_SHA},
            {'path': str(BASE / 'owner_pipe_consumer.py'),
             'sha256': hashlib.sha256(read(BASE / 'owner_pipe_consumer.py')).hexdigest()}],
        'runtime_tools': {'path': str(TOOLS), 'sha256': TOOLS_SHA},
        'runtime_elf': {'path': str(ELF), 'sha256': ELF_SHA},
        'owner_extra_elf': [],
        'prepared_result': {'path': str(PREPARED), 'sha256': PREPARED_SHA},
        'public_history': {'path': str(HISTORY), 'sha256': HISTORY_SHA},
        'public_tail': {'path': str(TAIL), 'sha256': TAIL_SHA},
        'candidate_metadata': {'path': str(CANDIDATE), 'identity': list(identity(info))},
        'public_output': str(BASE / 'owner-pipe-runs' / trial),
        'private_tor_state': str(PRIVATE_PARENT / 'diagnostics' / ('owner-stdio-functionality-' + trial)),
        'startup_grace_seconds': 60, 'execution_selected': bool(args.execution_selected),
        'controller_frame_body_read_or_hash': False, 'controller_receiver_body_read_or_hash': False,
        'privacy_or_financial_qualification': False, 'broadcast': False}
    for row in role['source_members']:
        read(Path(row['path']), row['sha256'])
    for row in role['runtime_members']:
        read(Path(row['host_path']), row['sha256'])
    # Rust's public verifier needs libgcc_s in addition to the existing selected
    # Tor/curl/Python closure. This is installed public runtime, not private data.
    libgcc = Path('/usr/lib/x86_64-linux-gnu/libgcc_s.so.1').resolve(strict=True)
    libraw = read(libgcc); _, libinfo = guard['m'].GUARD.metadata(libgcc)
    need(libinfo.st_uid == 0 and not libinfo.st_mode & 0o022, 'public-owner-unwinder-runtime')
    plan['owner_extra_elf'].append({'path': str(libgcc), 'sha256': hashlib.sha256(libraw).hexdigest(),
        **dict(zip(('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns', 'nlink', 'uid', 'mode'), identity(libinfo)))})
    directory = BASE / 'owner-pipe-plans'; directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / (trial + '.json'); save(path, plan)
    return {'status': 'OWNER_PIPE_FUNCTIONALITY_STAGED_NO_PRIVATE_BODY_READ_OR_NETWORK',
            'plan': str(path), 'sha256': hashlib.sha256(encoded(plan)).hexdigest()}


def run(args):
    guard = guard_loader(); read = guard['read']; metadata = guard['m'].GUARD.metadata
    raw_plan = read(Path(args.plan).absolute(), args.plan_sha256); plan = json.loads(raw_plan)
    need(set(plan) == {'schema', 'classification', 'trial_id', 'scope', 'mode', 'role_selection', 'source_members',
        'runtime_tools', 'runtime_elf', 'owner_extra_elf', 'prepared_result', 'public_history', 'public_tail',
        'candidate_metadata', 'public_output', 'private_tor_state', 'startup_grace_seconds', 'execution_selected',
        'controller_frame_body_read_or_hash', 'controller_receiver_body_read_or_hash',
        'privacy_or_financial_qualification', 'broadcast'}, 'exact-owner-functionality-plan-fields')
    need(plan['schema'] == 'kpb-owner-stdio-onion-functionality-plan/v1'
         and plan['classification'] == CLASSIFICATION and plan['scope'] == SCOPE
         and plan['mode'] in ('network-off-consumer', 'tor')
         and str(uuid.UUID(plan['trial_id'])) == plan['trial_id']
         and (args.operation == 'preflight' or plan['execution_selected'] is True)
         and plan['startup_grace_seconds'] == 60
         and plan['controller_frame_body_read_or_hash'] is False
         and plan['controller_receiver_body_read_or_hash'] is False
         and plan['privacy_or_financial_qualification'] is False and plan['broadcast'] is False,
         'explicit-functionality-only-selected-plan')
    need(plan['role_selection'] == {'path': str(ROLE_SELECTION), 'sha256': ROLE_SELECTION_SHA}
         and plan['runtime_tools'] == {'path': str(TOOLS), 'sha256': TOOLS_SHA}
         and plan['runtime_elf'] == {'path': str(ELF), 'sha256': ELF_SHA}, 'selected-fixed-code-and-runtime')
    role = json.loads(read(ROLE_SELECTION, ROLE_SELECTION_SHA))
    need(plan['prepared_result'] == {'path': str(PREPARED), 'sha256': PREPARED_SHA}
         and plan['public_history'] == {'path': str(HISTORY), 'sha256': HISTORY_SHA}
         and plan['public_tail'] == {'path': str(TAIL), 'sha256': TAIL_SHA}, 'fixed-public-preparation-and-context')
    source = {Path(row['path']).name: (row, read(Path(row['path']), row['sha256'])) for row in plan['source_members']}
    need(len(source) == len(plan['source_members']) == 6 and set(source) ==
         {'owner_pipe_launcher.py', 'owner_pipe_consumer.py', 'run_probe.py', 'receiver.py', 'packet.py', 'transport.py'},
         'exact-six-controller-transport-sources')
    need(source['run_probe.py'][0]['sha256'] == PROBE_SHA
         and source['receiver.py'][0]['sha256'] == RECEIVER_SHA
         and source['packet.py'][0]['sha256'] == PACKET_SHA
         and source['transport.py'][0]['sha256'] == TRANSPORT_SHA, 'qualified-fresh-receiver-transport-sources')
    prepared = json.loads(read(PREPARED, PREPARED_SHA)); candidate_info = candidate_metadata(prepared)
    need(plan['candidate_metadata'] == {'path': str(CANDIDATE), 'identity': list(identity(candidate_info))},
         'same-metadata-only-owner-candidate')
    history_raw = read(HISTORY, HISTORY_SHA); history = json.loads(history_raw); tail_raw = read(TAIL, TAIL_SHA)
    need(history['schema'] == 'kpb-private-batch-public-history/v1' and history['scope'] == SCOPE,
         'selected-supplied-public-context')
    public = Path(plan['public_output']); private = Path(plan['private_tor_state'])
    need(public == BASE / 'owner-pipe-runs' / plan['trial_id']
         and private == PRIVATE_PARENT / 'diagnostics' / ('owner-stdio-functionality-' + plan['trial_id'])
         and not public.exists() and not private.exists(), 'fresh-specific-functionality-roots')
    need(any(PRIVATE_PARENT == path or PRIVATE_PARENT.is_relative_to(path)
         for path in guard['m'].GUARD.directories), 'private-state-parent-already-protected')
    for path in (public, private):
        need(not any(parent.is_symlink() for parent in (path, *path.parents)), 'no-run-root-alias')
    public.mkdir(mode=0o700, parents=True); (public / 'observations').mkdir(mode=0o700)
    save(public / 'PLAN.json', raw_plan)
    event_output = (public / 'EVENTS.ndjson').open('xb')
    event_lock = threading.Lock()
    tools = json.loads(read(TOOLS, TOOLS_SHA)); elf = json.loads(read(ELF, ELF_SHA))
    rows = {row['path']: row for row in [*tools['files'], *elf['files']]}
    descriptors = {}; owned_fds = []; processes = []; status_threads = []; events = []; messages = queue.Queue(); latest = {}; stopped = set()
    masked_packages = []; namespace_sets = []
    probe_raw = source['run_probe.py'][1]
    base_environment = dict(vars(sys.modules[__name__]))
    base_environment.update(metadata=metadata, descriptors=descriptors)
    helper = selected_helpers(probe_raw, base_environment)
    def event(kind, **values):
        value = {'kind': kind, 'monotonic_ns': time.monotonic_ns(), **values}
        with event_lock:
            events.append(value); event_output.write(encoded(value)); event_output.flush()
    def status_stream(which, process, stream):
        for raw in iter(stream.readline, b''):
            try:
                value = json.loads(raw)
            except (ValueError, UnicodeError):
                value = {'schema': 'kpb-invalid-fixed-public-status/v1'}
            if status_ok(which, value):
                event('role-status', role=which, value=value)
            messages.put((which, value))
    def launch(which, argv, pass_fds, *, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, owner=False):
        started = time.monotonic_ns()
        process = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr,
            close_fds=True, pass_fds=tuple(pass_fds), env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        processes.append((which, process)); event('launch', role=which, pid=process.pid, argv=argv,
            started_ns=started, passed_setup_fds=list(pass_fds))
        stream = process.stderr if owner else process.stdout
        if stream is not None:
            thread = threading.Thread(target=status_stream, args=(which, process, stream), daemon=True)
            status_threads.append(thread); thread.start()
        return process
    def status_ok(which, value):
        if type(value) is not dict:
            return False
        schema = value.get('schema')
        if schema == 'kpb-owner-exit-pipe-status/v1':
            return (which == 'owner' and set(value) == {'schema', 'status', 'financial_or_chain_acceptance'}
                and value['status'] in ('FRAME_WRITTEN', 'REFUSED') and value['financial_or_chain_acceptance'] is False)
        if schema == 'kpb-owner-transport-input-fd/v1':
            return (which == 'transport' and set(value) == {'schema', 'inherited_fd', 'reader_fd'}
                and value['inherited_fd'] == 0 and type(value['reader_fd']) is int and value['reader_fd'] >= 3)
        if schema == 'kpb-exit-transport-status/v1':
            return (which == 'transport' and set(value) == {'schema', 'transport_receipt', 'financial_or_chain_acceptance'}
                and value['transport_receipt'] is True and value['financial_or_chain_acceptance'] is False)
        if schema == 'kpb-owner-pipe-consumer-status/v1':
            return (which == 'consumer' and set(value) == {'schema', 'frame_decoded', 'financial_or_chain_acceptance'}
                and type(value['frame_decoded']) is bool and value['financial_or_chain_acceptance'] is False)
        if schema == 'kpb-probe-listener-summary/v1':
            return (which == 'receiver' and set(value) == {'schema', 'accepted', 'completed', 'monotonic_ns'}
                and all(type(value[key]) is int and value[key] >= 0 for key in ('accepted', 'completed', 'monotonic_ns')))
        if schema == 'kpb-probe-listener/v1':
            return which == 'receiver' and set(value) == {'schema', 'port', 'monotonic_ns'} and type(value['port']) is int
        if schema == 'kpb-probe-public-onion/v1':
            import re
            return (which == 'service' and set(value) == {'schema', 'role', 'hostname', 'monotonic_ns'}
                and value['role'] == 'service' and re.fullmatch('[a-z2-7]{56}\\.onion', value['hostname']) is not None)
        if schema == 'kpb-probe-tor-progress/v1':
            return (which in ('service', 'client') and set(value) == {'schema', 'role', 'percent', 'monotonic_ns'}
                and value['role'] == which and type(value['percent']) is int and 0 <= value['percent'] <= 100)
        if schema == 'kpb-probe-tor-exit/v1':
            return (which in ('service', 'client')
                and set(value) == {'schema', 'role', 'returncode', 'monotonic_ns'}
                and value.get('role') == which and type(value.get('returncode')) is int
                and type(value['monotonic_ns']) is int and value['monotonic_ns'] >= 0)
        return False
    def wait_for(predicate):
        while True:
            for (which, _schema), value in latest.items():
                if predicate(which, value): return value
            try:
                which, value = messages.get(timeout=0.25)
                need(status_ok(which, value), 'fixed-public-role-status-only')
                latest[(which, value['schema'])] = value
                if predicate(which, value): return value
            except queue.Empty:
                pass
            need(all(process.poll() is None for which, process in processes
                 if which in ('service', 'client', 'receiver') and which not in stopped), 'dependency-exited')
    def stop(which, process):
        if which in stopped: return
        stopped.add(which)
        if process.poll() is None: process.terminate()
        process.wait(); event('role-exit', role=which, returncode=process.returncode)
    def public_memfd(raw):
        fd = helper['public_memfd'](raw); owned_fds.append(fd); return fd
    marker_fd = None; private_fd = None; incoming = outgoing = None
    result = {'schema': 'kpb-owner-stdio-onion-functionality-result/v1', 'trial_id': plan['trial_id'],
        'classification': CLASSIFICATION, 'scope': SCOPE, 'controller_frame_body_read_or_hash': False,
        'controller_receiver_body_read_or_hash': False, 'privacy_or_financial_qualification': False,
        'broadcast': False, 'Original_mounted': False}
    try:
        for path, row in rows.items(): helper['admit_runtime'](path, row)
        for path, row in [(row['path'], row) for row in plan['owner_extra_elf']]:
            _, info = metadata(Path(path)); need(identity(info) == tuple(row[key] for key in
                ('dev', 'ino', 'size', 'mtime_ns', 'ctime_ns', 'nlink', 'uid', 'mode')), 'owner-runtime-leaf-metadata')
        stdlib_admission = admit_stdlib(guard, descriptors, masked_packages)
        for path, record in elf['aliases'].items():
            if record['link_text'] is not None:
                need(Path(path).is_symlink() and os.readlink(path) == record['link_text']
                    and str(Path(path).resolve(strict=True)) == record['target'], 'unchanged-runtime-alias')
        event('runtime-admission', **stdlib_admission)
        marker_fd = public_memfd(b'')
        source_fds = {name: public_memfd(body) for name, (_row, body) in source.items()}
        owner_public = public / 'owner-public-leaves'; owner_public.mkdir(mode=0o700)
        owner_public_records = []
        def owner_regular(raw, virtual_path):
            # Only already-admitted PUBLIC bytes enter this function. It never
            # receives a candidate, frame, Original, or private-file descriptor.
            path = owner_public / ('public-' + str(len(owner_public_records)))
            save(path, raw); path.chmod(0o400)
            canonical, info = metadata(path)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o400, 'owned-public-single-link-readonly-leaf')
            fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            need(identity(os.fstat(fd)) == identity(info), 'owned-public-leaf-open-identity')
            owned_fds.append(fd)
            record = {'virtual_path': str(virtual_path), 'public_source': str(path),
                'sha256': hashlib.sha256(raw).hexdigest(), 'identity': list(identity(info)), 'fd': fd}
            owner_public_records.append(record); event('owner-public-regular-leaf', **record)
            return fd
        owner_sources = {row['path']: owner_regular(read(Path(row['path']), row['sha256']), row['path'])
                         for row in role['source_members']}
        owner_runtime = {}
        for row in role['runtime_members']:
            path = Path(row['host_path']); read(path, row['sha256'])
            if row['path'] == '/runtime/prover':
                canonical, info = metadata(path)
                fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW); owned_fds.append(fd)
                need(identity(os.fstat(fd)) == identity(info), 'owner-prover-open-identity')
                owner_runtime[row['path']] = ('path', fd)
            else: owner_runtime[row['path']] = ('path', owner_regular(read(path, row['sha256']), row['path']))
        owner_extra = {}
        for row in plan['owner_extra_elf']:
            path = Path(row['path']); canonical, info = metadata(path)
            fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW); owned_fds.append(fd)
            need(identity(os.fstat(fd)) == identity(info), 'owner-extra-runtime-open-identity'); owner_extra[str(path)] = fd
        identity_fields = ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32')
        config = {name: history[name] for name in identity_fields}
        config.update(schema='kpb-owner-exit-pipe-config/v1', history_sha256=HISTORY_SHA,
            tail_sha256=TAIL_SHA, manifest_sha256='bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f',
            source_members=[{'path': row['path'], 'sha256': row['sha256']} for row in role['source_members']],
            runtime_members=[{'path': row['path'], 'sha256': row['sha256']} for row in role['runtime_members']])
        config_fd = owner_regular(encoded(config), '/CONFIG.json')
        namespace_fd = owner_regular(encoded(role['namespace_marker']), '/NAMESPACE.json')
        history_fd = owner_regular(history_raw, '/public/PUBLIC-HISTORY.json')
        tail_fd = owner_regular(tail_raw, '/public/IMMUTABLE-TAIL.bin')
        def namespace(app_names, *, network=False, state=None, observations=False, owner=False):
            environment = dict(base_environment)
            environment.update(descriptors=dict(descriptors), elf=elf, masked_packages=masked_packages,
                app_fds={name: source_fds[name] for name in app_names}, setup_fds=[], marker_fd=marker_fd,
                private=private, public=public, STDLIB=Path('/usr/lib/python3.14'),
                TOR=Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/bundle/tor/tor'))
            if owner: environment['descriptors'].update(owner_extra)
            selected_helpers(probe_raw, environment)
            argv = environment['namespace'](network=network, state=state, observations=observations)
            def data(fd, path):
                independent = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY | os.O_CLOEXEC)
                environment['setup_fds'].append(independent)
                argv.extend(['--perms', '0400', '--ro-bind-data', str(independent), str(path)])
            if owner:
                for path, fd in owner_sources.items():
                    argv.extend(['--ro-bind', '/proc/self/fd/' + str(fd), path])
                for path, (kind, fd) in owner_runtime.items():
                    if kind == 'data': data(fd, path)
                    else: argv.extend(['--ro-bind', '/proc/self/fd/' + str(fd), path])
                for fd, path in ((config_fd, '/CONFIG.json'), (namespace_fd, '/NAMESPACE.json'),
                                 (history_fd, '/public/PUBLIC-HISTORY.json'), (tail_fd, '/public/IMMUTABLE-TAIL.bin')):
                    argv.extend(['--ro-bind', '/proc/self/fd/' + str(fd), path])
                if private_fd is not None:
                    argv.extend(['--ro-bind', '/proc/self/fd/' + str(private_fd), '/candidate/EXIT-CANDIDATE.json'])
            fds = environment['public_fds']()
            if owner:
                fds += tuple(fd for _kind, fd in owner_runtime.values()) + tuple(owner_sources.values())
                fds += (config_fd, namespace_fd, history_fd, tail_fd)
                if private_fd is not None: fds += (private_fd,)
            namespace_sets.append(environment)
            return argv, tuple(dict.fromkeys(fds))
        # Exercise the actual installed sparse runtime and stdout pipe before
        # opening even an O_PATH candidate handle or creating any Tor state.
        python = ['/usr/bin/python3.14', '-I', '-S', '-B']
        preflight = []
        loader_argv, loader_fds = namespace((), owner=True)
        done = subprocess.run(loader_argv + ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
            '--list', '/runtime/prover'], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, pass_fds=loader_fds,
            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        preflight.append({'check': 'actual-owner-prover-loader-closure', 'passed': done.returncode == 0,
            'returncode': done.returncode, 'public_stdout': done.stdout.decode('utf-8', 'replace'),
            'public_stderr': done.stderr.decode('utf-8', 'replace')})
        fifo_argv, fifo_fds = namespace((), owner=True)
        public_script = ("import ast,os,stat,fcntl,errno;from pathlib import Path;"
            "p=Path(" + repr(role['role']['path']) + ");t=ast.parse(p.read_bytes());"
            "n=next(n for n in t.body if isinstance(n,ast.FunctionDef) and n.name=='close_setup_fds');"
            "exec(compile(ast.fix_missing_locations(ast.Module(body=[n],type_ignores=[])),str(p),'exec'));"
            "close_setup_fds();s=os.fstat(1);f=fcntl.fcntl(1,fcntl.F_GETFL);"
            "assert stat.S_ISFIFO(s.st_mode) and f&os.O_ACCMODE==os.O_WRONLY and not f&os.O_NONBLOCK;"
            "assert not Path('/candidate').exists() and not Path('/original').exists();"
            "os.write(1,b'KPB_PUBLIC_OWNER_STDIO_OK\\n')")
        done = subprocess.run(fifo_argv + python + ['-c', public_script], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=fifo_fds,
            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        preflight.append({'check': 'actual-owner-stdio-startup-no-private-inputs',
            'passed': done.returncode == 0 and done.stdout == b'KPB_PUBLIC_OWNER_STDIO_OK\n',
            'returncode': done.returncode, 'public_stdout': done.stdout.decode('utf-8', 'replace'),
            'public_stderr': done.stderr.decode('utf-8', 'replace')})
        leaves_argv, leaves_fds = namespace((), owner=True)
        public_paths = ['/NAMESPACE.json', '/CONFIG.json', '/parameters/MANIFEST.json',
                        '/public/PUBLIC-HISTORY.json', '/public/IMMUTABLE-TAIL.bin',
                        *[row['path'] for row in role['source_members']]]
        expected_public_digests = {row['virtual_path']: row['sha256'] for row in owner_public_records}
        leaves_script = ("import ast,os,stat,hashlib,json;from pathlib import Path;"
            "p=Path(" + repr(role['role']['path']) + ");t=ast.parse(p.read_bytes());"
            "nodes=[n for n in t.body if isinstance(n,ast.FunctionDef) and n.name in ('need','public_leaf')];"
            "exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(p),'exec'));"
            "paths=" + repr(public_paths) + ";expected=" + repr(expected_public_digests) + ";"
            "print(json.dumps({'public_leaf_metadata':[{'path':s,'nlink':Path(s).stat().st_nlink,"
            "'mode':stat.S_IMODE(Path(s).stat().st_mode)} for s in paths]},sort_keys=True),flush=True);"
            "[public_leaf(s,expected[s]) for s in paths];print('KPB_PUBLIC_OWNER_LEAVES_OK')")
        done = subprocess.run(leaves_argv + python + ['-c', leaves_script], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=leaves_fds,
            env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        preflight.append({'check': 'actual-owner-public-leaf-invariants-no-private-inputs',
            'passed': done.returncode == 0 and done.stdout.endswith(b'KPB_PUBLIC_OWNER_LEAVES_OK\n'),
            'returncode': done.returncode, 'public_stdout': done.stdout.decode('utf-8', 'replace'),
            'public_stderr': done.stderr.decode('utf-8', 'replace')})
        if plan['mode'] == 'tor':
            # Actual selected curl + immutable88cb against a loopback SOCKS stub
            # inside the unshared namespace. This uses only a nonfinancial public
            # frame; the stub emits byte counts/status and never body/auth data.
            fd_argv, fd_fds = namespace(('transport.py', 'packet.py'))
            public_arguments = ['--frame-fd', '0', '--onion-endpoint',
                'http://' + 'a' * 56 + '.onion/exit', '--socks', '127.0.0.1:9',
                '--selected-curl', '/usr/bin/curl']
            original_script = ("import sys,runpy;sys.path.insert(0,'/app');sys.argv="
                + repr(['/app/transport.py', *public_arguments])
                + ";runpy.run_path('/app/transport.py',run_name='__main__')")
            corrected_script = isolated_transport_entry(python, public_arguments)[-1]
            fd_script = "scripts=" + repr([original_script, corrected_script]) + "\n" + PUBLIC_TRANSPORT_FD_CONTROL
            done = subprocess.run(fd_argv + python + ['-c', fd_script], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, pass_fds=fd_fds,
                env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            preflight.append({'check': 'actual-selected-curl-stdin0-payload-fd-control',
                'passed': done.returncode == 0, 'returncode': done.returncode,
                'public_stdout': done.stdout.decode('utf-8', 'replace'),
                'public_stderr': done.stderr.decode('utf-8', 'replace')})
        if plan['mode'] == 'tor':
            import_argv, import_fds = namespace(('transport.py', 'packet.py'))
            done = subprocess.run(import_argv + isolated_transport_entry(python, ['--help']),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, pass_fds=import_fds, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
            preflight.append({'check': 'actual-isolated-transport-entry-help-no-input-or-network',
                'passed': done.returncode == 0, 'returncode': done.returncode,
                'public_stdout': done.stdout.decode('utf-8', 'replace'),
                'public_stderr': done.stderr.decode('utf-8', 'replace')})
        save(public / 'PUBLIC-NAMESPACE-PREFLIGHT.json', {'checks': preflight,
            'all_passed': all(row['passed'] for row in preflight), 'private_candidate_opened': False,
            'private_tor_state_created': False, 'network': 'UNSHARED'})
        need(all(row['passed'] for row in preflight), 'public-owner-runtime-and-stdio-preflight')
        if args.operation == 'preflight':
            result.update(status='PUBLIC_OWNER_NAMESPACE_PREFLIGHT_PASSED')
            return {'schema': 'kpb-owner-stdio-launcher-status/v1', 'status': result['status'],
                    'result': str(public / 'RESULT.json'), 'controller_frame_body_read_or_hash': False,
                    'privacy_or_financial_qualification': False}
        private_fd = os.open(CANDIDATE, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
        need(identity(os.fstat(private_fd)) == identity(candidate_info), 'private-candidate-O_PATH-metadata-only')
        event('private-candidate-metadata-only', path=str(CANDIDATE), identity=list(identity(candidate_info)),
              mode='O_PATH', body_read=False, body_hash=False)
        if plan['mode'] == 'network-off-consumer':
            incoming, outgoing = os.pipe2(os.O_CLOEXEC)
            event('pipe-created', read_fd=incoming, write_fd=outgoing, pipe_inode=os.fstat(incoming).st_ino,
                  mapping={'owner_stdout': 1, 'consumer_stdin': 0})
            consumer_argv, consumer_fds = namespace(('owner_pipe_consumer.py', 'packet.py'))
            owner_argv, owner_fds = namespace((), owner=True)
            need(private_fd not in consumer_fds, 'private-candidate-capability-owner-only')
            try:
                consumer = launch('consumer', consumer_argv + python + ['/app/owner_pipe_consumer.py'],
                    consumer_fds, stdin=incoming)
                owner = launch('owner', owner_argv + python + [role['role']['path'], '--output-fd', '1'],
                    owner_fds, stdout=outgoing, stderr=subprocess.PIPE, owner=True)
                event('actual-stdio-link', owner_pid=owner.pid, owner_host_write_fd=outgoing,
                    owner_child_stdout=1, consumer_pid=consumer.pid, consumer_host_read_fd=incoming,
                    consumer_child_stdin=0)
            finally:
                os.close(incoming); os.close(outgoing); incoming = outgoing = None
                event('parent-pipe-ends-closed')
                os.close(private_fd); private_fd = None
            owner.wait(); consumer.wait()
            event('role-exit', role='owner', returncode=owner.returncode)
            event('role-exit', role='consumer', returncode=consumer.returncode)
            need(owner.returncode == 0 and consumer.returncode == 0, 'single-network-off-owner-pipe-attempt')
            wait_for(lambda which, value: which == 'owner' and value['schema'] == 'kpb-owner-exit-pipe-status/v1'
                     and value['status'] == 'FRAME_WRITTEN')
            wait_for(lambda which, value: which == 'consumer' and value['schema'] == 'kpb-owner-pipe-consumer-status/v1'
                     and value['frame_decoded'] is True)
            result.update(status='OWNER_VALIDATED_FRAME_DECODED_NETWORK_OFF', network='UNSHARED',
                frame_or_candidate_body_exported_to_controller=False, frame_or_candidate_digest_exported_to_controller=False,
                financial_validation='OWNER_EXISTING_AUTH_EXIT_VALIDATION_ONLY_NOT_CHAIN_OR_NATIVE_ADMISSION')
            return {'schema': 'kpb-owner-stdio-launcher-status/v1', 'status': result['status'],
                    'result': str(public / 'RESULT.json'), 'controller_frame_body_read_or_hash': False,
                    'privacy_or_financial_qualification': False}
        def port():
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0)); return reservation.getsockname()[1]
        socks, receiver_port = port(), port(); need(socks != receiver_port, 'distinct-fresh-listener-ports')
        private.mkdir(mode=0o700, parents=True)
        for name in ('service', 'client'): (private / name).mkdir(mode=0o700)
        argv, fds = namespace(('run_probe.py',), network=True, state='service')
        service = launch('service', argv + python + ['/app/run_probe.py', '--role', 'service', '--receiver-port', str(receiver_port)], fds)
        hostname = wait_for(lambda which, value: which == 'service' and value['schema'] == 'kpb-probe-public-onion/v1')['hostname']
        argv, fds = namespace(('run_probe.py', 'receiver.py', 'packet.py'), network=True, observations=True)
        receiver = launch('receiver', argv + python + ['/app/run_probe.py', '--role', 'receiver',
            '--common-host', hostname, '--receiver-port', str(receiver_port)], fds, stdin=subprocess.PIPE)
        wait_for(lambda which, value: which == 'receiver' and value['schema'] == 'kpb-probe-listener/v1')
        argv, fds = namespace(('run_probe.py',), network=True, state='client')
        client = launch('client', argv + python + ['/app/run_probe.py', '--role', 'client', '--socks-port', str(socks)], fds)
        for which in ('service', 'client'):
            wait_for(lambda name, value: name == which and value['schema'] == 'kpb-probe-tor-progress/v1' and value['percent'] == 100)
        deadline = time.monotonic() + plan['startup_grace_seconds']
        while time.monotonic() < deadline:
            time.sleep(0.25); need(all(process.poll() is None for _which, process in processes), 'dependency-during-grace')
        incoming, outgoing = os.pipe2(os.O_CLOEXEC)
        event('pipe-created', read_fd=incoming, write_fd=outgoing, pipe_inode=os.fstat(incoming).st_ino,
              mapping={'owner_stdout': 1, 'transport_stdin': 0})
        transport_argv, transport_fds = namespace(('transport.py', 'packet.py'), network=True)
        owner_argv, owner_fds = namespace((), owner=True)
        need(private_fd not in transport_fds, 'private-candidate-capability-owner-only')
        try:
            transport = launch('transport', transport_argv + isolated_transport_entry(python,
                ['--frame-fd', '0', '--onion-endpoint', 'http://' + hostname + '/exit',
                 '--socks', '127.0.0.1:' + str(socks), '--selected-curl', '/usr/bin/curl']),
                transport_fds, stdin=incoming)
            owner = launch('owner', owner_argv + python + [role['role']['path'], '--output-fd', '1'], owner_fds,
                stdout=outgoing, stderr=subprocess.PIPE, owner=True)
        finally:
            os.close(incoming); os.close(outgoing); incoming = outgoing = None
            event('parent-pipe-ends-closed')
            os.close(private_fd); private_fd = None
        owner.wait(); transport.wait()
        event('role-exit', role='owner', returncode=owner.returncode)
        event('role-exit', role='transport', returncode=transport.returncode)
        need(owner.returncode == 0 and transport.returncode == 0, 'single-owner-transport-attempt-incomplete')
        wait_for(lambda which, value: which == 'owner' and value['schema'] == 'kpb-owner-exit-pipe-status/v1'
                 and value['status'] == 'FRAME_WRITTEN')
        wait_for(lambda which, value: which == 'transport' and value['schema'] == 'kpb-exit-transport-status/v1')
        for which, process in reversed(processes):
            if which in ('service', 'client'): stop(which, process)
        # Graceful control is public fixed STOP only, never candidate/frame data.
        event('receiver-stop-control', bytes=5)
        receiver.stdin.write(b'STOP\n'); receiver.stdin.flush(); receiver.stdin.close()
        receiver.wait(); stopped.add('receiver'); event('role-exit', role='receiver', returncode=receiver.returncode)
        summary = wait_for(lambda which, value: which == 'receiver' and value['schema'] == 'kpb-probe-listener-summary/v1')
        need(receiver.returncode == 0 and summary['accepted'] == summary['completed'] == 1, 'single-arrival-drained')
        # The controller deliberately does not inspect even already-public
        # receiver files. Independent qualification is a separate reader role.
        result.update(status='OWNER_VALIDATED_FRAME_TRANSPORT_RECEIPT_AND_RECEIVER_DRAINED',
            receiver_summary=summary, receiver_artifacts=str(public / 'observations/arrivals'),
            financial_validation='NOT_RUN_BY_CONTROLLER', public_onion_hostname=hostname)
    except BaseException as error:
        result.update(status='REFUSED_OR_FAILED', category=type(error).__name__)
    finally:
        for fd in (incoming, outgoing, private_fd):
            if fd is not None: os.close(fd)
        for which, process in reversed(processes): stop(which, process)
        for thread in status_threads: thread.join()
        for environment in namespace_sets:
            for fd in environment['setup_fds']: os.close(fd)
        for fd in descriptors.values(): os.close(fd)
        for fd in owned_fds: os.close(fd)
        event_output.flush(); os.fsync(event_output.fileno()); event_output.close()
        save(public / 'EVENTS.json', events); save(public / 'RESULT.json', result)
    return {'schema': 'kpb-owner-stdio-launcher-status/v1', 'status': result['status'],
            'result': str(public / 'RESULT.json'), 'controller_frame_body_read_or_hash': False,
            'privacy_or_financial_qualification': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='operation', required=True)
    staged = sub.add_parser('stage'); staged.add_argument('--execution-selected', action='store_true')
    staged.add_argument('--mode', choices=('network-off-consumer', 'tor'), default='network-off-consumer')
    for mode in ('execute', 'preflight'):
        executed = sub.add_parser(mode); executed.add_argument('--plan', required=True); executed.add_argument('--plan-sha256', required=True)
    args = parser.parse_args(); os.umask(0o077)
    result = stage(args) if args.operation == 'stage' else run(args)
    print(json.dumps(result, sort_keys=True), flush=True)
    if result['status'] == 'REFUSED_OR_FAILED':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
