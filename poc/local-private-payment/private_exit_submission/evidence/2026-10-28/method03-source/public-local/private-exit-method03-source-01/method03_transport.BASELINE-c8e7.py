"""UNSELECTED METHOD03 experimental six-event orchestrator; source only.

Root must freeze the complete method/source/budget before any call to
open_vector. This module grants no Original, private-generation, capture,
network, broadcast, financial or privacy authority. Existing direct Exit and
every passed source remain unchanged. One submit_one call is one attempt.
"""

import ast
import fcntl
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import types
import uuid

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
HERE = ROOT / '.local/private-exit-method03-source-01'
OLD = ROOT / '.local/private-exit-submission-proposal-01'
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private')
PROBE = OLD / 'prototype/run_probe.py'
TOR = Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/bundle/tor/tor')
STDLIB = Path('/usr/lib/python3.14')
TOOLS = {'path': str(OLD / 'RUNTIME-ADMISSION-01.json'), 'sha256': '00a542151ec26f3ce5c6bf7118c2d52c869dd4d32c6700d196d7f54f805adc62'}
ELF = {'path': str(OLD / 'RUNTIME-ELF-CLOSURE-02.json'), 'sha256': '37de32f92ea7bbe130e122fca73cd7e69a99f02b737cbb2a00231306e883fe4c'}
ROLE = {'path': str(OLD / 'OWNER-PIPE-SOURCE-SELECTION.json'), 'sha256': '05d77baf6917aa5ac7a326ccee0e9b7877eddf4558f7046d3b3060282132e1f0'}
TAIL_SHA = '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d'
PROCESS_HELPER_SHA = 'f1860c20be1f6ff8d7384f26d44a7ad7906b2ba67618c3c4c88900167a89d99c'
SOURCES = {
    'owner_pipe_launcher.py': (OLD / 'owner_pipe_launcher.py', 'e2e4cb0c365ee10c979f9188dc5570215fa9628039d41b8e4f56aead465566c6'),
    'run_probe.py': (PROBE, '0582a871c6f03a1d512618cede051c6b36bae37acae4a26be25b11534fcd9dec'),
    'receiver.py': (OLD / 'prototype/receiver.py', '0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac'),
    'packet.py': (OLD / 'prototype/packet.py', '7c0ad5f630a94a1481384c8726d98ebcfbab7ff1f6ba5395b3d8da9fafda38a6'),
    'transport.py': (OLD / 'prototype/transport.py', '88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4'),
    'owner_release_pipe.py': (OLD / 'owner_release_pipe.py', '7d65b4c51c88b834f644088747f06e7926044411b3f77c945f238e2150970ed9'),
    'exit_release.py': (ROOT / 'poc/local-private-payment/private_batch_trial/exit_release.py', 'cafb737b2957b6a11743de8a319add82dc1dab520e708cd2ea0ca669b4577d4e'),
    'exit_wire.py': (ROOT / 'poc/local-private-payment/private_batch_trial/exit_wire.py', 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a'),
    'verification_wire.py': (ROOT / 'poc/local-private-payment/verification/wire.py', '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8'),
    'controller_metadata.py': (HERE / 'controller_metadata.py', '2086ecf2f3ff9248e1f1a41442539b7c88f68c004c7e69c857c8f8bf88a5324a'),
}
IDENTITY_FIELDS = ('chain_hex32', 'pool_hex32', 'profile_hex32', 'domain_hex32', 'service_hex32')
HEX32 = re.compile('[0-9a-f]{64}\\Z')
BINDING_FIELDS = {'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'}


def need(value, category):
    if not value:
        raise ValueError(category)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def save(path, value):
    raw = value if type(value) is bytes else encoded(value)
    with Path(path).open('xb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())


def identity(info):
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink', 'st_uid', 'st_mode'))


def validate_binding(binding):
    need(type(binding) is dict and set(binding) == BINDING_FIELDS, 'exact-vector-binding')
    need(all(type(binding[key]) is str and HEX32.fullmatch(binding[key]) for key in ('method_sha256', 'selection_sha256')), 'binding-source-identities')
    need(all(type(binding[key]) is str and str(uuid.UUID(binding[key])) == binding[key] for key in ('trial_id', 'attempt_id')), 'binding-fresh-identities')
    need(type(binding['phase']) is str and re.fullmatch('[a-z][a-z0-9-]{0,63}', binding['phase']), 'binding-phase')


def validate_slot(arm, owner_slot):
    need(arm in ('A', 'B') and type(owner_slot) is int and 0 <= owner_slot < 3, 'finite-arm-owner-slot')
    return owner_slot + (3 if arm == 'B' else 0)


def _ref(ref):
    need(type(ref) is dict and set(ref) == {'path', 'sha256'}
         and type(ref['path']) is str and Path(ref['path']).is_absolute()
         and type(ref['sha256']) is str and HEX32.fullmatch(ref['sha256']), 'exact-public-reference')


def selected_transport_source_pins(guard):
    """Source-stage map from the authenticated public admission receipt only.

    No binary execution, network, proc capture, private intake or vector start.
    Actual startup separately admits each selected installed runtime identity.
    """
    tools = json.loads(guard['read'](Path(TOOLS['path']), TOOLS['sha256']))
    rows = {row['path']: row for row in tools['files']}
    return {'transport_source_sha256': SOURCES['transport.py'][1],
            'tor_binary_sha256': rows[str(TOR)]['sha256'],
            'curl_binary_sha256': rows['/usr/bin/curl']['sha256'],
            'receiver_source_sha256': SOURCES['receiver.py'][1]}


def _private_path(path):
    path = Path(path)
    need(path.is_absolute() and path.is_relative_to(PRIVATE) and path != PRIVATE, 'specific-protected-leaf')
    need(not any(parent.is_symlink() for parent in (path, *path.parents)), 'no-private-path-alias')
    return path


def candidate_metadata(ref):
    """Metadata only, never open/read/hash this private body."""
    fields = {'path', 'mode', 'bytes', 'uid', 'gid', 'nlink', 'dev', 'inode', 'mtime_ns', 'ctime_ns'}
    need(type(ref) is dict and set(ref) == fields, 'exact-candidate-metadata-fields')
    need(type(ref['path']) is str and all(type(ref[key]) is int for key in fields - {'path'}), 'candidate-metadata-integer-types')
    path = _private_path(ref['path']); info = path.lstat()
    actual = {'path': str(path), 'mode': stat.S_IMODE(info.st_mode), 'bytes': info.st_size,
              'uid': info.st_uid, 'gid': info.st_gid, 'nlink': info.st_nlink,
              'dev': info.st_dev, 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}
    need(stat.S_ISREG(info.st_mode) and actual == ref and info.st_nlink == 1
         and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(), 'same-owned-private-candidate-metadata')
    return path, info


def _functions(raw, names, environment, label):
    nodes = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
    need({node.name for node in nodes} == set(names), 'exact-selected-helper-functions')
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), label, 'exec'), environment)


def _module(raw, name, path):
    module = types.ModuleType(name); module.__file__ = str(path); sys.modules[name] = module
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class ExperimentalVectorSession:
    """One selected experiment, six independent as-ready submission attempts."""

    def __init__(self, *, binding, selection_ref, early_controller_clock_ref, public_output, private_tor_state,
                 capture_root, guard, emit_metadata):
        validate_binding(binding); _ref(selection_ref); _ref(early_controller_clock_ref)
        self.binding = dict(binding); self.trial = binding['trial_id']; self.guard = guard
        self.read = guard['read']; self.metadata = guard['m'].GUARD.metadata
        need(any(PRIVATE == path or PRIVATE.is_relative_to(path)
                 for path in guard['m'].GUARD.directories), 'private-tor-capture-parent-already-protected')
        self.public = Path(public_output); self.private = _private_path(private_tor_state)
        self.capture = _private_path(capture_root)
        need(self.private == PRIVATE / 'diagnostics' / ('method03-tor-' + self.trial)
             and self.capture == PRIVATE / 'diagnostics' / ('method03-capture-' + self.trial), 'separate-finite-private-compartments')
        need(self.public.is_absolute() and self.public.is_relative_to(ROOT / '.local')
             and not self.public.is_relative_to(PRIVATE)
             and all(not path.exists() and not any(parent.is_symlink() for parent in path.parents)
                     for path in (self.public, self.private, self.capture)), 'fresh-vector-output-compartments')
        self.public.mkdir(mode=0o700, parents=True)
        (self.public / 'owner-public-leaves').mkdir(mode=0o700)
        (self.public / 'A-exposures').mkdir(mode=0o700)
        self.journal = (self.public / 'EVENTS.ndjson').open('xb')
        self.callback = emit_metadata; self.lock = threading.RLock(); self.condition = threading.Condition(self.lock)
        self.records = 0; self.owned = []; self.processes = {}; self.threads = []; self.latest = {}
        self.messages = queue.Queue(); self.invalid = set(); self.attempts = {}; self.active = set(); self.closed = False
        self.reported_exits = set(); self.regular_records = {}; self.a_exposures = {}
        self.sources = {}; self.descriptors = {}; self.masked_packages = []; self.leaf_count = 0
        self.consumer = threading.Thread(target=self._consume, daemon=True); self.consumer.start()
        try:
            selection_raw = self.read(Path(selection_ref['path']), selection_ref['sha256'])
            selection = json.loads(selection_raw)
            need(set(selection) == {'schema', 'source_members', 'runtime_tools', 'runtime_elf', 'role_selection'}
                 and selection['schema'] == 'kpb-method03-transport-source-selection/v1'
                 and selection['runtime_tools'] == TOOLS and selection['runtime_elf'] == ELF
                 and selection['role_selection'] == ROLE, 'fixed-source-and-runtime-selection')
            expected = dict(SOURCES)
            need(HEX32.fullmatch(PROCESS_HELPER_SHA), 'subprocess-helper-source-not-yet-selected')
            expected['role_subprocess_metadata.py'] = (HERE / 'role_subprocess_metadata.py', PROCESS_HELPER_SHA)
            members = {row['name']: row for row in selection['source_members']}
            need(len(members) == len(selection['source_members']) and set(members) == set(expected) | {'method03_transport.py'}, 'exact-vector-source-closure')
            for name, (path, pin) in expected.items():
                row = members[name]
                need(row == {'name': name, 'path': str(path), 'sha256': pin}, 'fixed-source-member')
                self.sources[name] = self.read(path, pin)
            own = members['method03_transport.py']; _ref({key: own[key] for key in ('path', 'sha256')})
            need(set(own) == {'name', 'path', 'sha256'} and own['path'] == str(HERE / 'method03_transport.py'), 'selected-driver-source')
            self.read(Path(own['path']), own['sha256'])
            self._event('source-admission', selection_ref=selection_ref, source_members=selection['source_members'], runtime_tools=TOOLS, runtime_elf=ELF, role_selection=ROLE)
            self.md = _module(self.sources['controller_metadata.py'], '_m03_controller_metadata', HERE / 'controller_metadata.py')
            # Install the selected module name only for this public helper's import.
            sys.modules['controller_metadata'] = self.md
            self.sp = _module(self.sources['role_subprocess_metadata.py'], '_m03_role_subprocess', HERE / 'role_subprocess_metadata.py')
            self.packet = _module(self.sources['packet.py'], '_m03_packet', OLD / 'prototype/packet.py')
            early = json.loads(self.read(Path(early_controller_clock_ref['path']), early_controller_clock_ref['sha256']))
            need(type(early) is dict and set(early) == {'schema', 'binding', 'value'}
                 and early['schema'] == 'kpb-method03-early-controller-clock/v1'
                 and early['binding'] == self.binding, 'bound-early-controller-clock-artifact')
            self.md._clock_record(early['value'], 'controller')
            current = self.md.clock_snapshot('controller')
            need(early['value']['pid'] == current['pid'] == os.getpid()
                 and all(early['value'][key] == current[key] for key in ('boot_id', 'time_namespace', 'time_for_children_namespace', 'timens_offsets'))
                 and early['value']['sample']['monotonic_after_ns'] <= current['sample']['monotonic_before_ns'], 'actual-same-controller-clock-continuation')
            self._event('controller-clock', value=early['value'], source_event_ref=early_controller_clock_ref)
            self._event('controller-clock-followup', value=current)
            environment = dict(globals()); environment.update(metadata=self.metadata, descriptors=self.descriptors)
            _functions(self.sources['owner_pipe_launcher.py'], {'selected_helpers', 'admit_stdlib', 'isolated_transport_entry'}, environment, str(OLD / 'owner_pipe_launcher.py'))
            self.environment = environment
            self.helpers = environment['selected_helpers'](self.sources['run_probe.py'], environment)
            self.tools = json.loads(self.read(Path(TOOLS['path']), TOOLS['sha256']))
            self.elf = json.loads(self.read(Path(ELF['path']), ELF['sha256']))
            self.runtime_rows = {row['path']: row for row in [*self.tools['files'], *self.elf['files']]}
            for path, row in self.runtime_rows.items(): self.helpers['admit_runtime'](path, row)
            self.owned.extend(self.descriptors.values())
            self._event('runtime-admission', **environment['admit_stdlib'](guard, self.descriptors, self.masked_packages))
            for path, row in self.elf['aliases'].items():
                if row['link_text'] is not None:
                    need(Path(path).is_symlink() and os.readlink(path) == row['link_text']
                         and str(Path(path).resolve(strict=True)) == row['target'], 'unchanged-runtime-alias')
            self.marker = self._memfd(b'')
            app_names = ('run_probe.py', 'receiver.py', 'packet.py', 'transport.py', 'controller_metadata.py', 'role_subprocess_metadata.py')
            self.app = {name: self._memfd(self.sources[name]) for name in app_names}
            self.role = json.loads(self.read(Path(ROLE['path']), ROLE['sha256']))
            self.owner_sources = {}
            known_source_pins = {pin for _path, pin in SOURCES.values()}
            for row in self.role['source_members']:
                need(row['sha256'] in known_source_pins, 'fixed-owner-source-closure')
                # The authenticated old role manifest retains its original
                # virtual paths, including the repo packet.py alias. Read those
                # exact public leaves through the guard; never remap HERE.
                raw = self.read(Path(row['path']), row['sha256'])
                self.owner_sources[row['path']] = self._regular(raw, row['path'])
            self.owner_runtime = {}
            for row in self.role['runtime_members']:
                raw = self.read(Path(row['host_path']), row['sha256'])
                if row['path'] == '/runtime/prover':
                    canonical, info = self.metadata(Path(row['host_path']))
                    fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
                    need(identity(os.fstat(fd)) == identity(info), 'same-owner-prover-open')
                    self.owned.append(fd); self.owner_runtime[row['path']] = fd
                else:
                    self.owner_runtime[row['path']] = self._regular(raw, row['path'])
            gcc = Path('/usr/lib/x86_64-linux-gnu/libgcc_s.so.1')
            self.read(gcc, '9d339ecb409578d6a5d587e6c537a8f9589b8a13fefba30d167433a4b5758bee')
            canonical, info = self.metadata(gcc); self.gcc = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            need(identity(os.fstat(self.gcc)) == identity(info), 'same-owner-extra-runtime-open'); self.owned.append(self.gcc)
            self._public_runtime_preflight()
            self.private.mkdir(mode=0o700, parents=True); self.capture.mkdir(mode=0o700, parents=True)
            (self.capture / 'observations').mkdir(mode=0o700)
            for name in ('service', 'client'): (self.private / name).mkdir(mode=0o700)
            self._start_network()
        except BaseException:
            self.close_incomplete()
            raise

    def _event(self, kind, **fields):
        with self.lock:
            row = {'schema': 'kpb-method03-controller-event/v1', 'binding': self.binding,
                   'sequence': self.records, 'recorded_monotonic_ns': time.clock_gettime_ns(time.CLOCK_MONOTONIC), 'kind': kind, **fields}
            self.records += 1; self.journal.write(encoded(row)); self.journal.flush()
            try:
                self.callback(row)
            except BaseException:
                # The durable journal remains authoritative. A missing live
                # callback is explicit incomplete evidence, never a receipt.
                self.invalid.add('controller-metadata-callback')

    def _consume(self):
        while True:
            item = self.messages.get()
            try:
                if item is None: return
                kind, role, value = item
                consumed = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                if kind == 'status':
                    self._event('status', role=role, observation=value, consumed_monotonic_ns=consumed)
                    with self.condition:
                        self.latest[(role, value['value']['schema'])] = value['value']; self.condition.notify_all()
                else:
                    self._event(kind, role=role, **value)
                    if kind == 'invalid-public-status': self.invalid.add(role)
            except BaseException:
                self.invalid.add('controller-metadata-journal')
            finally:
                self.messages.task_done()

    def _reader(self, role, stream):
        try:
            while True:
                observation = self.sp.read_role_event(stream, reader_id='controller/' + role, role=role)
                if observation is None: break
                self.messages.put(('status', role, observation))
        except BaseException as error:
            self.messages.put(('invalid-public-status', role, {'category': type(error).__name__}))
        finally:
            self.messages.put(('status-stream-ended', role, {'reader_finished_monotonic_ns': time.clock_gettime_ns(time.CLOCK_MONOTONIC)}))

    def _wait_value(self, role, schema, predicate=lambda value: True):
        with self.condition:
            while True:
                value = self.latest.get((role, schema))
                if value is not None and predicate(value): return value
                need(role not in self.invalid, 'invalid-public-role-status')
                process = self.processes.get(role)
                need(process is None or process.poll() is None, 'role-exited-before-required-status')
                self.condition.wait(0.25)

    def _memfd(self, raw):
        fd = self.helpers['public_memfd'](raw); self.owned.append(fd); return fd

    def _regular(self, raw, virtual):
        with self.lock:
            path = self.public / 'owner-public-leaves' / str(self.leaf_count); self.leaf_count += 1
            save(path, raw); path.chmod(0o400)
            canonical, info = self.metadata(path)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                 and stat.S_IMODE(info.st_mode) == 0o400, 'public-single-link-owner-leaf')
            fd = os.open(canonical, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            need(identity(os.fstat(fd)) == identity(info), 'same-public-owner-open'); self.owned.append(fd)
            self.regular_records[fd] = {'virtual_path': str(virtual), 'sha256': hashlib.sha256(raw).hexdigest(), 'identity': identity(info)}
            self._event('public-owner-leaf', virtual_path=str(virtual), host_path=str(path), sha256=hashlib.sha256(raw).hexdigest(), metadata=list(identity(info)), fd=fd)
            return fd

    def _namespace(self, names, *, network=False, state=None, capture=False, owner_files=None, candidate_fd=None):
        environment = dict(self.environment)
        descriptors = dict(self.descriptors)
        if owner_files is not None: descriptors['/usr/lib/x86_64-linux-gnu/libgcc_s.so.1'] = self.gcc
        environment.update(descriptors=descriptors, elf=self.elf, masked_packages=self.masked_packages,
                           app_fds={name: self.app[name] for name in names}, setup_fds=[], marker_fd=self.marker,
                           private=self.private, public=self.capture, STDLIB=STDLIB, TOR=TOR)
        self.environment['selected_helpers'](self.sources['run_probe.py'], environment)
        argv = environment['namespace'](network=network, state=state, observations=capture)
        extra = []
        if owner_files is not None:
            for path, fd in {**self.owner_sources, **self.owner_runtime, **owner_files}.items():
                argv += ['--ro-bind', '/proc/self/fd/' + str(fd), path]; extra.append(fd)
            if candidate_fd is not None:
                argv += ['--ro-bind', '/proc/self/fd/' + str(candidate_fd), '/candidate/EXIT-CANDIDATE.json']; extra.append(candidate_fd)
        fds = tuple(dict.fromkeys((*environment['public_fds'](), *extra)))
        # setup_fds are independent public read descriptions, not dup aliases.
        self.owned.extend(environment['setup_fds'])
        return argv, fds

    def _public_runtime_preflight(self):
        config_marker = self._regular(encoded(self.role['namespace_marker']), '/NAMESPACE.json')
        argv, fds = self._namespace((), owner_files={'/NAMESPACE.json': config_marker})
        self._public_check('actual-owner-prover-loader', argv + ['/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2', '--list', '/runtime/prover'], fds)

    def _public_check(self, label, argv, fds, expected=None):
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   close_fds=True, pass_fds=fds, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        self._event('public-preflight-launch', check=label, host_pid=process.pid,
                    popen_started_monotonic_ns=before, popen_returned_monotonic_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC),
                    argv=argv, passed_setup_fds=list(fds))
        out, error = process.communicate()  # Only the selected PUBLIC checker output.
        self._event('public-runtime-preflight', check=label, host_pid=process.pid, returncode=process.returncode,
                    public_stdout=out.decode('utf-8', 'replace'), public_stderr=error.decode('utf-8', 'replace'))
        need(process.returncode == 0 and (expected is None or out == expected), 'public-owner-runtime-refusal')

    def _owner_public_preflight(self, slot, files):
        # Same passed public_leaf predicate in the real sparse namespace; no
        # candidate mount/handle or Original is present in this checker.
        selected = {**self.owner_sources, **{path: fd for path, fd in self.owner_runtime.items() if path != '/runtime/prover'}, **files}
        digests = {path: self.regular_records[fd]['sha256'] for path, fd in selected.items()}
        argv, fds = self._namespace((), owner_files=files)
        script = ("import ast,os,stat,hashlib;from pathlib import Path;"
                  + "p=Path(" + repr(self.role['role']['path']) + ");t=ast.parse(p.read_bytes());"
                  + "nodes=[n for n in t.body if isinstance(n,ast.FunctionDef) and n.name in ('need','public_leaf')];"
                  + "exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),str(p),'exec'));"
                  + "expected=" + repr(digests) + ";[public_leaf(p,h) for p,h in expected.items()];"
                  + "assert not Path('/candidate').exists() and not Path('/original').exists();"
                  + "print('KPB_M03_PUBLIC_OWNER_LEAVES_OK')")
        self._public_check('actual-owner-public-leaves-' + str(slot), argv + ['/usr/bin/python3.14', '-I', '-S', '-B', '-c', script],
                           fds, b'KPB_M03_PUBLIC_OWNER_LEAVES_OK\n')

    def _wrapper(self, role, argv, *, owner=False, transport=False):
        stream = 'sys.stderr' if owner else 'sys.stdout'
        prefix = ("import sys,json,runpy;sys.path.insert(0,'/app');import role_subprocess_metadata as sm;"
                  + "emit=lambda value:print(json.dumps(value,sort_keys=True),file=" + stream + ",flush=True);"
                  + "emit(sm.clock_snapshot(" + repr(role) + "));hook=sm.install(" + repr(role) + ",emit);")
        if role in ('service/0', 'client/0'):
            # This control pipe has no frame and no Original. Terminate only the
            # known tracked Tor child, allowing unchanged0582 to observe/wait it
            # and emit actual lifecycle metadata before the namespace exits.
            prefix += ("\nimport threading,os\ndef _public_stop_control():\n"
                       " raw=sys.stdin.buffer.read(6)\n"
                       " if raw!=b'STOP\\n':os._exit(1)\n"
                       " hook.stop_tor()\n"
                       "threading.Thread(target=_public_stop_control,daemon=True).start()\n")
        python = ['/usr/bin/python3.14', '-I', '-S', '-B']
        if transport:
            command = self.environment['isolated_transport_entry'](python, argv)
            return [*python, '-c', prefix + command[-1]]
        return [*python, '-c', prefix + 'sys.argv=' + repr(argv) + ";runpy.run_path(sys.argv[0],run_name='__main__')"]

    def _launch(self, role, argv, fds, *, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, owner=False):
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        process = subprocess.Popen(argv, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True,
                                   pass_fds=fds, env={'PATH': '/usr/bin', 'LANG': 'C.UTF-8'})
        returned = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        with self.lock:
            need(role not in self.processes, 'one-role-launch-only'); self.processes[role] = process
        def fd_spec(value):
            if type(value) is int: return value
            return value.fileno() if hasattr(value, 'fileno') else None
        self._event('launch', role=role, host_pid=process.pid, controller_pid=os.getpid(), controller_ppid=os.getppid(),
                    popen_started_monotonic_ns=before, popen_returned_monotonic_ns=returned,
                    argv=argv, passed_setup_fds=list(fds),
                    stdio={name: {'parent_argument': fd_spec(value), 'child_fd': index,
                                  'parent_pipe_fd': getattr(process, name).fileno() if getattr(process, name) is not None else None}
                           for index, (name, value) in enumerate((('stdin', stdin), ('stdout', stdout), ('stderr', stderr)))})
        stream = process.stderr if owner else process.stdout
        thread = threading.Thread(target=self._reader, args=(role, stream), name=role, daemon=True)
        self.threads.append(thread); thread.start(); return process

    def _wait_process(self, role):
        process = self.processes[role]; process.wait()
        with self.lock:
            if role not in self.reported_exits:
                self.reported_exits.add(role)
                self._event('role-exit', role=role, host_pid=process.pid, returncode=process.returncode,
                            wait_returned_monotonic_ns=time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        return process.returncode

    def _start_network(self):
        def port():
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0)); return reservation.getsockname()[1]
        self.socks, self.receiver_port = port(), port(); need(self.socks != self.receiver_port, 'distinct-service-client-ports')
        apps = ('run_probe.py', 'controller_metadata.py', 'role_subprocess_metadata.py')
        argv, fds = self._namespace(apps, network=True, state='service')
        self._launch('service/0', argv + self._wrapper('service/0', ['/app/run_probe.py', '--role', 'service', '--receiver-port', str(self.receiver_port)]), fds, stdin=subprocess.PIPE)
        host = self._wait_value('service/0', 'kpb-probe-public-onion/v1')['hostname']; self.endpoint = 'http://' + host + '/exit'
        argv, fds = self._namespace((*apps, 'receiver.py', 'packet.py'), network=True, capture=True)
        self._launch('receiver/0', argv + self._wrapper('receiver/0', ['/app/run_probe.py', '--role', 'receiver', '--receiver-port', str(self.receiver_port)]), fds, stdin=subprocess.PIPE)
        self._wait_value('receiver/0', 'kpb-probe-listener/v1')
        argv, fds = self._namespace(apps, network=True, state='client')
        self._launch('client/0', argv + self._wrapper('client/0', ['/app/run_probe.py', '--role', 'client', '--socks-port', str(self.socks)]), fds, stdin=subprocess.PIPE)
        for role in ('service/0', 'client/0'):
            self._wait_value(role, 'kpb-probe-tor-progress/v1', lambda value: value['percent'] == 100)
        self._event('startup-grace', seconds=60)
        time.sleep(60)  # Same preselected operational grace as the qualified source.
        self.transport_parameters = {'transport_source_sha256': SOURCES['transport.py'][1],
                    'tor_binary_sha256': self.runtime_rows[str(TOR)]['sha256'], 'curl_binary_sha256': self.runtime_rows['/usr/bin/curl']['sha256'],
                    'onion_endpoint': self.endpoint, 'receiver_source_sha256': SOURCES['receiver.py'][1],
                    'request_policy': {'method': 'POST', 'http_version': '1.0', 'frame_bytes': 4096,
                                       'success_status': 202, 'redirects': 0, 'retries': 0,
                                       'proxy': 'SOCKS5_HOSTNAME', 'isolate_socks_auth': True,
                                       'socks_timeout_seconds': 900, 'fallback': 'NONE',
                                       'user_agent': 'kpb-exit-transport/1', 'accept': 'application/octet-stream',
                                       'content_type': 'application/octet-stream', 'expect': ''}}
        self._event('session-parameters', **self.transport_parameters)
        self._event('capture-source-limit', receiver_source_sha256=SOURCES['receiver.py'][1],
                    missing='037 does not retain full4096 packet padding; no new raw-capture seam is selected')

    def _owner_files(self, slot, history_ref, tail_ref, identity_tuple):
        _ref(history_ref); _ref(tail_ref)
        need(tail_ref['sha256'] == TAIL_SHA and type(identity_tuple) is dict and set(identity_tuple) == set(IDENTITY_FIELDS)
             and all(type(value) is str and HEX32.fullmatch(value) for value in identity_tuple.values()), 'fixed-policy-and-public-identity')
        history_raw = self.read(Path(history_ref['path']), history_ref['sha256']); history = json.loads(history_raw)
        tail_raw = self.read(Path(tail_ref['path']), tail_ref['sha256'])
        need(history['schema'] == 'kpb-private-batch-public-history/v1' and history['scope'] == 'UNFUNDED_SUPPLIED_CONTEXT'
             and all(history[key] == identity_tuple[key] for key in IDENTITY_FIELDS), 'same-supplied-public-head-identity')
        config = dict(identity_tuple)
        config.update(schema='kpb-owner-exit-pipe-config/v1', history_sha256=history_ref['sha256'], tail_sha256=tail_ref['sha256'],
                      manifest_sha256='bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f',
                      source_members=[{'path': row['path'], 'sha256': row['sha256']} for row in self.role['source_members']],
                      runtime_members=[{'path': row['path'], 'sha256': row['sha256']} for row in self.role['runtime_members']])
        self._event('public-head-reference', slot=slot, history_ref=history_ref, tail_ref=tail_ref, identity_tuple=identity_tuple)
        return {'/CONFIG.json': self._regular(encoded(config), '/CONFIG.json'),
                '/NAMESPACE.json': self._regular(encoded(self.role['namespace_marker']), '/NAMESPACE.json'),
                '/public/PUBLIC-HISTORY.json': self._regular(history_raw, '/public/PUBLIC-HISTORY.json'),
                '/public/IMMUTABLE-TAIL.bin': self._regular(tail_raw, '/public/IMMUTABLE-TAIL.bin')}

    def submit_one(self, arm, owner_slot, candidate_ref, history_ref, tail_ref, identity_tuple):
        """As-ready, callable concurrently. No peer wait/batch or automatic retry."""
        slot = validate_slot(arm, owner_slot); owner_role = 'owner/' + str(slot); transport_role = 'transport/' + str(slot)
        with self.lock:
            need(not self.closed and slot not in self.attempts, 'one-attempt-per-selected-slot')
            result = {'arm': arm, 'owner_slot': owner_slot, 'owner_role': owner_role, 'transport_role': transport_role,
                      'owner_returncode': None, 'transport_returncode': None, 'receipt': False}
            self.attempts[slot] = result; self.active.add(slot)
        candidate_fd = incoming = outgoing = None
        try:
            files = self._owner_files(slot, history_ref, tail_ref, identity_tuple)
            self._owner_public_preflight(slot, files)
            path, info = candidate_metadata(candidate_ref)
            need(not path.is_relative_to(self.capture) and not path.is_relative_to(self.private), 'candidate-disjoint-from-capture-and-tor-state')
            candidate_fd = os.open(path, os.O_PATH | os.O_CLOEXEC | os.O_NOFOLLOW)
            need(identity(os.fstat(candidate_fd)) == identity(info), 'same-private-candidate-open')
            self._event('candidate-metadata', slot=slot, arm=arm, owner_slot=owner_slot, candidate_ref=candidate_ref,
                        body_read=False, body_hash=False, handle_mode='O_PATH', setup_fd=candidate_fd)
            incoming, outgoing = os.pipe2(os.O_CLOEXEC)
            self._event('pipe-created', slot=slot, arm=arm, owner_slot=owner_slot, pipe_inode=os.fstat(incoming).st_ino,
                        parent_read_fd=incoming, parent_write_fd=outgoing,
                        child_mapping={'owner_stdout': 1, 'transport_stdin': 0 if arm == 'B' else None})
            owner_argv, owner_fds = self._namespace(('controller_metadata.py', 'role_subprocess_metadata.py'), owner_files=files, candidate_fd=candidate_fd)
            owner_command = owner_argv + self._wrapper(owner_role, [self.role['role']['path'], '--output-fd', '1'], owner=True)
            if arm == 'A':
                self._launch(owner_role, owner_command, owner_fds, stdout=outgoing, stderr=subprocess.PIPE, owner=True)
                just_closed = outgoing; os.close(outgoing); outgoing = None
                self._event('parent-pipe-ends-closed', slot=slot, parent_fds=[just_closed])
                os.close(candidate_fd); candidate_fd = None
                frame = bytearray()
                while len(frame) <= 4096:
                    part = os.read(incoming, 4097 - len(frame))
                    if not part: break
                    frame.extend(part)
                just_closed = incoming; os.close(incoming); incoming = None
                self._event('parent-pipe-ends-closed', slot=slot, parent_fds=[just_closed])
                result['owner_returncode'] = self._wait_process(owner_role)
                next(thread for thread in self.threads if thread.name == owner_role).join()
                self.messages.join()
                status = self.latest.get((owner_role, 'kpb-owner-exit-pipe-status/v1'), {}).get('status')
                exposure = {'schema': 'kpb-method03-controller-A-exposure/v1', 'binding': self.binding, 'arm': 'A',
                            'owner_slot': owner_slot, 'owner_role': owner_role, 'transport_role': transport_role,
                            'owner_returncode': result['owner_returncode'], 'owner_fixed_status': status,
                            'frame_hex': bytes(frame).hex(), 'frame_sha256': hashlib.sha256(frame).hexdigest(),
                            'framing_valid': False, 'projection_hex': None, 'projection_sha256': None, 'proof_hex128': None,
                            'packet_source_sha256': SOURCES['packet.py'][1], 'owner_source_sha256': SOURCES['owner_release_pipe.py'][1]}
                try:
                    decoded = self.packet.decode(bytes(frame)); exposure.update(framing_valid=True, projection_hex=decoded.projection.hex(),
                        projection_sha256=hashlib.sha256(decoded.projection).hexdigest(), proof_hex128=decoded.proof.hex())
                except ValueError:
                    pass
                artifact = self.public / 'A-exposures' / (str(owner_slot) + '.json'); save(artifact, exposure)
                with self.lock: self.a_exposures[owner_slot] = exposure
                self._event('A-exposure', slot=slot, arm='A', owner_slot=owner_slot, artifact_path=str(artifact))
                need(result['owner_returncode'] == 0 and status == 'FRAME_WRITTEN' and exposure['framing_valid'], 'A-owner-validation-incomplete')
                incoming, outgoing = os.pipe2(os.O_CLOEXEC)
                self._event('pipe-created', slot=slot, arm=arm, owner_slot=owner_slot, pipe_inode=os.fstat(incoming).st_ino,
                            parent_read_fd=incoming, parent_write_fd=outgoing, child_mapping={'controller_write': outgoing, 'transport_stdin': 0})
            transport_argv, transport_fds = self._namespace(('controller_metadata.py', 'role_subprocess_metadata.py', 'transport.py', 'packet.py'), network=True)
            arguments = ['--frame-fd', '0', '--onion-endpoint', self.endpoint, '--socks', '127.0.0.1:' + str(self.socks), '--selected-curl', '/usr/bin/curl']
            self._launch(transport_role, transport_argv + self._wrapper(transport_role, arguments, transport=True), transport_fds, stdin=incoming)
            if arm == 'B': self._launch(owner_role, owner_command, owner_fds, stdout=outgoing, stderr=subprocess.PIPE, owner=True)
            parent_read = incoming; parent_write = outgoing
            os.close(incoming); incoming = None
            if arm == 'A': self._event('parent-pipe-ends-closed', slot=slot, parent_fds=[parent_read])
            if arm == 'A':
                view = memoryview(frame)
                while view:
                    written = os.write(outgoing, view); need(written > 0, 'A-frame-forward-progress'); view = view[written:]
            os.close(outgoing); outgoing = None
            self._event('parent-pipe-ends-closed', slot=slot, parent_fds=[parent_read, parent_write] if arm == 'B' else [parent_write])
            if candidate_fd is not None: os.close(candidate_fd); candidate_fd = None
            if arm == 'B': result['owner_returncode'] = self._wait_process(owner_role)
            result['transport_returncode'] = self._wait_process(transport_role)
        except BaseException as error:
            self._event('submission-error', slot=slot, arm=arm, owner_slot=owner_slot, category=type(error).__name__)
        finally:
            for fd in (incoming, outgoing, candidate_fd):
                if fd is not None: os.close(fd)
            for role, key in ((owner_role, 'owner_returncode'), (transport_role, 'transport_returncode')):
                if role in self.processes and result[key] is None: result[key] = self._wait_process(role)
            # Read threads must finish queueing all real statuses, including a
            # valid202 followed by a nonzero process exit. Never erase that U.
            for thread in list(self.threads):
                if thread.name in (owner_role, transport_role): thread.join()
            self.messages.join()
            result['receipt'] = self.latest.get((transport_role, 'kpb-exit-transport-status/v1'), {}).get('transport_receipt') is True
            status = self.latest.get((owner_role, 'kpb-owner-exit-pipe-status/v1'), {}).get('status')
            self._event('submission-finished', slot=slot, arm=arm, owner_slot=owner_slot,
                        owner_returncode=result['owner_returncode'], transport_returncode=result['transport_returncode'],
                        receipt_seen=result['receipt'], owner_fixed_status=status, possibly_arrived=transport_role in self.processes)
            with self.lock: self.active.remove(slot)
        return dict(result)

    def _stop(self, role):
        process = self.processes.get(role)
        if process is not None and process.poll() is None: process.terminate()
        if process is not None: self._wait_process(role)

    def _stop_tor(self, role):
        process = self.processes.get(role)
        if process is not None and process.poll() is None:
            self._event('tor-stop-control', role=role, bytes=5)
            process.stdin.write(b'STOP\n'); process.stdin.flush(); process.stdin.close()
        if process is not None: self._wait_process(role)

    def finish(self):
        """Completeness only: never wait for missing owners before sending."""
        with self.lock:
            need(not self.closed and not self.active, 'finish-after-active-calls-return')
        summary = None
        try:
            for role in ('client/0', 'service/0'): self._stop_tor(role)
            receiver = self.processes.get('receiver/0')
            if receiver is not None and receiver.poll() is None:
                self._event('receiver-stop-control', bytes=5)
                receiver.stdin.write(b'STOP\n'); receiver.stdin.flush(); receiver.stdin.close()
                self._wait_process('receiver/0')
            for thread in self.threads: thread.join()
            self.messages.join(); summary = self.latest.get(('receiver/0', 'kpb-probe-listener-summary/v1'))
            complete = (len(self.attempts) == 6 and not self.invalid and summary is not None
                        and summary['accepted'] == summary['completed'] == 6
                        and all(row['receipt'] and row['owner_returncode'] == row['transport_returncode'] == 0 for row in self.attempts.values())
                        and self.processes['receiver/0'].returncode == 0)
            # Only ArmA has ever entered this collection. No receiver/body/B
            # file is opened or listed to produce this explicit baseline ref.
            a_path = self.public / 'A-exposures' / 'EXPOSURE.json'
            a_value = {'schema': 'kpb-method03-controller-A-exposures/v1', 'binding': self.binding,
                       'records': [self.a_exposures[key] for key in sorted(self.a_exposures)]}
            a_raw = encoded(a_value); save(a_path, a_raw)
            self._event('A-exposure-consolidated', artifact_path=str(a_path), records=len(a_value['records']))
            result = {'schema': 'kpb-method03-vector-transport-result/v1', 'binding': self.binding, 'trial_id': self.trial,
                      'status': 'COMPLETE' if complete else 'INCOMPLETE', 'attempts': [self.attempts[key] for key in sorted(self.attempts)],
                      'receiver_summary': summary, 'metadata_journal': {'path': str(self.public / 'EVENTS.ndjson'), 'format': 'kpb-method03-controller-journal/v1'},
                      'raw_capture': {'directory': str(self.capture / 'observations/arrivals'), 'receiver_source_sha256': SOURCES['receiver.py'][1], 'actual_filenames_and_order_preserved': True},
                      'arm_a_exposures': {'directory': str(self.public / 'A-exposures'), 'format': 'kpb-method03-controller-A-exposure/v1'},
                      'baseline_A_exposure': {'path': str(a_path), 'sha256': hashlib.sha256(a_raw).hexdigest()},
                      'transport_parameters': {'A': self.transport_parameters, 'B': self.transport_parameters},
                      'clock_channels': {'controller': 'direct', 'owner': 'stderr2', 'transport': 'stdout1', 'receiver': 'stdout1'},
                      'broadcast': False, 'privacy_or_financial_qualification': False}
            save(self.public / 'RESULT.json', result)
            self._event('session-finished', status=result['status'], result_path=str(self.public / 'RESULT.json'))
            return result
        finally:
            self.close_incomplete()

    def close_incomplete(self):
        if self.closed: return
        self.closed = True
        for role in list(self.processes):
            try: self._stop(role)
            except BaseException: pass
        for thread in self.threads: thread.join()
        self.messages.join(); self.messages.put(None); self.messages.join(); self.consumer.join()
        for fd in set(self.owned):
            try: os.close(fd)
            except OSError: pass
        self.journal.flush(); os.fsync(self.journal.fileno()); self.journal.close()


def open_vector(**kwargs):
    return ExperimentalVectorSession(**kwargs)
