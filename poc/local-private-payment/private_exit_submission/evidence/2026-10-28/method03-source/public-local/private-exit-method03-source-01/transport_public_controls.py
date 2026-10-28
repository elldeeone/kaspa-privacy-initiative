"""Fake-side-effect source controls; never open_vector or launch a role."""

import ast
import hashlib
import os
from pathlib import Path
import queue
import threading
from types import SimpleNamespace


def run(driver, packet, selected_transport_entry):
    checks = []
    binding = {'method_sha256': 'a' * 64, 'selection_sha256': 'b' * 64,
               'trial_id': 'f68ade8e-9c84-40cc-b925-4515684650d3',
               'phase': 'method03-public-fake-control', 'attempt_id': '47021572-6698-4979-b6f7-26349751942c'}
    driver.validate_binding(binding)
    assert [driver.validate_slot(arm, owner) for arm in ('A', 'B') for owner in range(3)] == list(range(6))
    for arm, slot in [('C', 0), ('B', True), ('A', 3), ('B', -1)]:
        try:
            driver.validate_slot(arm, slot)
        except ValueError:
            pass
        else:
            raise AssertionError('unselected slot accepted')
    checks.append({'check': 'finite-binding-and-slot-types', 'passed': True})

    projection = b'KPBXFX01' + bytes(1836)
    frame = packet.encode(projection, bytes(128), padding=bytes(2114))
    actual_os, actual_hashlib, actual_candidate, actual_save = driver.os, driver.hashlib, driver.candidate_metadata, driver.save

    class PublicFakeOS:
        O_PATH, O_CLOEXEC, O_NOFOLLOW = os.O_PATH, os.O_CLOEXEC, os.O_NOFOLLOW

        def __init__(self, arm):
            self.arm = arm; self.closed = []; self.reads = 0; self.writes = 0
            self.forwarded = bytearray(); self.next_pipe = 100; self.cursor = 0

        def open(self, path, flags):
            assert flags & self.O_PATH and flags & self.O_NOFOLLOW
            return 44

        def fstat(self, fd):
            return info if fd == 44 else SimpleNamespace(st_ino=5000 + fd)

        def pipe2(self, flags):
            assert flags == self.O_CLOEXEC
            pair = (self.next_pipe, self.next_pipe + 1); self.next_pipe += 2
            return pair

        def close(self, fd):
            assert fd not in self.closed
            self.closed.append(fd)

        def read(self, fd, width):
            self.reads += 1
            assert self.arm == 'A', 'B controller attempted a body read'
            assert fd == 100
            part = frame[self.cursor:self.cursor + min(width, 600)]
            self.cursor += len(part)
            return part

        def write(self, fd, value):
            self.writes += 1
            assert self.arm == 'A', 'B controller attempted a body write'
            assert fd == 103
            width = min(len(value), 700)
            self.forwarded.extend(value[:width])
            return width

    class HashTrap:
        calls = 0

        def sha256(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError('B controller attempted a body hash')

    class FakeThread:
        def __init__(self, name): self.name = name; self.joined = False
        def join(self): self.joined = True

    class FakeQueue:
        def join(self): pass

    info = SimpleNamespace(st_dev=9, st_ino=88, st_size=123, st_mtime_ns=11,
                           st_ctime_ns=12, st_nlink=1, st_uid=1000, st_gid=1000, st_mode=0o100600)
    fake_path = driver.PRIVATE / 'public-unit-only-not-a-real-file' / 'candidate.json'
    driver.candidate_metadata = lambda ref: (fake_path, info)
    artifacts = {}
    driver.save = lambda path, value: artifacts.__setitem__(str(path), value)

    def fake_session(arm, transport_code=0):
        session = object.__new__(driver.ExperimentalVectorSession)
        session.lock = threading.RLock(); session.closed = False; session.attempts = {}; session.active = set()
        session.closing = False; session.active_threads = {}; session.condition = threading.Condition(session.lock)
        session.processes = {}; session.threads = []; session.latest = {}; session.messages = FakeQueue()
        session.capture = driver.PRIVATE / 'diagnostics' / 'unit-capture'
        session.private = driver.PRIVATE / 'diagnostics' / 'unit-tor'
        session.public = Path('/PUBLIC-UNIT-ONLY-NOT-A-REAL-DIRECTORY')
        session.binding = binding; session.packet = packet
        session.a_exposures = {}
        session.endpoint = 'http://' + 'a' * 56 + '.onion/exit'; session.socks = 9050
        session.role = {'role': {'path': '/SELECTED-PUBLIC-OWNER-ROLE'}}
        session._owner_files = lambda *args: {'/CONFIG.json': 51}
        session._owner_public_preflight = lambda *args: None
        session._wrapper = lambda role, arguments, **kwargs: [role]
        events, namespaces, launches = [], [], []
        session._event = lambda kind, **fields: events.append({'kind': kind, **fields})

        def namespace(names, **kwargs):
            namespaces.append(kwargs.copy())
            return ['NAMESPACE'], (10, 11, 44) if kwargs.get('candidate_fd') is not None else (10, 11)

        session._namespace = namespace

        def launch(role, argv, fds, **kwargs):
            launches.append({'role': role, 'fds': fds, **kwargs})
            code = transport_code if role.startswith('transport/') else 0
            process = SimpleNamespace(returncode=code)
            session.processes[role] = process; session.threads.append(FakeThread(role))
            if role.startswith('owner/'):
                session.latest[(role, 'kpb-owner-exit-pipe-status/v1')] = {'status': 'FRAME_WRITTEN'}
            else:
                session.latest[(role, 'kpb-exit-transport-status/v1')] = {'transport_receipt': True}
            return process

        session._launch = launch
        session._wait_process = lambda role: session.processes[role].returncode
        return session, events, namespaces, launches

    try:
        for arm in ('B', 'A'):
            fake_os = PublicFakeOS(arm); driver.os = fake_os
            trap = HashTrap(); driver.hashlib = trap if arm == 'B' else actual_hashlib
            session, events, namespaces, launches = fake_session(arm)
            result = session.submit_one(arm, 0, {'PUBLIC_FAKE_ONLY': True}, {}, {}, {})
            assert result['owner_returncode'] == result['transport_returncode'] == 0 and result['receipt'] is True, (
                arm, result, [row for row in events if row['kind'] == 'submission-error'])
            owners = [row for row in launches if row['role'].startswith('owner/')]
            transports = [row for row in launches if row['role'].startswith('transport/')]
            assert len(owners) == len(transports) == 1
            assert 44 in owners[0]['fds'] and 44 not in transports[0]['fds']
            assert owners[0]['stdout'] == 101 and owners[0]['stderr'] == driver.subprocess.PIPE
            assert transports[0]['stdin'] == (100 if arm == 'B' else 102)
            assert all(thread.joined for thread in session.threads)
            assert set(fake_os.closed) == ({44, 100, 101} if arm == 'B' else {44, 100, 101, 102, 103})
            assert all('frame_hex' not in row and 'frame_sha256' not in row and 'projection_hex' not in row
                       and 'projection_sha256' not in row and 'exit_id' not in row for row in events)
            if arm == 'B':
                assert fake_os.reads == fake_os.writes == trap.calls == 0
                assert not any(row['kind'] == 'A-exposure' for row in events)
                checks.append({'check': 'B-controller-body-read-write-hash-traps-and-owner-only-private-fd', 'passed': True})
            else:
                assert bytes(fake_os.forwarded) == frame and fake_os.reads > 0 and fake_os.writes > 1
                exposure = artifacts[str(session.public / 'A-exposures/0.json')]
                assert exposure['frame_hex'] == frame.hex() and exposure['projection_hex'] == projection.hex()
                assert exposure['frame_sha256'] == hashlib.sha256(frame).hexdigest()
                checks.append({'check': 'A-deliberate-separate-exposure-and-exact-partial-write-forwarding', 'passed': True})
            try:
                session.submit_one(arm, 0, {}, {}, {}, {})
            except ValueError:
                pass
            else:
                raise AssertionError('same-slot retry accepted')
        driver.os = PublicFakeOS('B'); driver.hashlib = HashTrap()
        session, events, _, _ = fake_session('B', transport_code=1)
        result = session.submit_one('B', 1, {}, {}, {}, {})
        assert result['transport_returncode'] == 1 and result['receipt'] is True
        assert events[-1]['kind'] == 'submission-finished' and events[-1]['receipt_seen'] is True
        checks.append({'check': 'valid202-upper-retained-after-nonzero-exit-and-no-same-slot-retry', 'passed': True})
    finally:
        driver.os, driver.hashlib, driver.candidate_metadata, driver.save = actual_os, actual_hashlib, actual_candidate, actual_save

    wrapper_session = object.__new__(driver.ExperimentalVectorSession)
    wrapper_session.environment = {'isolated_transport_entry': selected_transport_entry}
    for role, owner, transport in [('owner/0', True, False), ('transport/3', False, True),
                                   ('receiver/0', False, False), ('service/0', False, False), ('client/0', False, False)]:
        arguments = ['--frame-fd', '0'] if transport else ['/PUBLIC-UNIT-ONLY']
        command = wrapper_session._wrapper(role, arguments, owner=owner, transport=transport)
        assert command[:4] == ['/usr/bin/python3.14', '-I', '-S', '-B']
        ast.parse(command[-1])
        assert ('file=sys.stderr' in command[-1]) is owner
        assert 'clock_snapshot(' + repr(role) + ')' in command[-1]
        if transport: assert 'os.dup(0)' in command[-1]
    checks.append({'check': 'actual-wrapper-generated-code-parses-fixed-role-clock-status-and-dup-entry', 'passed': True})

    # Public threads/opaque fake FD numbers only. Close must mark admission
    # closed atomically, refuse BOTH Popen sites, and retain shared descriptors
    # until an already-admitted submit has become quiescent.
    session = object.__new__(driver.ExperimentalVectorSession)
    session.lock = threading.RLock(); session.condition = threading.Condition(session.lock)
    session.closed = False; session.closing = False; session.cleanup_started = False; session.finish_ident = None
    session.active = {3}; session.active_threads = {3: -100}; session.callback_threads = set()
    session.processes = {}; session.check_processes = []; session.threads = []; session.owned = [17, 18]
    session.messages = queue.Queue(); session.attempts = {}; session._event = lambda *args, **kwargs: None
    session._stop = lambda role: None
    fake_closed = []; fake_fsync = []; popen_calls = []

    class FakeJournal:
        def flush(self): pass
        def fileno(self): return 99
        def close(self): pass

    session.journal = FakeJournal()

    def consume():
        while True:
            value = session.messages.get(); session.messages.task_done()
            if value is None: return

    session.consumer = threading.Thread(target=consume); session.consumer.start()
    previous_os, previous_subprocess = driver.os, driver.subprocess
    driver.os = SimpleNamespace(close=fake_closed.append, fsync=fake_fsync.append)
    driver.subprocess = SimpleNamespace(DEVNULL=-3, PIPE=-1,
        Popen=lambda *args, **kwargs: popen_calls.append((args, kwargs)))
    closer = threading.Thread(target=session.close_incomplete); closer.start()
    try:
        with session.condition:
            assert session.condition.wait_for(lambda: session.closing, timeout=2)
        assert not fake_closed and not session.closed
        for operation in (lambda: session._launch('transport/3', [], ()),
                          lambda: session._public_check('PUBLIC_FAKE_ONLY', [], ()),
                          lambda: session.submit_one('B', 0, {}, {}, {}, {})):
            try:
                operation()
            except ValueError:
                pass
            else:
                raise AssertionError('new launch/submit admitted after closing')
        assert not popen_calls and not fake_closed
        with session.condition:
            session.active.clear(); session.active_threads.clear(); session.condition.notify_all()
        closer.join(2)
        assert not closer.is_alive() and session.closed
        assert set(fake_closed) == {17, 18} and fake_fsync == [99]
    finally:
        with session.condition:
            session.active.clear(); session.active_threads.clear(); session.condition.notify_all()
        closer.join(2)
        driver.os, driver.subprocess = previous_os, previous_subprocess
    checks.append({'check': 'atomic-close-blocks-both-Popen-sites-and-keeps-shared-fds-until-active-quiescent', 'passed': True})

    session = object.__new__(driver.ExperimentalVectorSession)
    session.lock = threading.RLock(); session.condition = threading.Condition(session.lock)
    session.latest = {}; session.invalid = set(); session.consumer_failure = None
    session.processes = {'service/0': SimpleNamespace(poll=lambda: None)}
    session.messages = queue.Queue()
    def failed_journal(*args, **kwargs):
        raise OSError('PUBLIC_FAKE_JOURNAL_FAILURE')
    session._event = failed_journal
    consumer = threading.Thread(target=session._consume); consumer.start()
    waiter_done = threading.Event(); failures = []
    def wait_for_live_role():
        try:
            session._wait_value('service/0', 'kpb-probe-tor-progress/v1')
        except ValueError as error:
            failures.append(str(error)); waiter_done.set()
    waiter = threading.Thread(target=wait_for_live_role); waiter.start()
    session.messages.put(('status', 'service/0', {'value': {'schema': 'kpb-probe-tor-progress/v1', 'percent': 100}}))
    assert waiter_done.wait(2)
    waiter.join(); session.messages.join(); session.messages.put(None); session.messages.join(); consumer.join()
    assert failures == ['controller-journal-consumer-failure']
    assert session.consumer_failure == 'OSError' and 'controller-metadata-journal' in session.invalid
    checks.append({'check': 'terminal-journal-consumer-failure-notifies-live-role-waiter', 'passed': True})
    return {'schema': 'kpb-method03-transport-public-fake-controls/v1',
            'classification': 'SOURCE_UNIT_FAKE_CONTROLS_NOT_GENUINE_PROOF_OR_PIPELINE',
            'private_input': False, 'actual_subprocess': False, 'network': False,
            'checks': checks, 'all_passed': True}
