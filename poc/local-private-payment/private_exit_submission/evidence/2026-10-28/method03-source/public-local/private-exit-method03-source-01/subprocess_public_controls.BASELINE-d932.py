"""Fake-Popen SOURCE controls only; never launches a process or network."""

import io
import json
import subprocess
import time

import controller_metadata as metadata
import role_subprocess_metadata as observed


def curl_arguments():
    return ["/usr/bin/curl", "-q", "--silent", "--show-error", "--http1.0", "--socks5-hostname",
        "127.0.0.1:19050", "--noproxy", "", "--socks5-basic", "--config", "/proc/self/fd/4",
        "--proto", "=http", "--max-redirs", "0", "--retry", "0", "--user-agent", "kpb-exit-transport/1",
        "--header", "Accept: application/octet-stream", "--header", "Content-Type: application/octet-stream",
        "--header", "Expect:", "--data-binary", "@/proc/self/fd/3", "--output", "/dev/null", "--write-out",
        "%{http_code}", "http://" + "a" * 56 + ".onion/exit"]


def tor_arguments(kind):
    base = ["/tools/tor", "--defaults-torrc", "/app/empty-torrc", "-f", "/app/empty-torrc",
        "--RunAsDaemon", "0", "--DataDirectory", "/state/data", "--ControlPort", "0", "--SocksPort",
        "127.0.0.1:19050 IsolateSOCKSAuth" if kind == "client" else "0", "--Log", "notice stdout", "--ClientOnly", "1"]
    return base + (["--SocksTimeout", "900"] if kind == "client" else ["--HiddenServiceDir", "/state/hidden",
        "--HiddenServiceVersion", "3", "--HiddenServicePort", "80 127.0.0.1:18080"])


class Opaque:
    def __repr__(self):
        raise AssertionError("opaque value inspected")
    __str__ = __repr__
    def __iter__(self):
        raise AssertionError("opaque value iterated")
    def fileno(self):
        raise AssertionError("opaque stream inspected")


class FakePopen:
    calls = []
    next_pid = 101
    exit_code = 0
    def __init__(self, args, *pos, **kwargs):
        self.pid = FakePopen.next_pid
        FakePopen.next_pid += 1
        self.returncode = None
        self.original_args = args
        self.original_pos = pos
        self.original_kwargs = kwargs
        self.original_communicate = None
        self.output_buffers = (Opaque(), Opaque())
        FakePopen.calls.append(self)
    def wait(self, *args, **kwargs):
        self.returncode = FakePopen.exit_code
        return self.returncode
    def communicate(self, *args, **kwargs):
        self.original_communicate = (args, kwargs)
        self.wait()
        return self.output_buffers
    def poll(self, *args, **kwargs):
        return self.returncode


def run():
    checks = []
    real_popen = subprocess.Popen
    real_namespace = observed._pid_namespace
    observed._pid_namespace = lambda: {"link": "pid:[500]", "inode": 500}
    subprocess.Popen = FakePopen
    try:
        known = [("transport/0", curl_arguments(), "curl"), ("owner/0", ["/runtime/prover"], "auth-verifier"),
                 ("service/0", tor_arguments("service"), "tor"), ("client/0", tor_arguments("client"), "tor")]
        for role, argv, operation in known:
            events = []
            hook = observed.install(role, events.append)
            environment = Opaque()
            input_buffer = Opaque()
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, close_fds=True, env=environment, pass_fds=(3, 4))
                result = process.communicate(input=input_buffer)
                assert process.original_args is argv and process.original_kwargs["env"] is environment
                assert process.original_communicate[1]["input"] is input_buffer
                assert result is process.output_buffers
                process.wait(); process.poll()
                assert len(events) == 2 and events[0]["kind"] == "role-subprocess-launch"
                assert events[1]["kind"] == "role-subprocess-exit" and events[1]["observation"] == "wait"
                assert events[0]["operation"] == events[1]["operation"] == operation
                assert events[0]["actual_local_pid"] == process.pid
                assert events[0]["pre_Popen_monotonic_ns"] <= events[0]["post_Popen_monotonic_ns"] <= events[1]["observed_wait_monotonic_ns"]
                for event in events:
                    observed.validate_event(event, role)
                assert not hook.emitter_failures
            finally:
                hook.restore()
        checks.append({"check": "four-known-source-argv-unchanged-opaque-buffers-first-exit-once", "passed": True})

        cases = [(curl_arguments() + ["--proxy-user", "PUBLIC_TRIPWIRE"], {}),
                 (["/runtime/prover", Opaque()], {}),
                 (["/runtime/prover"], {"stdin": Opaque()}),
                 (["/runtime/prover"], {"input": Opaque()}),
                 (["/runtime/prover"], {"close_fds": False})]
        for argv, options in cases:
            role = "transport/0" if argv[0] == "/usr/bin/curl" else "owner/0"
            events = []
            hook = observed.install(role, events.append)
            try:
                process = subprocess.Popen(argv, **options)
                process.wait()
                assert process.original_args is argv
                assert len(events) == 2 and events[0]["kind"] == "role-subprocess-refusal"
                assert events[0]["actual_local_pid"] == process.pid
                assert events[1]["kind"] == "role-subprocess-exit" and events[1]["operation"] == "unrecognized"
                assert "PUBLIC_TRIPWIRE" not in json.dumps(events)
                for event in events:
                    observed.validate_event(event, role)
            finally:
                hook.restore()
        checks.append({"check": "unknown-or-buffer-options-refuse-metadata-without-dropping-popen-or-pid", "passed": True,
                       "refusals": len(cases)})

        events = []
        hook = observed.install("transport/2", events.append)
        try:
            FakePopen.exit_code = 7
            process = subprocess.Popen(curl_arguments())
            assert process.wait() == 7
            assert events[1]["returncode"] == 7
            saved_launch = events[0]
        finally:
            FakePopen.exit_code = 0
            hook.restore()
        invalid = [dict(saved_launch, frame_sha256="PUBLIC_TRIPWIRE"),
                   dict(saved_launch, actor_role="transport/1"),
                   dict(saved_launch, clock_role="controller"),
                   dict(saved_launch, actual_local_pid=True),
                   dict(saved_launch, actual_local_ppid=False),
                   dict(saved_launch, pid_namespace={"link": "pid:[501]", "inode": 500}),
                   dict(saved_launch, pass_fds=[3, True])]
        for event in invalid:
            try:
                observed.validate_event(event, "transport/2")
            except metadata.MetadataError:
                pass
            else:
                raise AssertionError("malformed process metadata admitted")
        checks.append({"check": "nonzero-exit-retained-and-strict-nested-event-refusals", "passed": True,
                       "refusals": len(invalid)})

        real_decoder = observed.json.loads
        real_clock = observed.time.clock_gettime_ns
        order = []
        class PublicStream:
            def readline(self):
                order.append("read")
                return (json.dumps(saved_launch) + "\n").encode()
        def clock(clock_id):
            order.append(clock_id)
            return real_clock(clock_id)
        def decode(*args, **kwargs):
            order.append("parse")
            return real_decoder(*args, **kwargs)
        observed.time.clock_gettime_ns = clock
        observed.json.loads = decode
        try:
            envelope = observed.read_role_event(PublicStream(), reader_id="controller/transport/2", role="transport/2")
        finally:
            observed.time.clock_gettime_ns = real_clock
            observed.json.loads = real_decoder
        assert order == ["read", time.CLOCK_MONOTONIC, time.CLOCK_REALTIME, time.CLOCK_BOOTTIME, "parse"]
        assert envelope["value"] == saved_launch
        checks.append({"check": "first-three-clocks-after-read-before-parse-and-queue", "passed": True})

        real_path, real_time_namespace = observed.Path, metadata._namespace
        class PublicKernelFixture:
            def __init__(self, path): self.path = path
            def read_bytes(self):
                assert self.path == "/proc/self/timens_offsets"
                return b"monotonic 0 0\nboottime 0 0\n"
            def read_text(self, **kwargs):
                assert self.path == "/proc/sys/kernel/random/boot_id"
                return "11111111-1111-4111-8111-111111111111\n"
        observed.Path = PublicKernelFixture
        metadata._namespace = lambda name: {"link": "time:[600]", "inode": 600}
        try:
            for role in ("service/0", "client/0"):
                snapshot = observed.clock_snapshot(role)
                assert snapshot["role"] == role and snapshot["time_namespace"] == snapshot["time_for_children_namespace"]
                line = (json.dumps(snapshot) + "\n").encode()
                result = observed.read_role_event(io.BytesIO(line), reader_id="controller/" + role, role=role)
                assert result["value"] == snapshot
            statuses = [("client/0", {"schema": "kpb-probe-tor-progress/v1", "role": "client", "percent": 100, "monotonic_ns": 100}),
                        ("service/0", {"schema": "kpb-probe-public-onion/v1", "role": "service", "hostname": "a" * 56 + ".onion", "monotonic_ns": 101})]
            for role, value in statuses:
                result = observed.read_role_event(io.BytesIO((json.dumps(value) + "\n").encode()), reader_id="controller/" + role, role=role)
                assert result["value"] == value
        finally:
            observed.Path, metadata._namespace = real_path, real_time_namespace
        checks.append({"check": "synthetic-kernel-service-client-extension-and-finite-tor-status-union", "passed": True})

        real_write = observed.os.write
        fallback = []
        observed.os.write = lambda fd, raw: (fallback.append((fd, bytes(raw))) or len(raw))
        def broken_emitter(_event): raise RuntimeError("public fake emitter failure")
        hook = observed.install("owner/1", broken_emitter)
        try:
            process = subprocess.Popen(["/runtime/prover"])
            process.wait()
            assert hook.emitter_failures == 2 and len(fallback) == 2
            assert all(fd == 2 for fd, _raw in fallback)
            assert all(json.loads(raw)["reason"] == "metadata-emitter-failed" for _fd, raw in fallback)
        finally:
            hook.restore()
            observed.os.write = real_write
        checks.append({"check": "emitter-failure-fixed-refusal-owner-stderr-only-original-process-preserved", "passed": True})
    finally:
        if observed._ACTIVE is not None:
            observed._ACTIVE.restore()
        subprocess.Popen = real_popen
        observed._pid_namespace = real_namespace
    return {"schema": "kpb-method03-role-subprocess-public-controls/v1",
            "classification": "SOURCE_PUBLIC_FAKE_POPEN_ONLY_NOT_PIPELINE_OR_KERNEL_CAPTURE",
            "actual_subprocess_launched": False, "network": False, "private_input": False,
            "checks": checks, "all_passed": True}
