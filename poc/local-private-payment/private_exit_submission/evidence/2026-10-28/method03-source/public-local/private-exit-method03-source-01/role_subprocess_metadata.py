"""Finite METHOD03 app/Popen metadata; source-only until Root freezes the vector.

No input/output/config/environment buffer is inspected. The selected wrapper
chooses a public metadata emitter (owner stderr2, never owner frame stdout1).
This covers known Python subprocess boundaries and their declared descriptors,
not transient C descriptors, syscall capture or a complete global-host view.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid

import controller_metadata as metadata


SCHEMA = "kpb-method03-role-subprocess-event/v1"
_ROLE = re.compile(r"(?:controller|receiver/0|(?:owner|transport)/[0-5]|service/0|client/0)\Z")
_PID_NS = re.compile(r"pid:\[([1-9][0-9]*)\]\Z")
_LOCAL = re.compile(r"127\.0\.0\.1:([1-9][0-9]{0,4})\Z")
_ONION = re.compile(r"http://[a-z2-7]{56}\.onion/exit\Z")
_FD_PATH = re.compile(r"/proc/self/fd/([0-9]+)\Z")
_COMMON = {"schema", "kind", "actor_role", "clock_role", "subprocess_index",
           "actual_local_pid", "actual_local_ppid", "pid_namespace", "operation"}
_REFUSALS = {"unselected-argv", "unselected-popen-options", "unselected-descriptor-options",
             "pid-namespace-unavailable", "pid-child-namespace-differs", "pid-namespace-changed",
             "popen-raised", "metadata-emitter-failed", "metadata-record-invalid"}
_ACTIVE = None


def _need(value, category):
    if not value:
        raise metadata.MetadataError(category)


def _role(value):
    _need(type(value) is str and _ROLE.fullmatch(value) is not None, "fixed-subprocess-actor-role")
    return value


def _int(value, minimum=0):
    return type(value) is int and value >= minimum


def _local(value):
    match = _LOCAL.fullmatch(value)
    return match is not None and int(match.group(1)) <= 65535


def _fd_path(value):
    match = _FD_PATH.fullmatch(value)
    return match is not None and int(match.group(1)) >= 3


def _operation(role, argv):
    """Only the exact current 88cb/0582/cafb argument grammars are public."""
    if type(argv) not in (list, tuple) or not argv or any(type(item) is not str for item in argv):
        return None
    values = list(argv)
    if role.startswith("owner/") and values == ["/runtime/prover"]:
        return "auth-verifier"
    if role in ("service/0", "client/0"):
        if len(values) not in (19, 23):
            return None
        base = ["/tools/tor", "--defaults-torrc", "/app/empty-torrc", "-f", "/app/empty-torrc",
            "--RunAsDaemon", "0", "--DataDirectory", "/state/data", "--ControlPort", "0",
            "--SocksPort", values[12], "--Log", "notice stdout", "--ClientOnly", "1"]
        if role == "client/0":
            suffix = " IsolateSOCKSAuth"
            if not values[12].endswith(suffix) or not _local(values[12][:-len(suffix)]):
                return None
            return "tor" if values == base + ["--SocksTimeout", "900"] else None
        prefix = "80 "
        if len(values) != 23 or values[12] != "0" or not values[22].startswith(prefix) or not _local(values[22][len(prefix):]):
            return None
        return "tor" if values == base + ["--HiddenServiceDir", "/state/hidden", "--HiddenServiceVersion", "3",
                                          "--HiddenServicePort", values[22]] else None
    return None


def _curl_operation(role, argv):
    if not role.startswith("transport/") or type(argv) not in (list, tuple) or len(argv) != 33:
        return None
    if any(type(value) is not str for value in argv):
        return None
    values = list(argv)
    expected = ["/usr/bin/curl", "-q", "--silent", "--show-error", "--http1.0",
        "--socks5-hostname", values[6], "--noproxy", "", "--socks5-basic", "--config", values[11],
        "--proto", "=http", "--max-redirs", "0", "--retry", "0", "--user-agent", "kpb-exit-transport/1",
        "--header", "Accept: application/octet-stream", "--header", "Content-Type: application/octet-stream",
        "--header", "Expect:", "--data-binary", values[27], "--output", "/dev/null", "--write-out", "%{http_code}", values[32]]
    return "curl" if (values == expected and _local(values[6]) and _fd_path(values[11])
        and values[27].startswith("@") and _fd_path(values[27][1:]) and _ONION.fullmatch(values[32])) else None


def operation(role, argv):
    _role(role)
    return _curl_operation(role, argv) or _operation(role, argv)


def _stdio(value):
    if value is None:
        return {"kind": "INHERITED"}
    if type(value) is int:
        if value in (subprocess.PIPE, subprocess.STDOUT, subprocess.DEVNULL):
            return {"kind": {subprocess.PIPE: "PIPE", subprocess.STDOUT: "STDOUT", subprocess.DEVNULL: "DEVNULL"}[value]}
        if value >= 0:
            return {"kind": "FD", "fd": value}
    raise metadata.MetadataError("unselected-descriptor-options")


def _stdio_record(value):
    _need(type(value) is dict and "kind" in value, "exact-subprocess-stdio")
    if value["kind"] == "FD":
        _need(set(value) == {"kind", "fd"} and _int(value["fd"]), "exact-subprocess-stdio-fd")
    else:
        _need(set(value) == {"kind"} and value["kind"] in ("INHERITED", "PIPE", "STDOUT", "DEVNULL"),
              "exact-subprocess-stdio-kind")


def _pid_namespace():
    def current(name):
        path = Path("/proc/self/ns") / name
        link = os.readlink(path)
        match = _PID_NS.fullmatch(link)
        _need(match is not None and path.stat().st_ino == int(match.group(1)), "pid-namespace-unavailable")
        return {"link": link, "inode": int(match.group(1))}
    actual, children = current("pid"), current("pid_for_children")
    _need(actual == children, "pid-child-namespace-differs")
    return actual


def clock_snapshot(role):
    """Capture inside this actual actor; never rename a proxy's clock."""
    _role(role)
    if role not in ("service/0", "client/0"):
        return metadata.clock_snapshot(role)
    try:
        current = metadata._namespace("time")
        children = metadata._namespace("time_for_children")
        offsets = metadata._offsets(Path("/proc/self/timens_offsets").read_bytes())
        boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        _need(str(uuid.UUID(boot)) == boot, "kernel-boot-identity")
        before = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
        boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        after = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        _need(after >= before and current == metadata._namespace("time")
              and children == metadata._namespace("time_for_children")
              and offsets == metadata._offsets(Path("/proc/self/timens_offsets").read_bytes()),
              "kernel-clock-evidence-changed")
    except metadata.MetadataError:
        raise
    except (OSError, ValueError, AttributeError):
        raise metadata.MetadataError("kernel-clock-evidence-unavailable") from None
    return {"schema": "kpb-method03-clock-snapshot/v1", "role": role, "pid": os.getpid(), "boot_id": boot,
        "clock_id": "CLOCK_MONOTONIC", "time_namespace": current, "time_for_children_namespace": children,
        "timens_offsets": offsets, "sample": {"monotonic_before_ns": before, "realtime_ns": realtime,
        "boottime_ns": boottime, "monotonic_after_ns": after}}


def validate_event(value, role):
    _role(role)
    _need(type(value) is dict and value.get("schema") == SCHEMA, "fixed-subprocess-event")
    kind = value.get("kind")
    extras = {
        "role-subprocess-launch": {"pre_Popen_monotonic_ns", "post_Popen_monotonic_ns", "argv", "pass_fds", "stdio", "close_fds", "env_mode"},
        "role-subprocess-exit": {"observed_wait_monotonic_ns", "returncode", "observation"},
        "role-subprocess-refusal": {"pre_Popen_monotonic_ns", "post_Popen_monotonic_ns", "reason"},
    }
    _need(type(kind) is str and kind in extras and set(value) == _COMMON | extras[kind], "exact-subprocess-event-fields")
    _need(value["actor_role"] == value["clock_role"] == role and _int(value["subprocess_index"])
          and _int(value["actual_local_ppid"], 1), "subprocess-actor-and-index")
    _need(_int(value["actual_local_pid"], 1) or
          (kind == "role-subprocess-refusal" and value["actual_local_pid"] is None), "subprocess-actual-pid")
    namespace = value["pid_namespace"]
    _need(type(namespace) is dict or (namespace is None and
          (kind == "role-subprocess-refusal" or value["operation"] == "unrecognized")), "subprocess-pid-namespace")
    if namespace is not None:
        _need(type(namespace) is dict and set(namespace) == {"link", "inode"}
              and type(namespace["link"]) is str and _int(namespace["inode"], 1), "subprocess-pid-namespace-fields")
        match = _PID_NS.fullmatch(namespace["link"])
        _need(match is not None and int(match.group(1)) == namespace["inode"], "subprocess-pid-namespace-identity")
    if kind == "role-subprocess-launch":
        _need(operation(role, value["argv"]) == value["operation"] and value["operation"] in ("curl", "tor", "auth-verifier"),
              "known-subprocess-argv")
        _need(type(value["argv"]) is list and type(value["pass_fds"]) is list
              and all(_int(fd) for fd in value["pass_fds"]) and len(set(value["pass_fds"])) == len(value["pass_fds"]),
              "subprocess-argv-and-pass-fds")
        _need(type(value["stdio"]) is dict and set(value["stdio"]) == {"stdin", "stdout", "stderr"}, "subprocess-stdio-fields")
        for item in value["stdio"].values():
            _stdio_record(item)
        _need(value["close_fds"] is True and value["env_mode"] in ("explicit", "inherited"), "subprocess-option-policy")
    elif kind == "role-subprocess-exit":
        _need(value["operation"] in ("curl", "tor", "auth-verifier", "unrecognized")
              and type(value["returncode"]) is int
              and value["observation"] in ("wait", "communicate", "poll")
              and _int(value["observed_wait_monotonic_ns"]), "subprocess-exit-outcome")
    else:
        _need(value["operation"] == "unrecognized" and type(value["reason"]) is str
              and value["reason"] in _REFUSALS, "fixed-subprocess-refusal")
    if kind != "role-subprocess-exit":
        _need(_int(value["pre_Popen_monotonic_ns"]) and _int(value["post_Popen_monotonic_ns"])
              and value["pre_Popen_monotonic_ns"] <= value["post_Popen_monotonic_ns"], "subprocess-launch-clock-order")


class Installation:
    """One selected actor's hook; restore is for isolated public controls."""
    def __init__(self, role, emit):
        self.role = _role(role)
        _need(callable(emit), "public-metadata-emitter")
        self.emit = emit
        self.original = subprocess.Popen
        self.lock = threading.Lock()
        self.counter = 0
        self.emitter_failures = 0
        self.tor_processes = []
        installation = self

        class ObservedPopen(self.original):
            def __init__(process, args, *pos, **kwargs):
                with installation.lock:
                    index = installation.counter
                    installation.counter += 1
                operation_name = operation(role, args)
                namespace = None
                reason = None
                try:
                    namespace = _pid_namespace()
                except (OSError, metadata.MetadataError):
                    reason = "pid-namespace-unavailable"
                record = None
                try:
                    _need(operation_name is not None, "unselected-argv")
                    allowed = {"stdin", "stdout", "stderr", "close_fds", "pass_fds", "env"}
                    _need(not pos and not (set(kwargs) - allowed) and kwargs.get("close_fds", True) is True,
                          "unselected-popen-options")
                    fds = kwargs.get("pass_fds", ())
                    _need(type(fds) in (tuple, list) and all(_int(fd) for fd in fds)
                          and len(set(fds)) == len(fds), "unselected-descriptor-options")
                    record = {"argv": list(args), "pass_fds": list(fds),
                        "stdio": {name: _stdio(kwargs.get(name)) for name in ("stdin", "stdout", "stderr")},
                        "close_fds": True, "env_mode": "inherited" if kwargs.get("env") is None else "explicit"}
                except metadata.MetadataError as error:
                    reason = error.args[0] if error.args and error.args[0] in _REFUSALS else "unselected-popen-options"
                process._metadata_exit_reported = False
                process._metadata_index = index
                process._metadata_operation = operation_name or "unrecognized"
                process._metadata_namespace = namespace
                process._metadata_parent = os.getpid()
                pre = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                try:
                    # No option is rewritten. In particular env and all standard
                    # streams/buffers remain opaque and are forwarded by identity.
                    super().__init__(args, *pos, **kwargs)
                except BaseException:
                    post = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                    actual_pid = getattr(process, "pid", None)
                    installation._send(process._common("role-subprocess-refusal", actual_pid if _int(actual_pid, 1) else None, namespace)
                        | {"pre_Popen_monotonic_ns": pre, "post_Popen_monotonic_ns": post, "reason": "popen-raised"})
                    raise
                post = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                if operation_name == "tor":
                    with installation.lock:
                        installation.tor_processes.append(process)
                try:
                    if namespace != _pid_namespace():
                        reason = "pid-namespace-changed"
                except (OSError, metadata.MetadataError):
                    reason = "pid-namespace-unavailable"
                if reason is None and record is not None:
                    installation._send(process._common("role-subprocess-launch", process.pid, namespace)
                        | {"pre_Popen_monotonic_ns": pre, "post_Popen_monotonic_ns": post, **record})
                else:
                    process._metadata_operation = "unrecognized"
                    installation._send(process._common("role-subprocess-refusal", process.pid, namespace)
                        | {"pre_Popen_monotonic_ns": pre, "post_Popen_monotonic_ns": post,
                           "reason": reason or "unselected-popen-options"})

            def _common(process, kind, pid, namespace):
                return {"schema": SCHEMA, "kind": kind, "actor_role": role, "clock_role": role,
                    "subprocess_index": process._metadata_index, "actual_local_pid": pid,
                    "actual_local_ppid": process._metadata_parent, "pid_namespace": namespace,
                    "operation": process._metadata_operation if kind != "role-subprocess-refusal" else "unrecognized"}

            def _exited(process, observation):
                with installation.lock:
                    if process.returncode is None or process._metadata_exit_reported:
                        return
                    process._metadata_exit_reported = True
                    observed = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
                installation._send(process._common("role-subprocess-exit", process.pid, process._metadata_namespace)
                    | {"observed_wait_monotonic_ns": observed, "returncode": process.returncode, "observation": observation})

            def wait(process, *args, **kwargs):
                result = super().wait(*args, **kwargs)
                process._exited("wait")
                return result

            def communicate(process, *args, **kwargs):
                # Do not inspect communicate(input), its arguments, or returned
                # buffers. Only the unchanged original method sees those bytes.
                result = super().communicate(*args, **kwargs)
                process._exited("communicate")
                return result

            def poll(process, *args, **kwargs):
                result = super().poll(*args, **kwargs)
                process._exited("poll")
                return result

        self.observed = ObservedPopen
        subprocess.Popen = ObservedPopen

    def _send(self, event):
        try:
            validate_event(event, self.role)
        except BaseException:
            with self.lock:
                self.emitter_failures += 1
            self._fallback(event, "metadata-record-invalid")
            return
        try:
            self.emit(event)
        except BaseException:
            with self.lock:
                self.emitter_failures += 1
            self._fallback(event, "metadata-emitter-failed")

    def _fallback(self, event, reason):
        # No rejected value is copied. Try the same fixed public channel if a
        # selected emitter fails; owner metadata can never reach frame fd1.
        now = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        pid = event.get("actual_local_pid")
        index = event.get("subprocess_index")
        value = {"schema": SCHEMA, "kind": "role-subprocess-refusal", "actor_role": self.role,
            "clock_role": self.role, "subprocess_index": index if _int(index) else 0,
            "actual_local_pid": pid if _int(pid, 1) else None, "actual_local_ppid": os.getpid(),
            "pid_namespace": None, "operation": "unrecognized", "pre_Popen_monotonic_ns": now,
            "post_Popen_monotonic_ns": now, "reason": reason}
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        try:
            remaining = memoryview(raw)
            fd = 2 if self.role.startswith("owner/") else 1
            while remaining:
                count = os.write(fd, remaining)
                if count <= 0:
                    break
                remaining = remaining[count:]
        except OSError:
            # A closed channel cannot be rescued by another descriptor. The
            # missing mandatory records remain incomplete evidence.
            pass

    def restore(self):
        global _ACTIVE
        _need(subprocess.Popen is self.observed, "selected-hook-lifetime")
        subprocess.Popen = self.original
        _ACTIVE = None

    def stop_tor(self):
        """Request only this actor's tracked known Tor children to terminate.

        The original0582 role retains its notices/poll/wait lifecycle. No
        namespace signal, buffer read, retry or fallback is introduced here.
        Unknown child metadata remains unqualified and belongs to the outer
        driver's explicit INCOMPLETE cleanup path.
        """
        _need(self.role in ("service/0", "client/0"), "tor-stop-actor-role")
        with self.lock:
            processes = tuple(self.tor_processes)
        requested = 0
        for process in processes:
            if process.poll() is None:
                self.original.terminate(process)
                requested += 1
        return requested


def install(role, emit_metadata):
    global _ACTIVE
    _need(_ACTIVE is None, "one-subprocess-hook-per-actor")
    _ACTIVE = Installation(role, emit_metadata)
    return _ACTIVE


def _tor_status(value, role):
    _need(type(value) is dict and value.get("role") == role.split("/", 1)[0], "fixed-tor-role-status")
    schema = value.get("schema")
    if schema == "kpb-probe-tor-progress/v1":
        valid = set(value) == {"schema", "role", "percent", "monotonic_ns"} and _int(value["percent"]) and value["percent"] <= 100
    elif schema == "kpb-probe-public-onion/v1":
        valid = (role == "service/0" and set(value) == {"schema", "role", "hostname", "monotonic_ns"}
            and type(value["hostname"]) is str and re.fullmatch(r"[a-z2-7]{56}\.onion", value["hostname"]) is not None)
    elif schema == "kpb-probe-tor-exit/v1":
        valid = set(value) == {"schema", "role", "returncode", "monotonic_ns"} and type(value["returncode"]) is int
    else:
        valid = False
    _need(valid and _int(value["monotonic_ns"]), "fixed-tor-status-fields")


def read_role_event(stream, *, reader_id, role):
    """Exact clock/status/process union; timestamp first after public read."""
    _role(role)
    _need(type(reader_id) is str and reader_id == "controller/" + role, "fixed-reader-key")
    raw = stream.readline()
    observed_monotonic = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    observed_realtime = time.clock_gettime_ns(time.CLOCK_REALTIME)
    observed_boottime = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    if raw == b"":
        return None
    _need(type(raw) is bytes and raw.endswith(b"\n"), "fixed-public-binary-line")
    try:
        value = json.loads(raw, object_pairs_hook=metadata._unique_object)
    except metadata.MetadataError:
        raise
    except (ValueError, UnicodeError):
        raise metadata.MetadataError("fixed-public-json") from None
    schema = value.get("schema") if type(value) is dict else None
    if schema == "kpb-method03-clock-snapshot/v1":
        metadata._clock_record(value, role)
    elif schema == SCHEMA:
        validate_event(value, role)
    elif role in ("service/0", "client/0"):
        _tor_status(value, role)
    else:
        metadata._fixed_status(value, role)
    return {"schema": "kpb-method03-status-observation/v1", "reader_id": reader_id, "role": role,
        "reader_pid": os.getpid(), "reader_observed_monotonic_ns": observed_monotonic,
        "reader_observed_realtime_ns": observed_realtime, "reader_observed_boottime_ns": observed_boottime,
        "value": value}
