#!/usr/bin/env python3
"""Launch one root-selected ordinary ELF inside the isolated setup namespace.

The root-frozen public plan is the executable authority. This ordinary-file
execution explicitly trusts the host and release to keep the selected inode
and pathname immutable from SHA256 validation through execution. Python,
bubblewrap, GNU time and the system loader/shared libraries are trusted runtime
inputs. No sealed-FD, memfd or special-loader execution is used.

The parent owns the private FIFO/raw log and resource limits. Bootstrap stage
names the private session root; only its precreated empty out directory is
mounted. It must send only the bootstrap line, then wait for setup's ready event
before queuing resident commands: Python's stdin buffer may prefetch beyond
that first line.
"""

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from private_paths import private_directory, private_file


CLEAN_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "TZ": "UTC",
    "RAYON_NUM_THREADS": "14",
}
MAX_BOOTSTRAP_BYTES = 1024 * 1024
FAILED = b'{"code":"runtime_bootstrap_failed","event":"error"}\n'
PROBE_RESULT = b'{"code":"parameters_unselected","event":"error"}\n'


class BootstrapFailed(Exception):
    pass


def require(condition):
    if not condition:
        raise BootstrapFailed


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def exact(value, fields):
    require(type(value) is dict and set(value) == fields)


def load_plan(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_BOOTSTRAP_BYTES + 1)
    require(len(raw) <= MAX_BOOTSTRAP_BYTES)
    plan = json.loads(raw, object_pairs_hook=unique)
    exact(plan, {"binary", "cpu_workers", "mode"})
    exact(plan["binary"], {"path", "sha256"})
    require(type(plan["cpu_workers"]) is int and plan["cpu_workers"] == 14)
    require(plan["mode"] in ("session", "probe"))
    require(type(plan["binary"]["path"]) is str and plan["binary"]["path"])
    digest = plan["binary"]["sha256"]
    require(type(digest) is str and len(digest) == 64)
    require(all(character in "0123456789abcdef" for character in digest))
    return plan


def checked_binary(selection):
    path = Path(selection["path"]).absolute()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o500)
        digest = hashlib.sha256()
        first = source.read(1024 * 1024)
        require(first.startswith(b"\x7fELF"))
        digest.update(first)
        while block := source.read(1024 * 1024):
            digest.update(block)
        require(digest.hexdigest() == selection["sha256"])
        after = os.fstat(source.fileno())
        named = path.stat(follow_symlinks=False)
        for item in (after, named):
            require(stat.S_ISREG(item.st_mode) and stat.S_IMODE(item.st_mode) == 0o500)
            require(
                (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
                == (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            )
    # These checks detect accidental changes, but the ordinary read-only bind
    # still depends on the explicit trusted-host/release immutability premise.
    return path


def bootstrap(mode):
    # Caller contract: nothing after this line is queued until setup emits ready.
    # Do not read the referenced shape contents here; only the child may do so.
    raw = sys.stdin.buffer.readline(MAX_BOOTSTRAP_BYTES + 1)
    require(raw.endswith(b"\n") and len(raw) <= MAX_BOOTSTRAP_BYTES)
    value = json.loads(raw, object_pairs_hook=unique)
    exact(value, {"schema", "shape", "stage"})
    require(value["schema"] == "kpx3-private-setup-runtime/v1")
    require(type(value["stage"]) is str and value["stage"])
    session = private_directory(value["stage"])
    # FIFO, raw logs and execution metadata remain outside the bound subtree.
    stage = session / "out"
    stage = private_directory(stage)
    require(next(stage.iterdir(), None) is None)
    if mode == "session":
        require(type(value["shape"]) is str and value["shape"])
        shape = private_file(value["shape"])
    else:
        require(value["shape"] in (None, ""))
        shape = None
    return shape, stage


def command(binary, shape, stage, mode):
    arguments = [
        "/usr/bin/bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--ro-bind", "/usr", "/usr",
    ]
    for directory in ("/lib", "/lib64"):
        if Path(directory).exists():
            arguments.extend(("--ro-bind", directory, directory))
    arguments.extend(("--dir", "/etc"))
    if Path("/etc/alternatives").exists():
        arguments.extend(("--ro-bind", "/etc/alternatives", "/etc/alternatives"))
    arguments.extend(("--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"))
    arguments.extend(("--ro-bind", str(binary), "/app", "--bind", str(stage), "/out"))
    if mode == "session":
        arguments.extend(("--ro-bind", str(shape), "/private-shape.json"))
    for name, value in CLEAN_ENVIRONMENT.items():
        arguments.extend(("--setenv", name, value))
    arguments.extend((
        "--chdir", "/out", "--", "/usr/bin/time", "-v", "-o", "/out/resources-app.log",
        "--", "/app",
    ))
    if mode == "session":
        arguments.extend(("session", "/private-shape.json", "/out/setup-01", "/out/public-parameters.pk"))
    else:
        arguments.extend(("prove", "/missing", "0", "/out/no-proof"))
    return arguments


def run():
    require(len(sys.argv) == 2)
    plan = load_plan(sys.argv[1])
    binary = checked_binary(plan["binary"])
    shape, stage = bootstrap(plan["mode"])
    # Parent captures stderr in its PRIVATE raw log outside the bound subtree;
    # no raw diagnostic is copied into public events or reports. This retains
    # actionable launch failures without exporting host mount paths.
    result = subprocess.run(
        command(binary, shape, stage, plan["mode"]),
        stdin=None,
        stdout=subprocess.PIPE if plan["mode"] == "probe" else None,
        stderr=subprocess.PIPE if plan["mode"] == "probe" else None,
        env=dict(CLEAN_ENVIRONMENT),
        check=False,
    )
    if plan["mode"] == "probe":
        require(result.returncode != 0 and result.stdout == PROBE_RESULT)
        require(not os.path.lexists(stage / "no-proof"))
        os.write(1, PROBE_RESULT)
    else:
        require(result.returncode == 0)


def main():
    try:
        run()
        return 0
    except BaseException:
        try:
            os.write(1, FAILED)
        except BaseException:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
