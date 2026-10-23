#!/usr/bin/env python3
"""Supervise a public-only fresh acquisition. Root releases actual RPC runs."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NODE = Path("/home/luke/.nvm/versions/node/v24.15.0/bin/node.forge-original")
NODE_SHA = "d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c"
SDK = Path("/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def save(path, value):
    with path.open("x") as file:
        json.dump(value, file, sort_keys=True, indent=2); file.write("\n")


def state(unit):
    try:
        result = subprocess.run(["systemctl", "--user", "show", unit,
            "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec"], capture_output=True, text=True)
    except OSError:
        return {"systemctl_returncode": None, "manager_observation": "UNAVAILABLE"}
    return {**dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line),
            "systemctl_returncode": result.returncode, "systemctl_stderr": result.stderr}


def number(path):
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return None


def main():
    parser = argparse.ArgumentParser(description="Read-only public acquisition; never a wallet or submission command")
    parser.add_argument("descriptor"); parser.add_argument("public_manifest"); parser.add_argument("new_output")
    parser.add_argument("--rpc", action="append", required=True)
    parser.add_argument("--release-marker")
    args = parser.parse_args()
    output = Path(args.new_output).resolve()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    client_output = output / "client-output"; client_output.mkdir(mode=0o700)
    software = output / "software"; software.mkdir(mode=0o700)
    pins = []
    def copy(source, name):
        raw = Path(source).read_bytes(); target = software / name
        target.write_bytes(raw); target.chmod(0o400)
        pins.append({"source_path": str(source), "snapshot": str(target), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        return target
    descriptor = copy(args.descriptor, "descriptor.json")
    manifest = copy(args.public_manifest, "public-manifest.json")
    for name in ("fetch.mjs", "parameter_manifest.mjs", "sealed_runtime.py", "run_fetch.py"):
        copy(HERE / name, name)
    for name in ("kpx3-policy-template.json", "kpx3-policy-template.bin"):
        copy(ROOT / "poc/private-exit-recovery" / name, name)
    if hashlib.sha256(NODE.read_bytes()).hexdigest() != NODE_SHA:
        raise ValueError("selected-node-ELF-identity")
    release = None
    if args.release_marker:
        raw = Path(args.release_marker).read_bytes()
        release = {"path": str(Path(args.release_marker)), "sha256": hashlib.sha256(raw).hexdigest(),
                   "json": json.loads(raw), "mounted_in_sandbox": False}
    unit = "kpi-kpx3-network-" + uuid.uuid4().hex[:12] + ".service"
    command = ["/usr/bin/bwrap", "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts",
        "--die-with-parent", "--new-session", "--clearenv", "--ro-bind", "/usr", "/usr",
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for name in ("/etc/alternatives", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/ssl/certs"):
        command.extend(["--ro-bind", name, name])
    command.extend(["--ro-bind", str(NODE), "/node", "--ro-bind", str(SDK), str(SDK)])
    for name in ("fetch.mjs", "parameter_manifest.mjs", "sealed_runtime.py", "run_fetch.py"):
        command.extend(["--ro-bind", str(software / name), "/work/poc/private-network-recovery/" + name])
    for name in ("kpx3-policy-template.json", "kpx3-policy-template.bin"):
        command.extend(["--ro-bind", str(software / name), "/work/poc/private-exit-recovery/" + name])
    command.extend(["--ro-bind", str(descriptor), "/descriptor.json", "--ro-bind", str(manifest), "/public-manifest.json",
        "--bind", str(client_output), "/out", "--chdir", "/work/poc/private-network-recovery", "--setenv", "PATH", "/usr/bin:/bin",
        "/usr/bin/time", "-v", "-o", "/out/resources.log", "/usr/bin/python3", "-B",
        "/work/poc/private-network-recovery/run_fetch.py", "/descriptor.json", "/public-manifest.json", "/out/network-data"])
    for endpoint in args.rpc:
        command.extend(["--rpc", endpoint])
    plan = {"schema": "kpx3-public-network-runtime/v1", "unit": unit, "prepared_at": now(),
            "command": command, "input_snapshots": pins, "node_elf_sha256": NODE_SHA,
            "cpu_quota_percent": 200, "memory_max_bytes": 4294967296, "memory_swap_max_bytes": 0,
            "runtime_max_seconds": 3600, "release": release, "network_read_only": True,
            "writable_client_output": str(client_output), "controller_directory_not_mounted": str(output),
            "not_mounted": ["backup", "seed", "PK blob", "prover", "native validator", "operator archive/tree/profile", "old fetch bundle", "test fixtures", "release marker"]}
    save(output / "RUNTIME-PLAN.json", plan)
    runtime = output / "runtime.sh"; runtime.write_text("#!/bin/bash\nset -euo pipefail\nexec " + shlex.join(command) + "\n")
    started = time.monotonic()
    last_group, peaks, swaps = None, [], []
    try:
        launch = subprocess.run(["systemd-run", "--user", "--collect", "--unit=" + unit,
            "--property=StandardOutput=journal", "--property=StandardError=journal", "--property=CPUQuota=200%",
            "--property=MemoryMax=4G", "--property=MemorySwapMax=0", "--property=RuntimeMaxSec=3600",
            "--property=KillMode=control-group", "/bin/bash", str(runtime)], capture_output=True, text=True)
        (output / "launch.log").write_text(launch.stdout + launch.stderr)
        if launch.returncode:
            raise ValueError("public-read-only-unit-launch-failed")
        with (output / "telemetry.jsonl").open("x") as file:
            while True:
                status = state(unit)
                if status.get("ControlGroup"):
                    last_group = Path("/sys/fs/cgroup") / status["ControlGroup"].lstrip("/")
                peak = number(last_group / "memory.peak") if last_group else None
                swap = number(last_group / "memory.swap.current") if last_group else None
                if peak is not None: peaks.append(peak)
                if swap is not None: swaps.append(swap)
                file.write(json.dumps({"at": now(), "elapsed_seconds": time.monotonic() - started, "state": status,
                                       "memory_peak": peak, "swap_current": swap}, sort_keys=True) + "\n"); file.flush()
                if status.get("ActiveState") in ("inactive", "failed") or status.get("LoadState") == "not-found": break
                time.sleep(0.5)
    finally:
        try:
            stop = subprocess.run(["systemctl", "--user", "stop", unit], capture_output=True, text=True)
            stop_result = {"returncode": stop.returncode, "stderr": stop.stderr}
        except OSError:
            stop_result = {"returncode": None, "observation": "UNAVAILABLE"}
        try:
            journal = subprocess.run(["journalctl", "--user", "-u", unit, "--no-pager", "-o", "cat"], capture_output=True, text=True)
            (output / "unit-output.log").write_text(journal.stdout + journal.stderr)
        except OSError:
            (output / "unit-output.log").write_text("JOURNAL_UNAVAILABLE\n")
        status = state(unit)
        empty, procs_observed = None, False
        if last_group is not None:
            try:
                empty = not (last_group / "cgroup.procs").read_text().strip(); procs_observed = True
            except OSError:
                pass
        stopped = True if status.get("LoadState") == "not-found" else (
            status.get("MainPID") == "0" and status.get("ActiveState") in ("inactive", "failed")
            if status.get("systemctl_returncode") == 0 and "MainPID" in status else None)
        save(output / "cleanup.json", {"at": now(), "state": status, "stop_command": stop_result,
            "owned_cgroup_path": str(last_group) if last_group is not None else None,
            "cgroup_procs_observed": procs_observed, "owned_cgroup_processes_empty": empty,
            "MainPID_zero_or_explicitly_unloaded": stopped,
            "missing_manager_or_process_observation_is_not_zero": True})
    path = client_output / "network-data/fetch.json"
    timing = (client_output / "resources.log").read_text() if (client_output / "resources.log").is_file() else ""
    status = re.search(r"Exit status:\s*(\d+)", timing)
    complete = path.is_file() and status is not None and status.group(1) == "0"
    data = json.loads(path.read_bytes()) if complete else None
    result = {"status": "FETCHED_PENDING_REPLAY" if complete else "INCOMPLETE", "completed_at": now(),
              "wall_seconds": time.monotonic() - started, "fetch_json_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if complete else None,
              "transactions_fetched": len(data["transactions"]) if complete else None,
              "sampled_cgroup_peak_bytes": max(peaks) if peaks else None, "sampled_swap_peak_bytes": max(swaps) if swaps else None,
              "no_balance_or_ownership_claim": True}
    save(output / "RESULT.json", result); print(json.dumps(result, sort_keys=True))
    if not complete: raise SystemExit(2)


if __name__ == "__main__":
    main()
