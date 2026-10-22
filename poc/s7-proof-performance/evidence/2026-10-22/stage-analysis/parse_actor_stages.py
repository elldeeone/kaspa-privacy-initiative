#!/usr/bin/env python3
"""Describe actor task overlap and owned-worker memory; never release a gate."""
import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LOG = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s+(?:TRACE|DEBUG|INFO|WARN|ERROR)\s+([^:]+(?:::[^:]+)*):\s+(.*)$")
WORKER = "/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/r0vm-cuda"


def epoch(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def union(intervals):
    result = []
    for start, end in sorted(intervals):
        if end < start:
            raise ValueError("Negative interval")
        if result and start <= result[-1][1]:
            result[-1][1] = max(end, result[-1][1])
        else:
            result.append([start, end])
    return result


def duration(intervals):
    return sum(end - start for start, end in intervals)


def overlap(left, right):
    result, i, j = [], 0, 0
    while i < len(left) and j < len(right):
        lo, hi = max(left[i][0], right[j][0]), min(left[i][1], right[j][1])
        if hi > lo:
            result.append([lo, hi])
        if left[i][1] < right[j][1]:
            i += 1
        else:
            j += 1
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("monitor", type=pathlib.Path)
    ap.add_argument("identities", type=pathlib.Path)
    ap.add_argument("output", type=pathlib.Path)
    args = ap.parse_args()
    if args.output.resolve().parent != pathlib.Path(__file__).resolve().parent:
        ap.error("Output must be a new file in stage-analysis")
    captured = {}

    def read(path):
        raw = path.read_bytes()
        captured[str(path.resolve())] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        return raw

    identities = json.loads(read(args.identities))
    roles = {entry["pid"]: entry for entry in identities["workers"]}
    if len(roles) != 3 or sorted(entry["role"] for entry in roles.values()) != ["primary_segment_keccak", "rpc_parent_execute_only", "secondary_recursion"]:
        raise ValueError("Exact three-role identity capture required")
    counts = collections.Counter()
    events, starts, ends, sdk_open, sdk_intervals = [], collections.defaultdict(dict), collections.defaultdict(dict), {}, []
    errors, worker_stats = [], {}

    for name in ["stdout.log", "stderr.log"]:
        path = args.monitor / name
        if not path.exists():
            continue
        for number, raw_line in enumerate(read(path).decode(errors="replace").splitlines(), 1):
            line = ANSI.sub("", raw_line)
            match = LOG.match(line)
            if not match:
                continue
            stamp, target, message = match.groups()
            when, kind, key = epoch(stamp), None, None
            if target == "risc0_r0vm::actors::worker":
                for prefix, label in [("Preflight", "preflight_start"), ("ProveSegmentCore", "primary_start"), ("Lift", "secondary_lift_start")]:
                    found = re.fullmatch(prefix + r": (\d+)", message)
                    if found:
                        kind, key = label, int(found.group(1))
                found = re.fullmatch(r"Join: SegmentRange \{ start: (\d+), end: (\d+) \}", message)
                if found:
                    kind, key = "secondary_join_start", tuple(map(int, found.groups()))
            elif target == "risc0_r0vm::actors::job":
                for prefix, label in [("ProveSegment", "segment_submitted"), ("ProveSegmentDone", "primary_end")]:
                    found = re.fullmatch(prefix + r": (\d+)", message)
                    if found:
                        kind, key = label, int(found.group(1))
                for prefix, label in [("LiftDone", "secondary_lift_end"), ("JoinDone", "secondary_join_end")]:
                    found = re.fullmatch(prefix + r": SegmentRange \{ start: (\d+), end: (\d+) \}", message)
                    if found:
                        kind, key = label, tuple(map(int, found.groups()))
                        if prefix == "LiftDone":
                            if key[1] != key[0] + 1:
                                errors.append("Unexpected lift range")
                            key = key[0]
                if message == "SessionDone":
                    kind = "session_done"
                elif message == "ProofRequest":
                    kind = "proof_request"
                elif message == "done":
                    kind = "actor_job_done"
            elif target == "risc0_zkvm::host::recursion::prove":
                for label in ["lift", "join"]:
                    opening = "Proving lift: claim =" if label == "lift" else "Proving join: a.claim ="
                    if message.startswith(opening):
                        kind = "sdk_" + label + "_start"
                        if sdk_open:
                            errors.append("Overlapping recursion SDK operations in the single secondary worker")
                        sdk_open[label] = when
                    elif message.startswith("Proving " + label + " finished:"):
                        kind = "sdk_" + label + "_end"
                        start = sdk_open.pop(label, None)
                        if start is None:
                            errors.append("Recursion end without start")
                        else:
                            sdk_intervals.append({"kind": label, "start": start, "end": when})
                if re.search(r"Proving (?:union|resolve|lift_povw|join_povw|join_unwrap_povw|unwrap_povw)|identity_p254", message):
                    kind = "unexpected_recursion"
            elif target == "risc0_zkvm::host::server::session":
                found = re.fullmatch(r"number of segments: (\d+)", message)
                if found:
                    worker_stats["segments"] = int(found.group(1))
                found = re.match(r"(\d+) (total|user|paging|reserved) cycles", message)
                if found:
                    worker_stats[found.group(2) + "_cycles"] = int(found.group(1))
            if kind:
                counts[kind] += 1
                events.append({"at": stamp, "epoch": when, "kind": kind, "key": key, "file": name, "line": number})
                if kind in ["primary_start", "secondary_lift_start", "secondary_join_start"]:
                    label = kind.removesuffix("_start")
                    if key in starts[label]:
                        errors.append("Duplicate task start: " + str((label, key)))
                    starts[label][key] = when
                elif kind in ["primary_end", "secondary_lift_end", "secondary_join_end"]:
                    label = kind.removesuffix("_end")
                    if key in ends[label]:
                        errors.append("Duplicate task end: " + str((label, key)))
                    ends[label][key] = when

    task_intervals = collections.defaultdict(list)
    for label, mapping in starts.items():
        for key, start in mapping.items():
            end = ends[label].get(key)
            if end is not None:
                task_intervals[label].append([start, end])
    primary_union = union(task_intervals["primary"])
    recursion_sdk_union = union([[item["start"], item["end"]] for item in sdk_intervals])
    secondary_service_union = union(task_intervals["secondary_lift"] + task_intervals["secondary_join"])
    stage_overlap = overlap(primary_union, recursion_sdk_union)
    sample_raw = read(args.monitor / "resource-samples.jsonl")
    prefix = sample_raw[:identities["captured_resource_prefix_bytes"]]
    if hashlib.sha256(prefix).hexdigest() != identities["captured_resource_prefix_sha256"]:
        raise ValueError("Role capture's exact telemetry prefix does not match")
    per_role, sum_peak, samples, simultaneous_rows = {}, {"used_mib": 0}, [], 0
    global_peak = 0
    for number, raw in enumerate(sample_raw.splitlines(), 1):
        try:
            sample = json.loads(raw)
        except ValueError:
            errors.append("Incomplete sample row " + str(number))
            continue
        infos = {info["pid"]: info for info in sample.get("processes", [])}
        total, positive_roles = 0, set()
        for gpu in sample.get("matching_gpu_processes", []):
            pid, used = gpu["pid"], gpu["used_mib"]
            identity, current = roles.get(pid), infos.get(pid)
            if not identity or not current or current["start_ticks"] != identity["start_ticks"] or current["exe"] != WORKER:
                errors.append("GPU PID lacks the captured exact worker identity: " + str(pid))
                continue
            role = identity["role"]
            total += used
            if used > 0:
                positive_roles.add(role)
            peak = per_role.get(role, {"used_mib": -1})
            if used > peak["used_mib"]:
                per_role[role] = {"used_mib": used, "at": sample["at"], "sample_line": number,
                                  "pid": pid, "start_ticks": identity["start_ticks"]}
            if role == "rpc_parent_execute_only" and used > 0:
                errors.append("Unexpected RPC parent CUDA memory")
        if total > sum_peak["used_mib"]:
            sum_peak = {"used_mib": total, "at": sample["at"], "sample_line": number,
                        "matching_gpu_processes": sample.get("matching_gpu_processes", [])}
        simultaneous_rows += positive_roles >= {"primary_segment_keccak", "secondary_recursion"}
        csv = sample.get("gpu_global_csv", "")
        if csv:
            global_peak = max(global_peak, int(csv.split(",")[1].strip()))
        if sample.get("gpu_sample_error") or sample.get("cgroup_sample_error") or sample.get("unmatched_gpu_processes"):
            errors.append("Telemetry or foreign-process error at sample " + str(number))
        samples.append(sample)
    expected = worker_stats.get("segments")
    terminal_path = args.monitor / "terminal-result.json"
    terminal = json.loads(read(terminal_path)) if terminal_path.exists() else None
    pending = []
    if not terminal:
        pending.append("Monitor terminal record unavailable")
    elif terminal.get("properties_before_stop", {}).get("Result") != "success" or terminal.get("properties_before_stop", {}).get("ExecMainStatus") != "0":
        errors.append("Unit unsuccessful")
    if terminal and terminal.get("unexpected_gpu_topology"):
        errors.append("Frozen runner reported unexpected GPU topology; resource qualification is incomplete")
    if terminal and terminal.get("actor_profile_memory_measurement_complete") is not True:
        errors.append("Frozen runner did not qualify complete actor profile memory measurement")
    if expected != 390:
        pending.append("Expected worker Session segment count not established")
    for key in ["segment_submitted", "preflight_start", "primary_start", "primary_end", "secondary_lift_start", "secondary_lift_end", "sdk_lift_start", "sdk_lift_end"]:
        if counts[key] != expected:
            pending.append(key + " count not yet equal to Session segments")
    for key in ["secondary_join_start", "secondary_join_end", "sdk_join_start", "sdk_join_end"]:
        if counts[key] != (expected or 0) - 1:
            pending.append(key + " count not yet N-1")
    if sdk_open:
        pending.append("Open recursion SDK operation")
    if counts["unexpected_recursion"]:
        errors.append("Unexpected recursion operation")
    role_details = [{**entry, "peak": per_role.get(entry["role"]),
                     "positive_gpu_memory_seen": entry["role"] in per_role and per_role[entry["role"]]["used_mib"] > 0}
                    for entry in identities["workers"]]
    for role in ["primary_segment_keccak", "secondary_recursion"]:
        if role not in per_role:
            pending.append("No GPU memory observation for " + role)
    primary_end = max(ends["primary"].values()) if ends["primary"] else None
    milestones = {}
    for name, kind, mode in [("first_primary_start", "primary_start", min),
                             ("last_primary_done", "primary_end", max),
                             ("first_lift_sdk_start", "sdk_lift_start", min),
                             ("last_lift_sdk_end", "sdk_lift_end", max),
                             ("first_join_sdk_start", "sdk_join_start", min),
                             ("last_join_sdk_end", "sdk_join_end", max),
                             ("actor_job_done", "actor_job_done", max)]:
        selected = [event for event in events if event["kind"] == kind]
        milestones[name] = mode(selected, key=lambda event: event["epoch"])["at"] if selected else None
    report = {
        "schema": "kpi-actor18-actual-task-overlap-v1", "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "monitor": str(args.monitor.resolve()), "captured_inputs": captured,
        "read_only_inputs": True, "gate_written": False, "counts": dict(counts),
        "worker_session_log_stats": worker_stats,
        "actor_sdk_stats": {"paging_cycles": None, "reserved_cycles": None,
                            "reason": "SDK DefaultProver fills these with zero placeholders; worker Session log counters above are a separately attributed observation"},
        "worker_roles": role_details, "sample_count": len(samples), "matching_sum_peak": sum_peak,
        "milestones": milestones,
        "joins_started_before_last_primary_done": sum(event["kind"] == "sdk_join_start" and event["epoch"] <= primary_end for event in events) if primary_end is not None else None,
        "joins_completed_before_last_primary_done": sum(event["kind"] == "sdk_join_end" and event["epoch"] <= primary_end for event in events) if primary_end is not None else None,
        "per_worker_peaks_sum_mib": sum(entry["used_mib"] for entry in per_role.values()),
        "global_device_sampled_peak_mib": global_peak,
        "samples_with_positive_gpu_memory_in_both_workers": simultaneous_rows,
        "stage_timing_seconds": {
            "primary_service_intervals_sum": duration(task_intervals["primary"]),
            "primary_service_union": duration(primary_union),
            "secondary_service_union": duration(secondary_service_union),
            "recursion_sdk_intervals_sum": duration([[item["start"], item["end"]] for item in sdk_intervals]),
            "recursion_sdk_union": duration(recursion_sdk_union),
            "primary_service_vs_recursion_sdk_overlap": duration(stage_overlap),
            "lift_sdk_sum": sum(item["end"] - item["start"] for item in sdk_intervals if item["kind"] == "lift"),
            "join_sdk_sum": sum(item["end"] - item["start"] for item in sdk_intervals if item["kind"] == "join"),
        },
        "events": events, "terminal": terminal,
        "trace_counts_complete": not pending,
        "resource_profile_memory_measurement_complete": terminal.get("actor_profile_memory_measurement_complete") if terminal else None,
        "complete": not errors and not pending, "errors": sorted(set(errors)), "pending": pending,
        "limits": ["Task logs carry no PID field; event-to-role mapping follows exact one-worker config and source task-kind dispatch, while telemetry roles use captured PID/start_ticks/executable/config",
                   "Primary service interval ends at manager ProveSegmentDone, including verification and message delivery after core proving",
                   "Manager Done messages can arrive after the next task starts; unions avoid counting that delivery lag twice",
                   "Recursion SDK markers include host preparation, proving and decoding; overlap is task-level, not CUDA kernel timing",
                   "Positive memory in both worker PIDs establishes resident allocation overlap, not simultaneous kernel execution",
                   "Peaks are sampled and noncoincident per-worker peaks must not be represented as the observed simultaneous sum",
                   "One run and different allocation/thermal/scheduling histories do not isolate a causal kernel-throughput improvement",
                   "Independent exact-claim receipt verification remains outside this descriptive parser"],
    }
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ["counts", "worker_session_log_stats", "sample_count", "matching_sum_peak", "per_worker_peaks_sum_mib", "stage_timing_seconds", "complete", "errors", "pending"]}, indent=2))


if __name__ == "__main__":
    main()
