#!/usr/bin/env python3
"""Read IPC18 tracing/telemetry; write an analysis, never an actor release gate."""
import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re
import statistics

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
STAMP = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))")
BOUNDARY_OVERLAP_SECONDS = 2.0
FIXED_MARGIN_MIB = 512
FIXED_LIMIT_MIB = 6656


def timestamp(value):
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("monitor", type=pathlib.Path)
    ap.add_argument("output", type=pathlib.Path,
                    help="New analysis JSON inside this script's stage-analysis directory")
    args = ap.parse_args()
    own_dir = pathlib.Path(__file__).resolve().parent
    if args.output.resolve().parent != own_dir:
        ap.error("Output must be a new file in the parser's own stage-analysis directory")
    captured = {}
    events = []
    declared_segments = None
    for name in ["stdout.log", "stderr.log"]:
        path = args.monitor / name
        if not path.exists():
            continue
        raw = path.read_bytes()
        captured[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        for line_num, raw_line in enumerate(raw.decode(errors="replace").splitlines(), 1):
            line = ANSI.sub("", raw_line)
            match = STAMP.search(line)
            if not match or "risc0_zkvm::host::" not in line:
                continue
            event = None
            if "::server::prove" in line:
                if "prove_session: exit_code" in line:
                    event = "session_start"
                    segment_match = re.search(r"segments:\s*(\d+)", line)
                    if segment_match:
                        declared_segments = int(segment_match.group(1))
                elif re.search(r":\s+segment_preflight\s*$", line):
                    event = "preflight_start"
                elif re.search(r":\s+prove_segment_core\s*$", line):
                    event = "segment_core_start"
            if "::recursion::prove" in line:
                if "Proving lift finished:" in line:
                    event = "lift_end"
                elif "Proving lift: claim =" in line:
                    event = "lift_start"
                elif "Proving join finished:" in line:
                    event = "join_end"
                elif "Proving join: a.claim =" in line:
                    event = "join_start"
                elif "Proving join: b.claim =" in line:
                    event = "join_second_operand"
                elif re.search(r"Proving (?:union|resolve|lift_povw|join_povw|join_unwrap_povw|unwrap_povw)|identity_p254", line):
                    event = "unexpected_recursion_operation"
            if event:
                events.append({"kind": event, "at": match.group(1),
                               "epoch": timestamp(match.group(1)),
                               "file": name, "line": line_num})
    events.sort(key=lambda event: (event["epoch"], event["file"], event["line"]))
    counts = dict(collections.Counter(event["kind"] for event in events))
    lifts = [event for event in events if event["kind"] == "lift_start"]
    boundary = lifts[0]["epoch"] if lifts else None
    sample_path = args.monitor / "resource-samples.jsonl"
    raw = sample_path.read_bytes() if sample_path.exists() else b""
    captured[sample_path.name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    samples, malformed_rows = [], []
    for number, line in enumerate(raw.splitlines(), 1):
        try:
            sample = json.loads(line)
            sample["epoch"] = timestamp(sample["at"])
            sample["matching_sum_mib"] = sum(row["used_mib"] for row in sample.get("matching_gpu_processes", []))
            sample["source_line"] = number
            samples.append(sample)
        except (ValueError, KeyError, TypeError) as error:
            malformed_rows.append({"line": number, "error": str(error)})
    samples.sort(key=lambda sample: sample["epoch"])
    primary, recursion = [], []
    if boundary is not None:
        primary = [s for s in samples if s["epoch"] <= boundary + BOUNDARY_OVERLAP_SECONDS]
        recursion = [s for s in samples if s["epoch"] >= boundary - BOUNDARY_OVERLAP_SECONDS]

    def peak(group):
        if not group:
            return None
        item = max(group, key=lambda s: s["matching_sum_mib"])
        return {"used_mib": item["matching_sum_mib"], "at": item["at"],
                "sample_line": item["source_line"],
                "matching_gpu_processes": item.get("matching_gpu_processes", [])}

    def operation_durations(kind):
        start = None
        seconds, errors = [], []
        for event in events:
            if event["kind"] == kind + "_start":
                if start is not None:
                    errors.append("start before previous end")
                start = event["epoch"]
            elif event["kind"] == kind + "_end":
                if start is None:
                    errors.append("end without start")
                else:
                    seconds.append(event["epoch"] - start)
                    start = None
        if start is not None:
            errors.append("last operation incomplete")
        return {"completed": len(seconds), "total_marker_seconds": sum(seconds),
                "min_marker_seconds": min(seconds) if seconds else None,
                "max_marker_seconds": max(seconds) if seconds else None,
                "pairing_errors": errors}

    def summarize_durations(values):
        return {"count": len(values), "sum_seconds": sum(values),
                "min_seconds": min(values) if values else None,
                "median_seconds": statistics.median(values) if values else None,
                "max_seconds": max(values) if values else None}

    preflights = [event["epoch"] for event in events if event["kind"] == "preflight_start"]
    cores = [event["epoch"] for event in events if event["kind"] == "segment_core_start"]
    preflight_times = [core - preflight for preflight, core in zip(preflights, cores)]
    # IPC is serial: the next preflight begins after the prior core and its
    # verification. The final interval also includes composite verification.
    core_proxy_times = [next_start - core for core, next_start in zip(cores, preflights[1:])]
    if boundary is not None and cores:
        core_proxy_times.append(boundary - cores[-1])

    terminal_path = args.monitor / "terminal-result.json"
    terminal = None
    if terminal_path.exists():
        raw_terminal = terminal_path.read_bytes()
        captured[terminal_path.name] = {"sha256": hashlib.sha256(raw_terminal).hexdigest(), "bytes": len(raw_terminal)}
        terminal = json.loads(raw_terminal)
    primary_peak, recursion_peak = peak(primary), peak(recursion)
    reasons = []
    if boundary is None:
        reasons.append("No first lift marker; broad phase attribution unavailable")
    if not primary_peak or not recursion_peak:
        reasons.append("One or both phase sample sets are empty")
    elif primary_peak["used_mib"] <= 0 or recursion_peak["used_mib"] <= 0:
        reasons.append("One or both phases have no positive matching GPU memory observation")
    if malformed_rows:
        reasons.append("Malformed or incompletely written sample rows")
    if any(sample.get("gpu_sample_error") for sample in samples):
        reasons.append("GPU query errors retained in telemetry")
    if any(sample.get("unmatched_gpu_processes") for sample in samples):
        reasons.append("Foreign GPU processes retained in telemetry")
    if not terminal:
        reasons.append("Proof/monitor still running or terminal result unavailable")
    else:
        props = terminal.get("properties_before_stop", {})
        if props.get("ExecMainStatus") != "0" or props.get("Result") != "success":
            reasons.append("Unit did not complete successfully")
        if terminal.get("vram_guard_exceeded"):
            reasons.append("VRAM guard exceeded")
        if terminal.get("actor_admission_telemetry_reliable") is not True:
            reasons.append("Final runner has not qualified actor-admission telemetry reliability")
    for name in ["preflight_start", "segment_core_start", "lift_start", "lift_end"]:
        if counts.get(name, 0) == 0:
            reasons.append("Missing expected event: " + name)
    if counts.get("preflight_start") != counts.get("segment_core_start"):
        reasons.append("Preflight/core count mismatch")
    if declared_segments is None or counts.get("segment_core_start") != declared_segments:
        reasons.append("Observed core count does not yet match declared session segment count")
    if counts.get("segment_core_start") != counts.get("lift_start"):
        reasons.append("Core/lift count mismatch")
    if counts.get("lift_start") != counts.get("lift_end"):
        reasons.append("Incomplete lift events")
    if counts.get("join_start", 0) != counts.get("join_end", 0):
        reasons.append("Incomplete join events")
    if counts.get("lift_start", 0) > 0 and counts.get("join_end", 0) != counts["lift_start"] - 1:
        reasons.append("Unexpected lift/join tree count")
    if counts.get("unexpected_recursion_operation", 0):
        reasons.append("Unexpected extra recursion operation requires source review")
    if boundary is not None and any(event["kind"] == "segment_core_start" and event["epoch"] >= boundary for event in events):
        reasons.append("Segment proof starts at/after first lift; expected serial IPC phase ordering violated")
    summed = None if primary_peak is None or recursion_peak is None else primary_peak["used_mib"] + recursion_peak["used_mib"] + FIXED_MARGIN_MIB
    gaps = [b["epoch"] - a["epoch"] for a, b in zip(samples, samples[1:])]
    descriptive_windows = {}
    if boundary is not None:
        for label, minimum, maximum in [
                ("minus_5_to_minus_2_seconds", -5, -2),
                ("minus_2_to_0_seconds", -2, 0),
                ("0_to_plus_2_seconds", 0, 2),
                ("plus_2_to_plus_5_seconds", 2, 5),
                ("after_plus_2_seconds", 2, float("inf"))]:
            selected = [s for s in samples if minimum <= s["epoch"] - boundary <= maximum]
            descriptive_windows[label] = {"sample_count": len(selected), "peak": peak(selected)}
    report = {
        "schema": "kpi-ipc18-source-backed-broad-phase-analysis-v1",
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "monitor": str(args.monitor.resolve()), "captured_inputs": captured,
        "read_only_inputs": True, "actor_release_gate_written": False,
        "first_lift_at": lifts[0]["at"] if lifts else None,
        "boundary_overlap_seconds_each_side": BOUNDARY_OVERLAP_SECONDS,
        "declared_session_segments": declared_segments,
        "counts": counts, "events": events,
        "primary_peak": primary_peak, "recursion_peak": recursion_peak,
        "primary_peak_mib": primary_peak["used_mib"] if primary_peak else None,
        "recursion_peak_mib": recursion_peak["used_mib"] if recursion_peak else None,
        "fixed_margin_mib": FIXED_MARGIN_MIB, "fixed_limit_mib": FIXED_LIMIT_MIB,
        "sum_plus_margin_mib": summed,
        "arithmetic_gate_passes": summed is not None and summed <= FIXED_LIMIT_MIB,
        "phase_attribution_complete": not reasons, "incomplete_or_review_reasons": reasons,
        "runner_actor_admission_telemetry_reliable": terminal.get("actor_admission_telemetry_reliable") if terminal else None,
        "sample_count": len(samples), "malformed_sample_rows": malformed_rows,
        "marker_local_descriptive_only": {
            "not_used_for_admission": True,
            "cannot_establish_separate_actor_worker_bound": True,
            "reason": "Single IPC process allocator/context history differs from two actor worker processes; carryover cannot be subtracted to establish their sum",
            "windows": descriptive_windows,
            "boundary_samples": [{"at": s["at"], "offset_from_first_lift_seconds": s["epoch"] - boundary,
                                  "matching_sum_mib": s["matching_sum_mib"],
                                  "sample_line": s["source_line"]}
                                 for s in samples if boundary is not None and abs(s["epoch"] - boundary) <= 5],
        },
        "sample_max_gap_seconds": max(gaps) if gaps else None,
        "phase_sample_counts": {"primary": len(primary), "recursion": len(recursion),
                                "both": sum(abs(s["epoch"] - boundary) <= BOUNDARY_OVERLAP_SECONDS for s in samples) if boundary is not None else 0},
        "lift_timing": operation_durations("lift"), "join_timing": operation_durations("join"),
        "primary_broad_marker_seconds": boundary - preflights[0] if boundary is not None and preflights else None,
        "cpu_preflight_marker_timing": summarize_durations(preflight_times),
        "core_and_verification_proxy_marker_timing": summarize_durations(core_proxy_times),
        "limits": ["Sample at is before NVML query; exact GPU observation occurs later",
                   "Both phases include all boundary samples within the frozen two-second overlap",
                   "Sampled peaks can miss brief allocations; 512MiB is a fixed admission margin, not a CUDA quota",
                   "Independent exact-claim receipt verification and reviewer acknowledgement remain separate gates",
                   "Log marker durations include host/prover work; they are not isolated CUDA kernel timings"],
    }
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ["first_lift_at", "counts", "primary_peak_mib", "recursion_peak_mib", "sum_plus_margin_mib", "arithmetic_gate_passes", "phase_attribution_complete", "incomplete_or_review_reasons", "sample_count", "sample_max_gap_seconds"]}, indent=2))


if __name__ == "__main__":
    main()
