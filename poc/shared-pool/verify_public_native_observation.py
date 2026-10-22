#!/usr/bin/env python3
"""Measure the new public adapter against a separately built native control bin.

Run under the coordinator's CPU/RAM/deadline cgroup. This wrapper denies network
and mounts only the named public input plus the exact binary at native runtime.
It never starts a build or discovers private/runtime/evaluation inputs.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import resource
import subprocess
import sys
import time
import unittest

import public_native_observation as observation
import public_native_observation_tests as python_controls

EXPECTED_DESCRIPTOR = "d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b"
EXPECTED_CONTROLS = {
    "canonical_proof_mutation", "canonical_authorization_fee_mutation",
    "canonical_unbound_ciphertext_mutation", "canonical_rebound_ciphertext_requires_new_proof",
    "canonical_public_witness_mutation", "canonical_successor_script_mutation",
    "parent_body_keeps_stale_id", "parent_signature_unverified_without_ancestry",
}
SOURCES = (
    "public_native_observation.py", "public_native_observation_tests.py", "verify_public_native_observation.py",
    "src/bin/kpi-public-native-observation-check.rs", "src/two_input/replay.rs", "src/two_input/tree.rs",
    "src/two_input/mod.rs", "src/two_input/covenant.rs", "src/native.rs", "src/compact/tree.rs",
    "src/protocol.rs", "src/lib.rs", "Cargo.toml", "Cargo.lock",
)


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


def compare(report, raw, result, input_bytes):
    need = observation.require
    need(report.get("schema") == "kpi-public-native-observation-native-check-v1"
         and report.get("passed") is True, "native report schema/pass")
    need(report["input_file_sha256"] == observation.sha(input_bytes).hex(), "native input digest mismatch")
    baseline = report["baseline"]
    need(baseline["state_hex"] == result["final_public_state_hex"], "independent final public-state mismatch")
    for key in ("admitted_sompi", "paid_sompi", "pool_fees_sompi", "remaining_reserve_sompi"):
        need(baseline["accounting"][key] == result["accounting"][key], "native accounting mismatch: " + key)
    for key in ("initial_reserve_sompi", "founding_input_sompi", "founding_change_sompi", "founding_fee_sompi"):
        python_key = {"initial_reserve_sompi": "reserve_sompi", "founding_input_sompi": "funding_input_sompi"}.get(key, key)
        need(baseline["accounting"][key] == result["initial"][python_key], "founding accounting mismatch: " + key)
    for key in ("transaction_id_recomputed", "native_vm_verified", "groth16_verified",
                "canonical_covenant_code_verified", "public_settlement_witness_recomputed"):
        need(baseline[key] is True, "missing native verification: " + key)
    for key in ("funding_parent_spends_verified", "chain_acceptance_verified"):
        need(baseline[key] is False, "unsupported native verification claim: " + key)
    need(len(baseline["records"]) == 14, "native record coverage")
    receipt_path = observation.HERE / observation.FIXTURE_PINS["receipt"][0]
    receipt_bytes = receipt_path.read_bytes()
    need(observation.sha(receipt_bytes).hex() == observation.FIXTURE_PINS["receipt"][1], "retained receipt drift")
    retained = observation.unique_json(receipt_bytes)["transactions"][1:]
    for i, (native, row) in enumerate(zip(baseline["records"], retained, strict=True)):
        need(native["transaction_id"] == row["transaction"]["id"]
             and native["full_hash"] == row["fullHash"], "native transaction identity/full-hash mismatch")
        if i:
            decoded = result["records"][i - 1]
            need(native["authorization_sha256"] == decoded["authorization_sha256"]
                 and native["proof_sha256"] == decoded["proof_sha256"], "native auth/proof bytes mismatch")
    controls = report["controls"]
    need(len(controls) == len(EXPECTED_CONTROLS)
         and {case["name"] for case in controls} == EXPECTED_CONTROLS
         and all(case["passed"] is True for case in controls), "native control coverage/pass")
    for case in controls:
        if case["name"] == "parent_signature_unverified_without_ancestry":
            need(case["outcome"] == "accepted_as_unverified_parent_context"
                 and case["parent_spends_verified"] is False, "parent ancestry limitation lost")
        else:
            need(case["outcome"] == "rejected" and case["expected_stage"] in case["error"], "native rejection stage")
    need([p["prefix_operations"] for p in report["prefixes"]] == [0, 1, 6], "native prefix coverage")
    for prefix in report["prefixes"]:
        count = prefix["prefix_operations"]
        decoded = observation.extract(raw, count, EXPECTED_DESCRIPTOR)
        need(prefix["state_hex"] == decoded["final_public_state_hex"], "native/Python prefix public-state mismatch")
        for key in ("admitted_sompi", "paid_sompi", "pool_fees_sompi", "remaining_reserve_sompi"):
            need(prefix["accounting"][key] == decoded["accounting"][key], "native/Python prefix accounting mismatch")
        need(prefix["bootstrap_validated"] is (count > 0)
             and prefix["chain_acceptance_verified"] is False, "native prefix trust flags")
        need(prefix["records"] == [{"transaction_id": r["transaction"]["id"], "full_hash": r["fullHash"]}
                                  for r in retained[:count + 1]], "native prefix transaction hash mismatch")
    return dict(passed=True, complete_public_witnesses=13, raw_regions=91,
                native_transaction_ids_and_full_hashes=14, native_controls=len(controls),
                native_prefix_operations=[0, 1, 6],
                scope="the same selected public bytes matched independent Python state/witness reconstruction and pinned native replay")


def run(binary, expected_binary_sha256, output):
    started = time.time()
    binary = binary.resolve(strict=True)
    observation.unhex(expected_binary_sha256, 32, "expected native binary hash")
    observation.require(binary.is_file() and file_sha(binary) == expected_binary_sha256, "native executable identity")
    output.mkdir(parents=True, exist_ok=False)
    raw = observation.load_public_rehearsal()
    selected = observation.select_prefix(raw, 13)
    result = observation.extract(raw, 13, EXPECTED_DESCRIPTOR)
    input_path = output / "selected-public-input.json"
    input_bytes = observation.canonical(selected)
    input_path.write_bytes(input_bytes)
    save(output / "observation.json", result)
    source_before = {relative: file_sha(observation.HERE / relative) for relative in SOURCES}
    test_log = io.StringIO()
    tests = unittest.defaultTestLoader.loadTestsFromModule(python_controls)
    measured_tests = unittest.TextTestRunner(stream=test_log, verbosity=2).run(tests)
    (output / "python-controls.txt").write_text(test_log.getvalue())
    observation.require(measured_tests.wasSuccessful() and measured_tests.testsRun == 20,
                        "Python public-observation controls failed/incomplete")
    save(output / "python-controls.json", dict(passed=True, tests=measured_tests.testsRun,
                                               failures=len(measured_tests.failures), errors=len(measured_tests.errors),
                                               source_sha256=source_before["public_native_observation_tests.py"]))
    command = [
        "/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
        "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
        "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
        "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--ro-bind", str(binary), "/native-check",
        "--ro-bind", str(input_path), "/input.json", "--chdir", "/tmp",
        "/native-check", "/input.json",
    ]
    process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240, check=False)
    (output / "native.stdout.json").write_bytes(process.stdout)
    (output / "native.stderr.txt").write_bytes(process.stderr)
    observation.require(process.returncode == 0, "native check failed: " + process.stderr.decode(errors="replace"))
    observation.require(not process.stderr, "unexpected native stderr")
    report = observation.unique_json(process.stdout)
    compared = compare(report, raw, result, input_bytes)
    observation.require(file_sha(binary) == expected_binary_sha256, "native executable changed during check")
    observation.require(source_before == {relative: file_sha(observation.HERE / relative) for relative in SOURCES},
                        "source changed during check")
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    validation = dict(
        schema="kpi-public-native-observation-integration-v1", **compared,
        elapsed_seconds=time.time() - started,
        child_cpu_seconds=children.ru_utime + children.ru_stime,
        child_peak_rss_bytes=children.ru_maxrss * 1024,
        native_binary_sha256=expected_binary_sha256,
        native_stdout_sha256=file_sha(output / "native.stdout.json"),
        python_control_tests=measured_tests.testsRun,
        input_sha256=observation.sha(input_bytes).hex(),
        command=command, returncode=process.returncode,
        verified=dict(native_vm=True, groth16=True, transaction_ids_and_full_hashes=True,
                      complete_public_witness_recomputation=True, canonical_v6_covenant=True,
                      funding_parent_input_spends=False, chain_acceptance=False),
        limitations=["author-operated implementation cross-check; not external cryptographic review",
                     "caller must authenticate descriptor expectation and accepted-chain view",
                     "parent input ancestry missing; changed parent signature remains accepted as unverified context",
                     "historical public rehearsal only; no privacy qualification, current wallet behavior or live acceptance"],
    )
    save(output / "validation.json", validation)
    files = {path.name: dict(bytes=path.stat().st_size, sha256=file_sha(path))
             for path in sorted(output.iterdir()) if path.is_file()}
    save(output / "MANIFEST.json", dict(
        schema="kpi-public-native-observation-manifest-v1", source_sha256=source_before,
        source_base_commit="ec6aa15d586bcc8a90f7232b433fd48d8c73d509",
        source_change_scope="additive public observation adapter, controls and integration wrapper; no inherited protocol code changed",
        fixture_pins=observation.FIXTURE_PINS, expected_descriptor_sha256=EXPECTED_DESCRIPTOR,
        native_binary_path=str(binary), native_binary_sha256=expected_binary_sha256,
        python_version=sys.version, artifacts=files,
        input_boundary="three named hash-pinned public rehearsal files only; legacy roster and receipt headers excluded",
        network="native execution unshare-all; only input JSON and executable exposed beyond OS runtime",
        absent_inputs=["wallets", "spending keys", "proving parameters", "setup", "seeds", "truth", "evaluation archives", "predictions"],
    ))
    print(json.dumps({key: validation[key] for key in ("passed", "complete_public_witnesses", "native_controls", "elapsed_seconds")}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-binary", type=Path, required=True)
    parser.add_argument("--expected-native-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    run(args.native_binary, args.expected_native_sha256, args.output_dir.resolve())


if __name__ == "__main__":
    try:
        main()
    except (observation.ObservationError, OSError, KeyError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print("public native observation verification: " + str(error), file=sys.stderr)
        sys.exit(1)
