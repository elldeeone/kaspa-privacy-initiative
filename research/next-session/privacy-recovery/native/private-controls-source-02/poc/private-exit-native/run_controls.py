#!/usr/bin/env python3
"""Execute one reviewed public control packet without preparing or tuning it."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    if path.exists():
        raise ValueError("refuse overwrite: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def check(item):
    path = Path(item["path"])
    if path.is_symlink():
        raise ValueError("symlink is not a frozen regular public artifact")
    data = path.read_bytes()
    if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise ValueError("frozen artifact changed: " + str(path))


def run(args):
    raw = args.freeze.read_bytes()
    frozen_sha = hashlib.sha256(raw).hexdigest()
    freeze = json.loads(raw)
    if (frozen_sha != args.reviewed_freeze_sha256 or freeze.get("runtime_authorized") is not True
            or freeze.get("scope") != "PRIVATE_EXIT_NATIVE_ORDINARY_CONTROLS"):
        raise ValueError("reviewed exact control runtime release required")
    frozen_paths = set()
    for item in freeze["files"]:
        check(item)
        frozen_paths.add(Path(item["path"]).resolve())
    expected = load(args.expected)
    binary = Path(expected["native_binary"]["path"])
    required = {Path(__file__).resolve(), args.expected.resolve(), binary.resolve()}
    required.update(Path(item["path"]).resolve() for item in expected["sources"])
    for case in expected["cases"]:
        for key in ("validation_case", "transaction", "supplied_context"):
            check(case[key])
            required.add(Path(case[key]["path"]).resolve())
    if (not required <= frozen_paths or expected["scope"] != freeze["scope"]
            or expected["classification"] != "PUBLIC_SYNTHETIC_DO_NOT_FUND"):
        raise ValueError("runtime freeze omitted required source, executable or body")
    if args.output.exists():
        raise ValueError("fresh control run identity required")
    args.output.mkdir(parents=True)
    rows = []
    for case in expected["cases"]:
        directory = args.output / case["case_id"]
        process = subprocess.run([str(binary), "validate-transaction", case["validation_case"]["path"], str(directory)],
                                 capture_output=True, text=True, check=False)
        save(directory / "command.json", {"returncode": process.returncode,
                                            "stdout": process.stdout, "stderr": process.stderr})
        report_path = directory / "native-validation.json"
        report = load(report_path) if report_path.is_file() else {}
        inputs = report.get("per_input_ScriptEngine", [])
        valid_shape = (process.returncode == 0 and len(inputs) == 1
                       and report.get("fixture_schema_rejected") is not True)
        engine = inputs[0] if inputs else {}
        units = engine.get("units", -1)
        if case["expected"] == "ACCEPT":
            outcome = (report.get("isolation") == "PASS" and report.get("Full", {}).get("accepted") is True
                       and engine.get("accepted") is True and units >= expected["g16_minimum_script_units"])
        else:
            outcome = (report.get("Full", {}).get("accepted") is False and engine.get("accepted") is False
                       and isinstance(engine.get("typed_error"), str))
            if case["expected"] == "REJECT_BEFORE_G16":
                outcome &= 0 <= units < expected["g16_minimum_script_units"]
            elif case["expected"] == "REJECT_AT_G16":
                outcome &= units >= expected["g16_minimum_script_units"]
            else:
                raise ValueError("unknown frozen expectation")
            if case["expected_exact_error"] is not None:
                expected_error = case["expected_exact_error"]
                outcome &= (engine.get("typed_error") == expected_error
                            and report.get("isolation") == "PASS"
                            and report.get("Full", {}).get("typed_error") == "SignatureInvalid(" + expected_error + ")")
        rows.append({"case_id": case["case_id"], "base_stage": case["base_stage"],
                     "expectation_matched": bool(valid_shape and outcome), "expected": case["expected"],
                     "expected_exact_error": case["expected_exact_error"], "native_validation": report,
                     "intended_cause": case["intended_cause"],
                     "supplied_context_counterfactual": case["supplied_context_counterfactual"]})
    for item in freeze["files"]:
        check(item)
    result = {"classification": expected["classification"], "scope": freeze["scope"],
              "reviewed_freeze_sha256": frozen_sha, "case_count": len(rows),
              "matched": sum(row["expectation_matched"] for row in rows),
              "mismatches": sum(not row["expectation_matched"] for row in rows), "cases": rows,
              "accepted_chain_backing": False, "network_or_broadcast": False,
              "scope_note": "Frozen supplied-context official Full and input engine; no accepted history/privacy/audit claim"}
    save(args.output / "RESULTS.json", result)
    print(json.dumps({key: result[key] for key in ("case_count", "matched", "mismatches")}, sort_keys=True))
    if result["mismatches"]:
        raise SystemExit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("freeze", "expected", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--reviewed-freeze-sha256", required=True)
    run(parser.parse_args())
