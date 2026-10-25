#!/usr/bin/env python3
"""Selected public-only Native Full + every-input validation; never chain authority."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("_kpxa_native_outer_guard", HERE / "outer.py")
_outer = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _outer
_spec.loader.exec_module(_outer)
need, read = _outer.need, _outer.read
ROOT = HERE.parents[2]
SCHEMA = "local-private-payment-native-job/v1"


def prepare(guard, module, job, output):
    need(type(job) is dict and set(job) == {"schema", "mode", "financial_profile_sha256", "compute_budget", "fee_rate_sompi_per_mass", "files"}, "exact-native-job-fields")
    need(job["schema"] == SCHEMA and job["mode"] in ("mixed-attach", "direct-exit"), "selected-native-job")
    module.external_pin(job["financial_profile_sha256"])
    need(type(job["compute_budget"]) is int and 1 <= job["compute_budget"] <= 65535, "selected-budget")
    need(type(job["fee_rate_sompi_per_mass"]) is int and 1 <= job["fee_rate_sompi_per_mass"] <= (1 << 64) - 1, "selected-native-fee-rate")
    names = {"engine", "codec", "case", "projection", "journal", "component", "selection"}
    if job["mode"] == "mixed-attach":
        names.add("proof")
    need(type(job["files"]) is dict and set(job["files"]) == names, "exact-selected-native-files")
    rows = dict(job["files"])
    for name, row in rows.items():
        need(type(row) is dict and set(row) == {"path", "sha256"} and type(row["path"]) is str, "selected-file-row")
        module.external_pin(row["sha256"])
        guard.metadata(row["path"])
    # This launcher's own fixed source closure is retained in the stage record.
    for name, relative in [("native_case.py", "native_case.py"), ("wire.py", "wire.py"), ("validator.py", "native/validate_selected_case.py")]:
        path = ROOT / "poc/local-private-payment/verification" / relative
        guard.metadata(path)
        raw = read(guard, path)
        rows[name] = {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    output = module.fresh(_outer.output_path(guard, output))
    public = output / "public"
    (public / "verification/native").mkdir(parents=True)
    for name, row in rows.items():
        dest = public / ("verification/native/validate_selected_case.py" if name == "validator.py" else "verification/" + name if name.endswith(".py") else name)
        module.staged(row["path"], dest, row["sha256"], name in ("engine", "codec"))
    client = output / "public-output"
    client.mkdir()
    command = module.bubble() + ["--ro-bind", str(public), "/public", "--bind", str(client), "/out", "--chdir", "/public", "/usr/bin/python3", "-B", "/public/verification/native/validate_selected_case.py", "--mode", job["mode"], "--financial-profile-sha", job["financial_profile_sha256"], "--compute-budget", str(job["compute_budget"]), "--fee-rate-sompi-per-mass", str(job["fee_rate_sompi_per_mass"]), "--out", "/out"]
    for name in sorted(names):
        command += ["--" + name, "/public/" + name, "--" + name + "-sha", rows[name]["sha256"]]
    plan = {"schema": "local-private-payment-native-stage/v1", "mode": job["mode"], "files": rows, "command": command, "selected_compute_budget": job["compute_budget"], "selected_fee_rate_sompi_per_mass": job["fee_rate_sompi_per_mass"], "network_namespace": "UNSHARED", "wallet_or_PK_or_host_home_mounted": False, "worker_started": False, "chain_confirmation": False}
    module.save(output / "STAGE.json", plan)
    return output, command, plan


def execute(guard, module, output, command, plan):
    for name, row in plan["files"].items():
        path = output / "public" / ("verification/native/validate_selected_case.py" if name == "validator.py" else "verification/" + name if name.endswith(".py") else name)
        read(guard, path, row["sha256"])
    resources = module.call(command, output)
    result = module.parse(read(guard, output / "public-output/RESULT.json"))
    need(result.get("native_Full_accepted") is True and result.get("all_input_scripts_accepted") is True and result.get("funding_or_broadcast") is False and result.get("accepted_backing_or_chain_confirmation") is False, "actual-native-Full-only")
    outcome = {"schema": "local-private-payment-native-result/v1", "worker_completed": True, "mode": plan["mode"], "resources": resources, "worker_report": result, "native_Full_and_all_inputs_accepted": True, "accepted_backing_or_chain_confirmation": False}
    module.save(output / "RESULT.json", outcome)
    return outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--exclude-private-directory", action="append", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    guard = _outer.Guard(args.exclude_private_directory)
    module = _outer.helper(guard)
    job = module.parse(read(guard, args.selection, module.external_pin(args.selection_sha256)))
    output, command, plan = prepare(guard, module, job, args.output)
    if args.execute:
        execute(guard, module, output, command, plan)
    print(json.dumps({"output": str(output), "mode": job["mode"], "worker_started": args.execute}, sort_keys=True))


if __name__ == "__main__":
    main()
