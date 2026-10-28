#!/usr/bin/env python3
"""PUBLIC parser/API controls; never starts MPC, clients, peers or a proof.

Reuse an explicitly selected successful standard-vendor BUILD-RESULT manifest.
No protocol source is edited or reimplemented. Run under the assigned resource
scope; all compiler outputs here concern these public test sources only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest_path = args.build_manifest.resolve()
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("success") is not True:
        raise SystemExit("Selected public build is not successful")
    compile_template = manifest["compile"][0]["argv"]
    flags = compile_template[:compile_template.index("-c")]
    if any(flag in flags for flag in ("-DINSECURE", "-DUSE_KOS", "-DDEBUG_MAC")):
        raise SystemExit("Unsupported selected build flags")
    if not any("mpc-prover-softspoken-vendor" in flag for flag in flags):
        raise SystemExit("Expected selected standard SoftSpoken source build")
    tests = Path(__file__).resolve().parent
    implementation = tests.parent
    selected = [implementation / "field_coin.hpp", implementation / "batched_assignment.hpp",
                implementation / "auth_field.hpp", tests / "field_coin_boundary.cpp",
                Path(__file__).resolve()]
    selected += sorted((tests / "validated_assignment_compile_fail").glob("*.cpp"))
    (output / "SOURCE.json").write_text(json.dumps({str(p): sha(p) for p in selected}, indent=2) + "\n")
    (output / "BUILD-MANIFEST-IDENTITY.json").write_text(json.dumps({
        "path": str(manifest_path), "sha256": sha(manifest_path),
        "implementation_source_sha256": manifest["source_sha256"],
    }, indent=2) + "\n")
    results = []

    def run(name, argv, expected_success=True, diagnostic=None):
        started = time.monotonic()
        completed = subprocess.run(argv, capture_output=True)
        (output / (name + ".stdout")).write_bytes(completed.stdout)
        (output / (name + ".stderr")).write_bytes(completed.stderr)
        passed = (completed.returncode == 0) == expected_success
        if diagnostic is not None:
            passed = passed and diagnostic in completed.stderr.decode(errors="replace")
        record = {"name": name, "argv": argv, "exit_code": completed.returncode,
                  "expected_success": expected_success, "passed": passed,
                  "seconds": time.monotonic() - started}
        if diagnostic is not None:
            record["required_diagnostic"] = diagnostic
        results.append(record)
        (output / "PROGRESS.json").write_text(json.dumps(results, indent=2) + "\n")
        return completed, passed

    directory = tests / "validated_assignment_compile_fail"
    _, positive = run("capability-positive", flags + ["-fsyntax-only", str(directory / "positive.cpp")])
    if positive:
        cases = {
            "from_bool": "no matching function", "copy": "use of deleted function",
            "move": "use of deleted function", "copy_assign": "use of deleted function",
            "move_assign": "use of deleted function", "mutate_assignment": "private within this context",
            "get_assignment_alias": "has no member named", "private_constructor": "private within this context",
            "consume_directly": "private within this context",
        }
        for name, diagnostic in cases.items():
            run("capability-" + name, flags + ["-fsyntax-only", str(directory / (name + ".cpp"))],
                expected_success=False, diagnostic=diagnostic)

    obj = output / "field_coin_boundary.cpp.o"
    _, compiled = run("field-coin-compile", flags + ["-c", str(tests / "field_coin_boundary.cpp"), "-o", str(obj)])
    if compiled:
        link = list(next(item["argv"] for item in manifest["link"] if item["binary"] == "mpc-fullproof"))
        binary = output / "field-coin-boundary"
        link[link.index("-o") + 1] = str(binary)
        link = [arg for arg in link if not arg.endswith("/fullproof_gate_main.cpp.o")]
        link.insert(4, str(obj))
        _, linked = run("field-coin-link", link)
        if linked:
            execution, executed = run("field-coin-execute", [str(binary)])
            if executed:
                controls = json.loads(execution.stdout)
                if controls.get("passed") is not True or controls.get("MPC_or_private_input_executed") is not False:
                    results[-1]["passed"] = False
                (output / "FIELD-CONTROLS.json").write_text(json.dumps(controls, indent=2) + "\n")
    final = {
        "schema": "kpi-validation-public-api-controls/v1", "passed": all(r["passed"] for r in results),
        "positive_compile_passed": positive, "results": results,
        "MPC_or_private_input_or_proof_executed": False,
        "runtime_context_epoch_model_reuse_checks": "not tested here; actual MPC controls remain separate",
    }
    (output / "RESULT.json").write_text(json.dumps(final, indent=2) + "\n")
    print(json.dumps({"passed": final["passed"], "public_stages": len(results), "receipt": str(output)}))
    return 0 if final["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
