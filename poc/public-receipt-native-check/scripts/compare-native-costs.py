#!/usr/bin/env python3
"""Compare retained public predicates and measured direct layouts, never quote settlement."""
import argparse
import hashlib
import json
from pathlib import Path

NATIVE_REV = "01b532e8b553523216471682649693af92f0fd16"
COMPUTE_LIMIT = 500_000
TRANSIENT_LIMIT = 1_000_000
TRANSIENT_PER_BYTE = 4
COMPUTE_PER_ESTIMATED_BYTE = 1
# Native config/params.rs and mass/mod.rs at NATIVE_REV; these are necessary
# bounds for an otherwise-empty block, not a measured aggregate transaction.


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    raw = path.read_bytes()
    return json.loads(raw), sha(raw)


def checked_file(path, expected_hash, expected_length):
    raw = path.read_bytes()
    if sha(raw) != expected_hash or len(raw) != expected_length:
        raise ValueError(f"saved artifact hash/size mismatch: {path}")
    return raw


def predicate(path, tag):
    report, digest = read_json(path)
    if (
        report["scope"] != "OFFLINE_BARE_KASPA_NATIVE_OPCODE_PREDICATE_ONLY"
        or report["native_kaspa_revision"] != NATIVE_REV
        or report["native_opcode_tag"] != tag
        or report["historical_harness_qualification"]
        or not report["paired_receipt_result"]
        or not report["all_expectations_met"]
        or report["transaction_or_covenant_acceptance_tested"]
    ):
        raise ValueError(f"not the required passing paired predicate report: {path}")
    cases = report["cases"]
    positives = [c for c in cases if c["case"] == "valid"]
    if len(positives) != 1 or not positives[0]["accepted"]:
        raise ValueError(f"missing unique positive native execution: {path}")
    if any(not c["matched_expectation"] or (c["case"] != "valid" and c["accepted"]) for c in cases):
        raise ValueError(f"failed native controls: {path}")
    valid = positives[0]
    script = checked_file(path.parent / "valid-native-script.bin", valid["native_script_sha256"], valid["native_script_bytes"])
    units = valid["used_script_units"]
    # Existing native free allowance: limit = b*10000+9999, not ceil(u/10000).
    budget = units // 10_000
    if budget != valid["bare_predicate_min_covering_compute_budget"]:
        raise ValueError("reported bare covering budget differs from native source bound")
    if tag == "0x20":
        for name, prefix in [("proof.compressed.bin", "compressed_proof"), ("vk.compressed.bin", "compressed_vk")]:
            checked_file(path.parent / name, report["fields"][prefix + "_sha256"], report["fields"][prefix + "_bytes"])
    # Conditional on embedding this literal flat script once in the current
    # transaction. Complete estimated size also includes transaction framing.
    compute_lower_bound = budget * 100 + len(script) * COMPUTE_PER_ESTIMATED_BYTE
    return report, {
        "report_sha256": digest,
        "receipt_file_bytes": report["receipt_file_bytes"],
        "native_script_bytes": len(script),
        "used_script_units": units,
        "bare_min_covering_compute_budget": budget,
        "bare_committed_budget_grams": budget * 100,
        "flat_script_embedding_compute_lower_bound_grams": compute_lower_bound,
        "positive_case_observed_seconds": valid["seconds"],
        "native_cases": len(cases),
        "remaining_compute_grams_before_empty_block_limit": COMPUTE_LIMIT - compute_lower_bound,
        "remaining_estimated_bytes_before_empty_block_transient_limit": TRANSIENT_LIMIT // TRANSIENT_PER_BYTE - len(script),
    }


def compare_native_costs(succinct_path, groth16_path, direct_path):
    """Pure evidence comparison; no proving, native execution, fees, or network I/O."""
    sr, succinct = predicate(succinct_path, "0x21")
    gr, groth16 = predicate(groth16_path, "0x20")
    for field in ["expected_image", "expected_journal_sha256", "expected_journal_bytes", "checker_binary_sha256"]:
        if sr[field] != gr[field]:
            raise ValueError(f"predicate expectation/build mismatch: {field}")
    direct, direct_sha = read_json(direct_path)
    if not direct["passed"] or direct["native_dependency"] != NATIVE_REV or direct["candidate_budget"] != 1600:
        raise ValueError("not the passing pinned budget1600 public native baseline")
    rows = direct["candidate1600"]
    if not rows or any(not r["full_native"]["passed"] or r["reserve_budget"] != 1600 for r in rows):
        raise ValueError("direct matrix contains an unqualified candidate")
    groups = {}
    for name, selected in [("all_observed_modes", rows), ("observed_spend_mode1", [r for r in rows if r["mode"] == 1])]:
        if not selected:
            raise ValueError("no measured direct SPEND layouts")
        masses = [r["metrics"]["compute_mass"] for r in selected]
        sizes = [r["metrics"]["estimated_bytes"] for r in selected]
        groups[name] = {
            "observed_layouts": len(selected),
            "compute_mass_range": [min(masses), max(masses)],
            "estimated_bytes_range": [min(sizes), max(sizes)],
        }
    bounds = []
    for count in [2, 4, 8, 16]:
        entry = {"operations": count, "repeated_measured_layout_sensitivity": {}}
        for name, group in groups.items():
            low, high = group["compute_mass_range"]
            entry["repeated_measured_layout_sensitivity"][name] = {
                "separate_direct_compute_mass_range": [count * low, count * high],
                "extra_outer_compute_grams_available_before_exceeding_separate_direct_sum": {
                    "0x21": [count * low - succinct["flat_script_embedding_compute_lower_bound_grams"], count * high - succinct["flat_script_embedding_compute_lower_bound_grams"]],
                    "0x20": [count * low - groth16["flat_script_embedding_compute_lower_bound_grams"], count * high - groth16["flat_script_embedding_compute_lower_bound_grams"]],
                },
            }
        entry["per_operation_publication_byte_upper_bound_if_all_other_bytes_were_zero"] = {
            tag: item["remaining_estimated_bytes_before_empty_block_transient_limit"] // count
            for tag, item in [("0x21", succinct), ("0x20", groth16)]
        }
        bounds.append(entry)
    return {
        "scope": "PUBLIC_NATIVE_PREDICATE_RESOURCE_COMPARISON_AND_NECESSARY_BOUNDS_ONLY",
        "native_revision": NATIVE_REV,
        "expected_image": sr["expected_image"],
        "expected_journal_sha256": sr["expected_journal_sha256"],
        "checker_binary_sha256": sr["checker_binary_sha256"],
        "direct_matrix_sha256": direct_sha,
        "predicates": {"0x21": succinct, "0x20": groth16},
        "measured_predicate_reduction": {
            "native_script_bytes": succinct["native_script_bytes"] - groth16["native_script_bytes"],
            "sdk_receipt_file_bytes": succinct["receipt_file_bytes"] - groth16["receipt_file_bytes"],
            "script_units": succinct["used_script_units"] - groth16["used_script_units"],
            "bare_committed_budget_grams": succinct["bare_committed_budget_grams"] - groth16["bare_committed_budget_grams"],
            "flat_script_embedding_compute_lower_bound_grams": succinct["flat_script_embedding_compute_lower_bound_grams"] - groth16["flat_script_embedding_compute_lower_bound_grams"],
        },
        "direct_measured_layouts": groups,
        "necessary_bounds": bounds,
        "aggregate_transaction_mass": None,
        "settlement_fee_saving": None,
        "limitations": [
            "Native times are single observed positive cases from the same checker build, not stable benchmarks or throughput rates.",
            "A bare predicate is compared with complete direct transaction layouts only to bound the remaining aggregate overhead; it cannot establish a fee win.",
            "The compute lower bound assumes this exact flat script is embedded once and includes its bytes at one compute gram per estimated byte; actual transaction framing, other inputs/outputs and execution add cost.",
            "Repeated layout ranges are arithmetic sensitivities, not measured 4/8/16-operation aggregates or a qualified worst case.",
            "Publication bounds assume every other transaction byte is zero; covenant framing, inputs, outputs, metadata and other execution must reduce them.",
            "Aggregate storage mass, exact data publication/recovery, state binding, transaction body and fee authorization remain unspecified.",
            "The fixed official Groth16 setup trust is an additional assumption; native acceptance does not validate its ceremony.",
            "No private inputs, funding, broadcast, privacy claim or production architecture selection.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("succinct_report", type=Path)
    parser.add_argument("groth16_report", type=Path)
    parser.add_argument("direct_1600_report", type=Path)
    parser.add_argument("new_output", type=Path)
    args = parser.parse_args()
    result = compare_native_costs(args.succinct_report, args.groth16_report, args.direct_1600_report)
    with args.new_output.open("x") as out:
        json.dump(result, out, indent=2)
        out.write("\n")
    print(json.dumps({"output": str(args.new_output), "predicate_reduction": result["measured_predicate_reduction"]}))


if __name__ == "__main__":
    main()
