#!/usr/bin/env python3
"""Apply frozen source arithmetic to the independently emitted union length."""
import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import resource
import sys

sys.dont_write_bytecode = True
resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
HERE = pathlib.Path(__file__).resolve().parent
model_path = HERE / "model.py"
assert hashlib.sha256(model_path.read_bytes()).hexdigest() == "ad6c25f8edc11662326033882d2e0f02d012bd26e3bcba2b3f18ca358911dc9e"
spec = importlib.util.spec_from_file_location("fee_model", model_path)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)
parser = argparse.ArgumentParser()
parser.add_argument("--redeem-bytes", type=int, required=True)
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()
if args.output.exists():
    raise SystemExit("refusing existing output")
L = args.redeem_bytes
assert 5979 <= L <= 49152
pilots = [model.complete_isolated_pilot(L, b, prep) for b in (1600, 1700) for prep in (False, True)]
selected = pilots[0]
f_private = selected["private_metrics"]["normalized_mining_mass"] * 100
main_funding = selected["exact_main_funding_input_sompi"]
target = {"reference_rate": 100, "genesis_note_sompi": 60_000_000,
          "genesis_funding_input_sompi": 120_000_000,
          "genesis_funding_fee_sompi": selected["founding"]["fee_sompi"],
          "genesis_returned_native_change_sompi": 60_000_000 - selected["founding"]["fee_sompi"],
          "main_admit_funding_input_sompi": main_funding,
          "main_admit_fee_sompi": selected["admission_metrics"]["normalized_mining_mass"] * 100,
          "main_admit_note_sompi": selected["admitted_note_value_sompi"],
          "main_admit_native_change_sompi": 0,
          "reserve_after_admit_sompi": 2_000_000_000 + f_private,
          "private_fee_sompi": f_private,
          "private_real_inputs": [60_000_000, selected["admitted_note_value_sompi"]],
          "private_real_recipient_outputs": [1_000_000_000, 1_000_000_000],
          "private_payer_change_notes": 0,
          "reserve_after_private_sompi": 2_000_000_000,
          "main_funding_preparation_if_needed": model.prepare_funding(main_funding)}
assert sum(target["private_real_inputs"]) == sum(target["private_real_recipient_outputs"]) + f_private
result = {"format": "emitted-length-prospective-economic-targets-v1",
          "redeem_bytes_reported_by_root_compiled_shape": L,
          "length_basis": "root/native agent compiled three-branch emitter; placeholder VK/state for size only; no padding",
          "actual_selected_vk_state_proof_native_execution_still_required": True,
          "budgets_are_not_qualified_by_arithmetic": {"private": 1600, "admit": 200, "funding": 10, "reveal": 200},
          "new_authorization_targets_not_existing_proof_repricing": target,
          "ordinary_fixed_body_quote_100_200_500": [
              {"rate": r, "required_fee_sompi": selected["private_metrics"]["normalized_mining_mass"] * r,
               "planned_fixed_fee_sompi": f_private, "planned_fixed_fee_covers_quote": r == 100}
              for r in (100, 200, 500)],
          "recipient_claim_agility": [{"rate": r, "first": model.exit_quote(L, 1_000_000_000, 1_000_000_000, r),
                                       "last": model.exit_quote(L, 1_000_000_000, 0, r)} for r in (100, 200, 500)],
          "supported_small_claim_agility": [{"rate": r, "terminal": model.exit_quote(L, 60_000_000, 0, r),
                                             "continuing_minimum_remaining_liability": model.exit_quote(L, 60_000_000, 60_000_000, r)}
                                            for r in (100, 200, 500)],
          "complete_prefix_pilots": pilots,
          "generic_conditional_aggregates": [model.route(L, ba, bp, "whole_utxo", prep, 1600)
                for ba, bp in ((1, 1), (1, 2), (1, 3), (2, 2), (2, 3), (2, 4), (4, 4)) for prep in (False, True)],
          "source_pins": [model.digest(model_path), model.digest(pathlib.Path(__file__).resolve()),
                           model.digest(model.ROOT / "poc/future-native-union/src/policy.rs")],
          "native_proof_or_funding_run_by_this_calculator": False}
args.output.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"output": str(args.output), **model.digest(args.output),
                  "target": target, "native_or_proving_executed": False}))
