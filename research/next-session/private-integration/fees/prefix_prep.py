#!/usr/bin/env python3
"""Exact prospective four-billion source -> two funding coins + all change."""
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
here = pathlib.Path(__file__).resolve().parent
p = here / "actual-size-22388.json"
raw = p.read_bytes()
assert hashlib.sha256(raw).hexdigest() == "a247aeffd4daa4c8ce911228e09beca3c65e6bdd8c14cfe0d067965ec172287c"
d = json.loads(raw)
spec = importlib.util.spec_from_file_location("fee_model", here / "model.py")
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
t = d["new_authorization_targets_not_existing_proof_repricing"]
source, founding_coin, main_coin = 4_000_000_000, 120_000_000, t["main_admit_funding_input_sompi"]
prep = m.quote(100, lambda fee: m.metrics(
    [66], [10], 0, [(1, source)],
    [(1, founding_coin), (1, main_coin), (1, source - founding_coin - main_coin - fee)],
    [34, 34, 34]))
source_change = source - founding_coin - main_coin - prep["fee_sompi"]
pilot = d["complete_prefix_pilots"][0]
shared = prep["fee_sompi"] + pilot["founding"]["fee_sompi"] + t["main_admit_fee_sompi"] + t["private_fee_sompi"]
shares = m.allocate(shared, 2)
orders = []
for first_user in (0, 1):
    users = []
    for i in (0, 1):
        claim = pilot["first_claim"] if i == first_user else pilot["final_claim"]
        users.append({"recipient": i, "principal_sompi_counted_once": 1_000_000_000,
                      "shared_prefix_fee_share_sompi": shares[i],
                      "own_reveal_fee_sompi": claim["fee_sompi"],
                      "native_payout_sompi": 1_000_000_000 - claim["fee_sompi"],
                      "all_modeled_route_fees_sompi": shares[i] + claim["fee_sompi"],
                      "ordinary_private_fee_share_sompi": t["private_fee_sompi"] // 2,
                      "remaining_2percent_headroom_sompi": 20_000_000 - shares[i] - claim["fee_sompi"]})
    fees = sum(u["all_modeled_route_fees_sompi"] for u in users)
    returned = source_change + t["genesis_returned_native_change_sompi"] + sum(u["native_payout_sompi"] for u in users)
    assert source - returned == fees
    orders.append({"first_recipient": first_user, "users": users,
                   "actual_shared_prefix_fee_sompi": shared, "exact_total_route_fee_sompi": fees,
                   "all_returned_native_outputs_sompi": returned,
                   "source_minus_returned_equals_fees": True, "final_reserve_sompi": 0})
out = here / "complete-prefix-4B-source.json"
if out.exists():
    raise SystemExit("refusing existing output")
result = {"format": "source-priced-one-source-complete-prefix-v1",
          "scope": "prospective signed-body targets; actual native MassCalculator/Full takes precedence",
          "reported_emitted_redeem_bytes": 22388, "private_budget": 1600,
          "one_external_source_oracle_sompi": source,
          "ordinary_preparation": prep,
          "preparation_outputs_sompi": [founding_coin, main_coin, source_change],
          "following_exact_target_packet_sha256": hashlib.sha256(raw).hexdigest(),
          "same_payer_two_real_notes_two_distinct_recipient_nochange": True,
          "full_payer_change_and_recipient_cashout_accounted": True,
          "per_order_integer_cost_allocation": orders,
          "maximum_individual_lifecycle_fee_sompi": max(u["all_modeled_route_fees_sompi"] for o in orders for u in o["users"]),
          "remaining_ordinary_service_retry_headroom_sompi": 10_000_000 - t["private_fee_sompi"] // 2,
          "service_proving_retry_costs_unpriced": True,
          "genuine_selected_proof_budget_nativeFull_backing_privacy_latency_not_qualified_by_this_calculator": True,
          "source_pins": [m.digest(here / "model.py"), m.digest(pathlib.Path(__file__).resolve()), m.digest(p)]}
out.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"output": str(out), **m.digest(out), "prep_fee_sompi": prep["fee_sompi"],
                  "max_individual_lifecycle_fee_sompi": result["maximum_individual_lifecycle_fee_sompi"],
                  "native_or_proving_executed": False}))
