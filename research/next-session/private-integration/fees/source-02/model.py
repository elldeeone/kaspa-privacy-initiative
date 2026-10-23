#!/usr/bin/env python3
"""Bounded integer fee research. No proving/native VM/RPC/wallet operations.

Prospective bodies below are size reservations, NOT emitted or accepted bodies.
All source/data dependencies are hashed; the frozen native arithmetic helper is
also checked against its known SHA before import. Unknown costs remain headroom.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
import pathlib
import resource

ROOT = pathlib.Path(__file__).resolve().parents[4]
BASE = "0c2f4c788a4274b381c4838e05cce5e9c32e8536"
HELPER = ROOT / "research/next-session/exit-fee/cost_envelope.py"
HELPER_SHA = "ea382803c79c07272c8485fb51505aabe27c90180e9f8e325de29f21f807a6df"
assert hashlib.sha256(HELPER.read_bytes()).hexdigest() == HELPER_SHA
SPEC = importlib.util.spec_from_file_location("frozen_native_cost", HELPER)
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)
PRINCIPAL = 1_000_000_000
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
ORDINARY_CAP = 10_000_000
LIFECYCLE_CAP = 20_000_000
MAX = 2_870_000_000_000_000_000
REFERENCE = 100
RATES = (100, 200, 500)
ARITIES = (1, 2, 3, 4, 5, 8, 12, 16)
ENVELOPES = (5_979, 16_384, 24_576, 32_768, 49_152)
COMMON_SIG_PREFIX = 199
CHECKS = {}


def digest(path):
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def allocate(total, count):
    """Deterministic maximum-difference-one shares; no phantom rounded costs."""
    q, r = divmod(total, count)
    shares = [q + (i < r) for i in range(count)]
    assert sum(shares) == total and max(shares) - min(shares) <= 1
    return shares


def metrics(sigs, budgets, payload, inputs, outputs, raw_spks):
    assert len(sigs) == len(inputs) == len(budgets)
    assert len(outputs) == len(raw_spks)
    assert all(0 < v <= MAX for _, v in inputs + outputs)
    # All modeled outputs have no covenant IDs. A future covenant ID is EXTRA.
    size = 94 + sum(54 + s for s in sigs) + sum(18 + s for s in raw_spks) + payload
    return native.mass(size, raw_spks, budgets, inputs, outputs)


def quote(rate, describe, cap=MAX):
    return native.least_fee(rate, describe, cap)


def exit_quote(envelope, value, remainder, rate, sig_prefix=COMMON_SIG_PREFIX):
    assert value >= NOTE_FLOOR and (remainder == 0 or remainder >= NOTE_FLOOR)
    def body(fee):
        outs = [(1, value - fee)] + ([(1, remainder)] if remainder else [])
        return metrics([envelope + sig_prefix], [200], 2029, [(1, value + remainder)],
                       outs, [34] + ([35] if remainder else []))
    row = quote(rate, body, value - PAYOUT_FLOOR)
    row["payout_sompi"] = value - row["fee_sompi"]
    row["claim_value_sompi"] = value
    row["reserve_remainder_sompi"] = remainder
    return row


def payment(envelope, useful, budget=1600):
    # ONE aggregate verifier, but preserve the native public state witnesses.
    # Current Auth484 minus NF64/CM64 leaves356 shared bytes; each logical
    # payment retains NF64+CM64+cipher528+public-witness3344=4000 bytes.
    # This reproduces core4356 atB1. Sharing header fields needs NEW binding;
    # arities>1 and budget are UNSELECTED, not accepted current wire.
    payload = 356 + 4000 * useful
    row = quote(REFERENCE, lambda fee: metrics(
        [envelope + COMMON_SIG_PREFIX], [budget], payload, [(1, 10**15)],
        [(1, 10**15 - fee)], [35]))
    row.update({"useful_payments": useful, "per_payment_shares_sompi": allocate(row["fee_sompi"], useful),
                "payload_reservation_bytes": payload, "budget_reservation": budget,
                "state_updates_attested_inside_aggregate_proof": False,
                "native_public_state_witness_bytes": 3344 * useful,
                "shared_authorization_header_bytes": 356,
                "new_relation_emitted_or_proved": False})
    return row


def admission(envelope, deposits, reserve, style, budget=200, whole_funding=None):
    count = len(deposits)
    # New minimal single-ingress proposal1344 bytes (includes genesis opening).
    # LargerB remains conditional:944/note plus400 shared, not frozen wire.
    payload = 400 + 944 * count
    if style == "whole_utxo":
        # Value deposited is actual funding input minus its own share; old
        # backing stays intact. No funding-change output or prep is necessary.
        funding = whole_funding or [1_100_000_000] * count
        def body(fee):
            shares = allocate(fee, count)
            new_notes = [v - f for v, f in zip(funding, shares)]
            return metrics([envelope + COMMON_SIG_PREFIX] + [66] * count,
                           [budget] + [10] * count, payload,
                           [(1, reserve)] + [(1, v) for v in funding],
                           [(1, reserve + sum(new_notes))], [35])
    else:
        assert style == "funding_change"
        funding = [v + NOTE_FLOOR for v in deposits]
        def body(fee):
            shares = allocate(fee, count)
            changes = [NOTE_FLOOR - f for f in shares]
            return metrics([envelope + COMMON_SIG_PREFIX] + [66] * count,
                           [budget] + [10] * count, payload,
                           [(1, reserve)] + [(1, v) for v in funding],
                           [(1, reserve + sum(deposits))] + [(1, c) for c in changes],
                           [35] + [34] * count)
    row = quote(REFERENCE, body, NOTE_FLOOR - PAYOUT_FLOOR)
    shares = allocate(row["fee_sompi"], count)
    actual_deposits = ([v - f for v, f in zip(funding, shares)]
                       if style == "whole_utxo" else deposits)
    changes = ([] if style == "whole_utxo" else [NOTE_FLOOR - f for f in shares])
    assert sum(funding) - sum(actual_deposits) - sum(changes) == row["fee_sompi"]
    row.update({"real_funders": count, "per_user_shares_sompi": shares,
                "funding_values_sompi": funding, "deposited_note_values_sompi": actual_deposits,
                "returned_native_change_sompi": changes, "old_reserve_sompi": reserve,
                "new_reserve_sompi": reserve + sum(actual_deposits),
                "payload_reservation_bytes": payload, "budget_reservation": budget,
                "style": style, "actual_new_admission_emitted_or_qualified": False})
    return row


def prepare_funding(target):
    # One actual generic P2PK topology: input -> target P2PK + native change.
    # The extra60M working capital remains the user's returned money and never
    # enlarges the payment principal. Small change can dominate KIP9 storage.
    return quote(REFERENCE, lambda fee: metrics(
        [66], [10], 0, [(1, target + NOTE_FLOOR)],
        [(1, target), (1, NOTE_FLOOR - fee)], [34, 34]),
        NOTE_FLOOR - PAYOUT_FLOOR)


def two_cashouts(envelope, value, change):
    """Worst of independent order/context endpoints; nobody waits to save fees.

    For a fixed claim V, S=K/(V-f)+K/r-K/(V+r) decreases as remaining r
    increases. Thus r=60M is a conservative bound over every backed state with
    another supported liability; terminal r=0 is checked separately.
    """
    assert change >= NOTE_FLOOR
    claims = []
    for note in (value, change):
        terminal = exit_quote(envelope, note, 0, REFERENCE)
        continuing = exit_quote(envelope, note, NOTE_FLOOR, REFERENCE)
        worst = max((terminal, continuing), key=lambda x: x["fee_sompi"])
        claims.append({"value_sompi": note, "terminal": terminal,
                       "independent_continuing_worst": continuing,
                       "conservative_fee_sompi": worst["fee_sompi"]})
    return claims


def two_recipient_pilot(envelope, budget, preparation):
    """ONE payer, ONE core2in2out proof, TWO real1B recipients, NO change.

    This is legitimate useful-payment amortization without sharing witnesses.
    It is not a general recipient+change transaction or multi-payer aggregate.
    """
    p = payment(envelope, 1, budget)
    fee_p = p["fee_sompi"]
    # Admission one-output storage is0 here, so amount choice does not affect
    # its mass. First quote then choose EXACT gross funding, with no lost tail.
    a = admission(envelope, [2 * PRINCIPAL + fee_p], NOTE_FLOOR,
                  "whole_utxo", whole_funding=[2_100_000_000])
    fee_a = a["fee_sompi"]
    exact_funding = 2 * PRINCIPAL + fee_p + fee_a
    exact_a = admission(envelope, [2 * PRINCIPAL + fee_p], NOTE_FLOOR,
                        "whole_utxo", whole_funding=[exact_funding])
    assert exact_a["fee_sompi"] == fee_a
    assert exact_a["deposited_note_values_sompi"] == [2 * PRINCIPAL + fee_p]
    prep = prepare_funding(exact_funding) if preparation else None
    f_prep = prep["fee_sompi"] if prep else 0
    # Both recipients can exit first while the other remains. Worst allowed
    # remaining liability60M also covers an unrelated existing pool liability.
    e = exit_quote(envelope, PRINCIPAL, NOTE_FLOOR, REFERENCE)
    shares_p, shares_a, shares_prep = (allocate(v, 2) for v in (fee_p, fee_a, f_prep))
    users = []
    for i in range(2):
        total = shares_p[i] + shares_a[i] + shares_prep[i] + e["fee_sompi"]
        users.append({"useful_recipient": i, "principal_sompi_counted_once": PRINCIPAL,
                      "ordinary_proof_fee_share_sompi": shares_p[i],
                      "same_payer_admission_fee_share_sompi": shares_a[i],
                      "ordinary_funding_fee_share_sompi": shares_prep[i],
                      "recipient_independent_cashout_fee_sompi": e["fee_sompi"],
                      "total_attributable_lifecycle_fee_sompi": total,
                      "ordinary_extra_cost_headroom_sompi": ORDINARY_CAP - shares_p[i],
                      "lifecycle_extra_cost_headroom_sompi": LIFECYCLE_CAP - total})
    assert exact_funding - 2 * (PRINCIPAL - e["fee_sompi"]) == fee_a + fee_p + 2 * e["fee_sompi"]
    exit500 = exit_quote(envelope, NOTE_FLOOR, NOTE_FLOOR, 500)
    return {"redeem_bytes": envelope, "private_payload_bytes": 4356,
            "private_script_sig_bytes": envelope + COMMON_SIG_PREFIX,
            "budget_reservation": budget, "funding_preparation": preparation,
            "ordinary_core_authorizations": 1, "actual_distinct_useful_recipient_outputs": 2,
            "payer_count": 1, "private_change_notes": 0,
            "gross_existing_funding_input_sompi": exact_funding,
            "admission_metrics": exact_a["metrics"], "private_metrics": p["metrics"],
            "recipient_claim_metrics": e["metrics"], "per_payment": users,
            "necessary_shape_screen_pass": exit500["passes"] and all(
                u["ordinary_extra_cost_headroom_sompi"] >= 0 and u["lifecycle_extra_cost_headroom_sompi"] >= 0 for u in users),
            "actual_genuine_proof_full_body_and_admission_still_required": True,
            "initialization_service_proving_retry_costs_unpriced": True}


def route(envelope, ba, bp, style, preparation, budget):
    cohort = math.lcm(ba, bp)
    p = payment(envelope, bp, budget)
    users = [{"index": i, "principal_sompi": PRINCIPAL} for i in range(cohort)]
    for start in range(0, cohort, bp):
        for j, share in enumerate(p["per_payment_shares_sompi"]):
            users[start + j]["payment_fee_sompi"] = share
    reserve = NOTE_FLOOR  # EXISTING authenticated liability; initialization EXTRA.
    admissions = []
    for start in range(0, cohort, ba):
        deposits = [PRINCIPAL + NOTE_FLOOR + u["payment_fee_sompi"]
                    for u in users[start:start + ba]]
        a = admission(envelope, deposits, reserve, style)
        admissions.append(a)
        reserve = a["new_reserve_sompi"]
        for j, u in enumerate(users[start:start + ba]):
            u["admission_fee_sompi"] = a["per_user_shares_sompi"][j]
            u["native_funding_input_sompi"] = a["funding_values_sompi"][j]
            u["deposited_note_sompi"] = a["deposited_note_values_sompi"][j]
            u["returned_native_change_sompi"] = (a["returned_native_change_sompi"][j]
                                                 if a["returned_native_change_sompi"] else 0)
            prep = prepare_funding(u["native_funding_input_sompi"]) if preparation else None
            u["funding_preparation_fee_sompi"] = prep["fee_sompi"] if prep else 0
            u["funding_preparation_metrics"] = prep["metrics"] if prep else None
    tail_valid = True
    for u in users:
        change = u["deposited_note_sompi"] - PRINCIPAL - u["payment_fee_sompi"]
        u["private_change_value_sompi"] = change
        if change < NOTE_FLOOR:
            tail_valid = False
            u["unsupported_private_tail"] = True
            continue
        cashouts = two_cashouts(envelope, PRINCIPAL, change)
        u["cashouts"] = cashouts
        u["cashout_fee_sompi"] = sum(x["conservative_fee_sompi"] for x in cashouts)
        u["recipient_pays_cashout_sompi"] = cashouts[0]["conservative_fee_sompi"]
        u["payer_pays_change_cashout_sompi"] = cashouts[1]["conservative_fee_sompi"]
        u["modeled_lifecycle_fee_sompi"] = sum(u[k] for k in (
            "payment_fee_sompi", "admission_fee_sompi", "funding_preparation_fee_sompi", "cashout_fee_sompi"))
        u["ordinary_headroom_sompi"] = ORDINARY_CAP - u["payment_fee_sompi"]
        u["lifecycle_headroom_sompi"] = LIFECYCLE_CAP - u["modeled_lifecycle_fee_sompi"]
        # All loss comes from the same user's actual inputs. Working capital,
        # reserve principal and returned change never enlarge the denominator.
        returned = PRINCIPAL + change + u["returned_native_change_sompi"] - u["cashout_fee_sompi"]
        assert (u["native_funding_input_sompi"] - returned ==
                u["modeled_lifecycle_fee_sompi"] - u["funding_preparation_fee_sompi"])
    if not tail_valid:
        return {"redeem_bytes": envelope, "Ba": ba, "Bp": bp, "style": style,
                "preparation": preparation, "passes_necessary_shape_screen": False,
                "reason": "private change below supported60M floor"}
    max_total = max(u["modeled_lifecycle_fee_sompi"] for u in users)
    max_payment = max(u["payment_fee_sompi"] for u in users)
    exit500 = exit_quote(envelope, NOTE_FLOOR, NOTE_FLOOR, 500)
    passes = (max_total <= LIFECYCLE_CAP and max_payment <= ORDINARY_CAP and exit500["passes"]
              and all(a["passes"] for a in admissions) and p["passes"])
    return {"redeem_bytes": envelope, "Ba": ba, "Bp": bp, "style": style,
            "funding_preparation": preparation, "aggregate_budget_reservation": budget,
            "cohort_users": cohort, "maximum_individual_payment_fee_sompi": max_payment,
            "maximum_individual_lifecycle_fee_sompi": max_total,
            "minimum_ordinary_extra_cost_headroom_sompi": ORDINARY_CAP - max_payment,
            "minimum_lifecycle_extra_cost_headroom_sompi": LIFECYCLE_CAP - max_total,
            "smallest_claim500_pass": exit500["passes"],
            "passes_necessary_shape_screen": passes,
            "all_in_or_genuine_lifecycle_qualified": False,
            "initialization_service_proving_retry_costs_unpriced": True,
            "admission_max_mass": max(a["metrics"]["normalized_mining_mass"] for a in admissions),
            "admission_max_storage": max(a["metrics"]["storage_mass"] for a in admissions),
            "payment_metrics": p["metrics"], "users": users}


def tests():
    for total in range(100):
        for n in ARITIES:
            assert sum(allocate(total, n)) == total
    CHECKS["exact_allocations"] = True
    assert native.mass(26114, [35], [1700], [(1, 1660000000)], [(1, 1580000000)])["normalized_mining_mass"] == 196484
    assert native.mass(30261, [35], [1600, 10], [(1, 800000000), (1, 900000000)], [(1, 1660000000)])["compute_mass"] == 191631
    assert native.mass(30141, [35], [1600], [(1, 1_000_000_000)], [(1, 960000000)])["compute_mass"] == 190511
    CHECKS["three_measured_mass_anchors"] = True
    for L, terminal_mass, continuing_mass in ((5979, 28637, 29060), (32768, 70132, 70238), (49152, 102900, 103006)):
        # Historical probe has old branch-specific69-byte prefix, preserved.
        t = exit_quote(L, NOTE_FLOOR, 0, 100, sig_prefix=69)
        c = exit_quote(L, PRINCIPAL, NOTE_FLOOR, 100, sig_prefix=69)
        assert t["metrics"]["normalized_mining_mass"] == terminal_mass
        assert c["metrics"]["normalized_mining_mass"] == continuing_mass
    CHECKS["exit_envelope_anchors"] = True
    assert payment(32768, 1)["metrics"]["compute_mass"] == 197894
    assert exit_quote(32768, NOTE_FLOOR, 0, 100)["metrics"]["normalized_mining_mass"] == 70392
    assert exit_quote(32768, PRINCIPAL, NOTE_FLOOR, 100)["metrics"]["normalized_mining_mass"] == 70498
    CHECKS["new_common_stack_core4356_and_reveal2029_sizes"] = True
    for rate in RATES:
        small = exit_quote(32768, NOTE_FLOOR, NOTE_FLOOR, rate)
        assert small["passes"] and small["payout_sompi"] >= PAYOUT_FLOOR
        assert not exit_quote(49152, NOTE_FLOOR, 0, 500)["passes"]
    # At each tested fee, the minimal other liability dominates larger reserve
    # remainders. This matches the separate algebraic derivative in the report.
    for value in (NOTE_FLOOR, PRINCIPAL, 100_000_000_000):
        for fee in (0, 1_000_000, 35_119_000):
            prior = None
            for rest in (NOTE_FLOOR, 100_000_000, PRINCIPAL, 10**15):
                stored = native.storage([(1, value + rest)], [(1, value - fee), (1, rest)])
                assert prior is None or stored <= prior
                prior = stored
    CHECKS["bounded_storage_monotonicity_and_minimum_exit"] = True
    # Verify monotone iteration yields the earliest sufficient fee on a small
    # integer toy, by exhaustive scan; real-fee space is not brute forced.
    for base in range(1, 20):
        def describe(f):
            m = base + f // 10
            return {"normalized_mining_mass": m, "native_dimension_limits_pass": True}
        q = quote(2, describe, 1000)
        exact = next(f for f in range(1000) if f >= 2 * (base + f // 10))
        assert q["fee_sompi"] == exact
    CHECKS["fixed_point_minimality_toy_exhaustive"] = True


def main():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing existing output")
    tests()
    sources = [HELPER, pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name("PLAN.md")]
    for p in ("docs/rfc/0012-useful-privacy-requirements.md", "research/next-session/AGGREGATE-COST-DESIGN.md",
              "research/next-session/ordinary-budget/REPORT.md", "research/next-session/ordinary-budget/actual-01/results/admit-report.json",
              "research/next-session/ordinary-budget/actual-01/results/paired1700-unchanged.json",
              "research/next-session/exit-fee/future-exit/FUTURE-COST-REVIEW.md",
              "research/next-session/exit-fee/future-exit/source-03/src/main.rs",
              "research/next-session/private-integration/NOTE-STATE-CONTRACT.md",
              "research/next-session/private-integration/native/INTEGRATION-PROPOSAL.md"):
        sources.append(ROOT / p)
    native_root = next(pathlib.Path("/home/luke/.cargo/git/checkouts").glob("rusty-kaspa-*/01b532e"))
    sources += [native_root / p for p in ("consensus/core/src/mass/mod.rs", "consensus/core/src/mass/units.rs",
                "consensus/core/src/config/params.rs", "crypto/txscript/src/zk_precompiles/groth16/mod.rs",
                "crypto/txscript/src/zk_precompiles/tags.rs")]
    rows = [route(L, ba, bp, style, prep, budget)
            for L in ENVELOPES[1:] for ba in ARITIES for bp in ARITIES
            for style, prep in (("whole_utxo", False), ("whole_utxo", True), ("funding_change", False))
            for budget in (1600, 1700)]
    # Keep full per-user evidence for small decisive rows; larger rows retain
    # exact maximum shares and dimensions rather than enormous repeated data.
    for row in rows:
        if row.get("cohort_users", 0) > 16 or row["Ba"] not in (1, 2, 4) or row["Bp"] not in (1, 2, 4, 8):
            row.pop("users", None)
    frontiers = []
    for L in ENVELOPES[1:]:
        for style, prep in (("whole_utxo", False), ("whole_utxo", True), ("funding_change", False)):
            for budget in (1600, 1700):
                candidates = [r for r in rows if r["redeem_bytes"] == L and r["style"] == style
                              and r.get("funding_preparation") == prep
                              and r.get("aggregate_budget_reservation") == budget
                              and r["passes_necessary_shape_screen"]]
                pareto = [r for r in candidates if not any(
                    s["Ba"] <= r["Ba"] and s["Bp"] <= r["Bp"] and
                    (s["Ba"], s["Bp"]) != (r["Ba"], r["Bp"]) for s in candidates)]
                frontiers.append({"redeem_bytes": L, "style": style, "funding_preparation": prep,
                                  "aggregate_budget_reservation": budget,
                                  "pareto_smallest_arity_pairs": [{k: r[k] for k in (
                                      "Ba", "Bp", "maximum_individual_payment_fee_sompi",
                                      "maximum_individual_lifecycle_fee_sompi",
                                      "minimum_lifecycle_extra_cost_headroom_sompi")} for r in pareto]})
    result = {"format": "candidate-C-complete-route-economic-screen-v1", "source_baseline": BASE,
              "scope": "source-derived conditional sizes and integer arithmetic; no new native/proof/runtime transactions",
              "principal_sompi_counted_once": PRINCIPAL, "ordinary_cap_sompi": ORDINARY_CAP,
              "lifecycle_cap_sompi": LIFECYCLE_CAP, "reference_rate": REFERENCE,
              "unknown_startup_service_proving_retry_costs_treated_as_unallocated_headroom": True,
              "old_authorized_fees_repriced": False,
              "actual_old_admit_fee_sompi": 40_000_000,
              "actual_old_B2_total_fee_sompi": 80_000_000,
              "direct_single_useful_payment_verifier_floor_fee_sompi": 14_750_000,
              "current_B2_shape_plus32KiB_1700_mass": 204676,
              "historical_branch_stack_unamortized_admit_plus32KiB_exit_floor_fee_sompi": 21763200,
              "new_common_stack_unamortized_admit_plus32KiB_exit_floor_fee_sompi": 21789200,
              "unimplemented_assumptions": ["native public ingress wire/emitter and privacy approval",
                  "one real aggregate proof, not B separately metered native proofs", "aggregate shared-header binding",
                  "new receipt/transcript lengths match reservation", "new aggregate1600/1700 native source bound",
                  "authentic genesis/lineage", "concrete per-user service/retry/startup costs", "healthy batch latency"],
              "checks": CHECKS, "source_pins": [digest(p) for p in sources],
              "two_real_recipient_nochange_core_pilot": [two_recipient_pilot(L, budget, prep)
                    for L in ENVELOPES[1:] for budget in (1600, 1700) for prep in (False, True)],
              "pilot_analytic_no_preparation_necessary_envelope_caps": [
                  {"private_budget_reservation": budget, "extra_per_payment_sompi": extra,
                   "maximum_redeem_bytes": (LIFECYCLE_CAP - (5000 * budget + 938900) - extra) // 350,
                   "formula_per_payment_fee_sompi": f"350*redeem_bytes+{5000 * budget + 938900}",
                   "scope": "1344 native ingress;4356 core;2029 reveal;common199;admit/reveal budget200;two equal1B recipients;no prep;high-L region;not emitted"}
                  for budget in (1600, 1700) for extra in (0, 500000, 1000000)],
              "small_claim_all_rates": [{"redeem_bytes": L, "rate": rate,
                   "terminal": exit_quote(L, NOTE_FLOOR, 0, rate),
                   "minimum_other_liability": exit_quote(L, NOTE_FLOOR, NOTE_FLOOR, rate)}
                   for L in ENVELOPES for rate in RATES],
              "pareto_necessary_shape_frontiers": frontiers, "routes": rows}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), **digest(args.output), "route_rows": len(rows),
                      "checks": CHECKS, "native_or_proving_executed": False}))


if __name__ == "__main__":
    main()
