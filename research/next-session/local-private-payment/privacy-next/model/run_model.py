"""Finite hypothetical information flow. Pure functions; no I/O or real crypto.

Load source and INPUTS through the unchanged guarded reader after source review.
run_model() returns evidence objects; this module has no automatic entry point.
"""

from copy import deepcopy
from itertools import combinations, permutations
import hashlib
import json
import re


PUBLIC_OUTPUT_FIELDS = ("tuple", "cm", "cv", "cf", "proof")


def need(condition, message):
    if not condition:
        raise AssertionError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def public_output(row):
    return {field: row[field] for field in PUBLIC_OUTPUT_FIELDS}


def check_inputs(data):
    need(data["schema"] == "fictional-finite-information-flow/v1", "input-schema")
    need(data["owner_order"] == list("ABCDE"), "frozen-owner-order")
    need(data["colluding_owner"] == "C", "frozen-colluder")
    need(data["honest_query_owners"] == ["A", "B"], "frozen-honest-queries")
    need(data["amounts"] == {"input": 2000000000, "payment": 100000000,
        "change": 1890000000, "fee": 10000000, "note_floor": 60000000,
        "max": 18446744073709551615}, "frozen-amounts")
    symbols = []
    for owner in data["owner_order"]:
        row = data["owners"][owner]
        symbols.extend(row[field] for field in ("nf", "nonce", "delta", "key", "backup", "upload"))
        need(len(row["outputs"]) == 2, "two-real-output-tuples")
        need({out["kind"] for out in row["outputs"]} == {"payment", "change"}, "output-roles")
        for out in row["outputs"]:
            symbols.extend(out[field] for field in PUBLIC_OUTPUT_FIELDS + ("spend_nf",))
    need(len(symbols) == len(set(symbols)), "all-opaque-symbols-distinct")
    need(all(re.fullmatch(r"[a-z][0-9a-f]{8}", symbol) for symbol in symbols), "opaque-literal-format")
    need(not any(owner in symbol for owner in data["owner_order"] for symbol in symbols),
         "opaque-symbols-do-not-contain-owner-labels")
    expected = {
        "accepted_single": [list("ABC")],
        "same_cohort": [list("ABC"), list("ABC")],
        "forced_exit_changed_cohort": [list("ABC"), list("ADE")],
        "reorg_then_changed_cohort": [list("ABC"), list("ADE")],
    }
    need({key: value["releases"] for key, value in data["schedules"].items()} == expected,
         "frozen-release-schedules")


def make_view(data, scenario, observer, variant="hidden", corrupt_servers=1):
    """Evaluator projection; no owner-to-row mapping enters hidden views."""
    owners = data["owners"]
    schedule = data["schedules"][scenario]
    represented = sorted(set().union(*map(set, schedule["releases"])))
    batches = []
    for cohort in schedule["releases"]:
        batches.append({
            "nfs": sorted(owners[owner]["nf"] for owner in cohort),
            "outputs": sorted(out["tuple"] for owner in cohort for out in owners[owner]["outputs"]),
            "known_owner_cohort": sorted(cohort) if observer == "O-active" else None,
        })
    view = {
        "observer": observer, "scenario": scenario, "variant": variant,
        "owner_universe": represented, "batches": batches,
        "events": schedule["events"] if observer == "O-active" else {
            "accepted_single": ["batch_egress_0", "batch_accepted_0"],
            "same_cohort": ["batch_egress_0", "unrelated_exit_moves_head", "batch_egress_1"],
            "forced_exit_changed_cohort": ["batch_egress_0", "independent_exit_wins", "old_batch_rejected", "batch_egress_1"],
            "reorg_then_changed_cohort": ["batch_egress_0", "apparent_acceptance", "reorg", "independent_exit_wins", "batch_egress_1"],
        }[scenario],
        "public_output_rows": sorted(
            [public_output(out) for owner in represented for out in owners[owner]["outputs"]],
            key=lambda out: out["tuple"]),
        "known_owner_nf": {}, "known_owner_outputs": {}, "public_nf_pair": {},
        "individual_delta_equality_answers": [], "session_metadata": [],
        "public_exits": [],
        "corrupt_servers": corrupt_servers,
        "owners_online_at_egress": [], "owner_contacts_after_upload": 0,
    }
    if scenario != "accepted_single":
        exit_owner = "D" if scenario == "same_cohort" else "C"
        view["public_exits"] = [{"nf": owners[exit_owner]["nf"],
            "payout_sompi": data["amounts"]["input"] - data["amounts"]["fee"],
            "destination": "u0b71e8a4", "outside_queued_intents": exit_owner not in represented}]
    if observer == "O-active":
        colluder = data["colluding_owner"]
        view["known_owner_nf"][colluder] = owners[colluder]["nf"]
        view["known_owner_outputs"][colluder] = sorted(out["tuple"] for out in owners[colluder]["outputs"])
        view["session_metadata"] = [{"owner": owner, "upload_handle": owners[owner]["upload"],
            "symbolic_upload_time": index, "stopped_before_egress": True}
            for index, owner in enumerate(represented)]
    if variant in ("plain", "pair_id", "individual_delta"):
        for owner in represented:
            nf = owners[owner]["nf"]
            pair = sorted(out["tuple"] for out in owners[owner]["outputs"])
            view["public_nf_pair"][nf] = pair
            if variant == "individual_delta":
                # Explicit ideal public equality oracle. The unique pair is an
                # assumption for this control, not a real group calculation.
                view["individual_delta_equality_answers"].append(
                    {"nf": nf, "delta": owners[owner]["delta"], "matching_pair": pair})
        if variant == "plain" and observer == "O-active":
            view["known_owner_nf"] = {owner: owners[owner]["nf"] for owner in represented}
            view["known_owner_outputs"] = {owner: sorted(out["tuple"] for out in owners[owner]["outputs"])
                for owner in represented}
    if observer == "O-active" and corrupt_servers >= data["server_model"]["reconstructing_coalition"]:
        view["known_owner_nf"] = {owner: owners[owner]["nf"] for owner in represented}
        view["known_owner_outputs"] = {owner: sorted(out["tuple"] for out in owners[owner]["outputs"])
            for owner in represented}
        view["threshold_privacy"] = "outside_assumption_reconstruction_allowed"
    else:
        view["threshold_privacy"] = "assumed_ideal_opacity_not_measured"
    return view


def enumerate_assignments(view):
    """Enumerate ALL bijections and two-output partitions allowed by this view.

    A row's complete appearance signature is public. Because one durable intent
    retains one NF and two exact output tuples, its NF and both outputs must
    have equal signatures across all released batches. This includes output-set
    intersection, even for O-ledger without named cohort observations.
    """
    owners = tuple(view["owner_universe"])
    batches = view["batches"]
    nfs = sorted(set().union(*(set(batch["nfs"]) for batch in batches)))
    outputs = sorted(set().union(*(set(batch["outputs"]) for batch in batches)))
    need(len(nfs) == len(owners) and len(outputs) == 2 * len(owners), "one-intent-per-model-owner")
    nf_signatures = {nf: tuple(i for i, batch in enumerate(batches) if nf in batch["nfs"]) for nf in nfs}
    out_signatures = {out: tuple(i for i, batch in enumerate(batches) if out in batch["outputs"])
                      for out in outputs}
    worlds = []
    for ordered_nfs in permutations(nfs):
        owner_nf = dict(zip(owners, ordered_nfs))
        if any(owner_nf[owner] != nf for owner, nf in view["known_owner_nf"].items()):
            continue
        if any(batch["known_owner_cohort"] is not None and
               {owner for owner in owners if owner_nf[owner] in batch["nfs"]} != set(batch["known_owner_cohort"])
               for batch in batches):
            continue
        choices = {}
        for owner in owners:
            nf = owner_nf[owner]
            eligible = [out for out in outputs if out_signatures[out] == nf_signatures[nf]]
            pairs = list(combinations(eligible, 2))
            known = view["known_owner_outputs"].get(owner)
            if known is not None:
                pairs = [pair for pair in pairs if pair == tuple(known)]
            linked = view["public_nf_pair"].get(nf)
            if linked is not None:
                pairs = [pair for pair in pairs if pair == tuple(linked)]
            choices[owner] = pairs

        def extend(index, used, selected):
            if index == len(owners):
                need(used == set(outputs), "complete-partition-coverage")
                worlds.append([[owner_nf[owner], list(selected[owner])] for owner in owners])
                return
            owner = owners[index]
            for pair in choices[owner]:
                if not used.intersection(pair):
                    extend(index + 1, used.union(pair), dict(selected, **{owner: pair}))

        extend(0, set(), {})
    need(worlds, "observer-view-has-no-consistent-assignment")
    nf_owner = {nf: set() for nf in nfs}
    nf_pair = {nf: set() for nf in nfs}
    owner_nf_candidates = {owner: set() for owner in owners}
    owner_pairs = {owner: set() for owner in owners}
    output_owner = {out: set() for out in outputs}
    for world in worlds:
        for owner, (nf, pair) in zip(owners, world):
            nf_owner[nf].add(owner)
            nf_pair[nf].add(tuple(pair))
            owner_nf_candidates[owner].add(nf)
            owner_pairs[owner].add(tuple(pair))
            for out in pair:
                output_owner[out].add(owner)
    summary = {
        "joint_assignment_count": len(worlds),
        "enumeration_sha256": hashlib.sha256(canonical(worlds).encode()).hexdigest(),
        "owner_order_for_compact_assignments": list(owners),
        "assignment_cell_format": "[NF, [complete_output_tuple_token_0, complete_output_tuple_token_1]]",
        "nf_owner_candidates": {key: sorted(value) for key, value in nf_owner.items()},
        "owner_nf_candidates": {key: sorted(value) for key, value in owner_nf_candidates.items()},
        "nf_output_pair_candidates": {key: [list(pair) for pair in sorted(value)] for key, value in nf_pair.items()},
        "owner_output_pair_candidates": {key: [list(pair) for pair in sorted(value)] for key, value in owner_pairs.items()},
        "output_owner_candidates": {key: sorted(value) for key, value in output_owner.items()},
    }
    return summary, worlds


def check_information_flow(data):
    summaries, assignments = {}, {}
    specifications = [("accepted_single", observer, variant, 1)
        for observer in ("O-ledger", "O-active")
        for variant in ("hidden", "plain", "pair_id", "individual_delta")]
    specifications += [("accepted_single", "O-active", "hidden", 2)]
    specifications += [(scenario, observer, "hidden", 1)
        for scenario in ("same_cohort", "forced_exit_changed_cohort", "reorg_then_changed_cohort")
        for observer in ("O-ledger", "O-active")]
    expected_counts = {
        ("accepted_single", "O-ledger", "hidden", 1): 540,
        ("accepted_single", "O-active", "hidden", 1): 12,
        ("accepted_single", "O-ledger", "plain", 1): 6,
        ("accepted_single", "O-active", "plain", 1): 1,
        ("accepted_single", "O-ledger", "pair_id", 1): 6,
        ("accepted_single", "O-active", "pair_id", 1): 2,
        ("accepted_single", "O-ledger", "individual_delta", 1): 6,
        ("accepted_single", "O-active", "individual_delta", 1): 2,
        ("accepted_single", "O-active", "hidden", 2): 1,
        ("same_cohort", "O-ledger", "hidden", 1): 540,
        ("same_cohort", "O-active", "hidden", 1): 12,
        ("forced_exit_changed_cohort", "O-ledger", "hidden", 1): 4320,
        ("forced_exit_changed_cohort", "O-active", "hidden", 1): 12,
        ("reorg_then_changed_cohort", "O-ledger", "hidden", 1): 4320,
        ("reorg_then_changed_cohort", "O-active", "hidden", 1): 12,
    }
    for specification in specifications:
        scenario, observer, variant, corrupt = specification
        key = "/".join((scenario, observer, variant, str(corrupt)))
        view = make_view(data, *specification[:3], corrupt_servers=corrupt)
        summary, worlds = enumerate_assignments(view)
        need(summary["joint_assignment_count"] == expected_counts[specification], "frozen-count:" + key)
        summary["view"] = view
        summaries[key] = summary
        assignments[key] = worlds
    a_nf = data["owners"]["A"]["nf"]
    baseline = summaries["accepted_single/O-active/hidden/1"]
    need(len(baseline["owner_nf_candidates"]["A"]) == 2, "baseline-A-NF-multiplicity")
    need(len(baseline["owner_output_pair_candidates"]["A"]) == 6, "baseline-A-output-multiplicity")
    for scenario in ("forced_exit_changed_cohort", "reorg_then_changed_cohort"):
        active = summaries[scenario + "/O-active/hidden/1"]
        ledger = summaries[scenario + "/O-ledger/hidden/1"]
        need(len(active["owner_nf_candidates"]["A"]) == 1, "expected-active-stable-NF-intersection")
        need(len(active["owner_output_pair_candidates"]["A"]) == 1, "expected-active-stable-output-intersection")
        need(len(ledger["nf_output_pair_candidates"][a_nf]) == 1, "expected-ledger-cross-attempt-partition-link")
    for observer in ("O-ledger", "O-active"):
        for variant in ("plain", "pair_id", "individual_delta"):
            cell = summaries["accepted_single/" + observer + "/" + variant + "/1"]
            need(all(len(pairs) == 1 for pairs in cell["nf_output_pair_candidates"].values()),
                 "expected-visible-partition-control:" + variant)
    return summaries, assignments


class Reject(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Reject(reason)


def amount(value, data, positive=True):
    require(type(value) is int, "amount-integer-sompi")
    require((1 if positive else 0) <= value <= data["amounts"]["max"], "amount-range")


def approved_intents(data):
    intents = {}
    for owner, source in data["owners"].items():
        outputs = []
        for out in source["outputs"]:
            receiver = source["payment_to"] if out["kind"] == "payment" else owner
            outputs.append(dict(out, value=data["amounts"][out["kind"]],
                                recipient_key=data["owners"][receiver]["key"]))
        intents[source["nonce"]] = {"pool": data["pool"], "profile": data["profile"],
            "anchor": data["anchor"], "anchor_count": 5, "nf": source["nf"],
            "nonce": source["nonce"], "input_value": data["amounts"]["input"],
            "fee": data["amounts"]["fee"], "outputs": outputs}
    return intents


def initial_state(data):
    notes, public_rows, decrypt = {}, [], {}
    for index, owner in enumerate(data["owner_order"]):
        row = data["owners"][owner]
        # Genesis descriptor recovery is an explicit oracle, not key derivation.
        cf = "genesis-ciphertext-" + str(index)
        note = {"nf": row["nf"], "value": data["amounts"]["input"],
            "key": row["key"], "position": index, "cf": cf}
        notes[row["nf"]] = note
        public_rows.append({"cf": cf, "position": index, "tuple": "genesis-output-" + str(index)})
        decrypt[cf] = deepcopy(note)
    return {"head": 0, "reserve": 5 * data["amounts"]["input"], "notes": notes,
        "spent": set(), "accepted_anchors": {data["anchor"]}, "next_position": 5,
        "public_rows": public_rows, "ideal_decrypt": decrypt, "paid": 0, "fees": 0}


def invariant(state, initial_reserve):
    need(state["reserve"] == sum(note["value"] for note in state["notes"].values()), "exact-remaining-backing")
    need(state["reserve"] + state["paid"] + state["fees"] == initial_reserve, "complete-integer-accounting")
    need(not state["spent"].intersection(state["notes"]), "no-spent-live-note")


def proposal(data, approved, owner_names, head):
    return {"pool": data["pool"], "profile": data["profile"], "head": head,
        "proof_valid": True, "native_payout": 0,
        "intents": [deepcopy(approved[data["owners"][owner]["nonce"]]) for owner in owner_names]}


def accept_batch(data, approved, state, candidate):
    """Ideal proof/consent/state gate. Every rejection leaves caller state intact."""
    require(candidate["pool"] == data["pool"], "wrong-pool")
    require(candidate["profile"] == data["profile"], "wrong-profile")
    require(candidate["head"] == state["head"], "stale-final-head")
    require(candidate["proof_valid"] is True, "invalid-ideal-proof")
    require(candidate["native_payout"] == 0, "unauthorized-native-payout")
    seen_nf, seen_nonce = set(), set()
    for intent in candidate["intents"]:
        require(intent["nonce"] not in seen_nonce, "duplicate-intent")
        require(intent["nf"] not in seen_nf, "duplicate-NF")
        seen_nf.add(intent["nf"])
        seen_nonce.add(intent["nonce"])
        require(intent["nonce"] in approved, "unknown-intent")
        require(intent == approved[intent["nonce"]], "restricted-consent-mismatch")
        require(intent["anchor"] in state["accepted_anchors"] and intent["anchor_count"] == 5,
                "bad-historical-anchor")
        require(intent["nf"] in state["notes"] and intent["nf"] not in state["spent"], "spent-or-missing-NF")
        amount(intent["input_value"], data)
        amount(intent["fee"], data)
        for out in intent["outputs"]:
            amount(out["value"], data)
            require(out["value"] >= data["amounts"]["note_floor"], "output-note-floor")
        require(len(intent["outputs"]) == 2, "exact-two-approved-outputs")
        require(intent["input_value"] == state["notes"][intent["nf"]]["value"], "input-value-opening")
        require(intent["input_value"] == sum(out["value"] for out in intent["outputs"]) + intent["fee"],
                "per-intent-value-conservation")
    tuples = [out["tuple"] for intent in candidate["intents"] for out in intent["outputs"]]
    require(len(tuples) == len(set(tuples)), "duplicate-output-tuple")
    total_fee = sum(intent["fee"] for intent in candidate["intents"])
    amount(total_fee, data)
    require(total_fee <= state["reserve"], "reserve-fee-underflow")
    following = deepcopy(state)
    for intent in candidate["intents"]:
        del following["notes"][intent["nf"]]
        following["spent"].add(intent["nf"])
    # Public positions use one global tuple order, with no per-intent framing.
    # Keeping each intent's two rows adjacent here would itself leak a partition.
    ordered_outputs = sorted((out for intent in candidate["intents"] for out in intent["outputs"]),
                             key=lambda out: out["tuple"])
    for out in ordered_outputs:
        require(out["spend_nf"] not in following["notes"] and out["spend_nf"] not in following["spent"],
                "output-authority-collision")
        note = {"nf": out["spend_nf"], "value": out["value"], "key": out["recipient_key"],
                "position": following["next_position"], "cf": out["cf"]}
        following["notes"][out["spend_nf"]] = note
        following["public_rows"].append(dict(public_output(out), position=note["position"]))
        following["ideal_decrypt"][out["cf"]] = deepcopy(note)
        following["next_position"] += 1
    following["reserve"] -= total_fee
    following["fees"] += total_fee
    following["head"] += 1
    return following


def direct_exit(data, state, nf, key, head, destination, approved_destination, proof_valid=True):
    require(head == state["head"], "stale-exit-head")
    require(proof_valid is True, "invalid-exit-proof-oracle")
    require(nf in state["notes"] and nf not in state["spent"], "spent-or-missing-exit-NF")
    require(key == state["notes"][nf]["key"], "wrong-exit-authority")
    require(destination == approved_destination, "exit-destination-substitution")
    fee = data["amounts"]["fee"]
    gross = state["notes"][nf]["value"]
    require(gross - fee >= data["amounts"]["note_floor"], "exit-payout-floor")
    following = deepcopy(state)
    del following["notes"][nf]
    following["spent"].add(nf)
    following["reserve"] -= gross
    following["paid"] += gross - fee
    following["fees"] += fee
    following["head"] += 1
    return following


def recover(data, state, backup, available_cf=True, available_tree=True):
    """Only fictional backup + accepted public rows and explicit crypto oracles.

    The ideal_decrypt table models encryption/key derivation. It is NOT a
    coordinator owner/partition table, a real algorithm or recovery evidence.
    """
    require(available_cf and available_tree, "public-data-unavailable")
    key = next((row["key"] for row in data["owners"].values() if row["backup"] == backup), None)
    require(key is not None, "unknown-fictional-backup")
    found = []
    for public in state["public_rows"]:
        opening = state["ideal_decrypt"][public["cf"]]
        if opening["key"] == key and opening["nf"] not in state["spent"]:
            require(opening["position"] == public["position"], "authenticated-position-oracle")
            found.append(deepcopy(opening))
    return found


def check_safety_and_availability(data):
    approved = approved_intents(data)
    initial = initial_state(data)
    total = initial["reserve"]
    results = []

    def reject_case(name, operation):
        before = deepcopy(initial)
        try:
            operation()
        except Reject as error:
            need(initial == before, "rejection-mutated-state:" + name)
            results.append({"case": name, "outcome": "expected_rejection", "reason": str(error)})
            return
        raise AssertionError("negative-control-accepted:" + name)

    base = proposal(data, approved, "ABC", initial["head"])
    accepted = accept_batch(data, approved, initial, base)
    invariant(accepted, total)
    results.append({"case": "offline_exact_consent", "outcome": "modeled_acceptance",
                    "owner_contacts_after_upload": 0})
    mutations = {}
    for name, field, value in [("wrong_pool", "pool", "fictional-foreign-pool"),
            ("wrong_profile", "profile", "fictional-foreign-profile"),
            ("stale_final_head", "head", -1), ("invalid_proof", "proof_valid", False),
            ("coordinator_payout", "native_payout", 1)]:
        changed = deepcopy(base)
        changed[field] = value
        mutations[name] = changed
    for name in ("tuple_substitution", "CF_substitution", "recipient_substitution", "fee_substitution",
                 "bad_anchor", "bad_anchor_count", "output_rerandomization", "bool_fee", "overflow_fee"):
        changed = deepcopy(base)
        intent = changed["intents"][0]
        if name == "tuple_substitution": intent["outputs"][0]["tuple"] = "o00112233"
        if name == "CF_substitution": intent["outputs"][0]["cf"] = "f00112233"
        if name == "recipient_substitution": intent["outputs"][0]["recipient_key"] = "k00112233"
        if name == "fee_substitution": intent["fee"] += 1
        if name == "bad_anchor": intent["anchor"] = "fictional-forged-anchor"
        if name == "bad_anchor_count": intent["anchor_count"] = 4
        if name == "output_rerandomization":
            for field in PUBLIC_OUTPUT_FIELDS: intent["outputs"][0][field] = field[0] + "00112233"
        if name == "bool_fee": intent["fee"] = True
        if name == "overflow_fee": intent["fee"] = data["amounts"]["max"] + 1
        mutations[name] = changed
    redistributed = deepcopy(base)
    redistributed["intents"][0]["fee"] += 1
    redistributed["intents"][0]["outputs"][1]["value"] -= 1
    redistributed["intents"][1]["fee"] -= 1
    redistributed["intents"][1]["outputs"][1]["value"] += 1
    need(sum(i["fee"] for i in redistributed["intents"]) == sum(i["fee"] for i in base["intents"]),
         "fee-redistribution-global-sum-control")
    mutations["global_balanced_fee_redistribution"] = redistributed
    duplicate = deepcopy(base)
    duplicate["intents"][1] = deepcopy(duplicate["intents"][0])
    mutations["duplicate_intent_and_NF"] = duplicate
    duplicate_nf = deepcopy(base)
    duplicate_nf["intents"][1]["nf"] = duplicate_nf["intents"][0]["nf"]
    mutations["duplicate_NF"] = duplicate_nf
    for name, changed in mutations.items():
        reject_case(name, lambda changed=changed: accept_batch(data, approved, initial, changed))
    stale_successor = deepcopy(base)
    reject_case("second_successor", lambda: accept_batch(data, approved, accepted, stale_successor))
    after_d_exit = direct_exit(data, initial, data["owners"]["D"]["nf"], data["owners"]["D"]["key"],
                               initial["head"], "fictional-D-payout", "fictional-D-payout")
    invariant(after_d_exit, total)
    reject_case("head_advanced_old_final_proof", lambda: accept_batch(data, approved, after_d_exit, base))
    rebuilt = proposal(data, approved, "ABC", after_d_exit["head"])
    rebuilt_accept = accept_batch(data, approved, after_d_exit, rebuilt)
    invariant(rebuilt_accept, total)
    need(rebuilt["intents"] == base["intents"], "durable-retry-exact-unchanged-consent")
    results.append({"case": "unrelated_exit_then_offline_rebuild", "outcome": "modeled_acceptance",
                    "owner_contacts_after_upload": 0, "exact_output_tuples_retained": True})
    c = data["owners"]["C"]
    after_c_exit = direct_exit(data, initial, c["nf"], c["key"], initial["head"],
                               "fictional-C-payout", "fictional-C-payout")
    invariant(after_c_exit, total)
    reject_case("colluder_exit_invalidates_egressed_batch", lambda: accept_batch(data, approved, after_c_exit, base))
    still_bad = proposal(data, approved, "ABC", after_c_exit["head"])
    reject_case("rebuild_cannot_reuse_spent_colluder_NF", lambda: accept_batch(data, approved, after_c_exit, still_bad))
    changed_cohort = proposal(data, approved, "ADE", after_c_exit["head"])
    changed_accept = accept_batch(data, approved, after_c_exit, changed_cohort)
    invariant(changed_accept, total)
    need(changed_cohort["intents"][0] == base["intents"][0], "A-outputs-and-consent-stable-after-abort")
    results.append({"case": "fixed_servers_allow_changed_owner_cohort", "outcome": "modeled_valid_but_retry_linkage_expected",
                    "A_B_unspent_after_C_exit": all(data["owners"][o]["nf"] in after_c_exit["notes"] for o in "AB")})
    a_source = data["owners"]["A"]
    fallback = direct_exit(data, after_c_exit, a_source["nf"], a_source["key"], after_c_exit["head"],
                           "fictional-A-fallback", "fictional-A-fallback")
    invariant(fallback, total)
    results.append({"case": "refuse_all_changed_cohort_retries_after_egress",
        "outcome": "private_payment_liveness_loss", "original_ABC_cannot_settle": True,
        "direct_exit_is_not_locked": True, "durable_seed_only_refusal_is_not_implemented": True})
    reorg = deepcopy(initial)
    orphaned_nf = base["intents"][0]["outputs"][0]["spend_nf"]
    orphaned_key = base["intents"][0]["outputs"][0]["recipient_key"]
    reject_case("orphaned_output_cannot_exit", lambda: direct_exit(data, reorg, orphaned_nf, orphaned_key,
        reorg["head"], "fictional-orphan-payout", "fictional-orphan-payout"))
    reject_case("replay_orphaned_final_head", lambda: accept_batch(data, approved, reorg,
        proposal(data, approved, "ABC", accepted["head"])))
    replay = accept_batch(data, approved, reorg, proposal(data, approved, "ABC", reorg["head"]))
    invariant(replay, total)
    need(replay["spent"] == accepted["spent"], "reorg-replay-NF-reconciliation")
    reject_case("operator_key_cannot_exit", lambda: direct_exit(data, initial, c["nf"], "fictional-operator-key",
        initial["head"], "fictional-C-payout", "fictional-C-payout"))
    reject_case("exit_destination_substitution", lambda: direct_exit(data, initial, c["nf"], c["key"],
        initial["head"], "fictional-attacker-payout", "fictional-C-payout"))
    reject_case("invalid_exit_proof", lambda: direct_exit(data, initial, c["nf"], c["key"],
        initial["head"], "fictional-C-payout", "fictional-C-payout", proof_valid=False))
    reject_case("double_exit", lambda: direct_exit(data, after_c_exit, c["nf"], c["key"],
        after_c_exit["head"], "fictional-C-payout", "fictional-C-payout"))
    a = data["owners"]["A"]
    before_found = recover(data, initial, a["backup"])
    need(len(before_found) == 1, "backup-recovers-unmaterialized-original-note")
    before_exit = direct_exit(data, initial, before_found[0]["nf"], before_found[0]["key"],
                             initial["head"], "fictional-A-payout", "fictional-A-payout")
    invariant(before_exit, total)
    after_found = recover(data, accepted, a["backup"])
    need(len(after_found) == 2, "backup-recovers-received-and-change-without-partition")
    after_exit = direct_exit(data, accepted, after_found[0]["nf"], after_found[0]["key"],
                            accepted["head"], "fictional-A-payout", "fictional-A-payout")
    invariant(after_exit, total)
    results.extend([
        {"case": "all_servers_disappear_before_acceptance", "outcome": "modeled_direct_exit_available",
         "private_batch_liveness": False, "authority_source": "fictional_backup_and_public_history_oracles"},
        {"case": "all_servers_disappear_after_acceptance", "outcome": "modeled_recovery_and_direct_exit_available",
         "received_and_change_notes_found": 2, "partition_or_pending_journal_required": False},
    ])
    reject_case("accepted_CF_withheld", lambda: recover(data, accepted, a["backup"], available_cf=False))
    reject_case("accepted_tree_history_withheld", lambda: recover(data, accepted, a["backup"], available_tree=False))
    results.append({"case": "missing_public_data", "outcome": "availability_failure_not_fund_authority_loss",
                    "current_state_exit_witness_unavailable": True})
    for name, state in [("initial", initial), ("accepted_ABC", accepted), ("C_exit", after_c_exit),
                        ("changed_ADE", changed_accept), ("post_acceptance_A_exit", after_exit)]:
        invariant(state, total)
        results.append({"case": "accounting_" + name, "outcome": "modeled_exact_accounting",
            "reserve_sompi": state["reserve"], "live_liability_sompi": sum(n["value"] for n in state["notes"].values()),
            "payout_sompi": state["paid"], "fee_sompi": state["fees"], "initial_sompi": total})
    return results


def run_model(data):
    check_inputs(data)
    information, assignments = check_information_flow(data)
    controls = check_safety_and_availability(data)
    return {"summary": {
        "schema": "fictional-finite-information-flow-result/v1",
        "verdict": "frozen_model_expectations_met",
        "evidence_boundary": "Ideal finite information flow and ideal accounting only; no cryptographic, native, network, actual recovery, paid-fee or production qualification.",
        "assumptions": data["assumptions"],
        "expected_active_retry_result": "known-cohort stable NF AND stable complete-output-set linkage retained",
        "liveness_limit": "Refusing cohort changes cannot settle the original batch after a member spends; original-seed direct exits remain a separate modeled route.",
        "fee_result": "unmeasured; old 21-KAS 2-percent FAIL unchanged",
        "information_flow": information, "safety_and_availability": controls,
    }, "enumerated_assignments": assignments}
