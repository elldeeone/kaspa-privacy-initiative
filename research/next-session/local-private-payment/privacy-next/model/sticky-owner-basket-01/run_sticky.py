"""Prospective finite sticky OWNER-basket control; no I/O or automatic run.

The caller supplies the exact pinned baseline fixture and pure baseline
namespace. No baseline source, expectation, or retained result is modified.
"""

from copy import deepcopy


def need(condition, message):
    if not condition:
        raise AssertionError(message)


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


class IdealStickyBasket:
    """Ideal threshold-owned state, never an individual server's plaintext view.

    No honesty flag enters a server decision. Internal owner-labelled records
    stand for secret-shared data; their secrecy and durability are oracles.
    """

    def __init__(self, fixture, approved, original_owners=tuple("ABC")):
        self.original_owners = tuple(original_owners)
        self.original = {owner: deepcopy(approved[fixture["owners"][owner]["nonce"]])
                         for owner in self.original_owners}
        self.history = []
        self.committed = []
        self.closed = False

    def eligible(self, accepted_spent):
        # No mempool, timer, request metadata or claimed participant failure.
        return tuple(owner for owner in self.original_owners
                     if self.original[owner]["nf"] not in accepted_spent)

    def check_requested_basket(self, requested, accepted_spent):
        require(tuple(sorted(requested)) == tuple(sorted(self.eligible(accepted_spent))),
                "sticky-owner-basket-cannot-add-replace-or-omit-eligible-intent")

    def prepare_egress(self, requested, accepted_spent, head, durable_commit=True):
        self.check_requested_basket(requested, accepted_spent)
        require(bool(self.eligible(accepted_spent)), "no-eligible-original-intent")
        require(durable_commit, "durable-history-must-commit-before-any-egress")
        record = {"ordinal": len(self.history), "head": head,
            "owners": list(self.eligible(accepted_spent)),
            "nfs": sorted(self.original[owner]["nf"] for owner in self.eligible(accepted_spent)),
            "outputs": sorted(out["tuple"] for owner in self.eligible(accepted_spent)
                              for out in self.original[owner]["outputs"])}
        # Model ordering: durable shared record first; only then may caller see
        # the returned NF/CM/CF set. A real atomic/durable protocol is unproved.
        self.committed.append(deepcopy(record))
        self.history.append(deepcopy(record))
        need(len(self.committed) == len(self.history), "publication-history-order")
        self.closed = False
        return deepcopy(record)

    def accept_conflicting_request(self, owner, replacement):
        require(owner in self.original, "no-owner-addition-while-original-basket-pending")
        require(replacement == self.original[owner], "no-post-egress-intent-replacement")
        return "idempotent-identical-intent-only"

    def open_other_session(self, requested_nfs, accepted_spent):
        pending = {self.original[owner]["nf"] for owner in self.eligible(accepted_spent)}
        require(not pending.intersection(requested_nfs), "global-history-detects-pending-NF-in-other-session")
        require(not pending, "no-new-basket-while-original-eligible-intents-remain")
        return "original-basket-fully-consumed-not-general-cross-session-proof"

    def rollback_eligibility(self, restored_accepted_spent):
        # The original archive and disclosure log never follow chain rollback.
        previous = deepcopy(self.history)
        eligible = self.eligible(restored_accepted_spent)
        need(self.history == previous, "reorg-erased-disclosure-history")
        self.closed = not bool(eligible)
        return eligible


def projection(fixture, case, observer):
    all_releases = case["releases"]
    releases = ([all_releases[case["final_accepted_index"]]]
                if observer == "O-confirmed-chain-only" else all_releases)
    owners = fixture["owners"]
    universe = sorted(set().union(*(set(cohort) for cohort in releases)))
    batches = [{"nfs": sorted(owners[owner]["nf"] for owner in cohort),
                "outputs": sorted(out["tuple"] for owner in cohort for out in owners[owner]["outputs"]),
                "known_owner_cohort": sorted(cohort) if observer == "O-coordinator" else None}
               for cohort in releases]
    public_fields = ("tuple", "cm", "cv", "cf", "proof")
    view = {"observer": observer, "scenario": case["id"], "variant": "prospective-sticky-control",
        "owner_universe": universe, "batches": batches,
        "public_output_rows": sorted([{field: row[field] for field in public_fields}
            for owner in universe for row in owners[owner]["outputs"]], key=lambda row: row["tuple"]),
        "known_owner_nf": {}, "known_owner_outputs": {}, "public_nf_pair": {},
        "individual_delta_equality_answers": [], "public_exits": [],
        "owner_contacts_for_reproof_or_egress": 0,
        "scope": "queued-intent NFs only; ideal opacity/proof/history/accepted-state oracles"}
    exit_owner = case["current_exit_owner"]
    if exit_owner is not None:
        view["public_exits"] = [{"nf": owners[exit_owner]["nf"],
            "payout_sompi": fixture["amounts"]["input"] - fixture["amounts"]["fee"],
            "destination": "u0b71e8a4", "outside_queued_intents": exit_owner not in universe}]
    if observer == "O-coordinator":
        view["known_owner_nf"]["C"] = owners["C"]["nf"]
        view["known_owner_outputs"]["C"] = sorted(row["tuple"] for row in owners["C"]["outputs"])
        view["known_submission_owners"] = universe
    if observer == "O-confirmed-chain-only":
        view["observation_inventory"] = {"currently_accepted_private_batches": 1,
            "old_aborted_or_orphaned_private_candidates": 0,
            "historical_candidate_disclosure_not_reconstructed": True}
    else:
        view["observation_inventory"] = {"all_private_candidate_egresses": len(releases),
            "old_aborted_or_orphaned_candidates_retained": True,
            "historical_C_exit_before_reorg_is_not_forgotten": case["id"].startswith("reorg")}
        if case["id"].startswith("reorg"):
            view["historical_observed_exit_now_orphaned"] = {
                "nf": owners["C"]["nf"], "payout_sompi": fixture["amounts"]["input"] - fixture["amounts"]["fee"],
                "destination": "u0b71e8a4", "currently_accepted": False, "observer_knowledge_retained": True}
    return view


def policy_controls(fixture, baseline):
    approved = baseline["approved_intents"](fixture)
    basket = IdealStickyBasket(fixture, approved)
    controls = []

    def refusal(name, operation):
        before = deepcopy(basket.__dict__)
        try:
            operation()
        except Refused as error:
            need(before == basket.__dict__, "refusal-mutated-basket:" + name)
            controls.append({"case": name, "outcome": "expected_policy_refusal", "reason": str(error)})
            return
        raise AssertionError("policy-control-unexpectedly-admitted:" + name)

    first = basket.prepare_egress("ABC", set(), "fictional-head-0")
    need(first["owners"] == list("ABC") and len(basket.committed) == 1, "initial-log-before-egress")
    c_nf = fixture["owners"]["C"]["nf"]
    b_nf = fixture["owners"]["B"]["nf"]
    refusal("coordinator_ADE_replacement_after_C_exit", lambda: basket.prepare_egress("ADE", {c_nf}, "fictional-head-1"))
    after_c = basket.prepare_egress("AB", {c_nf}, "fictional-head-1")
    need(after_c["owners"] == list("AB"), "only-accepted-consumed-C-pruned")
    need(set(first["nfs"]) - set(after_c["nfs"]) == {c_nf}, "prune-exact-original-NF")
    need(set(first["outputs"]) - set(after_c["outputs"]) ==
         {row["tuple"] for row in fixture["owners"]["C"]["outputs"]}, "prune-exact-approved-C-output-pair")
    controls.append({"case": "prune_C_only", "outcome": "modeled_sticky_AB_egress",
                     "private_pruning_oracle": True, "two_honest_remaining_is_evaluator_assumption": True})
    unchanged = basket.prepare_egress("AB", {c_nf}, "fictional-head-2")
    need(unchanged["nfs"] == after_c["nfs"] and unchanged["outputs"] == after_c["outputs"],
         "harmless-head-movement-retains-exact-NFs-and-output-tuples")
    refusal("publication_without_prior_durable_commit", lambda: basket.prepare_egress("AB", {c_nf}, "fictional-head-3", False))
    replacement = deepcopy(basket.original["A"])
    replacement["outputs"][0]["cf"] = "f00112233"
    refusal("conflicting_authorized_recipient_or_CF_request", lambda: basket.accept_conflicting_request("A", replacement))
    fee_request = deepcopy(basket.original["A"])
    fee_request["fee"] += 1
    refusal("conflicting_fee_request", lambda: basket.accept_conflicting_request("A", fee_request))
    nonce_request = deepcopy(basket.original["A"])
    nonce_request["nonce"] = "i00112233"
    refusal("same_owner_new_intent_cannot_replace_egressed_intent", lambda: basket.accept_conflicting_request("A", nonce_request))
    refusal("new_owner_cannot_join_while_AB_eligible", lambda: basket.accept_conflicting_request("D", {}))
    pending_a = {fixture["owners"]["A"]["nf"], fixture["owners"]["D"]["nf"], fixture["owners"]["E"]["nf"]}
    refusal("restored_wallet_uses_same_NF_in_new_session_with_history_present",
            lambda: basket.open_other_session(pending_a, {c_nf}))
    need(basket.accept_conflicting_request("A", deepcopy(basket.original["A"])) == "idempotent-identical-intent-only",
         "identical-request-idempotence")
    original_history = deepcopy(basket.history)
    need(basket.rollback_eligibility(set()) == tuple("ABC"), "reorg-restores-original-C-membership")
    need(basket.history == original_history, "reorg-preserves-all-egress-history")
    restored = basket.prepare_egress("ABC", set(), "fictional-restored-head")
    need(restored["nfs"] == first["nfs"] and restored["outputs"] == first["outputs"], "reorg-exact-original-tuples-restored")
    # A pending/mempool B Exit is not in accepted_spent, so it cannot prune B.
    refusal("proposed_B_exit_is_not_accepted_pruning_authority",
            lambda: basket.prepare_egress("AC", set(), "fictional-mempool-only-head"))
    # An honest B departure is allowed when actually accepted. No implementation
    # decision identifies C as dishonest or pretends the remaining AC is honest.
    ac = basket.prepare_egress("AC", {b_nf}, "fictional-B-exit-head")
    need(ac["owners"] == list("AC"), "accepted-honest-departure-prunes-B")
    controls.append({"case": "honest_B_left_C_remains", "outcome": "expected_privacy_failure_despite_two_owners",
                     "server_can_certify_honesty_from_count": False})
    # Explicitly remove/bypass the old global history oracle. The resulting
    # fresh session is possible only outside the positive sticky assumption.
    forgotten_session = IdealStickyBasket(fixture, approved, tuple("ADE"))
    escaped = forgotten_session.prepare_egress("ADE", {c_nf}, "fictional-new-session-head")
    need(set(first["nfs"]).intersection(escaped["nfs"]) == {fixture["owners"]["A"]["nf"]},
         "expected-forgotten-history-NF-intersection")
    need(set(first["outputs"]).intersection(escaped["outputs"]) ==
         {row["tuple"] for row in fixture["owners"]["A"]["outputs"]},
         "expected-forgotten-history-complete-output-intersection")
    controls.append({"case": "forget_global_history_or_publish_before_commit",
        "outcome": "outside_durability_oracle_expected_failure", "old_observer_knowledge_survives": True})
    controls.append({"case": "refuse_an_egressed_request_change", "outcome": "private_service_liveness_limit",
        "fee_or_destination_cannot_silently_change": True, "original_independent_exit_remains_separate": True})
    return controls


def financial_controls(fixture, control, baseline):
    """Only the baseline's ideal accounting kernel; no new native statement."""
    approved = baseline["approved_intents"](fixture)
    results = []
    for case in control["cases"]:
        state = baseline["initial_state"](fixture)
        total = state["reserve"]
        departed = case["current_exit_owner"]
        if departed is not None:
            row = fixture["owners"][departed]
            state = baseline["direct_exit"](fixture, state, row["nf"], row["key"], state["head"],
                "fictional-fixed-payout", "fictional-fixed-payout")
        owners = case["releases"][case["final_accepted_index"]]
        candidate = baseline["proposal"](fixture, approved, owners, state["head"])
        state = baseline["accept_batch"](fixture, approved, state, candidate)
        baseline["invariant"](state, total)
        # A uses precisely the original approved complete tuples, even in the
        # explicit bypass/failure cases. No unapproved rerandomization is used.
        a_intent = approved[fixture["owners"]["A"]["nonce"]]
        need(next(i for i in candidate["intents"] if i["nf"] == a_intent["nf"]) == a_intent,
             "unchanged-A-consent-and-complete-output-tuples:" + case["id"])
        results.append({"case": case["id"], "outcome": "ideal_accounting_acceptance_only",
            "basket_privacy_enforced_by_native_oracle": False,
            "reserve_sompi": state["reserve"], "live_liability_sompi": sum(n["value"] for n in state["notes"].values()),
            "payout_sompi": state["paid"], "fee_sompi": state["fees"], "initial_sompi": total})
    return results


def run_sticky(fixture, control, baseline):
    need(control["schema"] == "prospective-sticky-owner-basket-control/v1", "control-schema")
    need(control["original_basket"] == list("ABC") and control["colluding_owner"] == "C", "frozen-basket-and-colluder")
    baseline["check_inputs"](fixture)
    summaries, assignments = {}, {}
    for case in control["cases"]:
        for observer in control["observers"]:
            key = case["id"] + "/" + observer
            view = projection(fixture, case, observer)
            summary, worlds = baseline["enumerate_assignments"](view)
            need(summary["joint_assignment_count"] == case["expected_worlds"][observer], "frozen-count:" + key)
            if observer == "O-coordinator":
                need(len(summary["owner_nf_candidates"]["A"]) == case["A_coordinator_nf_candidates"], "frozen-A-NF:" + key)
                need(len(summary["owner_output_pair_candidates"]["A"]) == case["A_coordinator_output_pairs"], "frozen-A-output-pair:" + key)
            summary["view"] = view
            summary["classification"] = case["classification"]
            summaries[key] = summary
            assignments[key] = worlds
    need(len(summaries) == control["expected_view_count"] == 24, "frozen-view-count")
    need(sum(map(len, assignments.values())) == control["expected_total_joint_assignments"] == 21277, "frozen-complete-enumeration-count")
    return {"summary": {"schema": "prospective-sticky-owner-basket-result/v1",
        "verdict": "prospective_finite_control_expectations_met",
        "scope": "Unselected ideal threshold/durability/consent/current-state/proof oracles only; no native or cryptographic solution.",
        "baseline_unchanged": True, "assumptions": control["assumptions"],
        "information_flow": summaries, "policy_controls": policy_controls(fixture, baseline),
        "financial_controls": financial_controls(fixture, control, baseline),
        "fee_result": "unmeasured; frozen 21-KAS 2-percent all-in FAIL unchanged"},
        "enumerated_assignments": assignments}
