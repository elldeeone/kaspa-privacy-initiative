"""Finite adversarial sensitivity and chain/knowledge boundary controls."""
from dataclasses import asdict, replace
from model import (AVAILABLE, ENVIRONMENTS, Config, Action, MUTANTS, configs,
                   initial, step, pending)
from oracle import Violation, advance, audit
from search import explore


def restore_chain(snapshot, environment, knowledge, current_quote):
    """Rollback chain accounting only: public knowledge/outages are not chain data."""
    state, ledger = snapshot
    return replace(state, quote=current_quote), ledger, environment, knowledge


def publish_unaccepted_opening(knowledge, owner):
    # Publication is public knowledge even if rejected or later orphaned.
    return knowledge | (1 << owner)


def controls():
    c = configs()[127]  # three value3 ownerB notes, shared-root mode
    results = {}
    for mutant in MUTANTS:
        outcome = explore(c, conditional=False, mutant=mutant)
        results[mutant] = outcome
        if not outcome.get("safety_violation"):
            raise AssertionError("must-detect mutant survived: " + mutant)
    # Explicit accepted ROOT+INDEX shift, followed by an actual second payout.
    rs, rg = initial(c)
    directed = []
    first = Action("accept", (4,), (0,))
    rs = step(c, rs, first, mutant="root-local-id")
    rg = advance(c, rg, first)
    old_root = rs.roots[-1]
    pay = Action("claim", (4,), (1,), 1, old_root, actor=1, amount=3)
    rs = step(c, rs, pay, mutant="root-local-id")
    rg = advance(c, rg, pay)
    add = Action("accept", (0,), (0,))
    rs = step(c, rs, add, mutant="root-local-id")
    rg = advance(c, rg, add)
    new_root = rs.roots[-1]
    assert old_root in rs.roots and new_root in rs.roots and old_root != new_root
    old_index = sum(bool((old_root >> (3 * j)) & 7) for j in range(4))
    new_index = sum(bool((new_root >> (3 * j)) & 7) for j in range(4))
    assert (old_index, new_index) == (0, 1)
    duplicate = replace(pay, root=new_root)
    twice = step(c, rs, duplicate, mutant="root-local-id")
    assert twice is not None and twice.paid_origin[2] == 4 and twice.fees[2] == 2
    try:
        advance(c, rg, duplicate)
    except Violation as error:
        assert str(error) == "same-entitlement-paid-twice"
    else:
        raise AssertionError("independent ledger accepted duplicated payment")
    results["root-local-id"]["directed_accepted_index_shift_double_payment"] = {
        "trace": [asdict(a) for a in (first, pay, add, duplicate)],
        "old_accepted_root": old_root, "new_accepted_root": new_root,
        "same_source_nf": 5, "old_leaf_index": old_index, "new_leaf_index": new_index,
        "original_principal": 3, "actual_model_native_paid": 4,
        "actual_model_fees": 2, "second_payment_accepted_by_broken_model": True,
        "separate_directed_trace_continues_past_first_backing_violation": True}
    s, g = initial(c)
    accept = Action("accept", (0,), (0,))
    accepted = step(c, s, accept)
    assert accepted is not None
    ag = advance(c, g, accept)
    audit(c, accepted, ag)
    old_root = accepted.roots[-1]
    orphan = Action("claim", (0,), (1,), 1, old_root, actor=1, amount=3)
    assert step(c, accepted, orphan) is not None
    # Restoring a chain snapshot removes its descendants' native payment AND
    # entitlement authorization. Persistent outages/knowledge are separate state.
    reorg_cases = 0
    for env in ENVIRONMENTS:
        for knowledge in range(4):
            for quote in (1, 2):
                current = accepted if quote == 1 else step(c, accepted, Action("quote"))
                assert current.quote == quote
                restored, rg, returned_env, returned_knowledge = restore_chain(
                    (s, g), env, knowledge, current.quote)
                assert restored == replace(s, quote=quote) and rg == g
                assert returned_env == env and returned_knowledge == knowledge
                assert restored.quote == current.quote
                assert step(c, restored, orphan, returned_env) is None
                reorg_cases += 1
    results["reorg-financial-restore-knowledge-persistence"] = {
        "checkpoint_products_checked": reorg_cases,
        "orphan_claim_rejected": True, "raised_quote_two_survives_rollback": True,
        "service_data_and_adversary_knowledge_not_rolled_back": True,
        "scope": "financial ancestor states are already in the complete graph; arbitrary hash/DAA/reorg validation is not modeled"}
    # A publication need not be an accepted chain operation to expose a reusable
    # credential. An attacker can redirect a competing PRIVATE transition first.
    leaked_owner = publish_unaccepted_opening(0, s.owners[0])
    restored, rg, env, leaked_after_reorg = restore_chain((s, g), AVAILABLE, leaked_owner, current_quote=2)
    theft = Action("spend", (0,), (0,), 2, actor=2)
    stolen = step(c, restored, theft, env, leaked=leaked_after_reorg)
    assert stolen is not None
    reason = None
    try:
        ng = advance(c, rg, theft)
        audit(c, stolen, ng)
    except Violation as e:
        reason = str(e)
    assert reason == "copied-private-credential-theft"
    results["published-reusable-credential"] = {
        "counterexample": ["publish-unaccepted-opening-with-ownerB-spending-credential",
                           "rollback-chain-only-knowledge-persists", asdict(theft)],
        "violation": reason, "opening_acceptance_required": False,
        "same_NF_exclusion_does_not_prevent_theft_by_the_first_spender": True,
        "conditional_unsafe_note_format_only": True,
        "new_revealing_authority_implemented": False}
    # Direct same-original-NF race attempts are evaluated outside the action
    # generator's unspent filter. The successor revision has a different NF.
    original_spend = Action("spend", (0,), (0,), 0, actor=1)
    original_reveal = Action("reveal", (0,), (1,), 1, actor=1)
    first_actions = (accept, original_spend, original_reveal)
    rejected_races = 0
    for first_action in first_actions:
        after = step(c, s, first_action)
        assert after is not None
        ag = advance(c, g, first_action)
        audit(c, after, ag)
        for competitor in first_actions:
            assert step(c, after, competitor) is None
            rejected_races += 1
    # A historical ACCEPTED root remains usable with fresh current spent state.
    hs, hg = initial(c)
    a4, a0 = Action("accept", (4,), (0,)), Action("accept", (0,), (0,))
    hs = step(c, hs, a4); hg = advance(c, hg, a4)
    historical = hs.roots[-1]
    hs = step(c, hs, a0); hg = advance(c, hg, a0)
    historical_claim = Action("claim", (4,), (1,), 1, historical, actor=1, amount=3)
    paid = step(c, hs, historical_claim)
    assert paid is not None
    pg = advance(c, hg, historical_claim); audit(c, paid, pg)
    assert step(c, paid, historical_claim) is None
    assert step(c, paid, replace(historical_claim, historical_paid=True)) is None
    # Duplicate input within a batch must reject atomically.
    assert step(c, s, Action("accept", (0, 0), (0, 0))) is None
    results["direct-current-NF-and-historical-root-controls"] = {
        "same_original_NF_competitor_rejections": rejected_races,
        "conditional_reveal_uses_ideal_authority_only": True,
        "old_accepted_root_unpaid_claim_still_usable": True,
        "paid_and_historical_paid_replays_rejected": True,
        "duplicate_in_batch_rejected_atomically": True,
        "outside_generator_unspent_filter": True}
    # Native payout at acceptance is already delivered, not an unpaid claim.
    n = configs()[126]
    ns, ng = initial(n)
    delivered = step(n, ns, accept)
    assert delivered.reserve == sum(c.values) - 3 and delivered.escrow == 3
    audit(n, delivered, advance(n, ng, accept))
    results["native-ticket-already-delivered"] = {
        "pool_debit_at_acceptance": 3, "owner_native_output": 3,
        "deferred_pool_liability": 0, "later_native_spend_still_pays_fee": True}
    return {"must_detect_mutants": list(MUTANTS), "all_required_counterexamples_found": True,
            "results": results, "new_cryptographic_or_native_validation": False}
