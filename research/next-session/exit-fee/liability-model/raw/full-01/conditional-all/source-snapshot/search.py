"""Complete financial graph plus exact monotone environment product."""
from dataclasses import asdict, replace
from collections import deque, Counter
from model import (AVAILABLE, ENVIRONMENTS, Action, actions, availability, initial,
                   pending, step, claim_key)
from oracle import Violation, advance, audit


def trace(nodes, parents, index):
    out = []
    while parents[index] is not None:
        index, action = parents[index]
        out.append(asdict(action))
    out.reverse()
    return out


def environment_losses(env):
    names = ("ShutdownAcceptanceService", "LosePublicData", "LoseRetainedWitness")
    return [{"kind": name} for name, available in zip(names, env) if not available]


def explore(c, conditional=False, mutant=""):

    first = initial(c)
    audit(c, *first, mutant)
    nodes, parents = [first], [None]
    seen = {first: 0}
    queue = deque([0])
    counts = Counter()
    examples = {}
    env_enabled_edges = 0
    while queue:
        index = queue.popleft()
        s, g = nodes[index]
        counts["financial_states"] += 1
        # Every environment loss can occur after reaching the financial state.
        # It cannot enable a new financial transition. Enumerating all eight
        # products is therefore exact, without storing duplicate financial data.
        for env in ENVIRONMENTS:
            counts["environment_product_states"] += 1
            for i, principal in enumerate(g.claims):
                if not principal or g.paid & (1 << i):
                    continue
                feasible = principal > s.quote
                has_data = c.mode == "native-p2pk" or env[1] or env[2]
                roots = s.roots if c.mode == "shared-root" else (0,)
                valid_roots = [root for root in roots if c.mode == "native-p2pk" or ((root >> (3 * i)) & 7)]
                candidate = [Action("claim", (i,), (s.quote,), g.owners[i], root, actor=g.owners[i], amount=principal)
                             for root in valid_roots]
                reachable = any(step(c, s, a, env, mutant) is not None for a in candidate)
                if not feasible:
                    family = "economic-liveness-failure"
                elif not has_data:
                    family = "data-liveness-failure"
                elif not reachable:
                    family = "accepted-claim-service-dependence" if not env[0] else "accepted-claim-unreachable"
                    return failure(c, conditional, mutant, counts, examples,
                                   trace(nodes, parents, index), None, family, s, env)
                else:
                    family = "accepted-feasible-claim-reachable"
                counts[family] += 1
                isolating = AVAILABLE if family == "economic-liveness-failure" else (True, False, False)
                if family.endswith("failure") and family not in examples and env == isolating:
                    examples[family] = {"trace": trace(nodes, parents, index), "environment": env,
                                        "claim_nf": i + 1, "principal": s.claims[i], "quote": s.quote,
                                        "environment_loss_trace": environment_losses(env)}
            # No future opening primitive is credited in the base result.
            if not conditional and not env[0] and any(g.live):
                counts["unaccepted-private-service-failure"] += 1
                if "unaccepted-private-service-failure" not in examples and env == (False, True, True):
                    examples["unaccepted-private-service-failure"] = {
                        "trace": trace(nodes, parents, index), "environment": env,
                        "existing_format_reveal": "UNRESOLVED_AUTH_ASSUMPTION",
                        "environment_loss_trace": environment_losses(env)}
        for a in actions(c, s, conditional):
            counts["financial_proposals"] += 1
            nxt = step(c, s, a, AVAILABLE, mutant)
            if nxt is None:
                counts["rejected_financial_proposals"] += 1
                continue
            enabled = sum(availability(c, a, env, mutant) for env in ENVIRONMENTS)
            env_enabled_edges += enabled
            # Two symbolic binding controls for every otherwise accepted action.
            if a.kind not in ("quote", "retire"):
                assert step(c, s, replace(a, fresh=False), AVAILABLE, mutant) is None
                assert step(c, s, replace(a, authentic=False), AVAILABLE, mutant) is None
                counts["context_and_authority_rejections"] += 2
            try:
                ng = advance(c, g, a)
                audit(c, nxt, ng, mutant)
            except Violation as error:
                return failure(c, conditional, mutant, counts, examples,
                               trace(nodes, parents, index), a, str(error), nxt, AVAILABLE)
            pair = (nxt, ng)
            counts["accepted_financial_edges"] += 1
            if pair not in seen:
                seen[pair] = len(nodes)
                parents.append((index, a))
                nodes.append(pair)
                queue.append(len(nodes) - 1)
    counts["environment_loss_edges"] = 12 * len(nodes)  # three directed Boolean cube dimensions
    counts["accepted_environment_product_edges"] = env_enabled_edges + counts["environment_loss_edges"]
    return {"config": asdict(c), "conditional_reveal": conditional,
            "mutant": mutant or None, "complete": True, "safety_violation": None,
            "counts": dict(counts), "expected_liveness_failures": examples,
            "search_depth_cutoff": None, "state_or_time_cutoff": None,
            "environment_product_exact_not_sampled": True,
            "reveal_authority_status": "ASSUMED_IDEAL_UNRESOLVED" if conditional else "UNRESOLVED_NOT_ENABLED"}


def failure(c, conditional, mutant, counts, examples, prior, action, why, state, env):
    return {"config": asdict(c), "conditional_reveal": conditional, "mutant": mutant or None,
            "complete": False, "stopped_at_first_counterexample": True,
            "safety_violation": why, "counts": dict(counts),
            "expected_liveness_failures": examples,
            "counterexample": {"trace": prior + ([asdict(action)] if action else []),
                               "environment": env, "environment_loss_trace": environment_losses(env), "state": asdict(state)},
            "counterexample_is_model_not_native_execution": True}
