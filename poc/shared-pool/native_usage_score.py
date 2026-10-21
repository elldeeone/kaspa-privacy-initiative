"""Private scorer for one genuine offline native usage history.

Caller prerequisites: exact-byte native replay, ordinary-parent signature/UTXO
validation, frozen source/parameter identities, and ALL predictions sealed before
private truth is mounted. This scorer rechecks ownership/value/schedule binding,
whole native accounting and prefix coverage. It does not authenticate a chain,
certify cryptography, or turn a heuristic hit into a forced disclosure.

Rates and cap comparisons use exact rational arithmetic. One dependent history
is not a population sample; there are no confidence intervals or qualification
passes. Public outputs contain aggregate counts, never private target masks,
actual note values/owners or per-target correctness.
"""
import copy
from fractions import Fraction

import early_privacy_surface as raw_surface
import native_usage_surface as surface
import population_privacy_model as full

PROFILES = ("C", *(f"P{i}" for i in range(8)), "pooled")
HORIZONS = ("creation", "cashout", "final")
VARIANTS = ("prior", "residual", "split", "native_graph")
STRATA = ("primary", "all_undisclosed", "startup", "adversary_endpoint")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
CAPS = {"sender": Fraction(1, 10), "recipient": Fraction(1, 10),
        "amount_within_10pct": Fraction(1, 5)}
COVERAGES = (5, 10, 25)
SOMPI, FEE, FLOOR, MAX = 100_000_000, 40_000_000, 60_000_000, raw_surface.MAX
need, integer, fields, digest = surface.need, surface.integer, surface.fields, surface.digest


def members(profile):
    need(profile in PROFILES, "unknown profile")
    return [] if profile == "C" else list(range(8)) if profile == "pooled" else [int(profile[1:])]


def _fraction(value):
    return None if value is None else dict(numerator=value.numerator, denominator=value.denominator)


def _rate(counter):
    return Fraction(counter["correct"], counter["eligible"]) if counter["eligible"] else None


def _counter():
    return dict(correct=0, eligible=0)


def _selected(rows, percent):
    ordered = sorted(rows, key=lambda r: (tuple(-v for v in r["rank"]), r["event"]))
    n = (len(ordered) * percent + 99) // 100
    return dict(correct=sum(int(r["correct"]) for r in ordered[:n]), eligible=n,
                population=len(ordered), nominal_percent=percent,
                realized_coverage=_fraction(Fraction(n, len(ordered))) if ordered else None)


def _horizons(events):
    final = len(events) - 1
    result = {}
    for i, event in enumerate(events):
        if i and event["mode"] == 1:
            following = next((j for j in range(i + 1, len(events)) if events[j]["mode"] == 2), final)
            result[i] = dict(creation=i, cashout=following, final=final)
    return result


def _prefix(raw, directory, timing, events, through):
    """Independent prefix construction; do not call the observer's prefix helper."""
    lineage = raw["lineage"][:through + 2]
    points = [raw_surface.point(lineage[0]["inputs"][0]["previousOutpoint"])]
    points.extend(raw_surface.point(lineage[i + 1]["inputs"][1]["previousOutpoint"])
                  for i, event in enumerate(events[:through + 1]) if event["mode"] == 0)
    parent_ids = {p[0] for p in points}
    result = dict(descriptor=raw["descriptor"], vk_hex=raw["vk_hex"], lineage=lineage,
                  parents=[p for p in raw["parents"] if p["id"] in parent_ids])
    need({p["id"] for p in result["parents"]} == parent_ids, "prefix parent closure")
    selected = set(points)
    d = {**directory, "entries": [e for e in directory["entries"]
                                   if (e["transaction_id"], e["index"]) in selected]}
    t = dict(schema=timing["schema"], events=timing["events"][:through + 1])
    return result, d, t


def _view(truth, profile, through, count):
    included = members(profile)
    return dict(schema="kpi-native-usage-view-v1", members=included,
        receipts=[dict(owner=o, position=p, value=v) for p, (v, o) in
                  enumerate(zip(truth["values"][:count], truth["owners"][:count], strict=True))
                  if v and o in included],
        authored=[dict(owner=e["owner"], event_id=e["event_id"],
                       inputs=sorted(truth["inputs"][str(i)]), outputs=e["outputs"])
                  for i, e in enumerate(truth["events"][:through + 1]) if e["owner"] in included])


def _native_accounting(raw, expected_sources=32):
    """Separate DFS accountant: actual bodies, exact outpoints, every change.

    Synthetic root contexts are explicitly output0+1KAS, not verified ancestry.
    Native signature checks against those contexts are a caller prerequisite.
    """
    bodies = raw["parents"] + raw["lineage"]
    txs = {t["id"]: t for t in bodies}
    need(len(txs) == len(bodies), "duplicate native bodies")
    roots, values, spent, visiting, done, fees = {}, {}, set(), set(), set(), {}
    for tx in raw["parents"]:
        need(len(tx["inputs"]) == 1 and len(tx["outputs"]) == 2 and tx["payload"] == "",
             "ordinary parent envelope")
        point = raw_surface.point(tx["inputs"][0]["previousOutpoint"])
        if point[0] not in txs:
            need(point not in roots, "synthetic source reused")
            roots[point] = integer(raw_surface.decimal(tx["outputs"][0]["value"]) + SOMPI, 1)
    need(expected_sources is None or len(roots) == expected_sources, "synthetic source count")
    values.update(roots)

    def visit(txid):
        if txid in done:
            return
        need(txid not in visiting, "native dependency cycle")
        visiting.add(txid)
        tx = txs[txid]
        points = [raw_surface.point(i["previousOutpoint"]) for i in tx["inputs"]]
        need(points and len(points) == len(set(points)), "native empty/duplicate inputs")
        for point in points:
            if point[0] in txs:
                visit(point[0])
            need(point in values and point not in spent, "native missing/double-spent outpoint")
        outputs = [raw_surface.decimal(o["value"]) for o in tx["outputs"]]
        need(outputs and all(0 < n <= MAX for n in outputs), "native output range")
        input_value = sum(values[p] for p in points)
        need(input_value >= sum(outputs), "native value inflation")
        fees[txid] = input_value - sum(outputs)
        spent.update(points)
        for index, value in enumerate(outputs):
            point = (txid, index)
            need(point not in values, "native outpoint collision")
            values[point] = value
        visiting.remove(txid)
        done.add(txid)

    for tx in bodies:
        visit(tx["id"])
    pool_ids = {t["id"] for t in raw["lineage"][1:]}
    pool_fee = sum(fees[i] for i in pool_ids)
    ordinary_fee = sum(fees[i] for i in done - pool_ids)
    outside = sum(v for p, v in values.items() if p not in spent)
    injection = sum(roots.values())
    need(injection == outside + pool_fee + ordinary_fee, "whole native conservation")
    return dict(external_source_count=len(roots), external_injection_sompi=injection,
        final_native_unspent_sompi=outside, pool_fees_sompi=pool_fee,
        ordinary_fees_sompi=ordinary_fee, native_transaction_count=len(done),
        consumed_native_outpoints=len(spent), whole_experiment_conserved=True)


def _ledger(relation, truth, expected_roles=32):
    """Independent concrete-note walk, not the generation Notes/scheduler class."""
    fields(truth, "schema policy_sha256 schedule values owners inputs events bridges wallet_inspections author_inspections accounting", "truth")
    need(truth["schema"] == "kpi-native-usage-truth-v1", "truth schema")
    data, commitments = relation["algebra"], relation["commitments"]
    values, owners = truth["values"], truth["owners"]
    need(type(values) is list and type(owners) is list and len(values) == len(owners) == len(commitments),
         "truth note coverage")
    equal = {}
    for cm, value, owner in zip(commitments, values, owners, strict=True):
        integer(value)
        need(owner is None if not value else type(owner) is int and 0 <= owner < expected_roles,
             "true note owner")
        need(not value or value >= FLOOR, "true note floor")
        need(cm not in equal or equal[cm] == (value, owner), "equal commitment truth mismatch")
        equal[cm] = (value, owner)
    events = data["events"]
    need(type(truth["events"]) is list and len(truth["events"]) == len(events), "truth event coverage")
    need(type(truth["inputs"]) is dict and set(truth["inputs"]) == {str(i) for i in range(len(events))},
         "truth input coverage")
    need(values[0] == data["initial"]["value"] and owners[0] == relation["funding_owners"][data["initial"]["funding_group"]],
         "initial claim truth")
    need(type(truth["author_inspections"]) is list and len(truth["author_inspections"]) == len(events),
         "author nullifier-scan coverage")
    count, spent = 1, set()
    for i, (event, hidden) in enumerate(zip(events, truth["events"], strict=True)):
        fields(hidden, "event event_id kind owner recipient amount outputs minute request_index", "true event")
        need(type(hidden["event"]) is int and hidden["event"] == i and hidden["event_id"] == event["id"],
             "true event native identity")
        owner = integer(hidden["owner"], 0, expected_roles - 1)
        integer(hidden["amount"]); integer(hidden["minute"])
        if hidden["request_index"] is not None:
            integer(hidden["request_index"], 0, 63)
        need(hidden["kind"] == ("bootstrap" if i == 0 else {0: "admit", 1: "pay", 2: "exit"}[event["mode"]]),
             "true event kind")
        selected = truth["inputs"][str(i)]
        need(type(selected) is list and all(type(p) is int for p in selected)
             and len(selected) == len(set(selected)), "true input set")
        need(not selected if event["mode"] == 0 else 1 <= len(selected) <= 2, "true input arity")
        need(all(0 <= p < count and p < event["anchor_count"] and p not in spent
                 and values[p] >= FLOOR and owners[p] == owner for p in selected), "true spend/anchor/ownership")
        created = [] if event["mode"] == 2 else [count, count + 1]
        need(event["new"] == created and event["count_before"] == count, "true append positions")
        outputs = [dict(position=p, value=values[p], recipient=owners[p]) for p in created]
        need(type(hidden["outputs"]) is list, "true output list")
        for output in hidden["outputs"]:
            fields(output, "position value recipient", "true output")
            integer(output["position"]); integer(output["value"])
            need(output["recipient"] is None or type(output["recipient"]) is int,
                 "true output recipient")
        need(hidden["outputs"] == outputs, "true output vectors")
        need(event["fee"] == FEE, "native fixed fee")
        if event["mode"] == 0:
            known = relation["funding_owners"][event["funding_group"]]
            need(known is None or known == owner, "public funding owner contradicts truth")
            need(values[created[0]] == event["deposit"] - FEE and owners[created[0]] == owner
                 and values[created[1]] == 0 and hidden["amount"] == event["deposit"], "admission truth")
        else:
            need(sum(values[p] for p in selected) == sum(values[p] for p in created) + event["payout"] + FEE,
                 "private value conservation")
            if event["mode"] == 1:
                a, b = created
                need(values[a] > 0 and values[a] == hidden["amount"] and owners[a] == hidden["recipient"]
                     and (not values[b] or owners[b] == owner), "payment/change truth")
            else:
                need(hidden["amount"] == event["payout"] and hidden["recipient"] is None, "exit truth")
        count += len(created)
        spent.update(selected)
        need(sum(values[p] for p in range(count) if p not in spent) == event["reserve_out"], "liabilities versus reserve")
        inspection = truth["author_inspections"][i]
        fields(inspection, "owner event_id view", "private author scan")
        need(type(inspection["owner"]) is int and inspection["owner"] == owner
             and inspection["event_id"] == event["id"], "author scan identity")
        _check_scan(inspection["view"], values[:count], owners[:count], spent, owner,
                    event["reserve_out"] == 0, i + 2)
    need(count == len(values) and events[-1]["reserve_out"] == 0
         and all(not v or p in spent for p, v in enumerate(values)), "complete liability drainage")
    inspections = truth["wallet_inspections"]
    need(type(inspections) is list and len(inspections) == expected_roles, "wallet scan coverage")
    for owner, inspection in enumerate(inspections):
        fields(inspection, "owner view", "private scan")
        need(type(inspection["owner"]) is int and inspection["owner"] == owner, "private scan owner")
        _check_scan(inspection["view"], values, owners, spent, owner, True, len(events) + 1)
    return dict(complete=True, note_positions=len(values), positive_claims=sum(v > 0 for v in values),
                pool_fees_sompi=sum(e["fee"] for e in events), full_drainage=True,
                one_input_payments=sum(e["kind"] == "pay" and len(truth["inputs"][str(i)]) == 1
                                       for i, e in enumerate(truth["events"])),
                two_input_payments=sum(e["kind"] == "pay" and len(truth["inputs"][str(i)]) == 2
                                       for i, e in enumerate(truth["events"])))


def _check_scan(view, values, owners, spent, owner, drained, transaction_count):
    expected = [dict(position=p, value_sompi=str(v), spent=p in spent)
                for p, (v, o) in enumerate(zip(values, owners, strict=True)) if v and o == owner]
    balance = sum(v for p, (v, o) in enumerate(zip(values, owners, strict=True)) if v and o == owner and p not in spent)
    need(view["notes"] == expected and view["balance_sompi"] == str(balance)
         and view["drained"] is drained and view["chain_acceptance_verified"] is False
         and type(view["head"]["transaction_count"]) is int
         and view["head"]["transaction_count"] == transaction_count,
         "actual scan ownership/commitment/positioned-nullifier history")


class _TruthPair(full.Pair):
    """Original two relations, privately bound to actual admission owners only.

    This is a concrete witness consistency check, never an observer model or a
    uniqueness argument. Unknown fresh-bridge owners are not published as facts.
    """
    def __init__(self, relation, truth):
        self.public = copy.deepcopy(relation)
        self.data = self.public["algebra"]
        for i, event in enumerate(self.data["events"]):
            if event["mode"] == 0:
                self.public["funding_owners"][event["funding_group"]] = truth["events"][i]["owner"]
        self.view = dict(members=[])
        births, upper = full.decode(self.data, FLOOR, 10_000_000)
        self.facts = dict(births=births, upper=upper, receipts={}, authors={})
        self.cp = full.Model(self.data, FLOOR, 10_000_000)
        self.z = full.Z3Model(self.data, FLOOR, 10_000_000)
        need(sum(self.cp.upper) + sum(e["fee"] + e["deposit"] + e["payout"] for e in self.data["events"]) < 2**62,
             "fixed truth CP integer range")
        self.queries, self.context, self.diagnostics = {"cp_sat": 0, "z3": 0}, {}, False
        self._cp_owners(FLOOR)
        self._z3_owners(FLOOR)


def _fixed_truth(relation, truth):
    model = _TruthPair(relation, truth)
    cp, smt = [], []
    for p, (v, owner) in enumerate(zip(truth["values"], truth["owners"], strict=True)):
        cp.append(model.cp.values[p] == v); smt.append(model.z.values[p] == v)
        if v:
            cp.append(model.cp_owners[p] == owner); smt.append(model.z_owners[p] == owner)
    for i, selectors in model.cp.select.items():
        chosen = set(truth["inputs"][str(i)])
        cp.extend(x == int(p in chosen) for p, x in enumerate(selectors))
        smt.extend(x == (p in chosen) for p, x in enumerate(model.z.select[i]))
    results = [model.query("cp_sat", cp), model.query("z3", smt)]
    need(all(r is not None for r in results), "actual truth excluded by original relations")
    return dict(complete=True, cp_sat="SAT", z3="SAT", models=1,
                scope="Final concrete witness only; private admission owners pinned, no reconstruction or uniqueness search")


def _check_prediction(prediction, profile, through, raw, directory, timing, view, policy, facts):
    fields(prediction, "schema complete raw_sha256 directory_sha256 view_sha256 timing_sha256 policy_sha256 profile through_event rows boundary diagnostics", "prediction")
    need(prediction["schema"] == "kpi-native-usage-predictions-v1" and prediction["complete"] is True
         and prediction["profile"] == profile and type(prediction["through_event"]) is int
         and prediction["through_event"] == through, "prediction scope")
    for name, value in dict(raw=raw, directory=directory, timing=timing, view=view, policy=policy).items():
        need(prediction[name + "_sha256"] == digest(value), "prediction prefix identity: " + name)
    targets = [i for i, e in enumerate(facts["events"]) if i and e["mode"] == 1]
    need(type(prediction["rows"]) is list and len(prediction["rows"]) == len(targets), "all visible targets predicted")
    for i, row in zip(targets, prediction["rows"], strict=True):
        fields(row, "event event_id guesses", "prediction row")
        need(type(row["event"]) is int and row["event"] == i and row["event_id"] == facts["events"][i]["id"],
             "prediction target identity/order")
        need(type(row["guesses"]) is dict and set(row["guesses"]) == set(VARIANTS), "fixed variants")
        for name, guess in row["guesses"].items():
            fields(guess, "sender recipient amount relationship_rank", "guess")
            integer(guess["sender"], 0, 31); integer(guess["recipient"], 0, 31); integer(guess["amount"])
            rank = guess["relationship_rank"]
            need(type(rank) is list and len(rank) == 4 and all(type(v) is int and -(2**63) < v < 2**63 for v in rank),
                 "relationship rank")
            need(0 <= rank[0] <= 2 and rank[1] >= 0 and rank[2] >= 0 and rank[3] <= 0, "rank domains")
            need(name != "prior" or rank == [0, 0, 0, 0], "prior rank")
    need(prediction["diagnostics"] == facts["diagnostics"], "public byte diagnostics changed")
    need(type(prediction["boundary"]) is list and len(prediction["boundary"]) == len(facts["bridges"]), "bridge coverage")
    for row, edge in zip(prediction["boundary"], facts["bridges"], strict=True):
        fields(row, "transaction_id index source_event source_outpoint destination_owner source_owner_guess same_owner_guess", "boundary guess")
        need({k: row[k] for k in edge} == edge, "exact bridge source/outpoint/destination association")
        need(row["source_owner_guess"] is None or type(row["source_owner_guess"]) is int
             and row["source_owner_guess"] in range(32), "source owner guess")
        need(row["same_owner_guess"] is None or type(row["same_owner_guess"]) is bool, "common owner guess")


def _score_rows(events, truth, profile, horizon, predictions, horizons):
    variants = {v: {s: {m: _counter() for m in METRICS} for s in STRATA} for v in VARIANTS}
    ranks = {v: {s: [] for s in STRATA} for v in VARIANTS}
    direct = {m: 0 for m in METRICS}
    admitted, admitted_at = {0}, []
    for i, event in enumerate(events):
        if event["mode"] == 0:
            admitted.add(truth["events"][i]["owner"])
        admitted_at.append(len(admitted) == 32)
    member_set = set(members(profile))
    for ordinal, (i, ends) in enumerate(horizons.items()):
        hidden = truth["events"][i]
        sender, recipient, amount = hidden["owner"], hidden["recipient"], hidden["amount"]
        row = predictions[(profile, ends[horizon])][i]
        author_known = sender in member_set
        recipient_known = author_known or recipient in member_set
        policy_known = ordinal < 4
        sender_known = author_known or policy_known
        amount_known = recipient_known or policy_known
        known = dict(sender=sender_known, recipient=recipient_known,
                     relationship=sender_known and recipient_known,
                     amount_within_10pct=amount_known, amount_exact=amount_known)
        for metric in METRICS:
            direct[metric] += int(known[metric])
        adversarial = sender < 8 or recipient < 8
        strata = dict(primary=admitted_at[i] and not adversarial,
                      all_undisclosed=True, startup=not admitted_at[i], adversary_endpoint=adversarial)
        for variant, guess in row["guesses"].items():
            correct = dict(sender=guess["sender"] == sender, recipient=guess["recipient"] == recipient,
                relationship=guess["sender"] == sender and guess["recipient"] == recipient,
                amount_within_10pct=10 * abs(guess["amount"] - amount) <= amount,
                amount_exact=guess["amount"] == amount)
            for stratum, included in strata.items():
                if not included:
                    continue
                for metric in METRICS:
                    if not known[metric]:
                        variants[variant][stratum][metric]["eligible"] += 1
                        variants[variant][stratum][metric]["correct"] += int(correct[metric])
                if not known["relationship"]:
                    ranks[variant][stratum].append(dict(event=i, rank=guess["relationship_rank"],
                                                        correct=correct["relationship"]))
    warnings, diagnostic = [], []
    for name in VARIANTS:
        for stratum in STRATA:
            result = variants[name][stratum]
            for metric in METRICS:
                result[metric]["rate"] = _fraction(_rate(result[metric]))
                if metric in CAPS and _rate(result[metric]) is not None and _rate(result[metric]) > CAPS[metric]:
                    (warnings if stratum == "primary" else diagnostic).append(dict(
                        variant=name, stratum=stratum, metric=metric, kind="absolute",
                        cap=_fraction(CAPS[metric]), rate=result[metric]["rate"]))
            result["selective_relationship"] = {str(q): _selected(ranks[name][stratum], q) for q in COVERAGES}
            for q, counter in result["selective_relationship"].items():
                counter["rate"] = _fraction(_rate(counter))
                if _rate(counter) is not None and _rate(counter) > Fraction(1, 2):
                    (warnings if stratum == "primary" else diagnostic).append(dict(variant=name, stratum=stratum,
                        metric="selective_relationship", nominal_percent=int(q), kind="selective",
                        cap=_fraction(Fraction(1, 2)), rate=counter["rate"]))
    advantages = {}
    for name in VARIANTS[1:]:
        advantages[name] = {}
        for metric in CAPS:
            attack, prior = variants[name]["primary"][metric], variants["prior"]["primary"][metric]
            need(attack["eligible"] == prior["eligible"], "paired denominator mismatch")
            difference = _rate(attack) - _rate(prior) if attack["eligible"] else None
            advantages[name][metric] = dict(difference=_fraction(difference), eligible=attack["eligible"],
                                             cap=_fraction(Fraction(1, 20)))
            if difference is not None and difference > Fraction(1, 20):
                warnings.append(dict(variant=name, stratum="primary", metric=metric,
                    kind="prior_advantage", cap=_fraction(Fraction(1, 20)), difference=_fraction(difference)))
    complete = all(variants["prior"]["primary"][m]["eligible"] > 0 for m in METRICS)
    return dict(complete=complete, targets=len(horizons), known_exclusions=direct, variants=variants,
                primary_prior_advantages=advantages, observed_primary_warnings=warnings,
                diagnostic_exceedances=diagnostic)


def _boundary_score(prediction, truth, events):
    actual = {b["transaction_id"]: b for b in truth["bridges"]}
    counts = dict(edges=0, same_owner_true=0, cross_user_true=0, guesses=0, abstentions=0,
                  true_positive=0, false_positive=0, true_negative=0, false_negative=0,
                  source_owner_correct=0, source_owner_guesses=0)
    for row in prediction["boundary"]:
        need(row["transaction_id"] in actual, "bridge truth missing")
        bridge = actual[row["transaction_id"]]
        need(events[row["source_event"]]["id"] == bridge["event_id"], "bridge source event truth")
        same = bridge["source_owner"] == bridge["target_owner"]
        counts["edges"] += 1
        counts["same_owner_true" if same else "cross_user_true"] += 1
        guess = row["same_owner_guess"]
        if guess is None:
            counts["abstentions"] += 1
        else:
            counts["guesses"] += 1
            counts[("true_" if guess == same else "false_") + ("positive" if guess else "negative")] += 1
        if row["source_owner_guess"] is not None:
            counts["source_owner_guesses"] += 1
            counts["source_owner_correct"] += int(row["source_owner_guess"] == bridge["source_owner"])
    need(counts["edges"] == 4 and counts["same_owner_true"] == counts["cross_user_true"] == 2, "four boundary controls")
    return counts


def _required_activity(ledger, policy_checked):
    counts = {name: integer(policy_checked[name], 0, 64) for name in (
        "payments_with_noncapital_input", "payments_spending_payment_receipts",
        "payments_spending_readmission_credits")}
    counts.update({name: integer(ledger[name], 0, 64) for name in
                   ("one_input_payments", "two_input_payments")})
    need(counts["one_input_payments"] + counts["two_input_payments"] == 64,
         "ordinary payment input coverage")
    need(counts["payments_with_noncapital_input"] == counts["two_input_payments"]
         and counts["payments_spending_payment_receipts"] + counts["payments_spending_readmission_credits"]
         == counts["payments_with_noncapital_input"], "independent receipt/input coverage")
    missing = [name for name in ("payments_spending_payment_receipts", "one_input_payments",
                                 "two_input_payments") if counts[name] == 0]
    return dict(complete=not missing, counts=counts, missing=missing,
                scope="Missing required activity leaves this retained attempt incomplete; never resample.")


def score(raw, directory, timing, policy, truth, predictions):
    """One post-seal scorer call. No private data is passed into an observer."""
    import native_usage_generate as generator
    need(policy == generator.public_policy() and truth["policy_sha256"] == digest(policy), "frozen policy")
    relation = surface.native_relation(raw, directory)
    events = relation["algebra"]["events"]
    ledger = _ledger(relation, truth)
    native = _native_accounting(raw)
    need(native == truth["accounting"] and native["pool_fees_sompi"] == ledger["pool_fees_sompi"], "independent native accounting")
    policy_checked = generator.validate_generated(dict(raw=raw, directory=directory, timing=timing), truth, policy)
    need(policy_checked["complete"] is True and policy_checked["passed"] is True, "usage policy rejected")
    activity = _required_activity(ledger, policy_checked)
    horizons = _horizons(events)
    need(len(horizons) == 64, "exact ordinary payment coverage")
    points = sorted({end for ends in horizons.values() for end in ends.values()})
    expected = {(profile, end) for end in points for profile in PROFILES}
    need(type(predictions) is list and len(predictions) == len(expected), "complete profile/prefix batch")
    indexed, all_predictions = {}, {}
    prefix_cache = {}
    for entry in predictions:
        fields(entry, "profile through_event prediction", "prediction record")
        key = entry["profile"], entry["through_event"]
        need(type(key[1]) is int and key in expected and key not in indexed, "duplicate/foreign profile prefix")
        profile, end = key
        if end not in prefix_cache:
            prefix_cache[end] = _prefix(raw, directory, timing, events, end)
        r, d, t = prefix_cache[end]
        count = events[end]["count_before"] + len(events[end]["new"])
        view = _view(truth, profile, end, count)
        facts = surface.project(r, d, view, t, policy)
        p = entry["prediction"]
        _check_prediction(p, profile, end, r, d, t, view, policy, facts)
        indexed[key] = {row["event"]: row for row in p["rows"]}
        all_predictions[key] = p
    need(set(indexed) == expected, "profile/prefix coverage")
    consistency = _fixed_truth(relation, truth)
    profiles, warnings, complete = {}, [], activity["complete"]
    for profile in PROFILES:
        result = {h: _score_rows(events, truth, profile, h, indexed, horizons) for h in HORIZONS}
        for horizon, scored in result.items():
            complete &= scored["complete"]
            warnings.extend(dict(profile=profile, horizon=horizon, **w) for w in scored["observed_primary_warnings"])
        result["native_boundary_final"] = _boundary_score(all_predictions[(profile, len(events) - 1)], truth, events)
        profiles[profile] = result
    status = ("incomplete" if not complete else "observed-finite-case-cap-warning" if warnings
              else "completed-native-screen-no-observed-primary-warning")
    return dict(schema="kpi-native-usage-score-v1", complete=bool(complete), status=status,
        qualification_pass=False, independent_histories=1, raw_sha256=digest(raw), directory_sha256=digest(directory),
        timing_sha256=digest(timing), policy_sha256=digest(policy), predictions_sha256=digest(predictions),
        checked=dict(native_accounting=native, private_ledger=ledger, usage_policy=policy_checked,
                     required_activity=activity,
                     cashout_modes={mode: truth["schedule"]["modes"].count(mode)
                                    for mode in ("prompt", "accumulated", "retain")},
                     fixed_truth=consistency, observation_prefixes=len(points), predictions=len(predictions),
                     target_profile_horizons=64 * len(PROFILES) * len(HORIZONS)),
        profiles=profiles, observed_primary_warnings=warnings,
        validated_disclosure_search_performed=False,
        limits=["One dependent synthetic usage scenario with genuine offline native bytes, not a population qualification.",
                "Observed cap warnings are descriptive; no confidence intervals or statistically certified breaches.",
                "Heuristic hits and native value-flow edges are not forced internal disclosures or common-owner facts.",
                "Native signature/proof checks, freeze identity and sealing barrier are caller prerequisites; no accepted-chain claim."])


def controls():
    """Hand-built tests only; no proof generation, private paths or held-out data."""
    tests = []
    need(Fraction(1, 10) == CAPS["sender"] and not Fraction(1, 10) > CAPS["sender"], "cap equality")
    need(Fraction(11, 100) > CAPS["sender"] and Fraction(1, 5) == CAPS["amount_within_10pct"], "exact caps")
    need(Fraction(3, 20) - Fraction(1, 10) == Fraction(1, 20), "advantage exact boundary")
    tests.append("exact-rational-caps-and-advantage-boundaries")
    rows = [dict(event=2, rank=[1, 0, 0, -1], correct=True), dict(event=1, rank=[1, 0, 0, -1], correct=False)]
    need(_selected(rows, 5)["correct"] == 0 and _selected(rows, 5)["eligible"] == 1, "ordinal rank tie")
    need(_selected([], 25)["realized_coverage"] is None, "empty selective undefined")
    tests.append("rank-ties-ceiling-small-groups-empty")
    events = [dict(mode=1), dict(mode=1), dict(mode=0), dict(mode=2), dict(mode=1), dict(mode=2)]
    need(_horizons(events) == {1: dict(creation=1, cashout=3, final=5), 4: dict(creation=4, cashout=5, final=5)},
         "public next cashout")
    need(_horizons(events[:-1])[4]["cashout"] == 4, "missing cashout fallback")
    tests.append("cashout-cutoff-public-order-not-hidden-recipient")
    for role in range(8):
        need(members(f"P{role}") == [role], "individual profile")
    need(members("C") == [] and members("pooled") == list(range(8)), "profile boundaries")
    tests.append("explicit-public-individual-pooled-profiles")

    def reject(call, name):
        try:
            call()
        except ValueError:
            tests.append(name)
            return
        raise ValueError("control accepted: " + name)

    def tx(identifier, inputs, values):
        return dict(id=f"{identifier:064x}", payload="",
                    inputs=[dict(previousOutpoint=dict(transactionId=f"{source:064x}", index=index))
                            for source, index in inputs],
                    outputs=[dict(value=str(value)) for value in values])

    # Arithmetic-only bodies: no claim that these stand-ins contain proofs or signatures.
    parent = tx(100, [(1000, 0)], [10*SOMPI, SOMPI-10])
    founding = tx(200, [(100, 0)], [9*SOMPI, SOMPI-10])
    exited = tx(201, [(200, 0)], [5*SOMPI, 4*SOMPI-10])
    bridge = tx(300, [(201, 1)], [3*SOMPI, SOMPI-20])
    admitted = tx(202, [(201, 0), (300, 0)], [8*SOMPI-10])
    terminal = tx(203, [(202, 0)], [8*SOMPI-20])
    raw = dict(parents=[bridge, parent], lineage=[founding, exited, admitted, terminal])
    account = _native_accounting(raw, 1)
    need(account["external_injection_sompi"] == 11*SOMPI
         and account["ordinary_fees_sompi"] == 30 and account["pool_fees_sompi"] == 30
         and account["final_native_unspent_sompi"] == 11*SOMPI-60,
         "recycled bridge/change native accounting")
    tests.append("native-accounting-recycled-value-all-change-and-topological-order")
    bad = copy.deepcopy(raw); bad["parents"].append(tx(301, [(201, 1)], [3*SOMPI, SOMPI-20]))
    reject(lambda: _native_accounting(bad, 1), "native-global-double-spend-rejected")
    bad = copy.deepcopy(raw); bad["parents"][0]["outputs"][1]["value"] = str(2*SOMPI)
    reject(lambda: _native_accounting(bad, 1), "native-bridge-inflation-rejected")
    bad = copy.deepcopy(raw); bad["lineage"][-1]["inputs"][0]["previousOutpoint"]["index"] = 1
    reject(lambda: _native_accounting(bad, 1), "native-missing-outpoint-rejected")
    bad = copy.deepcopy(raw); bad["parents"].append(copy.deepcopy(parent))
    reject(lambda: _native_accounting(bad, 1), "native-duplicate-body-rejected")

    # Prefix includes a DRAIN but withholds the bridge until its consuming ADMIT.
    raw.update(descriptor={}, vk_hex="")
    events = [dict(mode=2), dict(mode=0), dict(mode=2)]
    directory = dict(schema="directory", entries=[dict(transaction_id=parent["id"], index=0, owner=0)])
    timing = dict(schema="timing", events=[dict(event_id=t["id"], minute=i) for i, t in enumerate(raw["lineage"][1:])])
    before, d, t = _prefix(raw, directory, timing, events, 0)
    after, _, _ = _prefix(raw, directory, timing, events, 1)
    need([x["id"] for x in before["parents"]] == [parent["id"]]
         and {x["id"] for x in after["parents"]} == {parent["id"], bridge["id"]}
         and len(before["lineage"]) == 2 and len(t["events"]) == 1 and d == directory,
         "independent prefix publication")
    hidden = dict(values=[100, 0, 200, 300], owners=[0, None, 1, 0],
                  inputs={"0": [2, 0], "1": []}, events=[
                      dict(owner=0, event_id="old", outputs=[]), dict(owner=0, event_id="future", outputs=[])])
    view = _view(hidden, "P0", 0, 3)
    need(view["receipts"] == [dict(owner=0, position=0, value=100)]
         and view["authored"] == [dict(owner=0, event_id="old", inputs=[0, 2], outputs=[])],
         "future receipt/author excluded and authored set sorted")
    tests.append("independent-prefix-parent-time-view-cuts")

    # Five explicit ordinary targets after all users join. First four are the
    # policy-known control tags, fifth is an honest primary payment.
    events = [dict(mode=1)] + [dict(mode=0) for _ in range(31)] + [dict(mode=1) for _ in range(5)] + [dict(mode=2)]
    truth = dict(events=[dict(owner=0)] + [dict(owner=i) for i in range(1, 32)] + [
        dict(owner=i, recipient=8+i, amount=100) for i in range(4)] +
        [dict(owner=8, recipient=9, amount=100), dict(owner=9)])
    horizons = _horizons(events)
    indexed = {}
    for profile in PROFILES:
        for end in {j for ends in horizons.values() for j in ends.values()}:
            indexed[(profile, end)] = {
                i: dict(guesses={variant: dict(sender=e["owner"], recipient=e["recipient"],
                                              amount=110, relationship_rank=[0, 0, 0, 0])
                                for variant in VARIANTS})
                for i, e in enumerate(truth["events"]) if i in horizons and i <= end}
    scored = _score_rows(events, truth, "C", "final", indexed, horizons)
    need(scored["complete"] and scored["known_exclusions"] == dict(sender=4, recipient=0,
         relationship=0, amount_within_10pct=4, amount_exact=4), "public policy field exclusions")
    need(scored["variants"]["prior"]["primary"]["amount_within_10pct"]["correct"] == 1
         and scored["variants"]["prior"]["primary"]["amount_exact"]["correct"] == 0
         and all(v["difference"] == dict(numerator=0, denominator=1)
                 for variant in scored["primary_prior_advantages"].values() for v in variant.values()),
         "amount boundary and exact paired denominator")
    need(scored["observed_primary_warnings"], "observed cap warnings retained")
    tests.append("metric-specific-public-facts-exact-amount-boundary-paired-denominators")
    # Recipient-only participant knowledge must leave the sender unknown.
    truth["events"][36]["recipient"] = 0
    recipient = _score_rows(events, truth, "P0", "final", indexed, horizons)
    need(recipient["known_exclusions"] == dict(sender=4, recipient=2, relationship=1,
         amount_within_10pct=5, amount_exact=5), "recipient-only fact exclusions")
    need(not recipient["complete"] and recipient["variants"]["prior"]["primary"]["sender"]["rate"] is None,
         "empty honest primary incomplete")
    tests.append("recipient-only-exclusion-empty-primary-incomplete")

    boundary_truth = dict(bridges=[dict(transaction_id=str(i), event_id=str(i), source_owner=8+i,
        target_owner=8+i if i < 2 else 12+i) for i in range(4)])
    boundary = dict(boundary=[dict(transaction_id=str(i), source_event=i,
        same_owner_guess=[True, None, True, False][i], source_owner_guess=[8, None, 14, 11][i]) for i in range(4)])
    confusion = _boundary_score(boundary, boundary_truth, [dict(id=str(i)) for i in range(4)])
    need(confusion == dict(edges=4, same_owner_true=2, cross_user_true=2, guesses=3, abstentions=1,
        true_positive=1, false_positive=1, true_negative=1, false_negative=0,
        source_owner_correct=2, source_owner_guesses=3), "bridge confusion matrix")
    tests.append("self-cross-unknown-bridge-false-positive-and-abstention-counts")

    activity = dict(payments_with_noncapital_input=20, payments_spending_payment_receipts=19,
                    payments_spending_readmission_credits=1)
    need(_required_activity(dict(one_input_payments=44, two_input_payments=20), activity)["complete"], "activity coverage")
    no_receipts = {**activity, "payments_spending_payment_receipts": 0, "payments_spending_readmission_credits": 20}
    need(not _required_activity(dict(one_input_payments=44, two_input_payments=20), no_receipts)["complete"]
         and not _required_activity(dict(one_input_payments=64, two_input_payments=0),
                                    {name: 0 for name in activity})["complete"]
         and not _required_activity(dict(one_input_payments=0, two_input_payments=64),
                                    {**activity, "payments_with_noncapital_input": 64,
                                     "payments_spending_payment_receipts": 63})["complete"],
         "missing activity incomplete")
    tests.append("missing-required-activity-retained-incomplete")

    # The scorer requires exactly all visible targets and the same prefix/view
    # identity as the isolated observer. These are schema controls, not native data.
    inputs = dict(raw={}, directory={}, timing={}, view={}, policy={})
    facts = dict(events=[dict(mode=1, id="boot"), dict(mode=1, id="pay1"),
                         dict(mode=1, id="pay2")], diagnostics={}, bridges=[])
    prediction = dict(schema="kpi-native-usage-predictions-v1", complete=True, profile="C",
                      through_event=2, boundary=[], diagnostics={},
                      **{name+"_sha256": digest(value) for name, value in inputs.items()},
                      rows=[dict(event=i, event_id=f"pay{i}", guesses={variant:
                            dict(sender=8, recipient=9, amount=SOMPI, relationship_rank=[0, 0, 0, 0])
                            for variant in VARIANTS}) for i in (1, 2)])
    def check_prediction(value):
        _check_prediction(value, "C", 2, facts=facts, **inputs)
    check_prediction(prediction)
    tests.append("complete-prediction-prefix-schema-positive")
    for name, mutation in (
        ("prediction-missing-target-rejected", lambda x: x["rows"].pop()),
        ("prediction-future-or-wrong-view-hash-rejected", lambda x: x.update(view_sha256="0"*64)),
        ("prediction-unknown-variant-rejected", lambda x: x["rows"][0]["guesses"].update(other={})),
        ("prediction-target-order-rejected", lambda x: x["rows"].reverse()),
        ("prediction-bool-amount-rejected", lambda x: x["rows"][0]["guesses"]["prior"].update(amount=True)),
        ("prediction-altered-public-diagnostics-rejected", lambda x: x.update(diagnostics=dict(extra=1))),
    ):
        bad = copy.deepcopy(prediction); mutation(bad)
        reject(lambda: check_prediction(bad), name)

    scan = dict(notes=[dict(position=0, value_sompi="100", spent=True),
                       dict(position=1, value_sompi="100", spent=False)], balance_sompi="100",
                drained=False, chain_acceptance_verified=False, head=dict(transaction_count=2))
    _check_scan(scan, [100, 100], [0, 0], {0}, 0, False, 2)
    reject(lambda: _check_scan(scan, [100, 100], [0, 0], {1}, 0, False, 2),
           "equal-value-same-owner-consumption-chronology-rejected")

    # Both original encodings, actual-sompi domains, no generated cryptography.
    steps = [(1, 0, [0], [(0, 700_000_000), (None, 0)]),
             (0, 1, [], [(1, 300_000_000), (None, 0)]),
             (1, 0, [1], [(1, 200_000_000), (0, 460_000_000)]),
             (2, 1, [3, 5], []), (2, 0, [6], [])]
    relation, truth = full._fixture(740_000_000, steps, roles=32, floor=FLOOR, fee=FEE)
    truth["events"] = [dict(owner=owner) for _, owner, _, _ in steps]
    need(_fixed_truth(relation, truth)["complete"], "both concrete truth encodings SAT")
    tests.append("original-cp-z3-fixed-truth-positive-two-input-drain")
    bad = copy.deepcopy(truth); bad["values"][5] += 1
    reject(lambda: _fixed_truth(relation, bad), "fixed-truth-one-sompi-inflation-rejected")
    bad = copy.deepcopy(truth); bad["owners"][5] = 2
    reject(lambda: _fixed_truth(relation, bad), "fixed-truth-cross-owner-spend-rejected")
    bad = copy.deepcopy(truth); bad["inputs"]["2"] = [0]
    reject(lambda: _fixed_truth(relation, bad), "fixed-truth-replayed-input-rejected")
    return dict(complete=True, passed=True, tests=tests,
                scope="Explicit scoring/accounting controls; no held-out execution or privacy qualification")
