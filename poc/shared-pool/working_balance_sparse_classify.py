"""Truth-side explanation of already sealed sparse-case guesses.

No file access, attack selection, workload generation or policy modification.
Structural ancestry is deliberately not an allocation of economic value.
"""
import json

METRICS = ("sender", "recipient", "relationship", "amount_exact", "amount_within_10pct")
FLAGS = ("inputs_match", "receipt_closed", "change_closed", "both_closed",
         "input_change_closed", "receipt_private_ancestry", "receipt_all_ancestry",
         "change_private_ancestry", "change_all_ancestry", "receipt_native_only",
         "change_native_only", "receipt_follows_change", "change_follows_receipt",
         "receipt_owner_matches", "change_owner_matches")
CLASSES = ("fallback", "all_both_closed", "some_both_closed", "closed_value_path_only",
           "ancestry_without_closed_value_path", "wrong_branch_only", "unrelated_selected_payouts")


def need(ok, message="sparse diagnostic invariant"):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def outcomes(guess, target):
    sender = guess["sender"] == target["sender"]
    recipient = guess["recipient"] == target["recipient"]
    return dict(sender=sender, recipient=recipient, relationship=sender and recipient,
                amount_exact=guess["amount"] == target["amount"],
                amount_within_10pct=10 * abs(guess["amount"] - target["amount"]) <= target["amount"])


def transitions(before, after):
    need(len(before) == len(after), "paired denominator")
    both = sum(a and b for a, b in zip(before, after, strict=True))
    gains = sum(not a and b for a, b in zip(before, after, strict=True))
    losses = sum(a and not b for a, b in zip(before, after, strict=True))
    neither = sum(not a and not b for a, b in zip(before, after, strict=True))
    need(both + gains + losses + neither == len(before), "paired partition")
    return dict(targets=len(before), before=sum(before), after=sum(after), both=both,
                gains=gains, losses=losses, neither=neither)


class Graph:
    """Actual note edges, plus a separate public-native re-entry ancestry graph."""
    def __init__(self, public, truth):
        self.public, self.events = public["events"], truth["events"]
        need(len(self.public) == len(self.events), "event alignment")
        self.notes, self.private, self.all = {}, {}, {}
        self.event_private, self.event_all, native_refs = {}, {}, {}
        self.consumers = {}
        for index, (event, hidden) in enumerate(zip(self.public, self.events, strict=True)):
            need(event["event"] == hidden["event"] == index, "ordered actual events")
            direct, extended = set(), set()
            for position in hidden["inputs"]:
                need(position in self.notes and position not in self.consumers, "actual unique consumption")
                self.consumers[position] = index
                direct.update(self.private[position])
                extended.update(self.all[position])
            bridge = event.get("bridge")
            if bridge is not None:
                need(not hidden["inputs"], "native admission has no private inputs")
                for source in bridge["sources"]:
                    need(source["ref"] in native_refs, "missing native bridge ancestry")
                    extended.update(native_refs[source["ref"]])
                if bridge["change_ref"]:
                    native_refs[bridge["change_ref"]] = set(extended)
            self.event_private[index], self.event_all[index] = set(direct), set(extended)
            for output in hidden["outputs"]:
                position = output["position"]
                need(position not in self.notes, "unique actual note position")
                self.notes[position] = dict(output, born=index)
                self.private[position] = set(direct) | {position}
                self.all[position] = set(extended) | {position}
            if event["payout"]:
                native_refs[event["event_id"]] = set(extended)

    def follows(self, position, events, *, native=True):
        graph = self.event_all if native else self.event_private
        return any(position in graph[event] for event in events)

    def closed(self, root, residue):
        """Does this entire selected payout flow exactly account for the root?

        A specified extra note is included once and must also be consumed.
        This is an actual-history compatibility test, never a uniqueness claim.
        """
        note = self.notes[root]
        events, coinput = residue["events"], residue["coinput"]
        if note["value"] == 0:
            return not events and coinput is None and residue["value"] == 0
        if (not events or events != sorted(set(events)) or residue["value"] != note["value"]
                or residue["owner"] not in (None, note["recipient"])):
            return False
        if coinput is not None and (coinput not in self.notes or coinput == root
                                    or self.notes[coinput]["value"] <= 0):
            return False
        frontier = {root} | ({coinput} if coinput is not None else set())
        paid = 0
        for event in events:
            if not 0 <= event < len(self.events):
                return False
            hidden, public = self.events[event], self.public[event]
            inputs = set(hidden["inputs"])
            if (hidden["kind"] not in ("partial", "exit") or not public["payout"]
                    or not inputs or not inputs <= frontier
                    or any(self.notes[p]["born"] >= event for p in inputs)):
                return False
            frontier.difference_update(inputs)
            frontier.update(out["position"] for out in hidden["outputs"] if out["value"] > 0)
            paid += public["payout"] + public["fee"]
        expected = note["value"] + (self.notes[coinput]["value"] if coinput is not None else 0)
        return not frontier and paid == expected


def construction(graph, target, route):
    hidden = graph.events[target["event"]]
    receipt, change = [out["position"] for out in hidden["outputs"]]
    r, c = route["receipt"], route["tail"]
    proposed = route["input_positions"]
    inputs = len(proposed) == len(set(proposed)) and set(proposed) == set(hidden["inputs"])
    receipt_closed, change_closed = graph.closed(receipt, r), graph.closed(change, c)
    rp = graph.follows(receipt, r["events"], native=False)
    ra = graph.follows(receipt, r["events"])
    cp = graph.follows(change, c["events"], native=False)
    ca = graph.follows(change, c["events"])
    return dict(inputs_match=inputs, receipt_closed=receipt_closed, change_closed=change_closed,
                both_closed=inputs and receipt_closed and change_closed,
                input_change_closed=inputs and change_closed,
                receipt_private_ancestry=rp, receipt_all_ancestry=ra,
                change_private_ancestry=cp, change_all_ancestry=ca,
                receipt_native_only=ra and not rp, change_native_only=ca and not cp,
                receipt_follows_change=graph.follows(change, r["events"]),
                change_follows_receipt=graph.follows(receipt, c["events"]),
                receipt_owner_matches=bool(r["events"]) and all(
                    graph.events[e]["owner"] == target["recipient"] for e in r["events"]),
                change_owner_matches=bool(c["events"]) and all(
                    graph.events[e]["owner"] == target["sender"] for e in c["events"]))


def classify_target(graph, target, trace):
    need(trace["event"] == target["event"] and trace["full_book_verified"] is True,
         "trace identity and book equality")
    original = trace["decompositions"]
    unique = {canonical(route): route for route in original}
    rows = [construction(graph, target, route) for route in unique.values()]
    any_flag = {key: any(row[key] for row in rows) for key in FLAGS}
    all_flag = {key: bool(rows) and all(row[key] for row in rows) for key in FLAGS}
    if trace["fallback"]:
        need(not rows, "fallback cannot have constructions")
        category = "fallback"
    else:
        need(rows, "selected nonempty book has no construction")
        category = ("all_both_closed" if all_flag["both_closed"] else
                    "some_both_closed" if any_flag["both_closed"] else
                    "closed_value_path_only" if any_flag["receipt_closed"] or any_flag["input_change_closed"] else
                    "ancestry_without_closed_value_path" if any_flag["receipt_all_ancestry"] or any_flag["change_all_ancestry"] else
                    "wrong_branch_only" if any_flag["receipt_follows_change"] or any_flag["change_follows_receipt"] else
                    "unrelated_selected_payouts")
    return dict(obligation=target["obligation"], event=target["event"],
                correct=outcomes(trace["guess"], target), prior_correct=outcomes(trace["prior"], target),
                same_amount_as_prior=trace["guess"]["amount"] == trace["prior"]["amount"],
                support_class=category, offers=len(original), unique_constructions=len(rows),
                old_union_supports=0 if trace["selected_record"] is None else len(trace["selected_record"]["supports"]),
                any=any_flag, all=all_flag,
                construction_flags={key: sum(row[key] for row in rows) for key in FLAGS})


def summarize(rows):
    return dict(targets=len(rows),
                correct={metric: sum(row["correct"][metric] for row in rows) for metric in METRICS},
                prior_correct={metric: sum(row["prior_correct"][metric] for row in rows) for metric in METRICS},
                prior_to_attack={metric: transitions([row["prior_correct"][metric] for row in rows],
                                                    [row["correct"][metric] for row in rows]) for metric in METRICS},
                same_amount_as_prior=sum(row["same_amount_as_prior"] for row in rows),
                support_classes={key: sum(row["support_class"] == key for row in rows) for key in CLASSES},
                hits_by_support_class={metric: {key: sum(row["correct"][metric] and row["support_class"] == key
                    for row in rows) for key in CLASSES} for metric in METRICS},
                offers=sum(row["offers"] for row in rows),
                unique_constructions=sum(row["unique_constructions"] for row in rows),
                old_union_supports=sum(row["old_union_supports"] for row in rows),
                targets_with_any={key: sum(row["any"][key] for row in rows) for key in FLAGS},
                targets_with_all={key: sum(row["all"][key] for row in rows) for key in FLAGS},
                construction_flags={key: sum(row["construction_flags"][key] for row in rows) for key in FLAGS})


def variant_counts(targets, indexed):
    names = set(next(iter(indexed.values()))["all_guesses"])
    result = {}
    for name in sorted(names):
        correct = [outcomes(indexed[target["event"]]["all_guesses"][name], target) for target in targets]
        result[name] = {metric: sum(row[metric] for row in correct) for metric in METRICS}
    return result


def classify_all(bundles, traces, original_summary):
    """Return public aggregates and private per-target diagnostics separately."""
    from working_balance_validate import validate_bundle
    need(set(bundles) == set(traces) == {"whole", "partial"}, "fixed arms")
    groups, private, validation, variants = {}, {}, {}, {}
    targets_by_arm = {}
    for arm in ("whole", "partial"):
        bundle = bundles[arm]
        validation[arm] = validate_bundle(bundle["public"], bundle["directory"], bundle["truth"], bundle["cost"])
        truth = bundle["truth"]
        need(truth["cell"] == "sparse-independent" and truth["arm"] == arm, "fixed case identity")
        for profile, members in (("C+D", []), ("pooled", list(range(8)))):
            expected_view = dict(schema="kpi-working-balance-view-v1", members=members,
                authored=[{key: row[key] for key in ("event", "owner", "inputs", "outputs")}
                          for row in truth["events"] if row["owner"] in members],
                receipts=[dict(position=out["position"], value=out["value"], owner=out["recipient"])
                          for row in truth["events"] for out in row["outputs"]
                          if out["value"] > 0 and out["recipient"] in members])
            need(canonical(expected_view) == canonical(bundle["views"][profile]), "permitted disclosure completeness")
        targets = [target for target in truth["targets"] if target["sender"] >= 8 and target["recipient"] >= 8]
        need(len(targets) == 37 and len({t["obligation"] for t in targets}) == 37, "original primary denominator")
        targets_by_arm[arm] = targets
        graph = Graph(bundle["public"], truth)
        groups[arm], private[arm], variants[arm] = {}, {}, {}
        for profile in ("C+D", "pooled"):
            indexed = {row["event"]: row for row in traces[arm][profile]}
            expected_events = {e["event"] for e in bundle["public"]["events"] if e["mode"] == 1 and not e["payout"]}
            need(set(indexed) == expected_events and len(indexed) == len(traces[arm][profile]), "all public targets traced")
            rows = [classify_target(graph, target, indexed[target["event"]]) for target in targets]
            aggregate = summarize(rows)
            counted = variant_counts(targets, indexed)
            saved = original_summary["cases"]["sparse-independent"]["arms"][arm][profile]["final"]
            need(saved["targets"] == 37, "published denominator")
            for name, metrics in counted.items():
                for metric, value in metrics.items():
                    need(value == saved["variants"][name][metric]["correct"], "sealed original score differs")
            need(aggregate["correct"] == counted["split_tail"] and aggregate["prior_correct"] == counted["prior"],
                 "classification counts differ")
            aggregate["published_final_family_max"] = saved["family_max"]
            aggregate["published_final_maximizers"] = {
                metric: sorted(name for name, row in saved["variants"].items()
                               if row[metric]["correct"] == saved["family_max"][metric])
                for metric in METRICS}
            groups[arm][profile], private[arm][profile], variants[arm][profile] = aggregate, rows, counted
    left, right = targets_by_arm["whole"], targets_by_arm["partial"]
    need([t["obligation"] for t in left] == [t["obligation"] for t in right]
         and bundles["whole"]["truth"]["plan"] == bundles["partial"]["truth"]["plan"], "paired plans and targets")
    paired = {}
    published_pairs = {}
    for profile in ("C+D", "pooled"):
        paired[profile] = {}
        for name in variants["whole"][profile]:
            indexed = {arm: {r["event"]: r for r in traces[arm][profile]} for arm in ("whole", "partial")}
            correct = {arm: [outcomes(indexed[arm][t["event"]]["all_guesses"][name], t)
                             for t in targets_by_arm[arm]] for arm in ("whole", "partial")}
            paired[profile][name] = {metric: transitions([r[metric] for r in correct["whole"]],
                                                       [r[metric] for r in correct["partial"]]) for metric in METRICS}
        saved_case = original_summary["cases"]["sparse-independent"]
        published_pairs[profile] = {}
        for name, metrics in saved_case["paired"][profile]["final"].items():
            published_pairs[profile][name] = {}
            for metric, saved_pair in metrics.items():
                before = saved_case["arms"]["whole"][profile]["final"]["variants"][name][metric]["correct"]
                after = saved_case["arms"]["partial"][profile]["final"]["variants"][name][metric]["correct"]
                gains, losses, count = saved_pair["gains"], saved_pair["losses"], saved_pair["eligible"]
                both, neither = before-losses, count-before-gains
                need(count == 37 and after-before == gains-losses and min(both, neither) >= 0,
                     "published carryforward pair arithmetic")
                saved = dict(targets=count, before=before, after=after, both=both,
                             gains=gains, losses=losses, neither=neither)
                if name in paired[profile]:
                    need(saved == paired[profile][name][metric], "independent base pair recount differs")
                published_pairs[profile][name][metric] = saved
    public_to_pooled = {arm: {metric: transitions(
        [row["correct"][metric] for row in private[arm]["C+D"]],
        [row["correct"][metric] for row in private[arm]["pooled"]]) for metric in METRICS}
        for arm in ("whole", "partial")}
    result = dict(schema="kpi-working-balance-sparse-diagnosis-v1", complete=True,
                  original_gate_changed=False, qualification_pass=False, primary_targets=37,
                  groups=groups, final_base_variant_counts=variants, whole_to_partial=paired,
                  published_whole_to_partial_all_strategies=published_pairs,
                  public_to_pooled=public_to_pooled,
                  accounting_validation=validation,
                  limits=["Exploratory on four sealed final observations of one paired sparse history.",
                          "Matching actual constructions does not establish unique inference or economic allocation.",
                          "Arithmetic model, same-host author controls; no native or real-user privacy evidence.",
                          "Old final family maxima retain public copies and earlier-prefix strategies; their paired comparisons are archived aggregates, not new construction traces."])
    # Only counts/booleans and constant labels are published; detailed target
    # identities and correctness vectors stay in the separate private result.
    return result, dict(schema="kpi-working-balance-sparse-private-v1", rows=private)
