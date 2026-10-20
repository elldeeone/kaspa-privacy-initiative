#!/usr/bin/env python3
"""Public native-script comparison and conditional exact owner/value inference.

Native replay is a caller prerequisite; this decoder does not verify proofs.
Different funding keys do not establish different shielded owners. The explicit
funding directory and current wallet's self-credit/exit-owner policy supply those
assumptions. Arithmetic alternatives are not alternate openings of commitments.
Only score() receives private truth, after the caller seals predictions.
"""
import copy
import json
import sys
from pathlib import Path

import early_privacy_surface as surface
import population_privacy_model as full
from population_privacy_index import witness_conditions
from two_input_privacy_observer import Model, decode, FLOOR, PAYOUT_FLOOR
from two_input_privacy_z3 import Z3Model

FEE = full.FEE
DIRECTORY = "kpi-address-reuse-funding-owners-v1"
PREDICTION = "kpi-address-reuse-predictions-v1"
TRUTH = "kpi-address-reuse-truth-v1"


def load_public(directory):
    path = directory / "funding_owner_directory.json"
    return surface.load_raw(directory), surface.read(path) if path.exists() else None


def _point(funding):
    return funding["transaction_id"], funding["index"]


def _funding(projection):
    return [projection["surface"]["funding"]] + [
        row["funding"] for row in projection["surface"]["events"] if row["funding"]]


def boundary(projection):
    """Compare selected funding outputs, never every output of an ancestor."""
    comparisons = []
    for source in _funding(projection):
        for row in projection["surface"]["events"]:
            if row["payout_script"] is not None:
                comparisons.append(dict(
                    funding_outpoint=dict(transaction_id=source["transaction_id"], index=source["index"]),
                    payout_transaction_id=row["transaction_id"], payout_event=row["ordinal"],
                    equal=source["script_public_key"] == row["payout_script"]))
    return dict(comparisons=comparisons,
                meaning="Equal native spending conditions only; no human or internal-payment identity follows alone")


def _association(projection, directory):
    full.fields(directory, {"schema", "entries"}, "funding directory")
    full.need(directory["schema"] == DIRECTORY and isinstance(directory["entries"], list), "directory schema")
    expected = {_point(row) for row in _funding(projection)}
    full.need(len(expected) == 2, "diagnostic needs exactly two selected funding outpoints")
    owners = {}
    for entry in directory["entries"]:
        full.fields(entry, {"transaction_id", "index", "owner"}, "funding association")
        surface.unhex(entry["transaction_id"], 32)
        full.integer(entry["index"], 0, 2**32 - 1)
        full.integer(entry["owner"], 0, 1)
        point = _point(entry)
        full.need(point in expected and point not in owners, "missing/ambiguous funding association")
        owners[point] = entry["owner"]
    full.need(set(owners) == expected and set(owners.values()) == {0, 1},
              "distinct wallet-owner associations required; script difference is insufficient")
    return owners


def _relation(projection, directory):
    """Adapt native public bytes, without synthetic-generator provenance tags."""
    owners = _association(projection, directory)
    data = copy.deepcopy(projection["algebra"])
    sources = _funding(projection)
    funding_owners = {}
    for source in sources:
        group = source["transaction_id"] + ":" + str(source["index"])
        funding_owners[group] = owners[_point(source)]
    data["initial"]["funding_group"] = sources[0]["transaction_id"] + ":" + str(sources[0]["index"])
    for row, event in zip(projection["surface"]["events"], data["events"], strict=True):
        if row["funding"]:
            source = row["funding"]
            event["funding_group"] = source["transaction_id"] + ":" + str(source["index"])
    payout_owners = {}
    for row in projection["surface"]["events"]:
        if row["payout_script"] is None:
            continue
        matched = {owners[_point(source)] for source in sources
                   if source["script_public_key"] == row["payout_script"]}
        full.need(len(matched) <= 1, "same payout script has contradictory funding owners")
        if matched:
            payout_owners[row["payout_script"]] = next(iter(matched))
    return dict(roles=[0, 1, 2], algebra=data, commitments=projection["commitments"],
                funding_owners=funding_owners, payout_owners=payout_owners)


class NativePair(full.Pair):
    """Original two arithmetic/ownership encodings, with a strict native adapter.

Role2 remains an unfunded possible recipient. Self-payments are permitted.
The existing owner constraints are reused rather than duplicating them.
"""
    def __init__(self, public, floor=FLOOR, payout_floor=PAYOUT_FLOOR, fee=FEE):
        full.fields(public, {"roles", "algebra", "commitments", "funding_owners", "payout_owners"}, "relation")
        full.need(public["roles"] == [0, 1, 2], "three-role abstraction")
        self.public, self.view, self.data = public, {"members": []}, public["algebra"]
        births, upper = decode(self.data, floor, payout_floor)
        full.need(len(public["commitments"]) == len(births), "commitment position count")
        for cm in public["commitments"]:
            surface.unhex(cm, 32)
            full.need(cm != "0" * 64, "zero commitment")
        events = self.data["events"]
        full.need(events[0]["mode"] == 1, "self-bootstrap required")
        groups = {self.data["initial"]["funding_group"]} | {
            e["funding_group"] for e in events if e["mode"] == 0}
        full.need(set(public["funding_owners"]) == groups and
                  all(type(o) is int and o in public["roles"] for o in public["funding_owners"].values()),
                  "funding-owner framing")
        destinations = {e["destination"] for e in events if e["payout"]}
        full.need(set(public["payout_owners"]) <= destinations and
                  all(type(o) is int and o in public["roles"] for o in public["payout_owners"].values()),
                  "payout-owner framing")
        for e in events:
            full.need(e["fee"] == fee, "fixed wallet fee")
            if e["mode"] != 0:
                full.need(e["anchor_count"] == e["count_before"], "current anchor policy")
            if e["mode"] == 1:
                full.need(e["payout"] == 0, "wallet PAY native payout")
            if e["new"]:
                a, b = e["new"]
                full.need(public["commitments"][a] != public["commitments"][b], "equal sibling commitments")
        self.facts = dict(births=births, upper=upper, receipts={}, authors={})
        self.cp, self.z = Model(self.data, floor, payout_floor), Z3Model(self.data, floor, payout_floor)
        full.need(sum(self.cp.upper) + sum(e["fee"] + e["deposit"] + e["payout"] for e in events)
                  < 2**62, "CP integer range unsupported")
        self.queries, self.diagnostics = {"cp_sat": 0, "z3": 0}, False
        self.context = {}
        self._cp_owners(floor)
        self._z3_owners(floor)


def _prefix(relation, end, linked):
    result = copy.deepcopy(relation)
    result["algebra"]["events"] = result["algebra"]["events"][:end + 1]
    events = result["algebra"]["events"]
    count = events[-1]["count_before"] + len(events[-1]["new"])
    result["commitments"] = result["commitments"][:count]
    groups = {result["algebra"]["initial"]["funding_group"]} | {
        e["funding_group"] for e in events if e["mode"] == 0}
    result["funding_owners"] = {k: v for k, v in result["funding_owners"].items() if k in groups}
    destinations = {e["destination"] for e in events if e["payout"]}
    result["payout_owners"] = {k: v for k, v in result["payout_owners"].items()
                               if linked and k in destinations}
    return result


def _queries(relation):
    events = relation["algebra"]["events"]
    targets = [i for i, e in enumerate(events) if i and e["mode"] == 1]
    full.need(len(targets) == 1, "diagnostic requires one ordinary PAY")
    target = targets[0]
    rows, queries = [], {"cp_sat": 0, "z3": 0}
    for horizon, end in (("creation", target), ("final", len(events) - 1)):
        for linked in (False, True):
            selected = _prefix(relation, end, linked)
            model = NativePair(selected)
            baseline = model.query("cp_sat")
            full.need(baseline is not None and model.query("z3") is not None, "inconsistent conditional relation")
            row = dict(horizon=horizon, event=target, through_event=end,
                       script_association_used=linked, relation_sha256=full.digest(selected))
            for field in ("sender", "recipient", "amount"):
                row[field] = model.proposition(target, field, baseline)
            rows.append(row)
            for engine in queries:
                queries[engine] += model.queries[engine]
    return rows, queries


def analyze(raw, directory):
    projection = surface.project(raw)
    result = dict(schema=PREDICTION, complete=False, public_sha256=full.digest(raw),
                  directory_sha256=full.digest(directory), boundary=boundary(projection),
                  conditional_available=False, rows=[],
                  native_proof_validation="Caller must independently validate/replay these native bytes",
                  meaning="Conditional deductions under wallet and funding-owner assumptions; not human identity or cryptographic indistinguishability")
    try:
        relation = _relation(projection, directory)
    except ValueError as error:
        result["association_error"] = str(error)
        return result
    result["conditional_available"] = True
    result["rows"], result["queries"] = _queries(relation)
    result["complete"] = True
    return result


def score(raw, directory, prediction, truth):
    """Scorer only: fixed actual truth is never passed into analyze()."""
    full.need(prediction["schema"] == PREDICTION and prediction["complete"] is True
              and prediction["conditional_available"] is True, "incomplete prediction")
    full.need(prediction["public_sha256"] == full.digest(raw) and
              prediction["directory_sha256"] == full.digest(directory), "prediction input identity")
    projection = surface.project(raw)
    full.need(prediction["boundary"] == boundary(projection), "boundary prediction changed")
    relation = _relation(projection, directory)
    full.fields(truth, {"schema", "values", "owners", "inputs", "payment", "expected_script_match"}, "truth")
    full.need(truth["schema"] == TRUTH and type(truth["expected_script_match"]) is bool, "truth schema")
    full.fields(truth["payment"], {"sender", "recipient", "amount"}, "true payment")
    events = relation["algebra"]["events"]
    targets = [i for i, e in enumerate(events) if i and e["mode"] == 1]
    full.need(len(targets) == 1, "truth target")
    target = targets[0]
    position = events[target]["new"][0]
    full.need(truth["payment"]["amount"] == truth["values"][position]
              and truth["payment"]["recipient"] == truth["owners"][position]
              and all(truth["owners"][p] == truth["payment"]["sender"] for p in truth["inputs"][str(target)]),
              "payment metadata differs from concrete notes")
    model = NativePair(relation)
    cp, smt = witness_conditions(model, truth)
    consistency = {"cp_sat": model.query("cp_sat", cp) is not None,
                   "z3": model.query("z3", smt) is not None}
    full.need(all(consistency.values()), "actual truth excluded by conditional relation")
    admitted = {_point(row["funding"]) for row in projection["surface"]["events"] if row["funding"]}
    observed_match = any(c["equal"] and _point(c["funding_outpoint"]) in admitted
                         for c in prediction["boundary"]["comparisons"])
    full.need(observed_match == truth["expected_script_match"], "boundary comparison contradicts private setup")
    expected = [(h, end, linked) for h, end in (("creation", target), ("final", len(events) - 1))
                for linked in (False, True)]
    full.need([(r["horizon"], r["through_event"], r["script_association_used"])
               for r in prediction["rows"]] == expected, "missing/reordered profiles")
    scored = []
    for row in prediction["rows"]:
        selected = _prefix(relation, row["through_event"], row["script_association_used"])
        full.need(row["event"] == target and row["relation_sha256"] == full.digest(selected), "profile relation changed")
        forced = {}
        for field in ("sender", "recipient", "amount"):
            claim = row[field]
            full.need(type(claim["forced"]) is bool, "forced flag")
            different = "UNSAT" if claim["forced"] else "SAT"
            full.need(all(claim["certificates"][engine] == {"candidate": "SAT", "different": different}
                          for engine in ("cp_sat", "z3")), "dual certificate framing")
            if claim["forced"]:
                full.need(claim["candidate"] == truth["payment"][field], "forced claim contradicts actual truth")
            forced[field] = claim["forced"]
        scored.append(dict(horizon=row["horizon"], script_association_used=row["script_association_used"], forced=forced))
    return dict(complete=True, boundary_matches_setup=True, truth_consistency=consistency,
                rows=scored, qualification_pass=False,
                scope="Constructed conditional diagnostic; no 32-role, cryptographic-security or chain-acceptance claim")


def _fixture(initial, steps, floor=1):
    public, truth = full._fixture(initial, steps, roles=3, floor=floor)
    return {key: public.get(key, {}) for key in
            ("roles", "algebra", "commitments", "funding_owners", "payout_owners")}, truth


def controls():
    tests = []
    relation, truth = _fixture(20, [(1, 0, [0], [(0, 19), (None, 0)]),
        (0, 1, [], [(1, 11), (None, 0)]), (1, 0, [1], [(1, 18), (None, 0)]),
        (2, 1, [3, 5], [])])
    unlinked = NativePair(relation, 1, 1, 1)
    other = dict(values=[20, 19, 0, 11, 0, 10, 0], owners=[0, 0, None, 1, None, 0, None],
                 inputs={"0": [0], "1": [], "2": [3], "3": [1, 5]})
    for witness in (truth, other):
        cp, smt = witness_conditions(unlinked, witness)
        assert unlinked.query("cp_sat", cp) is not None and unlinked.query("z3", smt) is not None
    baseline = unlinked.query("cp_sat")
    assert all(not unlinked.proposition(2, field, baseline)["forced"] for field in ("sender", "recipient", "amount"))
    tests.append("unlinked-both-actual-and-reversed-payment-histories")
    linked = copy.deepcopy(relation)
    linked["payout_owners"] = {linked["algebra"]["events"][-1]["destination"]: 1}
    model = NativePair(linked, 1, 1, 1)
    baseline = model.query("cp_sat")
    for field, expected in (("sender", 0), ("recipient", 1), ("amount", 18)):
        claim = model.proposition(2, field, baseline)
        assert claim["forced"] and claim["candidate"] == expected
    assert model.query("cp_sat", [sum(model.cp.select[3]) == 1]) is None
    import z3
    assert model.query("z3", [z3.PbEq([(x, 1) for x in model.z.select[3]], 1)]) is None
    assert model.z.solver.num_scopes() == 0
    tests.append("equality-owner-constraint-forces-payment-with-genuine-two-input-exit")
    early = _prefix(linked, 2, True)
    assert not early["payout_owners"] and early["algebra"]["events"][2]["anchor_count"] == 5
    before = NativePair(early, 1, 1, 1)
    for recipient in (0, 2):
        assert before.query("cp_sat", [before.cp_owners[5] == recipient]) is not None
        assert before.query("z3", [before.z_owners[5] == recipient]) is not None
    tests.append("creation-allows-self-payment-and-unfunded-other-without-future-link")
    swapped = copy.deepcopy(linked)
    swapped["funding_owners"] = {k: 1-v for k, v in swapped["funding_owners"].items()}
    swapped["payout_owners"] = {k: 1-v for k, v in swapped["payout_owners"].items()}
    model = NativePair(swapped, 1, 1, 1)
    baseline = model.query("cp_sat")
    for field, expected in (("sender", 1), ("recipient", 0), ("amount", 18)):
        claim = model.proposition(2, field, baseline)
        assert claim["forced"] and claim["candidate"] == expected
    tests.append("owner-label-permutation")
    # Even a known terminal owner must not force arbitrary payments with more activity.
    extra, _ = _fixture(20, [(1, 0, [0], [(0, 19), (None, 0)]),
        (0, 1, [], [(1, 11), (None, 0)]), (1, 0, [1], [(1, 8), (0, 10)]),
        (1, 0, [6], [(1, 9), (None, 0)]), (2, 1, [3, 5], []), (2, 1, [7], [])])
    extra["payout_owners"] = {e["destination"]: 1 for e in extra["algebra"]["events"] if e["payout"]}
    model = NativePair(extra, 1, 1, 1)
    baseline = model.query("cp_sat")
    assert not model.proposition(2, "amount", baseline)["forced"]
    tests.append("more-activity-does-not-automatically-force-private-amount")
    current, actual = full._fixture(2_000_000_000, [
        (1, 0, [0], [(0, 1_960_000_000), (None, 0)]),
        (0, 1, [], [(1, 1_160_000_000), (None, 0)]),
        (1, 0, [1], [(1, 1_920_000_000), (None, 0)]),
        (2, 1, [3, 5], [])], roles=3, floor=FLOOR, fee=FEE)
    current = {key: current.get(key, {}) for key in
               ("roles", "algebra", "commitments", "funding_owners", "payout_owners")}
    reversed_payment = dict(values=[2_000_000_000, 1_960_000_000, 0, 1_160_000_000,
                                    0, 1_120_000_000, 0],
                            owners=[0, 0, None, 1, None, 0, None],
                            inputs={"0": [0], "1": [], "2": [3], "3": [1, 5]})
    model = NativePair(current)
    for witness in (actual, reversed_payment):
        cp, smt = witness_conditions(model, witness)
        assert model.query("cp_sat", cp) is not None and model.query("z3", smt) is not None
    current["payout_owners"] = {current["algebra"]["events"][-1]["destination"]: 1}
    rows, _ = _queries(current)
    assert all(not row[field]["forced"] for row in rows[:-1]
               for field in ("sender", "recipient", "amount"))
    assert all(rows[-1][field]["forced"] and rows[-1][field]["candidate"] == expected
               for field, expected in (("sender", 0), ("recipient", 1), ("amount", 1_920_000_000)))
    tests.append("exact-current-sompi-four-profiles-and-192-versus-112-alternatives")
    sources = [dict(transaction_id="11"*32, index=0, script_public_key="aa"),
               dict(transaction_id="22"*32, index=1, script_public_key="bb")]
    projection = dict(algebra=relation["algebra"], commitments=relation["commitments"],
        surface=dict(funding=sources[0], events=[dict(funding=sources[1], payout_script=None),
            dict(funding=None, payout_script="bb", transaction_id="33"*32, ordinal=3)]))
    directory = dict(schema=DIRECTORY, entries=[dict(transaction_id=s["transaction_id"], index=s["index"], owner=i)
                                               for i, s in enumerate(sources)])
    assert [r["equal"] for r in boundary(projection)["comparisons"]] == [False, True]
    assert _association(projection, directory) == {_point(s): i for i, s in enumerate(sources)}
    for bad in (None, dict(directory, entries=directory["entries"][:1]),
                dict(directory, entries=[directory["entries"][0]]*2),
                dict(directory, entries=[dict(e, owner=0) for e in directory["entries"]]),
                dict(directory, native_key_index=3)):
        try:
            _association(projection, bad)
        except ValueError:
            pass
        else:
            raise AssertionError("missing/ambiguous/private-field directory accepted")
    projection["surface"]["events"][-1]["payout_script"] = "cc"
    assert not any(c["equal"] for c in boundary(projection)["comparisons"])
    tests.append("selected-outpoint-mismatch-wrong-owner-and-directory-poison-controls")
    return dict(passed=True, complete=True, controls=tests,
                scope="Explicit arithmetic/directory controls; no native proof or experimental truth used")


def main():
    command = sys.argv[1:]
    if command == ["controls"]:
        result = controls()
    elif len(command) == 2 and command[0] == "observe":
        result = analyze(*load_public(Path(command[1])))
    elif len(command) == 4 and command[0] == "score":
        raw, directory = load_public(Path(command[1]))
        result = score(raw, directory, surface.read(Path(command[2])), surface.read(Path(command[3])))
    else:
        raise SystemExit("controls | observe PUBLIC_DIR | score PUBLIC_DIR PREDICTION_JSON TRUTH_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
