"""Strict public adapter for native repeat-usage observations.

Caller prerequisite: pinned native replay of these exact pool bytes, plus
separate native validation of ordinary bridge transactions against ALL their
input UTXOs. The old replay only parses funding parents; it does not validate
their own spends. This module describes exact public dependency edges, never
proves chain acceptance, assigns a bridge's source owner, or reads private data.
Timing is an explicitly modeled sidecar, not a native-chain timestamp. This
fixture uses direct DRAIN-to-parent-to-ADMIT bridges; directory entries are
declared initial associations, not proven initial by absence of such an edge.
"""
import copy
import hashlib
import json

import early_privacy_surface as surface

ROLES = list(range(32))
ADVERSARIES = list(range(8))
MAX = surface.MAX
FLOOR = 60_000_000


def need(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names, label):
    need(type(value) is dict and set(value) == set(names.split()), label + " fields")


def integer(value, lower=0, upper=MAX):
    need(type(value) is int and lower <= value <= upper, "integer/range")
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _point(value):
    fields(value, "transaction_id index", "funding outpoint")
    surface.unhex(value["transaction_id"], 32)
    return value["transaction_id"], integer(value["index"], 0, 2**32 - 1)


def _group(point):
    return point[0] + ":" + str(point[1])


def _sources(projection):
    first = projection["surface"]["funding"]
    result = [(-1, first)]
    result.extend((row["ordinal"], row["funding"]) for row in projection["surface"]["events"]
                  if row["funding"] is not None)
    return result


def _public_graph(raw, projection):
    """Selected funding outputs and exact visible payout->parent references.

    One parent can supply several admitted outputs or consume several payouts.
    Its inputs are checked once; every funding-output/source-payout edge remains.
    An edge is dependency, not a claim that all its output value came from it.
    """
    sources = _sources(projection)
    consumed = {}
    for event, source in sources:
        point = _point({key: source[key] for key in ("transaction_id", "index")})
        need(point not in consumed, "repeated selected funding outpoint")
        consumed[point] = (event, source)
    parents = {}
    for parent in raw["parents"]:
        # Minimal exported parents must contain each body once, even if two
        # of its distinct outputs fund separate ADMITs.
        need(parent["id"] not in parents, "duplicate funding parent body")
        parents[parent["id"]] = parent
    need(set(parents) == {p[0] for p in consumed}, "parents must be exactly consumed funding bodies")
    all_transactions = list(parents.values()) + raw["lineage"]
    need(len({tx["id"] for tx in all_transactions}) == len(all_transactions), "duplicate native transaction identity")
    used_native = set()
    for tx in all_transactions:
        # native_shape has already required inputs on every real transaction;
        # absent inputs are useful only to keep hand-built graph controls small.
        for entry in tx.get("inputs", []):
            point = surface.point(entry["previousOutpoint"])
            need(point not in used_native, "native input reused across public graph")
            used_native.add(point)
    payouts = {}
    for row, tx in zip(projection["surface"]["events"], raw["lineage"][1:], strict=True):
        if row["mode"] == 2 and row["payout_script"] is not None:
            payouts[(tx["id"], len(tx["outputs"]) - 1)] = row["ordinal"]
    parent_edges, payout_consumers = {}, {}
    for txid, parent in parents.items():
        points = [surface.point(entry["previousOutpoint"]) for entry in parent["inputs"]]
        need(len(points) == len(set(points)), "duplicate parent input")
        edges = []
        for point in points:
            if point not in payouts:
                continue
            need(point not in payout_consumers, "payout consumed by distinct funding parents")
            payout_consumers[point] = txid
            edges.append((point, payouts[point]))
        parent_edges[txid] = edges
    bridges = []
    for point, (event, _) in consumed.items():
        for source, source_event in parent_edges[point[0]]:
            need(source_event < event, "bridge source payout must precede its ADMIT")
            bridges.append(dict(transaction_id=point[0], index=point[1], source_event=source_event,
                                source_outpoint=dict(transaction_id=source[0], index=source[1]),
                                destination_owner=None))
    bridges.sort(key=lambda b: (b["transaction_id"], b["index"], b["source_event"],
                               b["source_outpoint"]["index"]))
    return consumed, bridges


def _directory(directory, consumed, bridges):
    fields(directory, "schema roles adversaries entries", "directory")
    need(directory["schema"] == "kpi-native-usage-directory-v1", "directory schema")
    need(directory["roles"] == ROLES and all(type(x) is int for x in directory["roles"])
         and directory["adversaries"] == ADVERSARIES
         and all(type(x) is int for x in directory["adversaries"]), "directory role universe")
    need(type(directory["entries"]) is list, "directory entries")
    bridge_points = {(b["transaction_id"], b["index"]) for b in bridges}
    expected = set(consumed) - bridge_points
    owners, scripts = {}, {}
    for entry in directory["entries"]:
        fields(entry, "transaction_id index owner", "directory association")
        point = _point({k: entry[k] for k in ("transaction_id", "index")})
        owner = integer(entry["owner"], 0, len(ROLES) - 1)
        need(point in expected and point not in owners, "directory point absent, repeated or bridge")
        owners[point] = owner
        script = consumed[point][1]["script_public_key"]
        need(script not in scripts or scripts[script] == owner, "ambiguous initial funding-script ownership")
        scripts[script] = owner
    need(set(owners) == expected, "directory must cover exactly visible non-bridge funding points")
    return owners, scripts


def _timing(timing, events):
    fields(timing, "schema events", "modeled timing")
    need(timing["schema"] == "kpi-native-usage-timing-v1" and type(timing["events"]) is list,
         "timing schema")
    need(len(timing["events"]) == len(events), "complete prefix timing coverage")
    last = 0
    for event, row in zip(events, timing["events"], strict=True):
        fields(row, "event_id minute", "timing row")
        need(row["event_id"] == event["id"], "timing event identity/order")
        minute = integer(row["minute"])
        need(minute >= last, "modeled time order")
        event["minute"], last = minute, minute


def _view(view, events, commitments, births):
    fields(view, "schema members receipts authored", "participant view")
    need(view["schema"] == "kpi-native-usage-view-v1", "view schema")
    members = view["members"]
    need(type(members) is list and all(type(x) is int and x in ADVERSARIES for x in members)
         and members == sorted(set(members))
         and (not members or len(members) == 1 or members == ADVERSARIES), "supported participant profile")
    need(type(view["receipts"]) is list and type(view["authored"]) is list, "participant record lists")
    receipts, authors, facts = {}, {}, {}
    events_by_id = {e["id"]: i for i, e in enumerate(events)}
    for row in view["receipts"]:
        fields(row, "owner position value", "receipt")
        p = integer(row["position"], 0, len(commitments) - 1)
        integer(row["owner"], 0, len(ROLES) - 1)
        need(row["owner"] in members and p not in receipts, "receipt member/duplicate")
        integer(row["value"], FLOOR)
        receipts[p] = copy.deepcopy(row)
        facts[p] = (row["value"], row["owner"])
    spent = set()
    for row in view["authored"]:
        fields(row, "owner event_id inputs outputs", "authored record")
        integer(row["owner"], 0, len(ROLES) - 1)
        need(row["owner"] in members and row["event_id"] in events_by_id, "author member/event identity")
        i = events_by_id[row["event_id"]]
        need(i not in authors, "duplicate authored event")
        e, selected = events[i], row["inputs"]
        need(type(selected) is list and all(type(p) is int for p in selected)
             and selected == sorted(set(selected)), "authored input set")
        need(len(selected) == 0 if e["mode"] == 0 else 1 <= len(selected) <= 2, "authored input arity")
        need(all(p in receipts and receipts[p]["owner"] == row["owner"]
                 and births[p] < i and p < e["anchor_count"] for p in selected), "authored owned earlier inputs")
        need(not spent.intersection(selected), "disclosed double spend")
        spent.update(selected)
        need(type(row["outputs"]) is list
             and [n.get("position") if type(n) is dict else None for n in row["outputs"]] == e["new"],
             "authored output positions/order")
        for output in row["outputs"]:
            fields(output, "position value recipient", "authored output")
            p = integer(output["position"], 0, len(commitments) - 1)
            value, owner = integer(output["value"]), output["recipient"]
            need(value == 0 or value >= FLOOR, "authored note floor")
            need(owner is None if value == 0 else type(owner) is int and owner in ROLES, "authored output owner")
            need(p not in facts or facts[p] == (value, owner), "contradictory known note")
            facts[p] = (value, owner)
            need((p in receipts) == (value > 0 and owner in members), "complete participant-owned output receipts")
        output_total = sum(o["value"] for o in row["outputs"])
        if e["mode"] == 0:
            a, b = row["outputs"]
            need(a["value"] == e["deposit"] - e["fee"] >= FLOOR
                 and a["recipient"] == row["owner"] and b["value"] == 0,
                 "current-wallet ADMIT self-credit/padding")
        else:
            need(sum(receipts[p]["value"] for p in selected) == output_total + e["payout"] + e["fee"],
                 "authored conservation")
            if e["mode"] == 1:
                a, b = row["outputs"]
                need(a["value"] >= FLOOR and (b["value"] == 0 or b["recipient"] == row["owner"]),
                     "current-wallet PAY recipient/change")
        authors[i] = dict(owner=row["owner"], event=i, inputs=list(selected), outputs=copy.deepcopy(row["outputs"]))
    equal = {}
    for p, value_owner in facts.items():
        cm = commitments[p]
        need(cm not in equal or equal[cm] == value_owner, "equal commitment contradicts disclosed note facts")
        equal[cm] = value_owner
    return list(members), receipts, authors


def _diagnostics(raw, projection, directory, view, timing, policy):
    layouts = []
    for i, (tx, event) in enumerate(zip(raw["lineage"][1:], projection["surface"]["events"], strict=True)):
        layouts.append(dict(event=i, event_id=tx["id"], mode=event["mode"],
                            canonical_json_bytes=len(json.dumps(tx, sort_keys=True, separators=(",", ":")).encode()),
                            payload_bytes=len(bytes.fromhex(tx["payload"])),
                            signature_bytes=[len(bytes.fromhex(x["signatureScript"])) for x in tx["inputs"]],
                            ciphertext_bytes=[len(bytes.fromhex(c)) for c in event["ciphertexts"]],
                            proof_bytes=len(bytes.fromhex(event["proof_hex"])),
                            authorization_bytes=len(bytes.fromhex(event["authorization_hex"])),
                            inputs=len(tx["inputs"]), outputs=len(tx["outputs"])))
    return dict(
        input_sha256={k: digest(v) for k, v in dict(raw=raw, directory=directory, view=view,
                                                   timing=timing, policy=policy).items()},
        equality=copy.deepcopy(projection["surface"]["equality"]),
        zero_padding=copy.deepcopy(projection["surface"]["zero_padding"]), layouts=layouts,
        event_ids=[e["id"] for e in projection["algebra"]["events"]],
        timing="Declared modeled minutes; not native-chain timestamps",
        equality_meaning="Exact byte equality only; not a sender, recipient or human-identity inference",
        bridge_meaning="Exact serialized payout-to-parent-to-funding-output references; not separate value flows or source-owner labels",
        validation="Pinned pool replay and separate native validation of each funding bridge against all input UTXOs are caller prerequisites",
        chain_acceptance_verified=False,
        transaction_size_meaning="canonical_json_bytes counts the named JSON encoding, not Kaspa binary serialization or consensus mass")


def _associations(consumed, bridges, declared, scripts, authors, events):
    """Never turn a bridge's destination association into its source owner."""
    owners = {}
    for point, (event, source) in consumed.items():
        owner = declared.get(point)
        if owner is None:
            owner = scripts.get(source["script_public_key"])
        if event in authors:
            author = authors[event]["owner"]
            need(owner is None or owner == author, "funding association conflicts with disclosed ADMIT owner")
            owner = author
        owners[_group(point)] = owner
        if event >= 0:
            events[event]["funding_group"] = _group(point)
    for bridge in bridges:
        bridge["destination_owner"] = owners[_group((bridge["transaction_id"], bridge["index"]))]
    return owners


def _public_note_consistency(projection, events, owners, members, receipts, authors, commitments):
    """Reject disclosures contradicting public amounts and wallet ADMIT shape.

    This is local consistency, not proof that a participant supplied every
    receipt or authored operation. The isolated scorer checks that completeness.
    A receipt alone never becomes a funding identity association.
    """
    first = projection["surface"]["funding"]
    known = {0: (projection["algebra"]["initial"]["value"],
                 owners[_group((first["transaction_id"], first["index"]))])}
    need((0 in receipts) == (known[0][1] in members), "complete known initial-note receipt")
    for i, event in enumerate(events):
        if event["mode"] == 0:
            a, b = event["new"]
            credit = event["deposit"] - event["fee"]
            need(FLOOR <= credit <= MAX, "current-wallet ADMIT credit floor/range")
            owner = owners[event["funding_group"]]
            known[a] = (credit, owner)
            known[b] = (0, None)
            if owner in members:
                need(i in authors and a in receipts, "complete known participant ADMIT disclosures")
            if a in receipts:
                need(i in authors and authors[i]["owner"] == receipts[a]["owner"],
                     "ADMIT self-credit receipt requires own authored operation")
    facts = [(p, value, owner) for p, (value, owner) in known.items()]
    facts.extend((p, r["value"], r["owner"]) for p, r in receipts.items())
    facts.extend((o["position"], o["value"], o["recipient"])
                 for row in authors.values() for o in row["outputs"])
    equality = {}
    for p, value, owner in facts:
        cm = commitments[p]
        if cm in equality:
            previous_value, previous_owner = equality[cm]
            need(previous_value == value and
                 (previous_owner is None or owner is None or previous_owner == owner),
                 "disclosure contradicts public note facts/equal commitments")
            if owner is None:
                owner = previous_owner
        equality[cm] = value, owner


def _adapt(raw, projection, directory, view, timing, policy):
    need(type(policy) is dict and policy.get("schema") == "kpi-native-usage-policy-v1", "policy schema")
    events = copy.deepcopy(projection["algebra"]["events"])
    commitments = list(projection["commitments"])
    births = [-1]
    for i, event in enumerate(events):
        need(event["count_before"] == len(births), "position birth continuity")
        births.extend([i] * len(event["new"]))
    need(len(births) == len(commitments), "commitment birth count")
    _timing(timing, events)
    consumed, bridges = _public_graph(raw, projection)
    declared, scripts = _directory(directory, consumed, bridges)
    members, receipts, authors = _view(view, events, commitments, births)
    owners = _associations(consumed, bridges, declared, scripts, authors, events)
    _public_note_consistency(projection, events, owners, members, receipts, authors, commitments)
    return dict(projection=projection, events=events, commitments=commitments, births=births,
                roles=list(ROLES), adversaries=list(ADVERSARIES), members=members,
                receipts=receipts, authors=authors, funding_owners=owners,
                known_funding_scripts=dict(scripts), bridges=bridges,
                diagnostics=_diagnostics(raw, projection, directory, view, timing, policy))


def project(raw, directory, view, timing, policy):
    """Normalize only explicitly supplied public inputs, after native replay.

    The original projection is retained byte-for-byte in structure; its old
    initial funding_group is transaction-only. Consumers use funding_owners
    keyed by exact outpoint and normalized events, never that old group as an
    identity. Participant author event IDs become ordinal dictionary keys.
    """
    fields(raw, "descriptor vk_hex lineage parents", "raw")
    projection = surface.project(raw)
    return _adapt(raw, projection, directory, view, timing, policy)


def _observation_points(rows):
    """Creation, the next public DRAIN if present, and final; no hidden owner."""
    need(bool(rows), "nonempty event history")
    points = {len(rows) - 1}
    for i, row in enumerate(rows):
        if row["mode"] != 1 or row["bootstrap_sompi"] != "0":
            continue
        points.add(i)
        later = next((j for j in range(i + 1, len(rows)) if rows[j]["mode"] == 2), None)
        if later is not None:
            points.add(later)
    return sorted(points)


def observation_points(raw):
    """Public ordinals only; bootstrap PAY is identified by native bytes."""
    return _observation_points(surface.project(raw)["surface"]["events"])


def _prefix(raw, directory, view, timing, through_event, projection):
    rows = projection["surface"]["events"][:through_event + 1]
    sources = [projection["surface"]["funding"]] + [e["funding"] for e in rows if e["funding"]]
    points = {(s["transaction_id"], s["index"]) for s in sources}
    parent_ids = {p[0] for p in points}
    event_ids = {e["transaction_id"] for e in rows}
    positions = 1 + sum(len(e["appended_positions"]) for e in rows)
    cut_raw = copy.deepcopy(raw)
    cut_raw["lineage"] = cut_raw["lineage"][:through_event + 2]
    cut_raw["parents"] = [p for p in cut_raw["parents"] if p["id"] in parent_ids]
    cut_directory = copy.deepcopy(directory)
    cut_directory["entries"] = [e for e in cut_directory["entries"]
                                if (e["transaction_id"], e["index"]) in points]
    cut_view = copy.deepcopy(view)
    cut_view["receipts"] = [r for r in cut_view["receipts"] if r["position"] < positions]
    cut_view["authored"] = [r for r in cut_view["authored"] if r["event_id"] in event_ids]
    cut_timing = copy.deepcopy(timing)
    cut_timing["events"] = cut_timing["events"][:through_event + 1]
    return cut_raw, cut_directory, cut_view, cut_timing


def prefix_inputs(raw, directory, view, timing, through_event):
    """Cut complete inputs to exactly the public prefix and participant view.

    Receipt creation time determines visibility; later spend records are not
    backfilled. A consumed parent body is public in full, but unconsumed parent
    bodies and directory associations for its unconsumed outputs are omitted.
    This function is for the trusted exporter; the observer gets only the cut.
    """
    facts = project(raw, directory, view, timing, dict(schema="kpi-native-usage-policy-v1"))
    integer(through_event, 0, len(facts["events"]) - 1)
    return _prefix(raw, directory, view, timing, through_event, facts["projection"])


def native_relation(raw, directory):
    """Byte-derived accounting relation plus declared funding associations.

    No synthetic commitments, fabricated proofs, hidden truth or modeled-time
    assertions are introduced. The legacy algebra's minute field remains zero
    and is irrelevant to this relation. Unknown bridge owners remain None.
    """
    projection = surface.project(raw)
    timing = dict(schema="kpi-native-usage-timing-v1", events=[
        dict(event_id=e["id"], minute=0) for e in projection["algebra"]["events"]])
    facts = _adapt(raw, projection, directory,
                   dict(schema="kpi-native-usage-view-v1", members=[], receipts=[], authored=[]),
                   timing, dict(schema="kpi-native-usage-policy-v1"))
    initial = copy.deepcopy(projection["algebra"]["initial"])
    source = projection["surface"]["funding"]
    initial["funding_group"] = _group((source["transaction_id"], source["index"]))
    return dict(schema="kpi-native-usage-relation-v1",
                algebra=dict(schema=projection["algebra"]["schema"], initial=initial, events=facts["events"]),
                commitments=facts["commitments"], births=facts["births"], roles=facts["roles"],
                adversaries=facts["adversaries"], funding_owners=facts["funding_owners"],
                surface=copy.deepcopy(projection["surface"]))


def controls():
    """Hand-built graph/view controls; no files, generation, proofs or truth."""
    results = []

    def check(name, condition):
        need(condition, "surface control: " + name)
        results.append(name)

    def rejected(call):
        try:
            call()
        except (ValueError, KeyError, TypeError):
            return True
        return False

    h = lambda n: f"{n:064x}"
    spk = lambda n: "000020" + h(n) + "ac"
    point = lambda txid, index: dict(transactionId=txid, index=index)
    source = lambda txid, index, script: dict(transaction_id=txid, index=index,
                                             script_public_key=script, amount_sompi="1000000000")
    # Two outputs of parent 10 fund different owners. Parent 11 consumes the
    # public payout at event 0/output 1, then one output is admitted at event 1.
    raw = dict(parents=[dict(id=h(10), inputs=[dict(previousOutpoint=point(h(90), 0))]),
                        dict(id=h(11), inputs=[dict(previousOutpoint=point(h(1), 1))])],
               lineage=[dict(id=h(0)), dict(id=h(1), outputs=[{}, {}]), dict(id=h(2), outputs=[{}]),
                        dict(id=h(3), outputs=[{}])])
    first = source(h(10), 0, spk(1))
    projection = dict(surface=dict(funding=first, events=[
        dict(ordinal=0, mode=2, payout_script=spk(7), funding=None),
        dict(ordinal=1, mode=0, payout_script=None, funding=source(h(11), 0, spk(2))),
        dict(ordinal=2, mode=0, payout_script=None, funding=source(h(10), 1, spk(2)))]))
    consumed, edges = _public_graph(raw, projection)
    directory = dict(schema="kpi-native-usage-directory-v1", roles=list(ROLES), adversaries=list(ADVERSARIES),
                     entries=[dict(transaction_id=h(10), index=0, owner=8),
                              dict(transaction_id=h(10), index=1, owner=9)])
    owners, scripts = _directory(directory, consumed, edges)
    check("exact funding outpoints keep different parent-output owners", owners[(h(10), 0)] == 8
          and owners[(h(10), 1)] == 9 and len(scripts) == 2)
    check("bridge matches payout index one and preserves source ordinal", edges == [dict(
        transaction_id=h(11), index=0, source_event=0,
        source_outpoint=dict(transaction_id=h(1), index=1), destination_owner=None)])
    wrong_index = copy.deepcopy(raw)
    wrong_index["parents"][1]["inputs"][0]["previousOutpoint"]["index"] = 0
    check("same transaction id with reserve index is not a payout edge", not _public_graph(wrong_index, projection)[1])
    terminal = copy.deepcopy(raw)
    terminal["lineage"][1]["outputs"] = [{}]
    terminal["parents"][1]["inputs"][0]["previousOutpoint"]["index"] = 0
    check("terminal payout index zero", _public_graph(terminal, projection)[1][0]["source_outpoint"]["index"] == 0)
    future = copy.deepcopy(projection)
    future["surface"]["events"][0]["ordinal"] = 2
    check("future source payout rejected", rejected(lambda: _public_graph(raw, future)))
    extra = copy.deepcopy(raw)
    extra["parents"].append(dict(id=h(12), inputs=[]))
    check("future unused parent rejected", rejected(lambda: _public_graph(extra, projection)))
    duplicate = copy.deepcopy(raw)
    duplicate["parents"][1]["inputs"] *= 2
    check("duplicate parent input rejected", rejected(lambda: _public_graph(duplicate, projection)))
    bad_directory = copy.deepcopy(directory)
    bad_directory["entries"].append(dict(transaction_id=h(11), index=0, owner=9))
    check("bridge private label cannot enter initial directory", rejected(lambda: _directory(bad_directory, consumed, edges)))
    bad_consumed = copy.deepcopy(consumed)
    bad_consumed[(h(10), 1)][1]["script_public_key"] = spk(1)
    check("ambiguous same-script owners rejected", rejected(lambda: _directory(directory, bad_consumed, edges)))
    normalized = [{}, {}, {}]
    linked = copy.deepcopy(edges)
    association = _associations(consumed, linked, owners, scripts, {}, normalized)
    check("exact known initial script labels bridge destination only",
          association[_group((h(11), 0))] == 9 and linked[0]["destination_owner"] == 9
          and "source_owner" not in linked[0] and normalized[2]["funding_group"] == _group((h(10), 1)))
    unknown = copy.deepcopy(consumed)
    unknown[(h(11), 0)][1]["script_public_key"] = spk(3)
    unknown_edges = copy.deepcopy(edges)
    unknown_owners = _associations(unknown, unknown_edges, owners, scripts, {}, [{}, {}, {}])
    check("fresh bridge script leaves destination owner unknown",
          unknown_owners[_group((h(11), 0))] is None and unknown_edges[0]["destination_owner"] is None)
    disclosed = _associations(unknown, copy.deepcopy(edges), owners, scripts, {1: dict(owner=0)}, [{}, {}, {}])
    check("participant authored ADMIT can label its own funding destination", disclosed[_group((h(11), 0))] == 0)
    check("conflicting participant and script associations rejected", rejected(lambda:
          _associations(consumed, copy.deepcopy(edges), owners, scripts, {1: dict(owner=0)}, [{}, {}, {}])))
    multi_raw = copy.deepcopy(raw)
    multi_raw["lineage"] = [dict(id=h(0))] + [dict(id=h(i), outputs=[{}, {}]) for i in range(1, 5)]
    multi_raw["parents"][1]["inputs"].append(dict(previousOutpoint=point(h(2), 1)))
    multi_projection = dict(surface=dict(funding=first, events=[
        dict(ordinal=0, mode=2, payout_script=spk(7), funding=None),
        dict(ordinal=1, mode=2, payout_script=spk(8), funding=None),
        dict(ordinal=2, mode=0, payout_script=None, funding=source(h(11), 0, spk(2))),
        dict(ordinal=3, mode=0, payout_script=None, funding=source(h(11), 1, spk(3)))]))
    multi_edges = _public_graph(multi_raw, multi_projection)[1]
    check("multi-input parent preserves every selected output by source-payout edge",
          {(b["index"], b["source_event"]) for b in multi_edges} == {(0, 0), (0, 1), (1, 0), (1, 1)}
          and len(multi_edges) == 4)
    conflict_raw, conflict_projection = copy.deepcopy(multi_raw), copy.deepcopy(multi_projection)
    conflict_raw["parents"].append(dict(id=h(12), inputs=[dict(previousOutpoint=point(h(1), 1))]))
    conflict_projection["surface"]["events"][3]["funding"]["transaction_id"] = h(12)
    check("distinct parents cannot reuse one known payout", rejected(lambda: _public_graph(conflict_raw, conflict_projection)))
    shared_external = copy.deepcopy(raw)
    shared_external["parents"][1]["inputs"][0]["previousOutpoint"] = point(h(90), 0)
    check("distinct parents cannot reuse a non-payout input", rejected(lambda: _public_graph(shared_external, projection)))
    reused_funding = copy.deepcopy(raw)
    reused_funding["lineage"][0]["inputs"] = [dict(previousOutpoint=point(h(10), 0))]
    reused_funding["parents"][1]["inputs"][0]["previousOutpoint"] = point(h(10), 0)
    check("parent cannot respent founding funding outpoint", rejected(lambda: _public_graph(reused_funding, projection)))
    events = [dict(id=h(1)), dict(id=h(2))]
    timing = dict(schema="kpi-native-usage-timing-v1", events=[dict(event_id=h(1), minute=3),
                                                             dict(event_id=h(2), minute=5)])
    _timing(timing, events)
    check("modeled timing binds exact ordered event identities", [e["minute"] for e in events] == [3, 5])
    extra_time = copy.deepcopy(timing)
    extra_time["events"].append(dict(event_id=h(3), minute=6))
    check("future timing row rejected", rejected(lambda: _timing(extra_time, events)))
    bad_time = copy.deepcopy(timing)
    bad_time["events"][1]["minute"] = True
    check("boolean minute rejected", rejected(lambda: _timing(bad_time, events)))
    events = [dict(id=h(1), mode=1, anchor_count=1, new=[1, 2], fee=40_000_000, payout=0),
              dict(id=h(2), mode=1, anchor_count=3, new=[3, 4], fee=40_000_000, payout=0)]
    view = dict(schema="kpi-native-usage-view-v1", members=[0], receipts=[
        dict(owner=0, position=0, value=1_040_000_000), dict(owner=0, position=1, value=1_000_000_000),
        dict(owner=0, position=4, value=560_000_000)], authored=[
        dict(owner=0, event_id=h(1), inputs=[0], outputs=[dict(position=1, value=1_000_000_000, recipient=0),
                                                       dict(position=2, value=0, recipient=None)]),
        dict(owner=0, event_id=h(2), inputs=[1], outputs=[dict(position=3, value=400_000_000, recipient=9),
                                                       dict(position=4, value=560_000_000, recipient=0)])])
    cms, births = [h(x) for x in range(5)], [-1, 0, 0, 1, 1]
    members, receipts, authors = _view(view, events, cms, births)
    check("authored transaction ids normalize to ordinals without recipient sibling disclosure",
          members == [0] and set(authors) == {0, 1} and 3 not in receipts
          and authors[1]["outputs"][0]["recipient"] == 9)
    for name, mutate in (
        ("future authored event", lambda v: v["authored"][0].__setitem__("event_id", h(99))),
        ("wrong disclosed input owner", lambda v: v["receipts"][1].__setitem__("owner", 1)),
        ("missing own change receipt", lambda v: v["receipts"].pop()),
        ("disclosed amount conservation", lambda v: v["authored"][1]["outputs"][0].__setitem__("value", 400_000_001)),
        ("unsupported pooled subset", lambda v: v.__setitem__("members", [0, 1])),
        ("private extra field", lambda v: v.__setitem__("truth", {}))):
        bad = copy.deepcopy(view)
        mutate(bad)
        check(name + " rejected", rejected(lambda: _view(bad, events, cms, births)))
    equal_cms = list(cms)
    equal_cms[3] = equal_cms[1]
    check("equal commitment contradictory disclosures rejected", rejected(lambda: _view(view, events, equal_cms, births)))
    note_projection = dict(surface=dict(funding=first), algebra=dict(initial=dict(value=1_040_000_000)))
    note_owners = {_group((h(10), 0)): 0}
    _public_note_consistency(note_projection, events, note_owners, members, receipts, authors, cms)
    wrong_initial = copy.deepcopy(receipts)
    wrong_initial[0]["value"] += 1
    check("receipt cannot contradict public initial value", rejected(lambda:
          _public_note_consistency(note_projection, events, note_owners, members, wrong_initial, authors, cms)))
    admit_events = copy.deepcopy(events)
    admit_events[1].update(mode=0, deposit=1_040_000_000, funding_group=_group((h(10), 1)))
    admit_owners = {_group((h(10), 0)): 8, _group((h(10), 1)): 0}
    admit_receipts = {3: dict(owner=0, position=3, value=1_000_000_000)}
    admit_authors = {1: dict(owner=0, outputs=[dict(position=3, value=1_000_000_000, recipient=0),
                                             dict(position=4, value=0, recipient=None)])}
    _public_note_consistency(note_projection, admit_events, admit_owners, [0], admit_receipts, admit_authors, cms)
    check("complete publicly known participant ADMIT accepted", True)
    check("known participant ADMIT cannot omit authored record", rejected(lambda:
          _public_note_consistency(note_projection, admit_events, admit_owners, [0], admit_receipts, {}, cms)))
    check("known participant ADMIT cannot omit self-credit receipt", rejected(lambda:
          _public_note_consistency(note_projection, admit_events, admit_owners, [0], {}, admit_authors, cms)))
    zero_receipt = dict(admit_receipts)
    zero_receipt[4] = dict(owner=0, position=4, value=60_000_000)
    check("receipt cannot claim ADMIT zero padding as positive", rejected(lambda:
          _public_note_consistency(note_projection, admit_events, admit_owners, [0], zero_receipt, admit_authors, cms)))
    rows = [dict(mode=1, bootstrap_sompi="100"), dict(mode=1, bootstrap_sompi="0"),
            dict(mode=1, bootstrap_sompi="0"), dict(mode=2, bootstrap_sompi="0"),
            dict(mode=0, bootstrap_sompi="0"), dict(mode=1, bootstrap_sompi="0")]
    check("observation points use public next DRAIN and final with no bootstrap target",
          _observation_points(rows) == [1, 2, 3, 5])
    prefix_projection = copy.deepcopy(projection)
    for i, row in enumerate(prefix_projection["surface"]["events"]):
        row.update(transaction_id=h(i + 1), appended_positions=[] if i == 0 else [2 * i - 1, 2 * i])
    prefix_view = dict(schema="kpi-native-usage-view-v1", members=[0],
                       receipts=[dict(owner=0, position=p, value=100_000_000) for p in (0, 1, 3)],
                       authored=[dict(owner=0, event_id=h(i + 1), inputs=[], outputs=[]) for i in range(3)])
    prefix_timing = dict(schema="kpi-native-usage-timing-v1",
                         events=[dict(event_id=h(i + 1), minute=i) for i in range(3)])
    r, d, v, t = _prefix(raw, directory, prefix_view, prefix_timing, 0, prefix_projection)
    check("prefix drops future parent, future same-parent directory output and future disclosures",
          len(r["lineage"]) == 2 and [p["id"] for p in r["parents"]] == [h(10)]
          and d["entries"] == [directory["entries"][0]]
          and [x["position"] for x in v["receipts"]] == [0]
          and [x["event_id"] for x in v["authored"]] == [h(1)] and len(t["events"]) == 1)
    check("prefix cutting does not mutate complete inputs", len(raw["parents"]) == 2
          and len(directory["entries"]) == 2 and len(prefix_view["receipts"]) == 3)
    return dict(schema="kpi-native-usage-surface-controls-v1", complete=True, passed=True,
                tests=results, count=len(results), scope="Hand-built public adapter checks; no native proof or bridge-spend validation")
