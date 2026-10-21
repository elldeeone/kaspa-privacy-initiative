#!/usr/bin/env python3
"""Independent, solver-free checking of saved conditional SAT assignments.

Reads only explicitly named public directories and observer predictions. This is
not native proof verification, an UNSAT proof, or verification that hypothetical
values open actual cryptographic commitments. Known self-bootstrap and funding
owner labels are fixture assumptions. No repository or solver modules imported.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

MAX = 2_900_000_000_000_000_000
FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
FEE = 40_000_000
PUBLIC_FILES = ("descriptor.json", "vk.bin", "lineage.json", "parents.json",
                "funding_owner_directory.json")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def integer(x, lo=0, hi=MAX):
    require(type(x) is int and lo <= x <= hi, "exact integer/range")
    return x


def exact_keys(x, names):
    require(type(x) is dict and set(x) == set(names.split()), "object fields")


def digest_bytes(x):
    return hashlib.sha256(x).hexdigest()


def digest_json(x):
    return digest_bytes(json.dumps(x, sort_keys=True, separators=(",", ":")).encode())


def decimal(x):
    require(type(x) is str and x.isascii() and x.isdecimal() and str(int(x)) == x,
            "canonical decimal amount")
    return integer(int(x))


def hexbytes(x, length=None):
    require(type(x) is str, "hex string")
    b = bytes.fromhex(x)
    require(b.hex() == x and (length is None or len(b) == length), "canonical hex/length")
    return b


def hash_array(x):
    require(type(x) is list and len(x) == 32, "hash array")
    return bytes(integer(v, 0, 255) for v in x)


def point(x):
    exact_keys(x, "transactionId index")
    hexbytes(x["transactionId"], 32)
    return x["transactionId"], integer(x["index"], 0, 2**32 - 1)


def group(p):
    return p[0] + ":" + str(p[1])


def u32(b):
    return int.from_bytes(b, "little")


def compact(b):
    require(len(b) == 105, "compact-state length")
    if b == bytes(105):
        return None
    require(b[0] == 6, "compact-state version")
    return u32(b[1:5]), u32(b[5:9]), b[9:41]


def p2sh(b):
    return (bytes.fromhex("0000aa20") + hashlib.blake2b(b, digest_size=32).digest()
            + bytes.fromhex("87")).hex()


def decode_public(raw, directory):
    """Separate public-byte extraction; never calls the observer's projector."""
    d, chain = raw["descriptor"], raw["lineage"]
    exact_keys(d, "format network genesis domain initial_commitment initial_value_sompi "
               "vk_sha256 funding_txid funding_full_hash")
    require(d["format"] == "kpi-v6-public-replay-v1" and d["network"] == "testnet-10"
            and d["genesis"] == "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370",
            "public descriptor identity")
    domain = hash_array(d["domain"])
    cms = [hash_array(d["initial_commitment"]).hex()]
    require(cms[0] != "0" * 64, "initial zero commitment")
    require(digest_bytes(hexbytes(raw["vk_hex"], 328)) == d["vk_sha256"], "verifier bytes hash")
    require(type(chain) is list and len(chain) >= 2, "lineage")
    parents = {}
    for tx in raw["parents"]:
        require(tx["payload"] == "", "funding parent payload")
        require(tx["id"] not in parents or parents[tx["id"]] == tx, "conflicting parent")
        parents[tx["id"]] = tx
    selected = {}

    def select_funding(outpoint):
        p = point(outpoint)
        require(p not in selected and p[0] in parents, "fresh known funding outpoint")
        outputs = parents[p[0]]["outputs"]
        require(p[1] < len(outputs), "funding output index")
        out = outputs[p[1]]
        script = hexbytes(out["scriptPublicKey"], 36)
        require(script[:3] == bytes.fromhex("000020") and script[-1] == 0xac, "funding P2PK")
        selected[p] = {"script": script.hex(), "value": decimal(out["value"])}
        return p

    first = chain[0]
    require(first["id"] == d["funding_txid"] and first["payload"] == ""
            and len(first["inputs"]) == 1 and len(first["outputs"]) == 2, "founding transaction")
    initial = decimal(d["initial_value_sompi"])
    require(initial >= FLOOR and decimal(first["outputs"][0]["value"]) == initial, "initial reserve")
    founder = select_funding(first["inputs"][0]["previousOutpoint"])
    reserve, previous = initial, (first["id"], 0)
    script = first["outputs"][0]["scriptPublicKey"]
    events, roots, nullifiers = [], {}, set()
    nf_count, last_state, suffix = 0, None, None
    ids = {first["id"]}
    for i, tx in enumerate(chain[1:]):
        require(reserve > 0 and tx["id"] not in ids, "transaction after terminal/repeated id")
        ids.add(tx["id"])
        payload = hexbytes(tx["payload"], 5228)
        require(payload[:8] == b"KPICR06\0", "wrapper tag")
        auth, ciphers, next_state = payload[8:385], payload[385:755], payload[755:860]
        require(auth[:8] == b"KPICU06\0" and auth[8:40] == domain, "authorization domain")
        require(hashlib.sha256(ciphers).digest() == auth[345:377], "cipher digest")
        mode = integer(auth[204], 0, 2)
        require(len(tx["inputs"]) == (2 if mode == 0 else 1), "native input arity")
        require(point(tx["inputs"][0]["previousOutpoint"]) == previous, "reserve ancestry")
        sig = hexbytes(tx["inputs"][0]["signatureScript"], 24709)
        require(sig[:2] == bytes.fromhex("4c80") and sig[130:133] == bytes.fromhex("4d0060"),
                "proof/redeem framing")
        redeem = sig[133:]
        old = compact(redeem[36:141])
        require(old is not None and old[:2] == (len(cms), nf_count)
                and redeem[1:33] == domain and p2sh(redeem) == script, "old state/script")
        if i == 0:
            suffix = redeem[141:]
            roots[1] = old[2]
        else:
            require(redeem[36:141] == last_state and redeem[141:] == suffix, "state continuity")
        anchor = u32(auth[40:44])
        if mode == 0:
            require(i > 0 and auth[40:140] == bytes(100), "ADMIT anchor/nullifiers")
        else:
            require(anchor == len(cms) and roots.get(anchor) == auth[44:76], "current anchor/root")
            for nf in (auth[76:108], auth[108:140]):
                require(nf != bytes(32) and nf not in nullifiers, "nullifier uniqueness")
                nullifiers.add(nf)
                nf_count += 1
        payout, fee, deposit, bootstrap = [integer(u32(auth[j:j + 8])) for j in (205, 213, 257, 337)]
        require(fee == FEE and bootstrap == (initial if i == 0 else 0), "fee/bootstrap")
        require(payout == 0 or payout >= PAYOUT_FLOOR, "payout floor")
        destination = auth[221:257].hex() if payout else None
        require(payout > 0 or auth[221:257] == bytes(36), "zero payout script")
        funding = None
        if mode == 0:
            funding = select_funding(tx["inputs"][1]["previousOutpoint"])
            require(auth[265:301] == bytes.fromhex(funding[0]) + funding[1].to_bytes(4, "little")
                    and selected[funding]["script"] == auth[301:337].hex()
                    and selected[funding]["value"] == deposit >= FLOOR and payout == 0, "ADMIT binding")
        else:
            require(auth[257:337] == bytes(80), "non-ADMIT funding padding")
        require(mode != 1 or payout == 0, "PAY payout policy")
        before = len(cms)
        new = [] if mode == 2 else [before, before + 1]
        output_cms = [auth[140:172].hex(), auth[172:204].hex()]
        if mode == 2:
            require(output_cms == ["0" * 64] * 2 and ciphers == bytes(370) and payout > 0,
                    "DRAIN padding/payout")
        else:
            require("0" * 64 not in output_cms and output_cms[0] != output_cms[1], "commitment slots")
            cms.extend(output_cms)
        reserve = integer(reserve + deposit - payout - fee)
        require(reserve > 0 or mode == 2, "zero reserve mode")
        require(len(tx["outputs"]) == int(reserve > 0) + int(payout > 0), "native output arity")
        require(sum(decimal(o["value"]) for o in tx["outputs"]) == reserve + payout, "native output total")
        if payout:
            require(decimal(tx["outputs"][-1]["value"]) == payout
                    and tx["outputs"][-1]["scriptPublicKey"] == destination, "payout value/script")
        state = compact(next_state)
        if reserve:
            require(state is not None and state[:2] == (len(cms), nf_count), "successor counts")
            require(decimal(tx["outputs"][0]["value"]) == reserve
                    and tx["outputs"][0]["scriptPublicKey"] == p2sh(redeem[:36] + next_state + suffix),
                    "successor reserve/script")
            roots[len(cms)] = state[2]
            script = tx["outputs"][0]["scriptPublicKey"]
        else:
            require(state is None, "terminal successor")
        events.append(dict(id=tx["id"], minute=0, mode=mode, anchor_count=anchor,
                           count_before=before, new=new, fee=fee, deposit=deposit,
                           payout=payout, reserve_out=reserve, destination=destination,
                           funding_group=group(funding) if funding else None))
        previous, last_state = (tx["id"], 0), next_state
    exact_keys(directory, "schema entries")
    require(directory["schema"] == "kpi-address-reuse-funding-owners-v1" and len(selected) == 2,
            "funding directory schema/source count")
    owners = {}
    for entry in directory["entries"]:
        exact_keys(entry, "transaction_id index owner")
        p = point({"transactionId": entry["transaction_id"], "index": entry["index"]})
        require(p in selected and p not in owners, "directory point")
        owners[p] = integer(entry["owner"], 0, 1)
    require(set(owners) == set(selected) and set(owners.values()) == {0, 1}, "complete distinct directory")
    payout_owners, comparisons = {}, []
    for p, source in selected.items():
        for i, e in enumerate(events):
            if not e["payout"]:
                continue
            equal = source["script"] == e["destination"]
            comparisons.append(dict(funding_outpoint=dict(transaction_id=p[0], index=p[1]),
                                    payout_transaction_id=e["id"], payout_event=i, equal=equal))
            if equal:
                require(e["destination"] not in payout_owners or payout_owners[e["destination"]] == owners[p],
                        "contradictory script-owner association")
                payout_owners[e["destination"]] = owners[p]
    relation = dict(roles=[0, 1, 2], commitments=cms, funding_owners={group(p): o for p, o in owners.items()},
                    payout_owners=payout_owners, algebra=dict(schema="kpi-h14-public-v1",
                    initial=dict(id=first["id"], value=initial, funding_group=group(founder)), events=events))
    require(events[0]["mode"] == 1, "known self-bootstrap framing")
    return relation, comparisons


def prefix(relation, end, linked):
    p = copy.deepcopy(relation)
    events = p["algebra"]["events"] = p["algebra"]["events"][:end + 1]
    p["commitments"] = p["commitments"][:events[-1]["count_before"] + len(events[-1]["new"])]
    groups = {p["algebra"]["initial"]["funding_group"]} | {e["funding_group"] for e in events if e["mode"] == 0}
    p["funding_owners"] = {g: o for g, o in p["funding_owners"].items() if g in groups}
    p["payout_owners"] = {s: o for s, o in p["payout_owners"].items()
                          if linked and any(e["destination"] == s for e in events)}
    return p


def explicit_bounds(data):
    """Compute both encodings' redundant numeric limits using plain integers."""
    cap, birth = [data["initial"]["value"]], [-1]
    events = data["events"]
    for i, e in enumerate(events):
        if not e["new"]:
            continue
        budget = (e["deposit"] - e["fee"] if e["mode"] == 0 else
                  sum(sorted(cap[:e["anchor_count"]])[-2:]) - e["payout"] - e["fee"])
        cap += [min(budget, e["reserve_out"])] * 2
        birth += [i] * 2
    for p in range(len(cap) - 1, -1, -1):
        possible = [events[-1]["reserve_out"]]
        possible += [sum(cap[q] for q in e["new"]) + e["payout"] + e["fee"]
                     for i, e in enumerate(events) if i > birth[p] and e["mode"] != 0 and p < e["anchor_count"]]
        cap[p] = min(cap[p], max(possible))
    sibling = {}
    for i in range(len(events) - 1, -1, -1):
        e = events[i]
        if not e["new"]:
            sibling[i] = 0
            continue
        possible = [events[-1]["reserve_out"]]
        possible += [sibling[j] + f["payout"] + f["fee"] for j, f in enumerate(events)
                     if j > i and f["mode"] != 0 and f["anchor_count"] > e["new"][0]]
        sibling[i] = min(sum(cap[q] for q in e["new"]), sum(sorted(possible)[-2:]))
    require(sum(cap) + sum(e["fee"] + e["deposit"] + e["payout"] for e in events) < 2**62,
            "solver integer-domain safety")
    return cap, sibling


def check_assignment(relation, w):
    """Direct ledger replay, without asking a solver to accept its own witness."""
    exact_keys(w, "values owners inputs senders")
    values, owners, inputs, senders = (w[k] for k in ("values", "owners", "inputs", "senders"))
    data, cms = relation["algebra"], relation["commitments"]
    events = data["events"]
    require(type(values) is list and type(owners) is list and len(values) == len(owners) == len(cms), "note arrays")
    require(type(inputs) is dict and set(inputs) == {str(i) for i, e in enumerate(events) if e["mode"] != 0},
            "complete selected-input event map")
    require(type(senders) is dict and set(senders) == {str(i) for i in range(len(events))}, "complete sender map")
    cap, sibling = explicit_bounds(data)
    for p, value in enumerate(values):
        integer(value, 0, cap[p])
        require(value == 0 or value >= FLOOR, "positive note floor")
        if value:
            integer(owners[p], 0, 2)
        else:
            require(owners[p] is None, "zero-note owner representation")
    for sender in senders.values():
        integer(sender, 0, 2)
    founder = relation["funding_owners"][data["initial"]["funding_group"]]
    require(values[0] == data["initial"]["value"] and owners[0] == founder, "initial amount/owner")
    seen = {}
    for p, cm in enumerate(cms):
        if cm in seen:
            q = seen[cm]
            require((values[p], owners[p]) == (values[q], owners[q]), "equal-commitment amount/owner")
        seen[cm] = p
    spent, live = set(), {0}
    for i, e in enumerate(events):
        sender = senders[str(i)]
        require(e["count_before"] == 1 + sum(len(x["new"]) for x in events[:i]), "note birth order")
        output = sum(values[p] for p in e["new"])
        require(output <= sibling[i], "Z3 redundant sibling bound")
        if e["mode"] == 0:
            a, b = e["new"]
            require(sender == relation["funding_owners"][e["funding_group"]]
                    and values[a] == e["deposit"] - e["fee"] >= FLOOR
                    and values[b] == 0 and owners[a] == sender, "ADMIT self-credit/dummy")
        else:
            chosen = inputs[str(i)]
            require(type(chosen) is list and 1 <= len(chosen) <= 2, "one/two real inputs")
            for p in chosen:
                integer(p, 0, e["anchor_count"] - 1)
            require(chosen == sorted(set(chosen)) and not spent.intersection(chosen), "distinct/single-spend inputs")
            require(all(p in live and values[p] >= FLOOR and owners[p] == sender for p in chosen),
                    "earlier unspent positive inputs/common owner")
            require(sum(values[p] for p in chosen) == output + e["payout"] + e["fee"], "spend conservation")
            spent.update(chosen)
            live.difference_update(chosen)
            if e["mode"] == 1:
                a, b = e["new"]
                require(values[a] >= FLOOR and (values[b] == 0 or owners[b] == sender), "PAY recipient/change ordering")
        if e["destination"] in relation["payout_owners"]:
            require(sender == relation["payout_owners"][e["destination"]], "equal native script implies declared payout owner")
        if i == 0:
            a, b = e["new"]
            require(owners[a] == founder and values[b] == 0, "explicit known self-bootstrap")
        live.update(p for p in e["new"] if values[p] > 0)
        require(sum(values[p] for p in live) == e["reserve_out"], "per-event unspent backing")
    if events[-1]["reserve_out"] == 0:
        require(not live and spent == {p for p, value in enumerate(values) if value}, "terminal every positive spent exactly once")
    return True


def check_case(label, public_dir, prediction_path):
    public_dir, prediction_path = Path(public_dir), Path(prediction_path)
    blobs = {name: (public_dir / name).read_bytes() for name in PUBLIC_FILES}
    raw = {name: json.loads(blobs[name + ".json"]) for name in ("descriptor", "lineage", "parents")}
    raw["vk_hex"] = blobs["vk.bin"].hex()
    directory = json.loads(blobs["funding_owner_directory.json"])
    prediction_blob = prediction_path.read_bytes()
    prediction = json.loads(prediction_blob)
    require(prediction["schema"] == "kpi-address-reuse-predictions-v1" and prediction["complete"] is True
            and prediction["conditional_available"] is True, "prediction completion/schema")
    require(prediction["public_sha256"] == digest_json(raw) and prediction["directory_sha256"] == digest_json(directory),
            "prediction input identity")
    relation, comparisons = decode_public(raw, directory)
    require(prediction["boundary"]["comparisons"] == comparisons, "public boundary comparisons")
    events = relation["algebra"]["events"]
    targets = [i for i, e in enumerate(events) if i > 0 and e["mode"] == 1]
    require(len(targets) == 1, "one ordinary payment target")
    target = targets[0]
    profiles = [(h, end, linked) for h, end in (("creation", target), ("final", len(events) - 1)) for linked in (False, True)]
    require(type(prediction["rows"]) is list and len(prediction["rows"]) == len(profiles), "four profiles")
    result = []
    for row, expected in zip(prediction["rows"], profiles):
        horizon, end, linked = expected
        require(type(row["event"]) is int and row["event"] == target
                and type(row["through_event"]) is int and row["through_event"] == end
                and row["horizon"] == horizon and row["script_association_used"] is linked, "profile selection")
        selected = prefix(relation, end, linked)
        require(row["relation_sha256"] == digest_json(selected), "independent profile relation hash")
        witnesses, absent = 0, 0
        for field in ("sender", "recipient", "amount"):
            claim = row[field]
            exact_keys(claim, "candidate forced certificates hypothetical_witnesses")
            require(type(claim["forced"]) is bool, "forced flag")
            integer(claim["candidate"], FLOOR if field == "amount" else 0, MAX if field == "amount" else 2)
            exact_keys(claim["certificates"], "cp_sat z3")
            saved = claim["hypothetical_witnesses"]
            exact_keys(saved, "cp_sat_candidate cp_sat_alternative z3_candidate z3_alternative")
            for engine in ("cp_sat", "z3"):
                require(claim["certificates"][engine] == dict(candidate="SAT", different="UNSAT" if claim["forced"] else "SAT"),
                        "certificate framing only")
                for kind in ("candidate", "alternative"):
                    w = saved[engine + "_" + kind]
                    if kind == "alternative" and claim["forced"]:
                        require(w is None, "forced claim has alternative witness")
                        absent += 1
                        continue
                    try:
                        check_assignment(selected, w)
                        p = events[target]["new"][0]
                        value = w["senders"][str(target)] if field == "sender" else w["owners" if field == "recipient" else "values"][p]
                        require((value == claim["candidate"]) == (kind == "candidate"), "candidate/different proposition")
                    except (ValueError, KeyError, TypeError, IndexError) as error:
                        raise ValueError(f"{label}/{horizon}/linked={linked}/{field}/{engine}/{kind}: {error}") from error
                    witnesses += 1
        result.append(dict(horizon=horizon, linked=linked, sat_assignments_checked=witnesses,
                           absent_alternatives_requiring_separate_UNSAT_review=absent))
    return dict(label=label, public_file_sha256={name: digest_bytes(blob) for name, blob in blobs.items()},
                prediction_sha256=digest_bytes(prediction_blob), profiles=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", nargs=3, action="append", metavar=("LABEL", "PUBLIC_DIR", "PREDICTION"), required=True)
    args = parser.parse_args()
    require(len({c[0] for c in args.case}) == len(args.case), "unique case labels")
    rows = [check_case(*case) for case in args.case]
    print(json.dumps(dict(schema="kpi-independent-sat-witness-review-v1", complete=True,
                          checker_sha256=digest_bytes(Path(__file__).read_bytes()), cases=rows,
                          profiles_checked=sum(len(r["profiles"]) for r in rows),
                          sat_assignments_checked=sum(p["sat_assignments_checked"] for r in rows for p in r["profiles"]),
                          scope="Independent public-byte decoding and direct integer/ownership assignment checking; no private truth, solver invocation, native proof verification, or UNSAT validation",
                          zero_owner_scope="Saved zero owners are null; equal-commitment zero components admit arbitrary common role completion"), indent=2))


if __name__ == "__main__":
    main()
