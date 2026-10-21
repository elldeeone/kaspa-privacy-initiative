#!/usr/bin/env python3
"""One fresh offline native usage history. No networking or implicit execution.

The caller freezes code/policy/binaries before supplying a new private seed.
Only controls() uses a published development seed. Wallet crypto randomness is
fresh OS randomness, separate from the deterministic usage sampler. The warm
prover sees all fresh fixture backups: this is not participant process isolation.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from population_privacy_workload import Stream
from early_privacy_surface import project

HERE = Path(__file__).resolve().parent
SOMPI, FEE, FLOOR = 100_000_000, 40_000_000, 60_000_000
MAX = 2_900_000_000_000_000_000
ROLES, ADVERSARIES = list(range(32)), list(range(8))
PIN = {"sha256": "6f95db952f84420717b3b677e1368bc85776791eb1ccf409cb390a4e4fb39593", "bytes": 962197520}
VK_SHA = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef"


def need(ok, message):
    if not ok:
        raise ValueError(message)


def integer(value, low=0, high=MAX):
    need(type(value) is int and low <= value <= high, "integer/range")
    return value


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with Path(path).open("x") as out:
        os.chmod(path, 0o600)
        json.dump(value, out, indent=2)
        out.write("\n")


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def public_policy():
    return {
        "schema": "kpi-native-usage-policy-v1", "roles": ROLES, "adversaries": ADVERSARIES,
        "payments": 64, "initial_admissions_before_payments": 32,
        "initial_net_capitals_sompi": [350*SOMPI, 700*SOMPI, 1400*SOMPI],
        "honest_send_counts": {"0": 4, "1": 8, "2": 8, "6": 4}, "active_send_count": 2,
        "honest_amount_min_sompi": 10*SOMPI, "honest_amount_max_sompi": 50*SOMPI,
        "invoice_probability_percent": 60, "invoice_sompi": [n*SOMPI for n in (10, 20, 25, 40, 50)],
        "irregular_distribution": "uniform 4001 cent values inclusive", "irregular_step_sompi": 1_000_000,
        "preferred_contact_probability_percent": 70, "recipient_distribution": "preferred or uniform nonself",
        "tag_formula": "20*SOMPI+(role+1)*1000+zero_based_authored_payment_ordinal",
        "cashout_modes": {"prompt_honest": 8, "accumulated_honest": 8, "retaining_honest": 8, "active": "retain"},
        "mode_assignment": "independent honest permutation from activity permutation",
        "controls": ["self/reused", "self/fresh", "cross/reused", "cross/fresh"],
        "control_payments": "first four: active roles0..3 to first four prompt roles; included in64",
        "cross_targets": "fifth and sixth prompt roles", "bridge_funding_indices": [0, 1, 0, 1],
        "bridge_amount": "exact payout minus100000000sompi; positive ordinary change remains outside",
        "selection": "capital plus lowest-position noncapital unspent note if present; change becomes capital",
        "prompt_rule": "exit newly received PAY note, never capital or an ADMIT credit",
        "accumulated_rule": "after receipt, exit lowest two noncapital unspent notes if at least two",
        "final_drain": "one private shuffled role order, lowest-position pairs then singleton",
        "modeled_pay_gap_minutes": [1, 3, 10, 60], "modeled_final_gap_minutes": 60,
        "timing_scope": "modeled request times, not chain inclusion or prover timing",
        "fee_sompi": FEE, "note_floor_sompi": FLOOR, "payout_floor_sompi": 10_000_000,
        "funding_directory": "initial external selected outpoints only; explicit external role association",
        "native_scope": "genuine offline transactions/proofs; synthetic source UTXOs; no accepted chain",
        "participant_scope": "own authored operations and own positive decrypted receipts only",
    }


def schedule(seed):
    rng = Stream(seed, "native-usage-v1")
    h, q = rng.shuffle(list(range(8, 32))), rng.shuffle(list(range(8, 32)))
    counts = [2]*8 + [0]*24
    for group, n in ((h[4:12], 1), (h[12:20], 2), (h[20:], 6)):
        for role in group:
            counts[role] = n
    modes = ["retain"]*32
    for role in q[:8]: modes[role] = "prompt"
    for role in q[8:16]: modes[role] = "accumulated"
    capitals = [rng.choose(public_policy()["initial_net_capitals_sompi"]) for _ in ROLES]
    preferred = [rng.choose([r for r in ROLES if r != sender]) for sender in ROLES]
    remaining = [r for r in ROLES for _ in range(counts[r] - (r < 4))]
    senders = list(range(4)) + rng.shuffle(remaining)
    seen, minute, requests = [0]*32, 0, []
    for ordinal, sender in enumerate(senders):
        recipient = q[ordinal] if ordinal < 4 else (preferred[sender] if rng.below(100) < 70
                    else rng.choose([r for r in ROLES if r != sender]))
        if sender < 8:
            amount = 20*SOMPI + (sender+1)*1000 + seen[sender]
        elif rng.below(100) < 60:
            amount = rng.choose(public_policy()["invoice_sompi"])
        else:
            amount = 10*SOMPI + rng.below(4001)*1_000_000
        minute += rng.choose([1, 3, 10, 60])
        requests.append(dict(sender=sender, recipient=recipient, amount=amount, minute=minute))
        seen[sender] += 1
    return dict(activity_permutation=h, cashout_permutation=q, counts=counts, modes=modes,
                capitals=capitals, preferred=preferred, requests=requests, final_order=rng.shuffle(ROLES))


def validate_schedule(s):
    need(set(s) == set("activity_permutation cashout_permutation counts modes capitals preferred requests final_order".split()), "schedule fields")
    for key in ("activity_permutation", "cashout_permutation"):
        need(sorted(s[key]) == list(range(8, 32)) and all(type(v) is int for v in s[key]), "role permutation")
    need(sorted(s["final_order"]) == ROLES and all(type(v) is int for v in s["final_order"]), "drain permutation")
    h, q = s["activity_permutation"], s["cashout_permutation"]
    expected = [2]*8 + [0]*24
    for roles, count in ((h[4:12], 1), (h[12:20], 2), (h[20:], 6)):
        for role in roles: expected[role] = count
    need(s["counts"] == expected and all(type(v) is int for v in s["counts"]), "activity classes")
    modes = ["retain"]*32
    for role in q[:8]: modes[role] = "prompt"
    for role in q[8:16]: modes[role] = "accumulated"
    need(s["modes"] == modes and len(s["capitals"]) == len(s["preferred"]) == 32, "mode/capital/contacts")
    for role in ROLES:
        need(integer(s["capitals"][role]) in public_policy()["initial_net_capitals_sompi"], "capital support")
        need(integer(s["preferred"][role], 0, 31) != role, "self preferred")
    need(len(s["requests"]) == 64, "request coverage")
    seen, minute = [0]*32, 0
    for i, r in enumerate(s["requests"]):
        need(set(r) == {"sender", "recipient", "amount", "minute"}, "request fields")
        a, b = integer(r["sender"], 0, 31), integer(r["recipient"], 0, 31)
        need(a != b and integer(r["minute"]) - minute in (1, 3, 10, 60), "request identity/time")
        if i < 4: need(a == i and b == q[i], "bridge gift controls")
        value = integer(r["amount"])
        need(value == 20*SOMPI+(a+1)*1000+seen[a] if a < 8 else 10*SOMPI <= value <= 50*SOMPI and value % 1_000_000 == 0, "amount support")
        seen[a] += 1
        minute = r["minute"]
    need(seen == expected, "sender request counts")


class Notes:
    """Private driver bookkeeping, checked against actual wallet receipt scans."""
    def __init__(self, initial):
        self.values, self.owners, self.spent = [initial], [0], set()
        self.capital = {}
        self.events, self.inputs = [], {}

    def available(self, owner, noncapital=False):
        return [p for p, (v, o) in enumerate(zip(self.values, self.owners))
                if v and o == owner and p not in self.spent and (not noncapital or p != self.capital.get(owner))]

    def add(self, kind, owner, inputs, recipient=None, amount=0, minute=0, request_index=None, event_id=""):
        owner, amount, minute = integer(owner, 0, 31), integer(amount), integer(minute)
        need(kind in ("bootstrap", "admit", "pay", "exit"), "event kind")
        need(len(inputs) in ((0,) if kind == "admit" else (1, 2)) and len(set(inputs)) == len(inputs), "input arity/duplicates")
        for p in inputs:
            integer(p, 0, len(self.values)-1)
            need(p not in self.spent and self.values[p] >= FLOOR and self.owners[p] == owner, "private input ownership/spent")
        total = sum(self.values[p] for p in inputs)
        if kind == "admit":
            pairs = [(amount-FEE, owner), (0, None)]
        elif kind in ("bootstrap", "pay"):
            integer(recipient, 0, 31)
            pairs = [(amount, recipient), (total-amount-FEE, owner)]
        else:
            need(amount == total-FEE, "exit full selected value")
            pairs = []
        rows = []
        for value, target in pairs:
            need(value == 0 or FLOOR <= value <= MAX, "private output floor/range")
            p = len(self.values)
            self.values.append(value)
            self.owners.append(target if value else None)
            rows.append(dict(position=p, value=value, recipient=target if value else None))
        self.spent.update(inputs)
        index = len(self.events)
        event = dict(event=index, event_id=event_id, kind=kind, owner=owner, recipient=recipient,
                     amount=amount, outputs=rows, minute=minute, request_index=request_index)
        self.inputs[str(index)] = list(inputs)
        self.events.append(event)
        if kind == "bootstrap" or kind == "admit" and owner not in self.capital:
            self.capital[owner] = rows[0]["position"]
        elif kind == "pay":
            self.capital[owner] = rows[1]["position"]
        return event


def outpoint(txid, index):
    return f"{txid}:{index}"


def native_accounting(raw):
    """Independent transparent graph walk, including all change and recycle edges.

    Unknown root UTXOs use the declared fixture rule: an initial ordinary parent
    is funded with its output0 plus 1KAS. This is synthetic context, not ancestry
    acceptance. No owner labels or validation booleans are consulted.
    """
    txs = {t["id"]: t for t in raw["parents"] + raw["lineage"]}
    need(len(txs) == len(raw["parents"]) + len(raw["lineage"]), "duplicate native body")
    sources, used, unspent, fees, done = {}, set(), {}, {}, set()
    for t in raw["parents"]:
        need(len(t["inputs"]) == 1 and len(t["outputs"]) == 2 and t["payload"] == "", "ordinary shape")
        p = t["inputs"][0]["previousOutpoint"]
        if p["transactionId"] not in txs:
            key = outpoint(p["transactionId"], p["index"])
            need(key not in sources, "duplicate synthetic native source")
            sources[key] = int(t["outputs"][0]["value"]) + SOMPI
    need(len(sources) == 32, "exact external source count")
    unspent.update(sources)
    pending = dict(txs)
    while pending:
        ready = [t for t in pending.values() if all(outpoint(p["previousOutpoint"]["transactionId"], p["previousOutpoint"]["index"]) in unspent for p in t["inputs"])]
        need(ready, "native graph unresolved/double-spent input")
        for t in ready:
            keys = [outpoint(i["previousOutpoint"]["transactionId"], i["previousOutpoint"]["index"]) for i in t["inputs"]]
            need(len(set(keys)) == len(keys) and not set(keys) & used, "native outpoint reused")
            need(all(k in unspent for k in keys), "native conflicting spend")
            total = sum(unspent.pop(k) for k in keys)
            values = [int(o["value"]) for o in t["outputs"]]
            need(all(0 < v <= MAX for v in values) and total >= sum(values), "native value conservation")
            fees[t["id"]] = total-sum(values)
            used.update(keys)
            for i, value in enumerate(values): unspent[outpoint(t["id"], i)] = value
            done.add(t["id"])
            del pending[t["id"]]
    injected, outside = sum(sources.values()), sum(unspent.values())
    pool_fees = sum(fees[t["id"]] for t in raw["lineage"][1:])
    ordinary_fees = sum(fees[t["id"]] for t in raw["parents"] + raw["lineage"][:1])
    need(injected == outside + pool_fees + ordinary_fees, "whole-experiment accounting")
    return dict(external_source_count=32, external_injection_sompi=injected,
                final_native_unspent_sompi=outside, pool_fees_sompi=pool_fees,
                ordinary_fees_sompi=ordinary_fees, native_transaction_count=len(done),
                consumed_native_outpoints=len(used), whole_experiment_conserved=True)


def make_view(truth, members):
    need(sorted(set(members)) == members and all(r in ADVERSARIES for r in members), "participant members")
    return dict(schema="kpi-native-usage-view-v1", members=members,
                receipts=[dict(owner=o, position=p, value=v) for p, (v, o) in enumerate(zip(truth["values"], truth["owners"])) if v and o in members],
                authored=[dict(owner=e["owner"], event_id=e["event_id"], inputs=sorted(truth["inputs"][str(e["event"])]), outputs=e["outputs"])
                          for e in truth["events"] if e["owner"] in members])


def check_scan(notes, owner, view):
    rows = [dict(position=p,value_sompi=str(v),spent=p in notes.spent)
            for p,(v,o) in enumerate(zip(notes.values,notes.owners)) if v and o==owner]
    need(view["notes"]==rows and view["balance_sompi"]==str(sum(notes.values[p] for p in notes.available(owner))),
         "actual wallet scan/private prefix mismatch")


def validate_generated(public, truth, policy):
    """Exact policy/ownership/accounting check; cryptography is checked by Rust."""
    need(canonical(policy) == canonical(public_policy()) and truth["policy_sha256"] == canonical(policy), "policy identity")
    need(set(truth) == set("schema policy_sha256 schedule values owners inputs events bridges author_inspections wallet_inspections accounting".split())
         and truth["schema"] == "kpi-native-usage-truth-v1", "truth schema")
    for value in truth["values"]: integer(value)
    for owner in truth["owners"]:
        if owner is not None: integer(owner, 0, 31)
    validate_schedule(truth["schedule"])
    raw, directory, timing = public["raw"], public["directory"], public["timing"]
    projection = project(raw)
    algebra = projection["algebra"]
    need(len(algebra["events"]) == len(truth["events"]), "event coverage")
    need(len(truth["author_inspections"])==len(truth["events"]),"author scan coverage")
    n = Notes(int(raw["descriptor"]["initial_value_sompi"]))
    for e, actual in zip(truth["events"], algebra["events"]):
        integer(e["event"])
        if e["request_index"] is not None: integer(e["request_index"],0,63)
        need(e["event"] == len(n.events) and e["event_id"] == actual["id"], "native event identity")
        inputs = truth["inputs"][str(e["event"])]
        rebuilt = n.add(e["kind"], e["owner"], inputs, e["recipient"], e["amount"], e["minute"], e["request_index"], e["event_id"])
        need(rebuilt == e and actual["fee"] == FEE, "event/private output binding")
        need([r["position"] for r in e["outputs"]] == actual["new"], "native created positions")
        need(actual["mode"] == {"bootstrap": 1, "admit": 0, "pay": 1, "exit": 2}[e["kind"]], "native mode")
        need(actual["deposit"] == (e["amount"] if e["kind"] == "admit" else 0)
             and actual["payout"] == (e["amount"] if e["kind"] == "exit" else 0), "native boundary amounts")
        need(sum(v for p, v in enumerate(n.values) if p not in n.spent) == actual["reserve_out"], "private reserve sum")
        scan=truth["author_inspections"][e["event"]]
        need(scan["owner"]==e["owner"] and scan["event_id"]==e["event_id"],"author scan identity")
        check_scan(n,e["owner"],scan["view"])
    need(n.values == truth["values"] and n.owners == truth["owners"] and n.inputs == truth["inputs"], "truth arrays")
    need(not any(n.available(r) for r in ROLES) and algebra["events"][-1]["reserve_out"] == 0, "full drainage")
    need(timing == dict(schema="kpi-native-usage-timing-v1", events=[dict(event_id=e["event_id"], minute=e["minute"]) for e in n.events]), "modeled time binding")
    need(directory["schema"] == "kpi-native-usage-directory-v1" and directory["roles"] == ROLES and directory["adversaries"] == ADVERSARIES, "directory schema")
    expected_directory = []
    funding = raw["lineage"][0]["inputs"][0]["previousOutpoint"]
    expected_directory.append(dict(transaction_id=funding["transactionId"], index=funding["index"], owner=0))
    for i in range(1, 32):
        e = n.events[i]
        need(e["kind"] == "admit" and e["owner"] == i, "all initial admissions before PAY")
        funding = raw["lineage"][i+1]["inputs"][1]["previousOutpoint"]
        expected_directory.append(dict(transaction_id=funding["transactionId"], index=funding["index"], owner=i))
    need(directory["entries"] == expected_directory, "initial-only directory")
    # Re-run the declared event scheduler without a seed or native/prover calls.
    expected = Notes(n.values[0])
    cursor = 0
    def consume(kind, owner, positions, recipient=None, amount=0, minute=0, request_index=None):
        nonlocal cursor
        e = n.events[cursor]
        rebuilt = expected.add(kind, owner, positions, recipient, amount, minute, request_index, e["event_id"])
        need(rebuilt == e and expected.inputs[str(cursor)] == n.inputs[str(cursor)], "exact workload schedule/selection")
        cursor += 1
        return rebuilt
    s = truth["schedule"]
    need(n.values[0] == s["capitals"][0]+FEE, "founder capital")
    consume("bootstrap", 0, [0], 0, s["capitals"][0])
    for role in range(1, 32): consume("admit", role, [], amount=s["capitals"][role]+FEE)
    bridges = []
    noncapital_inputs = payment_receipt_inputs = readmission_inputs = 0
    births = {output["position"]:e for e in n.events for output in e["outputs"]}
    for i, request in enumerate(s["requests"]):
        a, b, amount, minute = (request[k] for k in ("sender", "recipient", "amount", "minute"))
        extra = expected.available(a, True)[:1]
        noncapital_inputs += bool(extra)
        payment_receipt_inputs += bool(extra and births[extra[0]]["kind"] == "pay")
        readmission_inputs += bool(extra and births[extra[0]]["kind"] == "admit")
        paid = consume("pay", a, [expected.capital[a]]+extra, b, amount, minute, i)
        receipt = paid["outputs"][0]["position"]
        positions = [receipt] if s["modes"][b] == "prompt" else (expected.available(b, True)[:2] if s["modes"][b] == "accumulated" else [])
        if s["modes"][b] == "accumulated" and len(positions) < 2: positions = []
        if positions:
            payout = sum(expected.values[p] for p in positions)-FEE
            exited = consume("exit", b, positions, amount=payout, minute=minute)
            if i < 4:
                target = b if i < 2 else s["cashout_permutation"][i+2]
                admitted = consume("admit", target, [], amount=payout-SOMPI, minute=minute)
                bridge = truth["bridges"][i]
                need(bridge["source_owner"] == b and bridge["target_owner"] == target
                     and bridge["funding_index"] == [0,1,0,1][i]
                     and bridge["event_id"] == exited["event_id"] and bridge["admit_event_id"] == admitted["event_id"], "bridge controls")
                bridges.append(bridge)
    final_minute = s["requests"][-1]["minute"]+60
    for role in s["final_order"]:
        while expected.available(role):
            positions = expected.available(role)[:2]
            consume("exit", role, positions, amount=sum(expected.values[p] for p in positions)-FEE, minute=final_minute)
    need(cursor == len(n.events) and len(bridges) == len(truth["bridges"]) == 4, "complete operation coverage")
    byid = {t["id"]: t for t in raw["parents"]+raw["lineage"]}
    for i, bridge in enumerate(bridges):
        exit_tx, tx, admit = (byid[bridge[k]] for k in ("event_id", "transaction_id", "admit_event_id"))
        need(tx["inputs"][0]["previousOutpoint"] == dict(transactionId=exit_tx["id"], index=len(exit_tx["outputs"])-1), "bridge exact payout input")
        need(admit["inputs"][1]["previousOutpoint"] == dict(transactionId=tx["id"], index=0), "bridge exact admission output")
        need(int(tx["outputs"][0]["value"]) == int(exit_tx["outputs"][-1]["value"])-SOMPI, "bridge amount rule")
        original = directory["entries"][bridge["target_owner"]]
        original_spk = byid[original["transaction_id"]]["outputs"][original["index"]]["scriptPublicKey"]
        need((tx["outputs"][0]["scriptPublicKey"] == original_spk) == (i in (0, 2)), "actual reused/fresh script controls")
    need(len(truth["wallet_inspections"]) == 32, "wallet scan coverage")
    for role, inspection in enumerate(truth["wallet_inspections"]):
        rows = [dict(position=p, value_sompi=str(v), spent=p in n.spent) for p, (v,o) in enumerate(zip(n.values,n.owners)) if v and o == role]
        need(inspection["owner"] == role and inspection["view"]["notes"] == rows
             and inspection["view"]["balance_sompi"] == "0" and inspection["view"]["drained"] is True, "actual wallet ownership/receipt scan")
    accounting = native_accounting(raw)
    need(accounting == truth["accounting"], "native accounting attestation")
    return dict(complete=True, passed=True, payments=64, roles=32, bridges=4,
                payments_with_noncapital_input=noncapital_inputs,
                payments_spending_payment_receipts=payment_receipt_inputs,
                payments_spending_readmission_credits=readmission_inputs,
                full_drainage=True, accounting=accounting,
                scope="policy/native graph and actual wallet receipt-scan consistency; Rust verifies proofs and native scripts")


def _lifecycle():
    spec = importlib.util.spec_from_file_location("native_usage_lifecycle", HERE / "two-input-lifecycle.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Warm:
    def __init__(self, experiment, backups):
        self.e, self.out = experiment, experiment.logdir("warm-all-fresh-wallets")
        self.stderr = (self.out/"stderr.txt").open("x")
        self.responses = []
        mounts = experiment.mounts()+[(experiment.params/"pk.bin", "/pk.bin")]
        mounts += [(backup, f"/wallet-{role}.json") for role, backup in enumerate(backups)]
        self.process = subprocess.Popen(_lifecycle().sandbox(experiment.wallet_binary, self.out, mounts,
            ["serve", "/pk.bin", "/pin.json", "/vk.bin"]), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=self.stderr, text=True, bufsize=1)
        audit = json.loads(self.process.stdout.readline())
        need("isolation" in audit, "warm process isolation audit")
        experiment.audits.append({"process":"warm-all-fresh-wallets", **audit["isolation"]})

    def request(self, snapshot, owner, action):
        base = f"/public/{snapshot.name}"
        request = dict(backup=f"/wallet-{owner}.json", descriptor=base+"/descriptor.json",
                       vk=base+"/vk.bin", lineage=base+"/lineage.json", parents=base+"/parents.json",
                       head=base+"/head.json", action=action)
        with (self.out/"private-requests.jsonl").open("a") as saved:
            saved.write(json.dumps(request)+"\n")
            saved.flush()
            os.fsync(saved.fileno())
        self.process.stdin.write(json.dumps(request)+"\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        need(bool(line), "warm prover terminated; private logs preserved")
        response = json.loads(line)
        self.responses.append(response)
        need(response.get("ok") is True, "warm proof failed; private logs preserved")
        result = response["result"]
        need(set(result) == set("scope chain_acceptance_verified descriptor_sha256 base_head transaction bundle metrics preparation_ms proof_ms native_validation_ms constraints".split()), "public prepared-result metadata")
        need(result["chain_acceptance_verified"] is False, "offline scope")
        return result

    def stop(self):
        self.process.stdin.close()
        status = self.process.wait()
        self.stderr.close()
        save(self.out/"responses.json", self.responses)
        need(status == 0, "warm prover exit status")


def run_replay(experiment, binary, public):
    """Replay prints pretty JSON; parse the entire document after the guard."""
    out = experiment.logdir("final-independent-replay")
    result = subprocess.run(_lifecycle().sandbox(binary, out, [(public,"/snapshot")],
        ["check","/snapshot/descriptor.json","/snapshot/vk.bin","/snapshot/lineage.json","/snapshot/parents.json"]),
        text=True, capture_output=True, check=False)
    (out/"stdout.txt").write_text(result.stdout)
    (out/"stderr.txt").write_text(result.stderr)
    audit, separator, document = result.stdout.partition("\n")
    need(separator and result.returncode == 0, "independent replay failed; logs preserved")
    audit = json.loads(audit)
    need("isolation" in audit,"replay isolation audit")
    experiment.audits.append({"process":"final-independent-replay",**audit["isolation"]})
    checked = json.loads(document)
    save(out/"result.json",checked)
    return checked


def generate(args):
    """Called only after the external runner freezes and approves the attempt."""
    os.umask(0o077)
    root = Path(args.output).resolve()
    root.mkdir(mode=0o700)
    private = root/"private"
    private.mkdir(mode=0o700)
    policy = read(args.policy)
    need(policy == public_policy(), "frozen policy mismatch")
    seed = read(args.seed_file)
    need(set(seed) == {"seed"} and isinstance(seed["seed"], str) and len(seed["seed"]) == 64, "private seed schema")
    key = bytes.fromhex(seed["seed"])
    need(key.hex() == seed["seed"], "canonical private seed")
    s = schedule(key)
    validate_schedule(s)
    save(private/"schedule.json", s)
    params = Path(args.params).resolve()
    binary = {name: Path(getattr(args, name+"_binary")).resolve() for name in ("wallet", "helper", "replay")}
    pins = {name: sha(path) for name,path in binary.items()}
    pins.update({"generator":sha(__file__), "lifecycle_driver":sha(HERE/"two-input-lifecycle.py"),
                 "sampler":sha(HERE/"population_privacy_workload.py"), "decoder":sha(HERE/"early_privacy_surface.py")})
    need((params/"pk.bin").stat().st_size == PIN["bytes"] and sha(params/"pk.bin") == PIN["sha256"]
         and sha(params/"vk.bin") == VK_SHA, "public parameter pins")
    save(root/"execution-pins-before.json", pins)
    e = _lifecycle().Experiment(root, params, binary["wallet"], binary["helper"])
    e.run("founder", binary["helper"], [(params/"vk.bin", "/vk.bin"),(e.pin,"/pin.json"),(root,"/destination","rw")],
          ["founder-amount","/vk.bin","/pin.json","/destination/founder",str(s["capitals"][0]+FEE)])
    snapshot = e.snapshot("000-initial")
    backups, receives = [root/"founder/backup.json"], [read(root/"founder/receive.json")]
    for role in range(1,32):
        backup, receive = e.create(f"role-{role:02d}", snapshot)
        backups.append(backup); receives.append(receive)
    initial_backup_hashes = [sha(p) for p in backups]
    notes = Notes(s["capitals"][0]+FEE)
    directory = dict(schema="kpi-native-usage-directory-v1", roles=ROLES, adversaries=ADVERSARIES, entries=[])
    timing = dict(schema="kpi-native-usage-timing-v1", events=[])
    bridges, operations, synthetic_inputs, validations, native_bodies, native_unspent = [], [], [], [], {}, {}
    author_inspections=[]
    used = set()

    def native_record(tx, source=None):
        if source is not None:
            point = outpoint(source["txid"], source["index"])
            need(point not in native_unspent and point not in used, "synthetic source collision")
            native_unspent[point] = source
            synthetic_inputs.append(source)
        need(tx["id"] not in native_bodies, "duplicate native transaction")
        keys = [outpoint(p["previousOutpoint"]["transactionId"], p["previousOutpoint"]["index"]) for p in tx["inputs"]]
        need(len(set(keys)) == len(keys) and not set(keys)&used and all(k in native_unspent for k in keys), "native input reuse/missing")
        inputs = [native_unspent[k] for k in keys]
        tx_path, input_path = private/f"native-{len(native_bodies):03d}.json", private/f"inputs-{len(native_bodies):03d}.json"
        save(tx_path, tx); save(input_path, inputs)
        checked = e.run("validate-native", binary["helper"], [(tx_path,"/tx.json"),(input_path,"/inputs.json")], ["check-native","/tx.json","/inputs.json"])
        need(checked["native_validation_passed"] is True, "native validation")
        validations.append(dict(transaction_id=tx["id"], **checked))
        for k in keys: native_unspent.pop(k)
        used.update(keys)
        for i, output in enumerate(tx["outputs"]):
            native_unspent[outpoint(tx["id"],i)] = dict(txid=tx["id"], index=i, amount=output["value"], spk=output["scriptPublicKey"], daa="0", is_coinbase=False)
        native_bodies[tx["id"]] = tx

    source = read(root/"founder/synthetic-parent.json")
    native_record(source["transaction"], source["input"])
    founding = read(snapshot/"lineage.json")[0]
    native_record(founding)
    directory["entries"].append(dict(transaction_id=source["transaction"]["id"], index=0, owner=0))

    def funding(role, index):
        return e.run("funding-address",binary["wallet"],[(backups[role],"/backup.json"),(snapshot,"/snapshot")],
            ["funding","/backup.json","/snapshot/descriptor.json",str(index)])["script_public_key"]

    warm = Warm(e, backups)
    begin = time.monotonic()
    def operation(kind, owner, positions, recipient=None, amount=0, minute=0, request_index=None, parent=None, funding_index=0):
        nonlocal snapshot
        if parent is not None:
            snapshot = e.snapshot(f"{len(notes.events):03d}-funding-visible", snapshot, parent=parent)
        if kind == "admit": action = dict(action="admit", txid=parent["id"], index=0, native_key_index=funding_index)
        elif kind == "exit": action = dict(action="exit", positions=positions, native_key_index=min(positions))
        else: action = dict(action="pay", positions=positions, recipient=receives[recipient], amount_sompi=str(amount))
        print(json.dumps({"stage":"proof-start","completed":len(notes.events),"planned_payments":64}), file=sys.stderr, flush=True)
        result = warm.request(snapshot,owner,action)
        native_record(result["transaction"])
        snapshot = e.snapshot(f"{len(notes.events)+1:03d}-accepted",snapshot,transaction=result["transaction"])
        event = notes.add(kind,owner,positions,recipient,amount,minute,request_index,result["transaction"]["id"])
        scanned=e.inspect("author-prefix-scan",backups[owner],snapshot)
        check_scan(notes,owner,scanned)
        author_inspections.append(dict(owner=owner,event_id=event["event_id"],view=scanned))
        with (private/"events.jsonl").open("a") as journal:
            journal.write(json.dumps(dict(event=event,inputs=positions))+"\n")
            journal.flush()
            os.fsync(journal.fileno())
        timing["events"].append(dict(event_id=event["event_id"],minute=minute))
        operations.append({k:result[k] for k in ("preparation_ms","proof_ms","native_validation_ms","constraints")})
        print(json.dumps({"stage":"proof-complete","completed":len(notes.events),"elapsed_seconds":round(time.monotonic()-begin,3)}),file=sys.stderr,flush=True)
        return event,result["transaction"]
    try:
        operation("bootstrap",0,[0],0,s["capitals"][0])
        for role in range(1,32):
            parent = e.run("external-funding",binary["helper"],[],["fund-amount",funding(role,0),str(s["capitals"][role]+FEE)])
            native_record(parent["transaction"],parent["input"])
            directory["entries"].append(dict(transaction_id=parent["transaction"]["id"],index=0,owner=role))
            operation("admit",role,[],amount=s["capitals"][role]+FEE,parent=parent["transaction"])
        for i,r in enumerate(s["requests"]):
            a,b,amount,minute = (r[k] for k in ("sender","recipient","amount","minute"))
            positions = [notes.capital[a]]+notes.available(a,True)[:1]
            event,_ = operation("pay",a,positions,b,amount,minute,i)
            receipt = event["outputs"][0]["position"]
            positions = [receipt] if s["modes"][b] == "prompt" else (notes.available(b,True)[:2] if s["modes"][b] == "accumulated" else [])
            if s["modes"][b] == "accumulated" and len(positions)<2: positions=[]
            if positions:
                payout = sum(notes.values[p] for p in positions)-FEE
                exited,tx = operation("exit",b,positions,amount=payout,minute=minute)
                if i<4:
                    target = b if i<2 else s["cashout_permutation"][i+2]
                    index = [0,1,0,1][i]
                    path = private/f"bridge-payout-{i}.json"
                    save(path,tx)
                    bridge = e.run("bridge",binary["helper"],[(backups[b],"/backup.json"),(snapshot,"/snapshot"),(path,"/payout.json")],
                        ["payout-to-funding","/backup.json","/snapshot/descriptor.json","/payout.json",str(min(positions)),str(len(tx["outputs"])-1),funding(target,index),str(payout-SOMPI)])
                    native_record(bridge["transaction"])
                    admitted,_ = operation("admit",target,[],amount=payout-SOMPI,minute=minute,parent=bridge["transaction"],funding_index=index)
                    bridges.append(dict(event_id=exited["event_id"],transaction_id=bridge["transaction"]["id"],source_owner=b,target_owner=target,funding_index=index,admit_event_id=admitted["event_id"]))
        minute=s["requests"][-1]["minute"]+60
        for role in s["final_order"]:
            while notes.available(role):
                positions=notes.available(role)[:2]
                operation("exit",role,positions,amount=sum(notes.values[p] for p in positions)-FEE,minute=minute)
    finally:
        warm.stop()
    inspections=[dict(owner=role,view=e.inspect("final-wallet-scan",backup,snapshot)) for role,backup in enumerate(backups)]
    final=e.public/"final"
    shutil.copytree(snapshot,final)
    save(final/"directory.json",directory); save(final/"timing.json",timing)
    raw=dict(descriptor=read(final/"descriptor.json"),vk_hex=(final/"vk.bin").read_bytes().hex(),lineage=read(final/"lineage.json"),parents=read(final/"parents.json"))
    ledger=dict(schema="kpi-native-usage-native-ledger-v1",synthetic_inputs=synthetic_inputs,validations=validations,
                scope="synthetic initial context; every ordinary and pool spend validated against exact input outputs; global once-only outpoints")
    save(e.public/"native-ledger.json",ledger)
    truth=dict(schema="kpi-native-usage-truth-v1",policy_sha256=canonical(policy),schedule=s,values=notes.values,owners=notes.owners,
               inputs=notes.inputs,events=notes.events,bridges=bridges,author_inspections=author_inspections,
               wallet_inspections=inspections,accounting=native_accounting(raw))
    checked=validate_generated(dict(raw=raw,directory=directory,timing=timing),truth,policy)
    need(initial_backup_hashes == [sha(p) for p in backups],"original backups changed")
    save(private/"truth.json",truth)
    views=private/"views"; views.mkdir(mode=0o700)
    for name,members in [("C",[])]+[(f"P{i}",[i]) for i in ADVERSARIES]+[("pooled",ADVERSARIES)]: save(views/f"{name}.json",make_view(truth,members))
    final_replay=run_replay(e,binary["replay"],final)
    save(e.public/"final-replay.json",final_replay)
    after={name:sha(path) for name,path in binary.items()}
    after.update({"generator":sha(__file__),"lifecycle_driver":sha(HERE/"two-input-lifecycle.py"),"sampler":sha(HERE/"population_privacy_workload.py"),"decoder":sha(HERE/"early_privacy_surface.py")})
    need(after==pins,"execution files changed")
    save(root/"execution-pins-after.json",after)
    save(e.public/"component-timings.json",operations)
    save(e.public/"isolation.json",dict(audits=e.audits,shared_generation_process_sees_all_fresh_backups=True))
    result=dict(schema="kpi-native-usage-generation-v1",completed=True,public_dir="public/final",truth_file="private/truth.json",views_dir="private/views",
                native_ledger_file="public/native-ledger.json",native_ledger_sha256=sha(e.public/"native-ledger.json"),
                policy_sha256=sha(args.policy),policy_canonical_sha256=canonical(policy),truth_sha256=sha(private/"truth.json"),
                views_sha256={p.name:sha(p) for p in sorted(views.iterdir())},
                public_files={p.name:sha(p) for p in sorted(final.iterdir())},proof_count=len(notes.events),genuine_proof_count=len(notes.events),
                checked=checked,accounting=truth["accounting"],original_backups_unchanged=True,chain_acceptance_verified=False,
                elapsed_seconds=time.monotonic()-begin)
    save(root/"native-result.json",result)
    return result


def controls():
    s=schedule(bytes(range(32))); validate_schedule(s)
    need(sum(s["counts"])==64 and min(s["capitals"])-6*(50*SOMPI+FEE)==4_760_000_000,"affordability bound")
    # Explicit note flow demonstrates receipt selection and exact capital carry.
    n=Notes(350*SOMPI+FEE); n.add("bootstrap",0,[0],0,350*SOMPI)
    n.add("admit",1,[],amount=350*SOMPI+FEE)
    gift=n.add("pay",0,[1],1,20*SOMPI)
    receipt=gift["outputs"][0]["position"]
    n.add("pay",1,[n.capital[1],receipt],0,10*SOMPI)
    need(n.values[n.capital[1]]==360*SOMPI-FEE and receipt in n.spent,"receipt spending/capital carry")
    rejected=0
    for mutate in (lambda x:x["requests"][0].update(recipient=0),lambda x:x["counts"].__setitem__(8,True),lambda x:x["requests"][0].update(amount=True),lambda x:x["cashout_permutation"].__setitem__(0,x["cashout_permutation"][1])):
        bad=copy.deepcopy(s); mutate(bad)
        try: validate_schedule(bad)
        except (ValueError,TypeError): rejected+=1
    need(rejected==4,"malformed schedule controls")
    try: n.add("exit",1,[receipt],amount=20*SOMPI-FEE)
    except ValueError: rejected+=1
    need(rejected==5,"double spend control")
    # Complete deterministic development schedule: no wallet/crypto generation.
    model=Notes(s["capitals"][0]+FEE)
    model.add("bootstrap",0,[0],0,s["capitals"][0])
    for role in range(1,32): model.add("admit",role,[],amount=s["capitals"][role]+FEE)
    receipt_spends=0
    for i,r in enumerate(s["requests"]):
        a,b=r["sender"],r["recipient"]
        extra=model.available(a,True)[:1]
        receipt_spends+=bool(extra)
        e=model.add("pay",a,[model.capital[a]]+extra,b,r["amount"],r["minute"],i)
        positions=[e["outputs"][0]["position"]] if s["modes"][b]=="prompt" else (model.available(b,True)[:2] if s["modes"][b]=="accumulated" else [])
        if s["modes"][b]=="accumulated" and len(positions)<2: positions=[]
        if positions:
            payout=sum(model.values[p] for p in positions)-FEE
            model.add("exit",b,positions,amount=payout)
            if i<4:
                target=b if i<2 else s["cashout_permutation"][i+2]
                old_capital=model.capital[target]
                model.add("admit",target,[],amount=payout-SOMPI)
                need(model.capital[target]==old_capital,"bridge preserves capital tracker")
    need(receipt_spends>0,"development receipt-spend coverage")
    need(min(model.values[model.capital[r]] for r in ROLES)>=4_760_000_000,"capital affordability induction")
    for role in s["final_order"]:
        while model.available(role):
            positions=model.available(role)[:2]
            model.add("exit",role,positions,amount=sum(model.values[p] for p in positions)-FEE)
    need(not any(model.available(r) for r in ROLES)
         and sum(e["kind"]=="pay" for e in model.events)==64
         and sum(e["kind"]=="admit" for e in model.events)==35,"complete development schedule")
    # Independent arithmetic graph fixture. These small dictionaries are NOT
    # native-valid transactions and are never passed off as proof evidence.
    def tx(identifier, inputs, values):
        return dict(id=f"{identifier:064x}",payload="",inputs=[dict(previousOutpoint=dict(transactionId=f"{source:064x}",index=index)) for source,index in inputs],
                    outputs=[dict(value=str(value)) for value in values])
    parents=[tx(100+r,[(1000+r,0)],[10*SOMPI,SOMPI-10]) for r in ROLES]
    founding=tx(200,[(100,0)],[9*SOMPI,SOMPI-10])
    exited=tx(201,[(200,0)],[5*SOMPI,4*SOMPI-10])
    bridge=tx(300,[(201,1)],[3*SOMPI,SOMPI-20])
    admitted=tx(202,[(201,0),(300,0)],[8*SOMPI-10])
    terminal=tx(203,[(202,0)],[8*SOMPI-20])
    raw=dict(parents=parents+[bridge],lineage=[founding,exited,admitted,terminal])
    accounting=native_accounting(raw)
    need(accounting["external_injection_sompi"]==352*SOMPI and accounting["ordinary_fees_sompi"]==340
         and accounting["pool_fees_sompi"]==30 and accounting["final_native_unspent_sompi"]==352*SOMPI-370,
         "independent native graph accounting incl bridge change")
    bad=copy.deepcopy(raw); bad["parents"].append(tx(301,[(201,1)],[3*SOMPI,SOMPI-20]))
    try: native_accounting(bad)
    except ValueError: rejected+=1
    need(rejected==6,"global bridge duplicate spend rejection")
    bad=copy.deepcopy(raw); bad["parents"][-1]["outputs"][1]["value"]=str(2*SOMPI)
    try: native_accounting(bad)
    except ValueError: rejected+=1
    need(rejected==7,"ordinary bridge inflation rejection")
    return dict(complete=True,passed=True,controls=13,development_only=True,
                development_payments=64,development_pool_operations=len(model.events))


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--controls",action="store_true")
    parser.add_argument("--policy",action="store_true")
    a=parser.parse_args()
    if a.controls: print(json.dumps(controls()))
    elif a.policy: print(json.dumps(public_policy(),sort_keys=True,indent=2))
    else: parser.error("use --controls or --policy; generation is called by the frozen external runner")
