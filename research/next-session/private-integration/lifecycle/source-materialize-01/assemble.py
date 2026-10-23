"""New-format fixture assembly, real delivery and exact native-output linking.

This is a deliberately finite offline integration experiment. It imports only
the selected new receive-V2 module and the Python standard library. Accepted
genesis/current-head/data availability remain explicitly supplied oracles.
No node, wallet, ledger replayer, network, old proof key or prior-format code.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "poc/future-recipient/v2"))
from recipient import (Crypto, Delivery, ExpectedState, NFEntry, Receiver, Receipt,
                       Snapshot, Tree, CM_DEPTH, CM_NODE, CM_EMPTY, NF_DEPTH,
                       NF_NODE, NF_EMPTY, ZERO, h, u32, u64, recover, exit_witness)

DOMAIN = h(b"KPI/future-private-native-integration/DO-NOT-FUND/v1/2026-10-23")
CLASS = "PUBLIC_SYNTHETIC_DO_NOT_FUND"
GENESIS_VALUE = 60_000_000
PAYMENT_VALUE = 1_000_000_000
RATE = 100
STATE_MAGIC = b"KPX2ST01"
AUTH_MAGIC = b"KPX2AU01"


def save(path, value):
    path = Path(path)
    if path.exists():
        raise ValueError("refuse overwrite: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load(path):
    return json.loads(Path(path).read_text())


def exact(raw, length):
    if not isinstance(raw, str):
        raise ValueError("hex type")
    value = bytes.fromhex(raw)
    if len(value) != length or value.hex() != raw:
        raise ValueError("canonical hex length")
    return value


def public_seed(label):
    return h(b"KPI/FUTURE-LIFECYCLE/PUBLIC_SYNTHETIC_DO_NOT_FUND/", label.encode())


def state(snapshot):
    cm, nf = snapshot.roots()
    return (STATE_MAGIC + DOMAIN + cm.root + u32(len(snapshot.deliveries))
            + nf.root + u32(len(snapshot.nullifiers)))


def insert(snapshot, value):
    """Construct actual physical-index preserving NF witnesses, not sorted leaves."""
    value_int = int.from_bytes(value, "little")
    if value == ZERO or any(e.value == value for e in snapshot.nullifiers):
        raise ValueError("spent or zero NF")
    cm, tree = snapshot.roots()
    m = len(snapshot.nullifiers)
    pred_index, pred = max(
        ((i, e) for i, e in enumerate(snapshot.nullifiers)
         if int.from_bytes(e.value, "little") < value_int),
        key=lambda pair: int.from_bytes(pair[1].value, "little"))
    if pred.next_value != ZERO and value_int >= int.from_bytes(pred.next_value, "little"):
        raise ValueError("NF interval")
    leaf = pred.value + pred.next_value + u32(pred.next_index)
    witness = u32(pred_index) + leaf + b"".join(tree.path(pred_index))
    replacement = NFEntry(pred.value, value, m)
    intermediate = tree.with_leaf(pred_index, replacement.leaf())
    witness += b"".join(intermediate.path(m))
    entries = list(snapshot.nullifiers)
    entries[pred_index] = replacement
    entries.append(NFEntry(value, pred.next_value, pred.next_index))
    result = Snapshot(list(snapshot.deliveries), entries)
    if len(witness) != 1160:
        raise ValueError("NF witness width")
    return result, witness


def private_case(snapshot, receivers, input_indices, output_records, output_notes,
                 previous_outpoint, reserve, fee):
    old_state = state(snapshot)
    old_cm, _ = snapshot.roots()
    inputs = []
    nfs = []
    for position, receiver, invoice_index in input_indices:
        delivery = snapshot.deliveries[position]
        receipt = receiver.open(delivery.ciphertext)
        if receipt.index != invoice_index or receipt.commitment() != delivery.cm:
            raise ValueError("input ownership/position")
        keys = receiver.keys(invoice_index)
        nf = receiver.nullifier(receipt, position)
        nfs.append(nf)
        inputs.append({"real": True, "note_hex168": receipt.note_bytes().hex(),
            "s_hex32": keys.owner_secret.hex(), "k_hex32": keys.nf_secret.hex(),
            "position": position, "cm_path_hex": [x.hex() for x in old_cm.path(position)],
            "dummy_key_hex32": ZERO.hex(), "dummy_seed_hex32": ZERO.hex()})
    current = Snapshot(list(snapshot.deliveries), list(snapshot.nullifiers))
    public_witness = b""
    for nf in nfs:
        current, witness = insert(current, nf)
        public_witness += witness
    for delivery in output_records:
        cm_tree, _ = current.roots()
        if delivery.position != len(current.deliveries):
            raise ValueError("CM append position")
        public_witness += b"".join(cm_tree.path(delivery.position))
        current.deliveries.append(delivery)
    next_state = state(current)
    ciphers = b"".join(d.ciphertext for d in output_records)
    auth = (AUTH_MAGIC + DOMAIN + previous_outpoint + old_state + u64(reserve)
            + u64(fee) + b"".join(nfs) + b"".join(d.cm for d in output_records)
            + h(ciphers) + next_state + u64(reserve - fee))
    if len(auth) != 484 or len(public_witness) != 3344 or len(ciphers) != 528:
        raise ValueError("private widths")
    if sum(int.from_bytes(bytes.fromhex(i["note_hex168"])[64:72], "little") for i in inputs) != sum(n.value_sompi for n in output_notes) + fee:
        raise ValueError("private exact conservation")
    fixture = {"classification": CLASS, "auth_hex484": auth.hex(), "inputs": inputs,
               "outputs": [{"note_hex168": note.note_bytes().hex()} for note in output_notes]}
    vector = {"auth_hex": auth.hex(), "cipher_hex": ciphers.hex(),
              "public_witness_hex": public_witness.hex(), "proof_hex": bytes(128).hex(),
              "vk_hex": bytes(328).hex()}
    return current, fixture, vector


def assemble_receipts(crypto, fee):
    wallets = {label: Receiver(public_seed(label), DOMAIN, crypto)
               for label in ("Alice", "Bob", "Charlie")}
    # Every seed backup is fixed before its first invoice and payment. No later
    # receipt, log, key index or precomputed withdrawal is included in backups.
    specifications = [("Alice", 0, GENESIS_VALUE),
                      ("Alice", 1, 2 * PAYMENT_VALUE + fee - GENESIS_VALUE),
                      ("Bob", 0, PAYMENT_VALUE), ("Charlie", 0, PAYMENT_VALUE)]
    notes, records, invoices = [], [], []
    for position, (owner, index, value) in enumerate(specifications):
        wallet = wallets[owner]
        invoice = wallet.invoice(index)
        note = Receipt.for_invoice(invoice, value,
            h(b"PUBLIC_SYNTHETIC_LIFECYCLE_RHO_DO_NOT_FUND", u32(position)))
        ciphertext = crypto.seal(invoice.delivery_pk, note.encode())
        if len(ciphertext) != 264:
            raise ValueError("receipt width")
        notes.append(note)
        records.append(Delivery(position, note.commitment(), ciphertext))
        invoices.append({"owner": owner, "invoice208_hex": invoice.encode().hex()})
    return wallets, notes, records, invoices


def initial_fixture(crypto, fee):
    wallets, notes, records, invoices = assemble_receipts(crypto, fee)
    snapshot = Snapshot(records[:2], [NFEntry(ZERO, ZERO, 0)])
    after, fixture, vector = private_case(snapshot, wallets,
        [(0, wallets["Alice"], 0), (1, wallets["Alice"], 1)], records[2:], notes[2:],
        bytes(36), 2 * PAYMENT_VALUE + fee, fee)
    return wallets, notes, records, invoices, snapshot, after, fixture, vector


def dump_snapshot(snapshot):
    return {"deliveries": [d.public() for d in snapshot.deliveries],
            "nullifiers": [{"value": e.value.hex(), "next_value": e.next_value.hex(),
                             "next_index": e.next_index} for e in snapshot.nullifiers]}


def parse_snapshot(value):
    return Snapshot([Delivery(d["position"], exact(d["cm"], 32),
                             exact(d["ciphertext"], 264)) for d in value["deliveries"]],
                    [NFEntry(exact(e["value"], 32), exact(e["next_value"], 32),
                             e["next_index"]) for e in value["nullifiers"]])


def validate_backups(backups):
    if (backups.get("classification") != CLASS or backups.get("domain") != DOMAIN.hex()
            or backups.get("profile") != "KPX2-INVOICE208-INCOMING-PER-INDEX"
            or backups.get("created_before_any_invoice_or_payment") is not True
            or backups.get("backup_fields") != ["seed32", "domain", "profile"]):
        raise ValueError("backup profile/domain/pre-payment boundary")
    for label in ("Alice", "Bob", "Charlie"):
        item = backups["backups"][label]
        if set(item) != {"seed32"} or item["seed32"] != public_seed(label).hex():
            raise ValueError("wrong synthetic seed-only pre-payment backup")


def prepare(args):
    # Shape-only preliminary fixture. Actual prior outpoint/fees/VK/body are not
    # known until the selected new setup and native quote stages complete.
    if args.output.exists():
        raise ValueError("fresh output required")
    args.output.mkdir(parents=True)
    crypto = Crypto(args.crypto)
    # Persist the actual seed-only backup before constructing invoices/receipts.
    save(args.output / "PUBLIC-SYNTHETIC-backups.json", {"classification": CLASS,
        "created_before_any_invoice_or_payment": True,
        "profile": "KPX2-INVOICE208-INCOMING-PER-INDEX", "domain": DOMAIN.hex(),
        "backup_fields": ["seed32", "domain", "profile"],
        "backups": {label: {"seed32": public_seed(label).hex()}
                    for label in ("Alice", "Bob", "Charlie")}})
    wallets, notes, records, invoices, before, after, fixture, vector = initial_fixture(crypto, args.fee)
    save(args.output / "shape-fixture.json", fixture)
    save(args.output / "shape-native-vector.json", vector)
    save(args.output / "shape-records.json", {"before": dump_snapshot(before), "after": dump_snapshot(after)})
    save(args.output / "invoice-directory-DO-NOT-FUND.json", {"classification": CLASS,
        "observer_boundary": "directory only, excluded from native public payload", "entries": invoices})
    save(args.output / "PLAN.json", {"classification": CLASS,
        "scope": "Finitely scripted offline new-format integration; no chain acceptance",
        "rate_sompi_per_mass": RATE, "preliminary_fee_sompi": args.fee,
        "ordered_operations": ["ordinary funding→coherent Alice60M singleton founding",
            "public ADMIT Alice(2B+privatefee−60M)",
            "genuine private two-real Alice→Bob1B+Charlie1B no change",
            "discard wallets; restore Bob/Charlie pre-payment seed backups",
            "preferred services absent BEFORE any withdrawal authorization",
            "Bob current native reveal", "Charlie current terminal native reveal"],
        "source_fixture_review_required_before_setup_or_proof": True,
        "actual_body_links_required": True,
        "all_positive_liabilities": [{"position": i, "value_sompi": n.value_sompi} for i, n in enumerate(notes)],
        "external_oracles": ["canonical genesis and current ordered lineage",
            "ordinary funding UTXOs", "complete authenticated ciphertext archive"],
        "not_claimed": ["testnet payout", "real chain backing", "unreviewed cryptographic security",
            "financial privacy", "2% lifecycle target", "general wallet or ledger replay"]})


def native_call(binary, mode, vector, directory):
    directory = Path(directory)
    if directory.exists():
        raise ValueError("fresh native operation directory")
    vector_path = directory.with_suffix(".vector.json")
    save(vector_path, vector)
    proc = subprocess.run([str(binary), mode, str(vector_path), str(directory)],
                          capture_output=True, text=True, check=False)
    directory.mkdir(parents=True, exist_ok=True)
    save(directory / "command-result.json", {"returncode": proc.returncode,
        "mode": mode, "stdout": proc.stdout, "stderr": proc.stderr,
        "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest()})
    if proc.returncode:
        raise ValueError("native operation failed; preserved at " + str(directory))
    metrics = load(directory / "metrics.json")
    kind = mode.rsplit("-", 1)[0]
    if kind == "private":
        expected_fee = int.from_bytes(bytes.fromhex(vector["auth_hex"])[196:204], "little")
    elif kind == "admit":
        expected_fee = int.from_bytes(bytes.fromhex(vector["payload_hex"])[1160:1168], "little")
    elif kind == "reveal":
        expected_fee = int.from_bytes(bytes.fromhex(vector["payload_hex"])[2013:2021], "little")
    else:
        expected_fee = vector["fee_sompi"]
    if metrics["actual_fee_sompi"] != expected_fee:
        raise ValueError("native actual fee differs from frozen vector")
    if mode.endswith("-run"):
        actual_full = load(directory / "native-validation.json")["Full"]
        if actual_full.get("accepted") is not True or actual_full["fee_sompi"] != expected_fee:
            raise ValueError("native Full fee differs from actual/vector fee")
    return metrics


def quote(binary, kind, make_vector, output, rate=RATE):
    """Monotone integer actual-body fee iteration; no native execution."""
    fee = 1
    attempts = []
    # A generous diagnostic limit: reaching it preserves every attempted body
    # and reports incomplete, rather than treating an unpriced body as passing.
    for attempt in range(256):
        vector = make_vector(fee)
        directory = output / f"quote-{kind}-{attempt:03d}"
        metrics = native_call(binary, kind + "-freeze", vector, directory)
        required = rate * metrics["mining_mass"]
        attempts.append({"fee_sompi": fee, "required_sompi": required,
                         "mining_mass": metrics["mining_mass"],
                         "directory": directory.name})
        if fee >= required:
            save(output / f"{kind}-fee-fixedpoint.json", {"rate": rate,
                "fee_sompi": fee, "attempts": attempts, "native_executed": False,
                "algorithm": "from1, monotone max(fee, rate*actual mining mass)"})
            return fee, vector, directory
        fee = max(fee, required)
    raise ValueError("fee iteration incomplete; all 256 attempted bodies preserved")


def outpoint(directory, index=0):
    # Native official serialization is authoritative for raw txid byte order.
    txid = exact((directory / "txid-raw.hex").read_text().strip(), 32)
    return txid + u32(index)


def admit_payload(genesis, note, record, before, after, fee, change):
    cm_tree, _ = before.roots()
    payload = (b"KPX2AD01" + DOMAIN + note.note_bytes() + record.cm
        + record.ciphertext + h(record.ciphertext)
        + b"".join(cm_tree.path(len(before.deliveries))) + state(after)
        + u64(fee) + u64(change) + genesis.note_bytes())
    if len(payload) != 1344:
        raise ValueError("ADMIT payload width")
    return payload


def materialize(args):
    """Prepare exact native-linked inputs; source/input review precedes run."""
    if args.output.exists():
        raise ValueError("fresh output required")
    args.output.mkdir(parents=True)
    vk = args.vk.read_bytes()
    if len(vk) != 328:
        raise ValueError("selected genuine VK328")
    crypto = Crypto(args.crypto)
    backups = load(args.backups)
    validate_backups(backups)
    save(args.output / "PUBLIC-SYNTHETIC-backups.json", backups)

    # Fee-dependent Alice admission and exact no-change private conservation.
    prepared = {}
    def make_private(fee):
        items = initial_fixture(crypto, fee)
        vector = items[-1]
        vector["vk_hex"] = vk.hex()
        prepared[fee] = items
        return vector
    private_fee, _, _ = quote(args.native, "private", make_private, args.output)
    wallets, notes, records, invoices, before, after, fixture, vector = prepared[private_fee]
    genesis = Snapshot(records[:1], [NFEntry(ZERO, ZERO, 0)])
    reserve = 2 * PAYMENT_VALUE + private_fee
    founding_funding = 120_000_000
    def make_founding(fee):
        return {"note_hex": notes[0].note_bytes().hex(),
            "cipher_hex": records[0].ciphertext.hex(),
            "funding_previous_txid_raw_hex": public_seed("FoundingInputOutpoint").hex(),
            "funding_previous_index": 0, "funding_amount_sompi": founding_funding,
            "funding_secret_hex": public_seed("FoundingFundingSecret").hex(),
            "fee_sompi": fee, "change_sompi": founding_funding - GENESIS_VALUE - fee,
            "vk_hex": vk.hex()}
    founding_fee, founding_vector, founding_dir = quote(args.native, "founding", make_founding, args.output)
    founding_previous = outpoint(founding_dir)
    def make_admission(fee):
        admission_funding = notes[1].value_sompi + fee
        change = 0
        return {"state_hex": state(genesis).hex(),
            "previous_txid_raw_hex": founding_previous[:32].hex(), "previous_index": 0,
            "reserve_sompi": GENESIS_VALUE,
            "payload_hex": admit_payload(notes[0], notes[1], records[1], genesis, before,
                                          fee, change).hex(),
            "funding_previous_txid_raw_hex": public_seed("AdmissionInputOutpoint").hex(),
            "funding_previous_index": 0, "funding_amount_sompi": admission_funding,
            "funding_secret_hex": public_seed("AdmissionFundingSecret").hex(),
            "vk_hex": vk.hex()}
    admit_fee, admit_vector, admit_dir = quote(args.native, "admit", make_admission, args.output)
    admission_funding = notes[1].value_sompi + admit_fee
    def make_prep(fee):
        return {"source_previous_txid_raw_hex": public_seed("OrdinarySourceOutpoint").hex(),
            "source_previous_index": 0, "source_amount_sompi": 4_000_000_000,
            "source_secret_hex": public_seed("OrdinarySourceSecret").hex(),
            "outputs": [{"value_sompi": founding_funding,
                         "xonly_public_key_hex": crypto.xonly(public_seed("FoundingFundingSecret")).hex()},
                        {"value_sompi": admission_funding,
                         "xonly_public_key_hex": crypto.xonly(public_seed("AdmissionFundingSecret")).hex()}],
            "fee_sompi": fee,
            "source_change_sompi": 4_000_000_000 - founding_funding - admission_funding - fee}
    prep_fee, prep_vector, prep_dir = quote(args.native, "funding-prep", make_prep, args.output)
    actual_prepared_source = outpoint(prep_dir)
    # Preliminary quote outpoints are superseded BEFORE proof/execution. Native
    # fees depend on complete body shape/values, not fixed-width outpoint bytes.
    founding_vector["funding_previous_txid_raw_hex"] = actual_prepared_source[:32].hex()
    founding_vector["funding_previous_index"] = 0
    founding_dir = args.output / "founding-final"
    native_call(args.native, "founding-freeze", founding_vector, founding_dir)
    founding_previous = outpoint(founding_dir)
    admit_vector["previous_txid_raw_hex"] = founding_previous[:32].hex()
    admit_vector["funding_previous_txid_raw_hex"] = actual_prepared_source[:32].hex()
    admit_vector["funding_previous_index"] = 1
    admit_dir = args.output / "admit-final"
    native_call(args.native, "admit-freeze", admit_vector, admit_dir)
    actual_previous = outpoint(admit_dir)
    after, fixture, vector = private_case(before, wallets,
        [(0, wallets["Alice"], 0), (1, wallets["Alice"], 1)], records[2:], notes[2:],
        actual_previous, reserve, private_fee)
    vector["vk_hex"] = vk.hex()
    metrics = native_call(args.native, "private-freeze", vector, args.output / "private-final-unsigned")
    if metrics["actual_fee_sompi"] != private_fee or private_fee < RATE * metrics["mining_mass"]:
        raise ValueError("final private actual-context fee mismatch")
    save(args.output / "private-fixture.json", fixture)
    save(args.output / "private-native-vector.json", vector)
    save(args.output / "founding-native-vector.json", founding_vector)
    save(args.output / "admit-native-vector.json", admit_vector)
    save(args.output / "funding-prep-native-vector.json", prep_vector)
    save(args.output / "records.json", {"genesis": dump_snapshot(genesis),
        "before-private": dump_snapshot(before), "after-private": dump_snapshot(after)})
    save(args.output / "invoice-directory-DO-NOT-FUND.json", {"classification": CLASS, "entries": invoices})
    # Independent accounting lists every positive note, including consumed Alice
    # notes. Native change is ordinary owner-controlled value, never omitted pool
    # liability or a second useful private payment.
    save(args.output / "ghost-accounting.json", {"classification": CLASS,
        "canonical_genesis_and_ordered_current_lineage": "EXTERNAL_SUPPLIED_ORACLE",
        "notes": [{"position": i, "owner": owner, "value_sompi": n.value_sompi,
                   "spent_after_private": i < 2} for i, (owner, n) in enumerate(zip(
                       ["Alice", "Alice", "Bob", "Charlie"], notes))],
        "steps": [{"stage": "founding", "reserve": GENESIS_VALUE, "liability": GENESIS_VALUE,
                   "unspent_positions": [0]},
                  {"stage": "admit", "reserve": reserve, "liability": reserve,
                   "unspent_positions": [0, 1]},
                  {"stage": "private", "reserve": 2 * PAYMENT_VALUE,
                   "liability": 2 * PAYMENT_VALUE, "unspent_positions": [2, 3]}],
        "actual_fees_sompi": {"fundingprep": prep_fee, "founding": founding_fee,
                             "admit": admit_fee, "private": private_fee},
        "ordinary_source_input_sompi": 4_000_000_000,
        "source_funding_inputs_sompi": [founding_funding, admission_funding],
        "counting": "two distinct useful10KAS recipients; no private change; all founding and funding change costs retained"})
    auth = bytes.fromhex(fixture["auth_hex484"])
    digest = h(auth)
    case = {"case_id": "actual-native-linked-private-two-real-two-recipients",
        **fixture, "actual_previous_outpoint_hex36": actual_previous.hex(),
        "actual_reserve_sompi": reserve, "actual_fee_sompi": private_fee,
        "actual_successor_reserve_sompi": 2 * PAYMENT_VALUE,
        "actual_successor_state_hex112": state(after).hex(),
        "ciphertexts_hex264": [d.ciphertext.hex() for d in records[2:]],
        "public_witness_hex3344": vector["public_witness_hex"],
        "public_limbs_decimal": [str(int.from_bytes(digest[i:i+16], "little")) for i in (0,16)],
        "payload_hex4356": auth.hex() + vector["cipher_hex"] + vector["public_witness_hex"],
        "transaction_path": str((args.output / "private-final-unsigned/transaction.json").resolve()),
        "transaction_sha256": hashlib.sha256((args.output / "private-final-unsigned/transaction.json").read_bytes()).hexdigest(),
        "supplied_context_path": str((args.output / "private-final-unsigned/supplied-context.json").resolve()),
        "supplied_context_sha256": hashlib.sha256((args.output / "private-final-unsigned/supplied-context.json").read_bytes()).hexdigest(),
        "proof_stage": "PLACEHOLDER_NOT_VERIFIED"}
    save(args.output / "independent-private-auth-cases.json", {
        "schema": "independent-private-auth-cases-v1", "cases": [case]})
    save(args.output / "MATERIALIZED.json", {"classification": CLASS,
        "selected_vk_sha256": hashlib.sha256(vk).hexdigest(), "actual_native_execution": False,
        "native_full_validation_pending": True, "private_proof_pending": True,
        "funding_prep_quote_directory": prep_dir.name,
        "founding_quote_directory": founding_dir.name, "admit_quote_directory": admit_dir.name,
        "private_fee_sompi": private_fee,
        "native_source_output_fields": {
            "previous_outpoint": admit_dir.name + "/txid-raw.hex+index0",
            "prior_reserve_and_spk": admit_dir.name + "/outputs.json#index0",
            "private_actual_context": "private-final-unsigned/{transaction,supplied-context,metrics}.json"},
        "accepted_chain_backing": False})


def reveal_payload(receiver, claim, expected, snapshot, fee):
    witness = exit_witness(receiver, claim, expected, snapshot)
    note = claim.receipt
    pred = witness["predecessor"]
    # Retains the public candidate-C 2029-byte offsets, selected V2 magic only.
    payload = (b"KPX2RV01" + b"\x01" + note.owner + note.incoming
        + u64(note.value_sompi) + note.rho + receiver.keys(note.index).nf_secret
        + note.native_pk + u32(claim.position)
        + note.key_commitment + note.commitment()
        + b"".join(bytes.fromhex(p) for p in witness["cm_path"])
        + u32(witness["predecessor_index"])
        + bytes.fromhex(pred["value"]) + bytes.fromhex(pred["next_value"])
        + u32(pred["next_index"])
        + b"".join(bytes.fromhex(p) for p in witness["predecessor_path"])
        + b"".join(bytes.fromhex(p) for p in witness["append_path_after_predecessor_update"])
        + bytes.fromhex(witness["nf"]) + bytes.fromhex(witness["intermediate_nf_root"])
        + bytes.fromhex(witness["successor_nf_root"]) + u64(fee)
        + u64(note.value_sompi - fee))
    if len(payload) != 2029:
        raise ValueError("reveal payload width")
    return payload, witness


def verify_link(previous_directory, next_directory, output_index=0, input_index=0):
    previous = load(previous_directory / "transaction.json")
    following = load(next_directory / "transaction.json")
    supplied = load(next_directory / "supplied-context.json")
    expected = previous["outputs"][output_index]
    consumed = following["inputs"][input_index]["previousOutpoint"]
    if consumed != {"transactionId": previous["id"], "index": output_index}:
        raise ValueError("actual prior output outpoint mismatch")
    if (supplied[input_index]["amount_sompi"] != expected["value"]
            or supplied[input_index]["script_public_key"] != expected["scriptPublicKey"]):
        raise ValueError("supplied input amount/SPK differs from actual previous output")
    return {"previous_txid_raw_hex": previous["id"], "index": output_index,
            "amount_sompi": expected["value"],
            "script_public_key": expected["scriptPublicKey"],
            "checked_actual_body_and_supplied_context": True}


def validate_freeze(freeze_path):
    freeze = load(freeze_path)
    if freeze.get("runtime_authorized") is not True or freeze.get("classification") != CLASS:
        raise ValueError("reviewed source/input release missing")
    for pin in freeze["files"]:
        path = Path(pin["path"])
        if not path.is_absolute():
            path = REPO / path
        data = path.read_bytes()
        if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise ValueError("frozen source/input changed: " + str(path))
    return hashlib.sha256(freeze_path.read_bytes()).hexdigest()


def execute(args):
    """Finite supplied-context integration; every native step executes Full."""
    freeze_sha = validate_freeze(args.freeze)
    if args.output.exists():
        raise ValueError("fresh output required")
    args.output.mkdir(parents=True)
    prepared = args.prepared
    before = parse_snapshot(load(prepared / "records.json")["before-private"])
    after = parse_snapshot(load(prepared / "records.json")["after-private"])
    fees = load(prepared / "ghost-accounting.json")["actual_fees_sompi"]
    founding = load(prepared / "founding-native-vector.json")
    funding_prep = load(prepared / "funding-prep-native-vector.json")
    admission = load(prepared / "admit-native-vector.json")
    private = load(prepared / "private-native-vector.json")
    proof_report = load(args.proof / "report.json")
    proof = (args.proof / "proof128.bin").read_bytes()
    if (len(proof) != 128 or proof_report.get("genuine_Groth16_verified") is not True
            or proof_report["proof_hex128"] != proof.hex()
            or proof_report["vk_hex328"] != private["vk_hex"]
            or proof_report["fixture_sha256"] != hashlib.sha256((prepared / "private-fixture.json").read_bytes()).hexdigest()):
        raise ValueError("genuine proof/source fixture/VK identity mismatch")
    private["proof_hex"] = proof.hex()
    links = []
    for kind, vector in (("funding-prep", funding_prep), ("founding", founding),
                         ("admit", admission), ("private", private)):
        native_call(args.native, kind + "-run", vector, args.output / kind)
        if kind == "founding":
            links.append(verify_link(args.output / "funding-prep", args.output / "founding"))
        if kind == "admit":
            links.append(verify_link(args.output / "founding", args.output / "admit"))
            links.append(verify_link(args.output / "funding-prep", args.output / "admit", 1, 1))
        if kind == "private":
            links.append(verify_link(args.output / "admit", args.output / "private"))
    # Proving changes the fixed-width input witness, never the owner-authorized
    # outputs/payload/outpoint. Verify actual raw ID identity rather than assume.
    if outpoint(args.output / "admit") != outpoint(prepared / load(prepared / "MATERIALIZED.json")["admit_quote_directory"]):
        raise ValueError("actual admit differs from prepared body")
    if (load(args.output / "private/transaction.json")["payload"]
            != load(prepared / "private-final-unsigned/transaction.json")["payload"]):
        raise ValueError("proof-bearing body changed owner-authorized payload")
    # No preferred-service interface exists in this process. This marker precedes
    # reconstruction, quote signing and every withdrawal authorization. Complete
    # records/current head are retained via the explicit external archive oracle.
    save(args.output / "services-absent-before-withdrawal.json", {
        "preferred_service_interface_present": False,
        "withdrawal_authorization_created_before_this_marker": False,
        "available_inputs": ["pre-payment seed backups", "complete authenticated public archive",
                             "supplied ordered accepted-head oracle", "immutable VK/policy"],
        "not_demonstrated": "independent network discovery or durable public data availability"})
    backups = load(prepared / "PUBLIC-SYNTHETIC-backups.json")
    validate_backups(backups)
    crypto = Crypto(args.crypto)
    current = after
    previous_directory = args.output / "private"
    reserve = 2 * PAYMENT_VALUE
    recoveries, all_witnesses = {}, []
    for label, position in (("Bob", 2), ("Charlie", 3)):
        # Fresh receiver object uses only the backup persisted before invoices.
        restored = Receiver(exact(backups["backups"][label]["seed32"], 32), DOMAIN, crypto)
        cm, nf = current.roots()
        expected = ExpectedState(DOMAIN, cm.root, len(current.deliveries), nf.root,
                                 len(current.nullifiers), current.delivery_digest())
        recovered = recover(restored, expected, current)
        claims = [claim for claim in recovered.owned if claim.position == position and not claim.spent]
        if len(claims) != 1 or recovered.all_owned_unspent_sompi != PAYMENT_VALUE:
            raise ValueError("recipient backup recovery/credit mismatch")
        claim = claims[0]
        def make_reveal(fee):
            payload, witness = reveal_payload(restored, claim, expected, current, fee)
            return {"state_hex": state(current).hex(),
                "previous_txid_raw_hex": outpoint(previous_directory)[:32].hex(),
                "previous_index": 0, "reserve_sompi": reserve,
                "payload_hex": payload.hex(),
                "native_secret_hex": restored.keys(claim.receipt.index).native_secret.hex(),
                "vk_hex": private["vk_hex"]}
        fee, vector, quote_dir = quote(args.native, "reveal", make_reveal,
            args.output / (label.lower() + "-quotes"))
        directory = args.output / (label.lower() + "-reveal")
        native_call(args.native, "reveal-run", vector, directory)
        links.append(verify_link(previous_directory, directory))
        payload, witness = reveal_payload(restored, claim, expected, current, fee)
        current, _ = insert(current, claim.nf)
        reserve -= PAYMENT_VALUE
        actual = load(directory / "transaction.json")
        payout_index = 1 if reserve else 0
        payout = actual["outputs"][payout_index]
        if (payout["value"] != PAYMENT_VALUE - fee
                or payout["scriptPublicKey"] != "000020" + claim.receipt.native_pk.hex() + "ac"):
            raise ValueError("actual recipient payout amount/key mismatch")
        if reserve:
            if actual["outputs"][0]["value"] != reserve:
                raise ValueError("remaining reserve amount mismatch")
            successor_path = directory / "successor-state.hex"
            if exact(successor_path.read_text().strip(), 112) != state(current):
                raise ValueError("native successor differs from reconstructed current roots")
        elif len(actual["outputs"]) != 1:
            raise ValueError("terminal reserve output survived")
        fees[label.lower() + "_reveal"] = fee
        recoveries[label] = {"restored_position": position,
            "seed_only_backup": True, "owned_unspent_before_reveal_sompi": PAYMENT_VALUE,
            "actual_payout_sompi": payout["value"], "fee_sompi": fee,
            "native_Full": load(directory / "native-validation.json")["Full"],
            "archive_oracle": expected.oracle}
        all_witnesses.append({"owner": label, **witness})
        previous_directory = directory
    # Complete ghost liabilities were two1B notes, both consumed exactly once.
    if reserve != 0 or len(current.nullifiers) != 5:
        raise ValueError("terminal accounting/NF count")
    final_recoveries = {}
    final_expected = current.pin(DOMAIN)
    for label in ("Alice", "Bob", "Charlie"):
        restored = Receiver(exact(backups["backups"][label]["seed32"], 32), DOMAIN, crypto)
        restored_result = recover(restored, final_expected, current)
        final_recoveries[label] = restored_result.all_owned_unspent_sompi
    if any(final_recoveries.values()):
        raise ValueError("positive owned tail survived terminal reserve")
    save(args.output / "actual-body-links.json", {"links": links})
    save(args.output / "restored-current-witnesses.json", {"classification": CLASS,
        "witnesses": all_witnesses})
    save(args.output / "final-public-records.json", dump_snapshot(current))
    shared = fees["founding"] + fees["admit"] + fees["private"] + fees.get("fundingprep", 0)
    quotient, remainder = divmod(shared, 2)
    # Assign the indivisible shared sompi deterministically to Bob. Each owner
    # then bears their own actual reveal fee; never hide it in an average.
    burdens = {"Bob": quotient + remainder + fees["bob_reveal"],
               "Charlie": quotient + fees["charlie_reveal"]}
    if sum(burdens.values()) != sum(fees.values()):
        raise ValueError("per-recipient exact fee allocation mismatch")
    save(args.output / "RESULTS.json", {"classification": CLASS,
        "source_input_freeze_sha256": freeze_sha,
        "native_Full_operations": 6, "genuine_private_proofs": 1,
        "actual_prior_output_links_checked": len(links), "recoveries": recoveries,
        "all_remaining_pool_liability_sompi": 0, "all_remaining_reserve_sompi": reserve,
        "final_owned_unspent_sompi": final_recoveries, "fees_sompi": fees,
        "total_lifecycle_fee_sompi": sum(fees.values()),
        "two_useful_payments_sompi": [PAYMENT_VALUE, PAYMENT_VALUE],
        "shared_fee_allocation_sompi": {"Bob": quotient + remainder, "Charlie": quotient},
        "per_recipient_lifecycle_burden_sompi": burdens,
        "maximum_individual_lifecycle_burden_sompi": max(burdens.values()),
        "complete_supplied_context_native_sequence_passed": True,
        "accepted_chain_backing": False, "testnet_broadcast_or_payout": False,
        "privacy_qualified": False, "durable_archive_or_network_recovery_proved": False})
    validate_freeze(args.freeze)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--crypto", type=Path, required=True)
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--fee", type=int, default=20_000_000)
    mat = commands.add_parser("materialize")
    mat.add_argument("--crypto", type=Path, required=True)
    mat.add_argument("--native", type=Path, required=True)
    mat.add_argument("--vk", type=Path, required=True)
    mat.add_argument("--backups", type=Path, required=True)
    mat.add_argument("--output", type=Path, required=True)
    run = commands.add_parser("execute")
    run.add_argument("--crypto", type=Path, required=True)
    run.add_argument("--native", type=Path, required=True)
    run.add_argument("--prepared", type=Path, required=True)
    run.add_argument("--proof", type=Path, required=True)
    run.add_argument("--freeze", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "materialize":
        materialize(args)
    elif args.command == "execute":
        execute(args)


if __name__ == "__main__":
    main()
