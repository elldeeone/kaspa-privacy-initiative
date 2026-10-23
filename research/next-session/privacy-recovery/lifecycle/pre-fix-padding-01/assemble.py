#!/usr/bin/env python3
"""Unfunded, finite Auth528 lifecycle assembly using actual native body quotes.

Every secret and fixture here is PUBLIC_SYNTHETIC_DO_NOT_FUND. No network,
wallet, proving key, setup, prover or prior funded trial is loaded by this tool.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "poc/future-recipient/v2"))
from recipient import (Crypto, Delivery, NFEntry, Receiver, Receipt, Snapshot,
                       ZERO, h, u32, u64, recover)

CLASS = "PUBLIC_SYNTHETIC_DO_NOT_FUND"
DOMAIN = h(b"KPI/private-exit/DO-NOT-FUND/v1/2026-10-23")
STATE_MAGIC = b"KPX2ST01"
AUTH_MAGIC = b"KPX3AU01"
NOTE_TAG = b"KPX1NOT\0"
GENESIS_VALUE = 60_000_000
PAYMENT_VALUE = 1_000_000_000
PARTIAL_PAYOUT = 200_000_000
SOURCE_VALUE = 4_000_000_000
RATE = 100
STAGES = ("spend", "bob-partial", "bob-full", "charlie-terminal")


def exact(value, length):
    if not isinstance(value, str):
        raise ValueError("hex type")
    raw = bytes.fromhex(value)
    if len(raw) != length or raw.hex() != value:
        raise ValueError("canonical fixed-width hex")
    return raw


def save(path, value):
    path = Path(path)
    if path.exists():
        raise ValueError("fresh output required: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write("\n")


def load(path):
    return json.loads(Path(path).read_bytes())


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def public_seed(label):
    return h(b"KPI/PRIVATE-EXIT-LIFECYCLE/PUBLIC_SYNTHETIC_DO_NOT_FUND/", label.encode())


def state(snapshot):
    cm, nf = snapshot.roots()
    return (STATE_MAGIC + DOMAIN + cm.root + u32(len(snapshot.deliveries))
            + nf.root + u32(len(snapshot.nullifiers)))


def dump_snapshot(snapshot):
    return {"deliveries": [entry.public() for entry in snapshot.deliveries],
            "nullifiers": [{"value": entry.value.hex(), "next_value": entry.next_value.hex(),
                            "next_index": entry.next_index} for entry in snapshot.nullifiers]}


def parse_snapshot(value):
    return Snapshot([Delivery(row["position"], exact(row["cm"], 32), exact(row["ciphertext"], 264))
                     for row in value["deliveries"]],
                    [NFEntry(exact(row["value"], 32), exact(row["next_value"], 32), row["next_index"])
                     for row in value["nullifiers"]])


def insert(snapshot, value):
    """Append one physical NF record after its authenticated logical predecessor."""
    value_int = int.from_bytes(value, "little")
    if value == ZERO or any(entry.value == value for entry in snapshot.nullifiers):
        raise ValueError("spent or zero nullifier")
    _, tree = snapshot.roots()
    m = len(snapshot.nullifiers)
    index, predecessor = max(((i, entry) for i, entry in enumerate(snapshot.nullifiers)
        if int.from_bytes(entry.value, "little") < value_int),
        key=lambda pair: (int.from_bytes(pair[1].value, "little"), pair[0]))
    if predecessor.next_value != ZERO and value_int >= int.from_bytes(predecessor.next_value, "little"):
        raise ValueError("nullifier interval")
    leaf = predecessor.value + predecessor.next_value + u32(predecessor.next_index)
    witness = u32(index) + leaf + b"".join(tree.path(index))
    replacement = NFEntry(predecessor.value, value, m)
    intermediate = tree.with_leaf(index, replacement.leaf())
    witness += b"".join(intermediate.path(m))
    entries = list(snapshot.nullifiers)
    entries[index] = replacement
    entries.append(NFEntry(value, predecessor.next_value, predecessor.next_index))
    if len(witness) != 1160:
        raise ValueError("NF witness width")
    return Snapshot(list(snapshot.deliveries), entries), witness


def insert_spent_negative(snapshot, value):
    """Rejected-only fixture: authenticate the CURRENT equal occupied NF leaf.

    This deliberately violates predecessor<NF. Never pass its successor as an
    accepted state or a positive ledger. Both Merkle paths remain authentic.
    """
    matches = [(index, entry) for index, entry in enumerate(snapshot.nullifiers) if entry.value == value]
    if value == ZERO or len(matches) != 1:
        raise ValueError("negative requires one current occupied NF")
    index, predecessor = matches[0]
    _, tree = snapshot.roots()
    m = len(snapshot.nullifiers)
    witness = (u32(index) + predecessor.value + predecessor.next_value + u32(predecessor.next_index)
               + b"".join(tree.path(index)))
    replacement = NFEntry(predecessor.value, value, m)
    intermediate = tree.with_leaf(index, replacement.leaf())
    witness += b"".join(intermediate.path(m))
    entries = list(snapshot.nullifiers)
    entries[index] = replacement
    entries.append(NFEntry(value, predecessor.next_value, predecessor.next_index))
    if len(witness) != 1160:
        raise ValueError("negative NF witness width")
    return Snapshot(list(snapshot.deliveries), entries), witness


def make_receipt(wallet, index, value, position, crypto, rho):
    invoice = wallet.invoice(index)
    note = Receipt.for_invoice(invoice, value, rho)
    ciphertext = crypto.seal(invoice.delivery_pk, note.encode())
    if len(ciphertext) != 264:
        raise ValueError("ciphertext width")
    return note, Delivery(position, note.commitment(), ciphertext)


def dummy_output(position, rho, ciphertext):
    raw = bytes(72) + rho + bytes(64)
    if len(raw) != 168 or len(ciphertext) != 264:
        raise ValueError("dummy output widths")
    return raw, Delivery(position, h(NOTE_TAG, DOMAIN, raw), ciphertext)


def action(snapshot, input_specs, outputs, previous, reserve, fee, payout, destination,
           dummy_material, *, expected_spent_rejection=False):
    """Construct actual sequential public updates and one complete fixed-shape fixture."""
    if len(input_specs) != 2 or len(previous) != 36 or len(destination) != 36:
        raise ValueError("fixed action dimensions")
    if payout == 0 and destination != bytes(36):
        raise ValueError("P0 destination")
    if payout and (payout < 10_000_000 or destination[:3] != b"\0\0\x20" or destination[-1:] != b"\xac"):
        raise ValueError("canonical payout")
    remaining = reserve - payout - fee
    terminal = remaining == 0
    if remaining < 0 or 0 < remaining < GENESIS_VALUE or terminal and payout == 0:
        raise ValueError("remaining reserve")
    old_cm, _ = snapshot.roots()
    inputs, nfs, positions = [], [], []
    for slot, specification in enumerate(input_specs):
        if specification is None:
            key, seed = dummy_material[slot]
            nf = hmac.digest(key, b"KPX2DMY\0" + DOMAIN + seed + bytes([slot]), "sha256")
            inputs.append({"real": False, "note_hex168": bytes(168).hex(),
                "s_hex32": ZERO.hex(), "k_hex32": ZERO.hex(), "position": 0,
                "cm_path_hex": [ZERO.hex()] * 16, "dummy_key_hex32": key.hex(),
                "dummy_seed_hex32": seed.hex()})
        else:
            position, wallet, invoice_index = specification
            note = wallet.open(snapshot.deliveries[position].ciphertext)
            if note.index != invoice_index or note.commitment() != snapshot.deliveries[position].cm:
                raise ValueError("input receipt/position")
            if position in positions:
                raise ValueError("duplicate real position")
            positions.append(position)
            keys = wallet.keys(invoice_index)
            nf = wallet.nullifier(note, position)
            if payout and destination[3:35] == note.native_pk:
                raise ValueError("consumed emergency key reused as private payout key")
            inputs.append({"real": True, "note_hex168": note.note_bytes().hex(),
                "s_hex32": keys.owner_secret.hex(), "k_hex32": keys.nf_secret.hex(),
                "position": position, "cm_path_hex": [value.hex() for value in old_cm.path(position)],
                "dummy_key_hex32": ZERO.hex(), "dummy_seed_hex32": ZERO.hex()})
        nfs.append(nf)
    if not positions or len(set(nfs)) != 2 or ZERO in nfs:
        raise ValueError("real input / distinct NF requirements")
    current = Snapshot(list(snapshot.deliveries), list(snapshot.nullifiers))
    public_witness = b""
    for slot, nf in enumerate(nfs):
        if expected_spent_rejection and slot == 0:
            current, witness = insert_spent_negative(current, nf)
        else:
            current, witness = insert(current, nf)
        public_witness += witness
    if terminal:
        if outputs:
            raise ValueError("terminal has private output")
        output_notes = [bytes(168), bytes(168)]
        commitments = [ZERO, ZERO]
        ciphertexts = bytes(528)
        public_witness += bytes(1024)
    else:
        if len(outputs) != 2:
            raise ValueError("continuing output count")
        output_notes, commitments, ciphers = [], [], []
        for raw_note, delivery in outputs:
            tree, _ = current.roots()
            if delivery.position != len(current.deliveries):
                raise ValueError("CM append position")
            public_witness += b"".join(tree.path(delivery.position))
            current.deliveries.append(delivery)
            output_notes.append(raw_note)
            commitments.append(delivery.cm)
            ciphers.append(delivery.ciphertext)
        if commitments[0] == commitments[1]:
            raise ValueError("duplicate output CM")
        ciphertexts = b"".join(ciphers)
    input_sum = sum(int.from_bytes(bytes.fromhex(row["note_hex168"])[64:72], "little") for row in inputs)
    output_sum = sum(int.from_bytes(raw[64:72], "little") for raw in output_notes)
    if input_sum > reserve or input_sum != output_sum + payout + fee:
        raise ValueError("exact action conservation")
    if payout == 0 and not output_sum:
        raise ValueError("P0 needs positive private output")
    auth = (AUTH_MAGIC + DOMAIN + previous + state(snapshot) + u64(reserve) + u64(fee)
            + b"".join(nfs) + b"".join(commitments) + h(ciphertexts) + state(current)
            + u64(remaining) + u64(payout) + destination)
    if len(auth) != 528 or len(public_witness) != 3344 or len(ciphertexts) != 528:
        raise ValueError("Auth528/cipher/witness widths")
    fixture = {"classification": CLASS, "auth_hex528": auth.hex(), "inputs": inputs,
               "outputs": [{"note_hex168": raw.hex()} for raw in output_notes]}
    vector = {"auth_hex": auth.hex(), "cipher_hex": ciphertexts.hex(),
              "public_witness_hex": public_witness.hex(), "proof_hex": bytes(128).hex(),
              "vk_hex": bytes(328).hex()}
    return current, fixture, vector


def native_call(binary, mode, vector, directory):
    directory = Path(directory)
    if directory.exists():
        raise ValueError("fresh native operation directory")
    save(directory.with_suffix(".vector.json"), vector)
    proc = subprocess.run([str(binary), mode, str(directory.with_suffix(".vector.json")), str(directory)],
                          text=True, capture_output=True, check=False)
    directory.mkdir(parents=True, exist_ok=True)
    save(directory / "command-result.json", {"returncode": proc.returncode, "mode": mode,
        "stdout": proc.stdout, "stderr": proc.stderr, "binary_sha256": digest(binary)})
    if proc.returncode:
        raise ValueError("native operation failed: " + str(directory))
    metrics = load(directory / "metrics.json")
    kind = mode.rsplit("-", 1)[0]
    if kind == "private":
        fee = int.from_bytes(bytes.fromhex(vector["auth_hex"])[196:204], "little")
    elif kind == "admit":
        fee = int.from_bytes(bytes.fromhex(vector["payload_hex"])[1160:1168], "little")
    elif kind == "reveal":
        fee = int.from_bytes(bytes.fromhex(vector["payload_hex"])[2013:2021], "little")
    else:
        fee = vector["fee_sompi"]
    if metrics["actual_fee_sompi"] != fee:
        raise ValueError("actual fee differs from authorization")
    if mode.endswith("-run"):
        validation = load(directory / "native-validation.json")
        if (validation["Full"].get("accepted") is not True
                or validation["Full"]["fee_sompi"] != fee
                or validation.get("all_input_engines_accepted") is not True):
            raise ValueError("native Full/engine/fee mismatch")
    return metrics


def quote(binary, kind, builder, output, rate=RATE):
    output.mkdir(parents=True, exist_ok=True)
    fee, attempts = 1, []
    for attempt in range(256):
        vector = builder(fee)
        directory = output / f"quote-{kind}-{attempt:03d}"
        metrics = native_call(binary, kind + "-freeze", vector, directory)
        required = rate * metrics["mining_mass"]
        attempts.append({"fee_sompi": fee, "required_sompi": required,
                         "mining_mass": metrics["mining_mass"], "directory": directory.name})
        if fee >= required:
            save(output / "fee-fixedpoint.json", {"rate": rate, "fee_sompi": fee,
                "attempts": attempts, "native_executed": False})
            return fee, vector, directory
        fee = max(fee, required)
    raise ValueError("fee iteration incomplete; all attempts retained")


def outpoint(directory, index=0):
    return exact((Path(directory) / "txid-raw.hex").read_text().strip(), 32) + u32(index)


def verify_link(previous, following, output_index=0, input_index=0):
    prior, body = load(Path(previous) / "transaction.json"), load(Path(following) / "transaction.json")
    entry = load(Path(following) / "supplied-context.json")[input_index]
    output = prior["outputs"][output_index]
    expected = {"transactionId": prior["id"], "index": output_index}
    if (body["inputs"][input_index]["previousOutpoint"] != expected
            or entry["amount_sompi"] != output["value"]
            or entry["script_public_key"] != output["scriptPublicKey"]):
        raise ValueError("actual prior-output link mismatch")
    return {"outpoint": expected, "amount_sompi": output["value"],
            "script_public_key": output["scriptPublicKey"], "verified": True}


def wallets(crypto):
    return {label: Receiver(public_seed(label), DOMAIN, crypto) for label in ("Alice", "Bob", "Charlie")}


def entropy():
    return {"rho": [secrets.token_bytes(32).hex() for _ in range(8)],
            "dummy_inputs": [[secrets.token_bytes(32).hex(), secrets.token_bytes(32).hex()] for _ in range(8)],
            "dummy_ciphertexts": [secrets.token_bytes(264).hex() for _ in range(3)]}


def prepare_shape(args):
    if args.output.exists():
        raise ValueError("fresh shape directory")
    args.output.mkdir(parents=True)
    randomness = entropy()
    save(args.output / "PUBLIC-SYNTHETIC-entropy.json", randomness)
    save(args.output / "PUBLIC-SYNTHETIC-backups.json", {"classification": CLASS,
        "domain_hex32": DOMAIN.hex(), "created_before_any_invoice": True,
        "seeds": {label: public_seed(label).hex() for label in ("Alice", "Bob", "Charlie")}})
    ws = wallets(Crypto(args.crypto))
    fee = 20_000_000
    specs = [("Alice", 0, GENESIS_VALUE), ("Alice", 1, 2 * PAYMENT_VALUE + fee - GENESIS_VALUE),
             ("Bob", 0, PAYMENT_VALUE), ("Charlie", 0, PAYMENT_VALUE)]
    notes, records = [], []
    for position, (owner, index, value) in enumerate(specs):
        note, delivery = make_receipt(ws[owner], index, value, position, ws[owner].crypto,
                                      exact(randomness["rho"][position], 32))
        notes.append(note)
        records.append(delivery)
    before = Snapshot(records[:2], [NFEntry(ZERO, ZERO, 0)])
    _, fixture, _ = action(before, [(0, ws["Alice"], 0), (1, ws["Alice"], 1)],
        [(notes[2].note_bytes(), records[2]), (notes[3].note_bytes(), records[3])], bytes(36),
        2 * PAYMENT_VALUE + fee, fee, 0, bytes(36),
        [(exact(row[0], 32), exact(row[1], 32)) for row in randomness["dummy_inputs"][:2]])
    save(args.output / "shape-fixture.json", fixture)
    save(args.output / "PLAN.json", {"classification": CLASS, "domain_hex32": DOMAIN.hex(),
        "setup_or_proof_generated_here": False, "native_or_chain_execution_here": False,
        "stages": ["funding-prep", "founding", "admit", *STAGES],
        "source_sompi": SOURCE_VALUE, "two_useful_payment_values_sompi": [PAYMENT_VALUE] * 2,
        "partial_payout_sompi": PARTIAL_PAYOUT,
        "fresh_setup_owner": "private_exit_proof", "all_fixture_secrets_public": True,
        "not_claimed": ["privacy qualification", "accepted chain backing", "testnet payout", "security audit"]})


def admit_payload(genesis, note, record, before, after, fee, change=0):
    tree, _ = before.roots()
    payload = (b"KPX2AD01" + DOMAIN + note.note_bytes() + record.cm + record.ciphertext
        + h(record.ciphertext) + b"".join(tree.path(len(before.deliveries))) + state(after)
        + u64(fee) + u64(change) + genesis.note_bytes())
    if len(payload) != 1344:
        raise ValueError("ADMIT width")
    return payload


def materialize(args):
    if args.output.exists():
        raise ValueError("fresh materialization directory")
    args.output.mkdir(parents=True)
    vk = args.vk.read_bytes()
    if len(vk) != 328:
        raise ValueError("selected new VK328 required")
    randomness = load(args.shape / "PUBLIC-SYNTHETIC-entropy.json")
    backups = load(args.shape / "PUBLIC-SYNTHETIC-backups.json")
    if (backups["classification"] != CLASS or backups["domain_hex32"] != DOMAIN.hex()
            or backups["created_before_any_invoice"] is not True
            or backups["seeds"] != {label: public_seed(label).hex() for label in ("Alice", "Bob", "Charlie")}):
        raise ValueError("source/backup/domain mismatch")
    save(args.output / "PUBLIC-SYNTHETIC-backups.json", backups)
    save(args.output / "PUBLIC-SYNTHETIC-entropy.json", randomness)
    crypto = Crypto(args.crypto)
    ws = wallets(crypto)
    rho = [exact(value, 32) for value in randomness["rho"]]
    dummy_inputs = [(exact(key, 32), exact(seed, 32)) for key, seed in randomness["dummy_inputs"]]
    dummy_ciphers = [exact(value, 264) for value in randomness["dummy_ciphertexts"]]
    spend_cache = {}

    def prepare_spend(fee):
        specs = [("Alice", 0, GENESIS_VALUE),
                 ("Alice", 1, 2 * PAYMENT_VALUE + fee - GENESIS_VALUE),
                 ("Bob", 0, PAYMENT_VALUE), ("Charlie", 0, PAYMENT_VALUE)]
        notes, records = [], []
        for position, (owner, index, value) in enumerate(specs):
            note, record = make_receipt(ws[owner], index, value, position, crypto, rho[position])
            notes.append(note)
            records.append(record)
        before = Snapshot(records[:2], [NFEntry(ZERO, ZERO, 0)])
        after, fixture, vector = action(before,
            [(0, ws["Alice"], 0), (1, ws["Alice"], 1)],
            [(notes[2].note_bytes(), records[2]), (notes[3].note_bytes(), records[3])],
            bytes(36), 2 * PAYMENT_VALUE + fee, fee, 0, bytes(36), dummy_inputs[:2])
        vector["vk_hex"] = vk.hex()
        spend_cache[fee] = notes, records, before, after, fixture, vector
        return vector

    spend_fee, _, _ = quote(args.native, "private", prepare_spend, args.output / "quotes/spend")
    notes, records, before, _, _, _ = spend_cache[spend_fee]
    genesis = Snapshot(records[:1], [NFEntry(ZERO, ZERO, 0)])
    reserve = 2 * PAYMENT_VALUE + spend_fee
    founding_funding = 120_000_000

    def make_founding(fee):
        return {"note_hex": notes[0].note_bytes().hex(), "cipher_hex": records[0].ciphertext.hex(),
            "funding_previous_txid_raw_hex": public_seed("FoundingInputOutpoint").hex(),
            "funding_previous_index": 0, "funding_amount_sompi": founding_funding,
            "funding_secret_hex": public_seed("FoundingFundingSecret").hex(),
            "fee_sompi": fee, "change_sompi": founding_funding - GENESIS_VALUE - fee,
            "vk_hex": vk.hex()}

    founding_fee, founding_vector, founding_quote = quote(args.native, "founding", make_founding,
                                                         args.output / "quotes/founding")

    def make_admit(fee):
        return {"state_hex": state(genesis).hex(),
            "previous_txid_raw_hex": outpoint(founding_quote)[:32].hex(), "previous_index": 0,
            "reserve_sompi": GENESIS_VALUE,
            "payload_hex": admit_payload(notes[0], notes[1], records[1], genesis, before, fee).hex(),
            "funding_previous_txid_raw_hex": public_seed("AdmissionInputOutpoint").hex(),
            "funding_previous_index": 0, "funding_amount_sompi": notes[1].value_sompi + fee,
            "funding_secret_hex": public_seed("AdmissionFundingSecret").hex(), "vk_hex": vk.hex()}

    admit_fee, admit_vector, _ = quote(args.native, "admit", make_admit, args.output / "quotes/admit")
    admission_funding = notes[1].value_sompi + admit_fee

    def make_prep(fee):
        return {"source_previous_txid_raw_hex": public_seed("OrdinarySourceOutpoint").hex(),
            "source_previous_index": 0, "source_amount_sompi": SOURCE_VALUE,
            "source_secret_hex": public_seed("OrdinarySourceSecret").hex(),
            "outputs": [{"value_sompi": founding_funding,
                         "xonly_public_key_hex": crypto.xonly(public_seed("FoundingFundingSecret")).hex()},
                        {"value_sompi": admission_funding,
                         "xonly_public_key_hex": crypto.xonly(public_seed("AdmissionFundingSecret")).hex()}],
            "fee_sompi": fee, "source_change_sompi": SOURCE_VALUE - founding_funding - admission_funding - fee}

    prep_fee, prep_vector, prep_quote = quote(args.native, "funding-prep", make_prep,
                                             args.output / "quotes/funding-prep")
    founding_vector["funding_previous_txid_raw_hex"] = outpoint(prep_quote)[:32].hex()
    founding_directory = args.output / "founding-final"
    native_call(args.native, "founding-freeze", founding_vector, founding_directory)
    admit_vector["previous_txid_raw_hex"] = outpoint(founding_directory)[:32].hex()
    admit_vector["funding_previous_txid_raw_hex"] = outpoint(prep_quote)[:32].hex()
    admit_vector["funding_previous_index"] = 1
    admit_directory = args.output / "admit-final"
    native_call(args.native, "admit-freeze", admit_vector, admit_directory)
    after, fixture, vector = action(before,
        [(0, ws["Alice"], 0), (1, ws["Alice"], 1)],
        [(notes[2].note_bytes(), records[2]), (notes[3].note_bytes(), records[3])],
        outpoint(admit_directory), reserve, spend_fee, 0, bytes(36), dummy_inputs[:2])
    vector["vk_hex"] = vk.hex()
    spend_directory = args.output / "spend-final-unsigned"
    spend_metrics = native_call(args.native, "private-freeze", vector, spend_directory)
    if spend_fee < RATE * spend_metrics["mining_mass"]:
        raise ValueError("actual P0 fee differs from quoted complete body")
    save(args.output / "spend-fixture.json", fixture)
    save(args.output / "spend-native-vector.json", vector)
    snapshots = {"genesis": dump_snapshot(genesis), "before-spend": dump_snapshot(before),
                 "after-spend": dump_snapshot(after)}
    fees = {"funding-prep": prep_fee, "founding": founding_fee, "admit": admit_fee, "spend": spend_fee}
    destinations = {label: b"\0\0\x20" + crypto.xonly(public_seed(label + "PayoutSecret")) + b"\xac"
                    for label in ("bob-partial", "bob-full", "charlie-terminal")}
    current, previous, reserve = after, spend_directory, 2 * PAYMENT_VALUE
    stage_entries = [{"stage": "spend", "fixture_path": str((args.output / "spend-fixture.json").resolve()),
        "fixture_sha256": digest(args.output / "spend-fixture.json"),
        "native_vector_path": str((args.output / "spend-native-vector.json").resolve()),
        "body_directory": str(spend_directory.resolve()), "reserve_after_sompi": reserve, "payout_sompi": 0}]
    partial_cache = {}

    def make_partial(fee):
        change_value = PAYMENT_VALUE - PARTIAL_PAYOUT - fee
        note, record = make_receipt(ws["Bob"], 1, change_value, len(current.deliveries), crypto, rho[4])
        raw_dummy, dummy = dummy_output(len(current.deliveries) + 1, rho[5], dummy_ciphers[0])
        next_snapshot, f, v = action(current, [(2, ws["Bob"], 0), None],
            [(note.note_bytes(), record), (raw_dummy, dummy)], outpoint(previous), reserve,
            fee, PARTIAL_PAYOUT, destinations["bob-partial"], dummy_inputs[2:4])
        v["vk_hex"] = vk.hex()
        partial_cache[fee] = next_snapshot, f, v, note
        return v

    fee, _, quoted = quote(args.native, "private", make_partial, args.output / "quotes/bob-partial")
    current, fixture, vector, change_note = partial_cache[fee]
    directory = args.output / "bob-partial-final-unsigned"
    native_call(args.native, "private-freeze", vector, directory)
    save(args.output / "bob-partial-fixture.json", fixture)
    save(args.output / "bob-partial-native-vector.json", vector)
    reserve -= PARTIAL_PAYOUT + fee
    fees["bob-partial"] = fee
    snapshots["after-bob-partial"] = dump_snapshot(current)
    stage_entries.append({"stage": "bob-partial", "fixture_path": str((args.output / "bob-partial-fixture.json").resolve()),
        "fixture_sha256": digest(args.output / "bob-partial-fixture.json"),
        "native_vector_path": str((args.output / "bob-partial-native-vector.json").resolve()),
        "body_directory": str(directory.resolve()), "reserve_after_sompi": reserve, "payout_sompi": PARTIAL_PAYOUT})
    previous = directory
    full_cache = {}

    def make_full(fee):
        outputs = [dummy_output(len(current.deliveries) + slot, rho[6 + slot], dummy_ciphers[1 + slot])
                   for slot in range(2)]
        next_snapshot, f, v = action(current, [(4, ws["Bob"], 1), None], outputs,
            outpoint(previous), reserve, fee, change_note.value_sompi - fee,
            destinations["bob-full"], dummy_inputs[4:6])
        v["vk_hex"] = vk.hex()
        full_cache[fee] = next_snapshot, f, v
        return v

    fee, _, _ = quote(args.native, "private", make_full, args.output / "quotes/bob-full")
    current, fixture, vector = full_cache[fee]
    directory = args.output / "bob-full-final-unsigned"
    native_call(args.native, "private-freeze", vector, directory)
    save(args.output / "bob-full-fixture.json", fixture)
    save(args.output / "bob-full-native-vector.json", vector)
    payout = change_note.value_sompi - fee
    reserve -= payout + fee
    if reserve != PAYMENT_VALUE:
        raise ValueError("Bob full exit omitted or consumed another liability")
    fees["bob-full"] = fee
    snapshots["after-bob-full"] = dump_snapshot(current)
    stage_entries.append({"stage": "bob-full", "fixture_path": str((args.output / "bob-full-fixture.json").resolve()),
        "fixture_sha256": digest(args.output / "bob-full-fixture.json"),
        "native_vector_path": str((args.output / "bob-full-native-vector.json").resolve()),
        "body_directory": str(directory.resolve()), "reserve_after_sompi": reserve, "payout_sompi": payout})
    previous = directory
    terminal_cache = {}

    def make_terminal(fee):
        next_snapshot, f, v = action(current, [(3, ws["Charlie"], 0), None], [],
            outpoint(previous), reserve, fee, PAYMENT_VALUE - fee,
            destinations["charlie-terminal"], dummy_inputs[6:8])
        v["vk_hex"] = vk.hex()
        terminal_cache[fee] = next_snapshot, f, v
        return v

    fee, _, _ = quote(args.native, "private", make_terminal, args.output / "quotes/charlie-terminal")
    terminal, fixture, vector = terminal_cache[fee]
    directory = args.output / "charlie-terminal-final-unsigned"
    native_call(args.native, "private-freeze", vector, directory)
    save(args.output / "charlie-terminal-fixture.json", fixture)
    save(args.output / "charlie-terminal-native-vector.json", vector)
    fees["charlie-terminal"] = fee
    snapshots["terminal"] = dump_snapshot(terminal)
    stage_entries.append({"stage": "charlie-terminal", "fixture_path": str((args.output / "charlie-terminal-fixture.json").resolve()),
        "fixture_sha256": digest(args.output / "charlie-terminal-fixture.json"),
        "native_vector_path": str((args.output / "charlie-terminal-native-vector.json").resolve()),
        "body_directory": str(directory.resolve()), "reserve_after_sompi": 0,
        "payout_sompi": PAYMENT_VALUE - fee})
    for label, value in (("funding-prep", prep_vector), ("founding", founding_vector), ("admit", admit_vector)):
        save(args.output / (label + "-native-vector.json"), value)
    save(args.output / "records.json", snapshots)
    save(args.output / "MATERIALIZED.json", {"classification": CLASS, "domain_hex32": DOMAIN.hex(),
        "vk_sha256": hashlib.sha256(vk).hexdigest(), "proofs_generated_here": False,
        "native_VM_or_Full_executed_here": False, "stages": stage_entries, "fees_sompi": fees,
        "source_sompi": SOURCE_VALUE, "funding_prep_quote_directory": str(prep_quote.resolve()),
        "founding_body_directory": str(founding_directory.resolve()),
        "admit_body_directory": str(admit_directory.resolve()),
        "final_cm_count": len(terminal.deliveries), "final_nf_count": len(terminal.nullifiers),
        "final_state_hex112": state(terminal).hex(),
        "positive_liabilities_after_spend_sompi": 2 * PAYMENT_VALUE,
        "final_positive_liability_sompi": 0, "final_reserve_sompi": 0,
        "final_owner_recognized_unspent_sompi": {label: recover(wallet, terminal.pin(DOMAIN), terminal).all_owned_unspent_sompi
                                                 for label, wallet in ws.items()},
        "privacy_qualified": False, "accepted_chain_backing": False, "fee_qualified": False})


def reveal_vector(wallet, position, snapshot, previous, reserve, fee, vk, *, spent_negative=False):
    note = wallet.open(snapshot.deliveries[position].ciphertext)
    if note.commitment() != snapshot.deliveries[position].cm:
        raise ValueError("reveal note/position mismatch")
    nf = wallet.nullifier(note, position)
    following, witness = (insert_spent_negative if spent_negative else insert)(snapshot, nf)
    index = int.from_bytes(witness[:4], "little")
    _, tree = snapshot.roots()
    pred_value = witness[4:36]
    intermediate = tree.with_leaf(index, NFEntry(pred_value, nf, len(snapshot.nullifiers)).leaf())
    cm, _ = snapshot.roots()
    payload = (b"KPX2RV01\x01" + note.owner + note.incoming + u64(note.value_sompi) + note.rho
        + wallet.keys(note.index).nf_secret + note.native_pk + u32(position) + note.key_commitment
        + note.commitment() + b"".join(cm.path(position)) + witness + nf + intermediate.root
        + following.roots()[1].root + u64(fee) + u64(note.value_sompi - fee))
    if len(payload) != 2029:
        raise ValueError("reveal payload width")
    return following, {"state_hex": state(snapshot).hex(),
        "previous_txid_raw_hex": previous[:32].hex(), "previous_index": int.from_bytes(previous[32:], "little"),
        "reserve_sompi": reserve, "payload_hex": payload.hex(),
        "native_secret_hex": wallet.keys(note.index).native_secret.hex(), "vk_hex": vk.hex()}


def prepare_races(args):
    if args.output.exists():
        raise ValueError("fresh control preparation output required")
    args.output.mkdir(parents=True)
    materialized = load(args.prepared / "MATERIALIZED.json")
    snapshots = load(args.prepared / "records.json")
    vk = exact(load(args.prepared / "spend-native-vector.json")["vk_hex"], 328)
    if hashlib.sha256(vk).hexdigest() != materialized["vk_sha256"]:
        raise ValueError("new VK identity")
    crypto = Crypto(args.crypto)
    ws = wallets(crypto)
    after_spend = parse_snapshot(snapshots["after-spend"])
    after_partial = parse_snapshot(snapshots["after-bob-partial"])
    p0_directory = Path(materialized["stages"][0]["body_directory"])
    partial_directory = Path(materialized["stages"][1]["body_directory"])
    partial_reserve = materialized["stages"][1]["reserve_after_sompi"]
    reveal_cache = {}

    def make_valid_reveal(fee):
        following, vector = reveal_vector(ws["Bob"], 2, after_spend, outpoint(p0_directory),
                                          2 * PAYMENT_VALUE, fee, vk)
        reveal_cache[fee] = following, vector
        return vector

    fee, _, _ = quote(args.native, "reveal", make_valid_reveal, args.output / "quotes/reveal-first")
    after_reveal, reveal = reveal_cache[fee]
    reveal_directory = args.output / "reveal-first-positive"
    native_call(args.native, "reveal-freeze", reveal, reveal_directory)
    save(args.output / "reveal-first-native-vector.json", reveal)

    def make_losing_reveal(fee):
        return reveal_vector(ws["Bob"], 2, after_partial, outpoint(partial_directory),
                             partial_reserve, fee, vk, spent_negative=True)[1]

    _, losing_reveal, _ = quote(args.native, "reveal", make_losing_reveal,
                                args.output / "quotes/reveal-after-private")
    native_call(args.native, "reveal-freeze", losing_reveal, args.output / "reveal-after-private-negative")
    save(args.output / "reveal-after-private-native-vector.json", losing_reveal)
    randomness = load(args.prepared / "PUBLIC-SYNTHETIC-entropy.json")
    # Separate branch dummy randomness; never reuse a zero or mainline dummy key.
    seed_material = exact(randomness["dummy_inputs"][3][0], 32)
    dummy = [(h(b"UNFUNDED_RACE_KEY", seed_material, bytes([i])),
              h(b"UNFUNDED_RACE_SEED", seed_material, bytes([i]))) for i in range(2)]
    rho = h(b"UNFUNDED_RACE_CHANGE_RHO", seed_material)
    dummy_rho = h(b"UNFUNDED_RACE_PAD_RHO", seed_material)
    cipher = bytes.fromhex(randomness["dummy_ciphertexts"][0])
    destination = b"\0\0\x20" + crypto.xonly(public_seed("RacePayoutSecret")) + b"\xac"
    race_cache = {}

    def make_losing_private(fee):
        note, delivery = make_receipt(ws["Bob"], 2, PAYMENT_VALUE - PARTIAL_PAYOUT - fee,
                                      len(after_reveal.deliveries), crypto, rho)
        dummy_note, dummy_delivery = dummy_output(len(after_reveal.deliveries) + 1, dummy_rho, cipher)
        bad_after, fixture, vector = action(after_reveal, [(2, ws["Bob"], 0), None],
            [(note.note_bytes(), delivery), (dummy_note, dummy_delivery)], outpoint(reveal_directory),
            PAYMENT_VALUE, fee, PARTIAL_PAYOUT, destination, dummy, expected_spent_rejection=True)
        vector["vk_hex"] = vk.hex()
        race_cache[fee] = fixture, vector
        return vector

    _, _, _ = quote(args.native, "private", make_losing_private, args.output / "quotes/private-after-reveal")
    chosen = load(args.output / "quotes/private-after-reveal/fee-fixedpoint.json")["fee_sompi"]
    fixture, vector = race_cache[chosen]
    native_call(args.native, "private-freeze", vector, args.output / "private-after-reveal-negative")
    save(args.output / "race-after-reveal-fixture.json", fixture)
    save(args.output / "race-after-reveal-native-vector.json", vector)
    save(args.output / "CONTROL-PLAN.json", {"classification": CLASS,
        "separate_alternatives_not_extra_mainline_payouts": True,
        "accepted_chain_backing": False, "native_VM_or_Full_executed_here": False,
        "cases": [{"id": "reveal-first", "expected": "ACCEPT", "genuine_private_proof": False},
                  {"id": "reveal-after-private", "expected": "SignatureInvalid(VerifyError)",
                   "original_signer_and_current_cm_nf_paths": True},
                  {"id": "private-after-reveal", "expected": "SignatureInvalid(VerifyError)",
                   "needs_additional_genuine_rebound_private_proof": True,
                   "fixture_sha256": digest(args.output / "race-after-reveal-fixture.json"),
                   "current_occupied_original_nf": True,
                   "expected_private_relation_satisfied": True}],
        "partial_private_positive_is_mainline": True,
        "notes": ["Strict predecessor<NF fails on the authentic equal current leaf.",
                  "Bad successor roots are rejected-only fixtures, never accepted snapshots."]})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("shape")
    p.add_argument("--crypto", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("races")
    p.add_argument("--crypto", type=Path, required=True)
    p.add_argument("--native", type=Path, required=True)
    p.add_argument("--prepared", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p = sub.add_parser("materialize")
    p.add_argument("--crypto", type=Path, required=True)
    p.add_argument("--shape", type=Path, required=True)
    p.add_argument("--native", type=Path, required=True)
    p.add_argument("--vk", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "shape":
        prepare_shape(args)
    elif args.command == "materialize":
        materialize(args)
    elif args.command == "races":
        prepare_races(args)
    print(json.dumps({"command": args.command, "output": str(args.output), "classification": CLASS}))


if __name__ == "__main__":
    main()
