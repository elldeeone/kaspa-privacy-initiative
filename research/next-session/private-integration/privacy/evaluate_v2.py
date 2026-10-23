#!/usr/bin/env python3
"""One frozen, offline candidate-C V2 byte-channel screen; never a privacy proof.

No candidate implementation imports, subprocesses, networking, RNG or proving.
The public wire and invoice directory are separate observer inputs. Synthetic
truth is accessed only for the explicit direct-note-amount diagnostic.
"""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import resource
import time


KEY_TAG = b"KPX1KEY\x00"
NOTE_TAG = b"KPX1NOT\x00"
NF_TAG = b"KPX1NF\x00\x00"
AUTHORITY_FIELDS = ("O", "incoming", "K", "nativePK")
DIRECTORY_FIELDS = ("O", "incoming", "K", "nativePK", "deliveryPK")
NOTE_FLOOR = 60_000_000
PAYOUT_FLOOR = 10_000_000
MAX = 2_870_000_000_000_000_000


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unhex(value, size=32):
    require(isinstance(value, str), "hex input must be a string")
    parsed = bytes.fromhex(value)
    require(len(parsed) == size, f"expected {size}-byte field")
    require(parsed.hex() == value, "hex must use canonical lowercase encoding")
    return parsed


def uint(value, bits):
    require(type(value) is int and 0 <= value < 2**bits, "unsigned integer range")
    return value.to_bytes(bits // 8, "little")


def derive_nf(key, domain, cm, position):
    return hmac.new(key, NF_TAG + domain + cm + uint(position, 32), hashlib.sha256).hexdigest()


def classes(entries, field):
    buckets = {}
    for index, entry in enumerate(entries):
        buckets.setdefault((entry["domain"], entry[field]), []).append(index)
    return sorted((indices for indices in buckets.values() if len(indices) > 1), key=lambda x: x[0])


def check_wire_boundary(wire):
    require(wire["schema"] == "kpx1-recipient-public-wire/v1", "public wire schema")
    require(wire["classification"] == "SYNTHETIC_OFFLINE_CANDIDATE_C", "synthetic classification")
    require(set(wire) == {"schema", "classification", "domain", "chainrecords", "NFrecords", "reveals", "limitations", "recipient_profile"}, "unexpected public wire fields")
    require(wire["recipient_profile"] == "V2_INVOICE208_NOTE_INCOMING_PER_INDEX", "V2 recipient profile must be explicit")
    require(wire["limitations"] == ["Not accepted or relation-valid history", "Reveals are not transactions", "No private proof, accepted backing, relay or chain confirmation"], "reference trace limitations must remain explicit")
    domain = unhex(wire["domain"])
    require(wire["chainrecords"] and wire["reveals"], "actual trace must contain receipt and reveal")
    positions = set()
    for record in wire["chainrecords"]:
        require(set(record) == {"position", "cm", "ciphertext"}, "outer chain record exports extra fields")
        uint(record["position"], 32)
        require(record["position"] not in positions, "duplicate chain position")
        positions.add(record["position"])
        unhex(record["cm"])
        unhex(record["ciphertext"], 264)
    for record in wire["NFrecords"]:
        require(set(record) == {"value", "next_value", "next_index"}, "NF record exports extra fields")
        unhex(record["value"])
        unhex(record["next_value"])
        uint(record["next_index"], 32)
    return domain


def evaluate(inputs):
    wire = inputs["public_wire"]
    directory = inputs["invoice_directory"]
    truth = inputs["synthetic_truth"]
    domain = check_wire_boundary(wire)
    require(directory["schema"] == "kpx2-recipient-invoice-directory/v2", "invoice directory schema")
    require(set(directory) == {"schema", "entries"}, "invoice directory top-level fields")
    entries = directory["entries"]
    require(entries, "invoice directory is empty")
    for entry in entries:
        require(set(entry) == {"owner_label", "index", "domain", "O", "incoming", "K", "nativePK", "deliveryPK", "invoice208"}, "invoice directory fields")
        require(unhex(entry["domain"]) == domain, "invoice uses a different domain")
        require(isinstance(entry["owner_label"], str), "declared directory owner label")
        uint(entry["index"], 64)
        for field in DIRECTORY_FIELDS:
            unhex(entry[field])
        expected_invoice = b"KPX2IN01" + domain + uint(entry["index"], 64) + b"".join(unhex(entry[field]) for field in DIRECTORY_FIELDS)
        require(unhex(entry["invoice208"], 208) == expected_invoice, "invoice208 byte/field mismatch")

    disclosures = []
    openings = []
    for record in wire["reveals"]:
        require(set(record) == {"opening", "payout", "stage", "ordering"}, "revealing record fields")
        require(record["ordering"] == "INDEPENDENT_REFERENCE_SNAPSHOT_NOT_SEQUENTIAL_CHAIN", "reference reveals must not imply accepted ordering")
        require(record["stage"] == "PUBLIC_WITNESS_UNBROADCAST", "reference trace must not imply broadcast")
        opening, payout = record["opening"], record["payout"]
        require(set(opening) == {"domain", "owner", "incoming", "value_sompi", "rho", "k", "native_pk", "position", "cm", "nf"}, "public opening fields")
        require(set(payout) == {"fee_sompi", "payout_sompi", "classification"}, "payout fields")
        require(payout["classification"] == "ARITHMETIC_ONLY_NO_TRANSACTION_OR_RELAY_QUOTE", "payout is reference arithmetic only")
        require(unhex(opening["domain"]) == domain, "revealing domain mismatch")
        key = unhex(opening["k"])
        key_commitment = digest(KEY_TAG + domain + key)
        require(NOTE_FLOOR <= opening["value_sompi"] <= MAX, "note value outside selected profile")
        value = uint(opening["value_sompi"], 64)
        cm = digest(NOTE_TAG + domain + unhex(opening["owner"]) + unhex(opening["incoming"]) + value + unhex(opening["rho"]) + bytes.fromhex(key_commitment) + unhex(opening["native_pk"]))
        require(cm == opening["cm"], "CM mismatch under exact candidate encoding")
        require(derive_nf(key, domain, unhex(cm), opening["position"]) == opening["nf"], "NF mismatch under exact candidate encoding")
        require(any(x["cm"] == cm and x["position"] == opening["position"] for x in wire["chainrecords"]), "reveal lacks matching public CM position")
        require(opening["value_sompi"] == payout["fee_sompi"] + payout["payout_sompi"], "whole-note V != P + fee")
        uint(payout["fee_sompi"], 64)
        uint(payout["payout_sompi"], 64)
        require(1 <= payout["fee_sompi"] <= MAX, "fee outside selected profile")
        require(PAYOUT_FLOOR <= payout["payout_sompi"] <= MAX, "payout outside selected profile")
        matches = [i for i, entry in enumerate(entries) if entry["O"] == opening["owner"] and entry["incoming"] == opening["incoming"] and entry["K"] == key_commitment and entry["nativePK"] == opening["native_pk"]]
        require(len(matches) == 1, "reveal must match exactly one issued invoice")
        disclosures.append({"cm": cm, "position": opening["position"], "matching_invoice_record_indices": matches, "incoming_directory_record_indices": [i for i, entry in enumerate(entries) if entry["incoming"] == opening["incoming"]], "note_value_disclosed_sompi": opening["value_sompi"], "source_stage": record["stage"]})
        openings.append(opening)

    # Byte-channel canaries deliberately alter one field; they are not notes.
    base = entries[0]
    equality_canaries = []
    for field in DIRECTORY_FIELDS:
        fresh = dict(base)
        for candidate in DIRECTORY_FIELDS:
            fresh[candidate] = digest(b"BYTE-CANARY-NOT-A-NOTE" + candidate.encode() + unhex(base[candidate]))
        fresh[field] = base[field]
        equality = [candidate for candidate in DIRECTORY_FIELDS if base[candidate] == fresh[candidate]]
        require(equality == [field], "equality canary did not expose exactly its edited field")
        equality_canaries.append({"repeated_field": field, "observable_equal_fields": equality, "relation_valid_note": False})

    # Consistent k/K controls: public CM set without the sibling-key assignment.
    # Sibling CM uses an independently constructed opening with the same k/K.
    # The sibling opening/key assignment is withheld from the observer's scan.
    # These are field-level hash relations, not claimed accepted/proved notes.
    selected = openings[0]
    key = unhex(selected["k"])
    other_key = hashlib.sha256(b"INDEPENDENT-KEY-CONTROL" + key).digest()
    same_kc = hashlib.sha256(KEY_TAG + domain + key).digest()
    other_kc = hashlib.sha256(KEY_TAG + domain + other_key).digest()
    prefix = NOTE_TAG + domain + unhex(selected["owner"]) + unhex(selected["incoming"]) + uint(selected["value_sompi"], 64)
    same_rho = hashlib.sha256(b"REUSED-KEY-RHO-CONTROL" + unhex(selected["rho"])).digest()
    other_rho = hashlib.sha256(b"FRESH-KEY-RHO-CONTROL" + unhex(selected["rho"])).digest()
    sibling_cm = hashlib.sha256(prefix + same_rho + same_kc + unhex(selected["native_pk"])).digest()
    other_cm = hashlib.sha256(prefix + other_rho + other_kc + unhex(selected["native_pk"])).digest()
    control_cms = [unhex(selected["cm"]), sibling_cm, other_cm]
    positions = [selected["position"], selected["position"] + 1, selected["position"] + 2]
    control_nfs = [derive_nf(key, domain, control_cms[0], positions[0]), derive_nf(key, domain, control_cms[1], positions[1]), derive_nf(other_key, domain, control_cms[2], positions[2])]
    public_nf_set = set(control_nfs)
    scan_matches = [i for i, (cm, position) in enumerate(zip(control_cms, positions)) if derive_nf(key, domain, cm, position) in public_nf_set]
    require(scan_matches == [0, 1], "disclosed-key scan canary failed")

    # Chain state is intentionally rolled back while observed bytes persist.
    retained_knowledge = {"cm": selected["cm"], "position": selected["position"], "k": selected["k"]}
    chain_spent_after_rollback = set()
    later_nf = derive_nf(key, domain, unhex(selected["cm"]), selected["position"])
    recognized_after_rollback = later_nf == derive_nf(unhex(retained_knowledge["k"]), domain, unhex(retained_knowledge["cm"]), retained_knowledge["position"])
    require(recognized_after_rollback and not chain_spent_after_rollback, "observer lost published knowledge on rollback")

    arity_shapes = [{"real_inputs": 1, "private_nf_insertions": 2}, {"real_inputs": 2, "private_nf_insertions": 2}, {"real_inputs": 1, "revealing_nf_insertions": 1}]
    require(arity_shapes[0]["private_nf_insertions"] == arity_shapes[1]["private_nf_insertions"], "private fixed-delta control")
    require(1 != arity_shapes[0]["private_nf_insertions"], "revealing branch distinction control")

    require(truth["classification"] == "PUBLIC_TEST_FIXTURES_DO_NOT_FUND_NOT_OBSERVER_INPUT", "truth fixture classification")
    historical = []
    for payment in truth["ordinary_payments"]:
        require(payment["relation"] == "SYNTHETIC_RECEIPT_NOT_PRIVATE_PROOF", "unexpected historical truth qualification")
        for opening in openings:
            if payment["position"] == opening["position"]:
                require(payment["value_sompi"] == opening["value_sompi"], "synthetic direct-payment value binding mismatch")
                historical.append({"position": opening["position"], "value_sompi": opening["value_sompi"], "logical_diagnostic": "exact historical direct-note value follows when payment=V", "real_private_payment_evidence": False})

    revealed_note_fields = [{"domain": opening["domain"], "O": opening["owner"], "incoming": opening["incoming"], "K": digest(KEY_TAG + domain + unhex(opening["k"])), "nativePK": opening["native_pk"]} for opening in openings]

    return {
        "schema": "candidate-c-incremental-privacy-result-v2",
        "classification": "OFFLINE_SYNTHETIC_BYTE_CHANNEL_DIAGNOSTIC_NOT_QUALIFICATION",
        "old_amount_workload": {"prior_numerator": 21103, "prior_denominator": 100025, "absolute_cap_percent": 20, "status": "UNQUALIFIED_UNCHANGED"},
        "actual_source_derived": {"chain_receipts": len(wire["chainrecords"]), "reveal_records": len(openings), "invoice_records": len(entries), "native_or_private_execution": False},
        "directory_equality_classes": {field: classes(entries, field) for field in DIRECTORY_FIELDS},
        "C_public_reveal_equality_classes": {field: classes(revealed_note_fields, field) for field in AUTHORITY_FIELDS},
        "fresh_note_authority_field_repetitions": {field: classes(entries, field) for field in AUTHORITY_FIELDS},
        "actual_reveal_disclosures": disclosures,
        "byte_only_equality_canaries": equality_canaries,
        "synthetic_disclosed_key_scan": {"public_cm_count": 3, "public_cm_positions": [{"cm": cm.hex(), "position": position} for cm, position in zip(control_cms, positions)], "public_nf_set": sorted(public_nf_set), "matched_public_record_indices": scan_matches, "sibling_key_assignment_given_to_observer": False, "sibling_openings_given_to_observer": False, "candidate_field_level_CM_K_NF_relation": True, "private_or_native_validity_established": False},
        "synthetic_rollback_knowledge": {"restored_unspent": True, "later_same_note_nf_recognized": recognized_after_rollback, "native_authorization_test": False},
        "conditional_arity_shapes": arity_shapes,
        "arity_verdict": "counter-delta-only cannot distinguish one versus two real private inputs; branch itself differs; actual private bytes not qualified",
        "synthetic_historical_amount_bindings": historical,
        "gates": {"reference_public_field_conformance": "PASS", "equality_and_disclosed_key_canaries": "PASS", "rollback_knowledge_control": "PASS", "C_note_incoming_equality": "FAIL_INCOMING_EQUALITY" if classes(revealed_note_fields, "incoming") else "NO_EQUALITY_OBSERVED_NOT_HIDING_PROOF", "directory_whole_descriptor_unlinkability": "FAIL_STABLE_DELIVERYPK_EQUALITY" if classes(entries, "deliveryPK") else "NO_EQUALITY_OBSERVED_NOT_HIDING_PROOF", "real_historical_private_payment_amount": "INCOMPLETE_NO_PRIVATE_PROOF", "public_hash_ADMIT_bytes": "INCOMPLETE_SOURCE_PROPOSAL_ONLY", "RFC0012_qualification": "OPEN_OLD_AMOUNT_WORKLOAD_REMAINS_FAILED"},
        "interpretation": ["V2 separates per-note incoming from stable directory-visible deliveryPK", "directory observers still link matching deliveryPK and exact invoice-to-reveal records", "absence of byte equality is not a hiding proof", "revealed reused k identifies matching NFs over the public CM position set", "published knowledge survives chain rollback", "no 32-role C/P/A privacy qualification and no old failure retuning"]
    }


def main():
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    parser = argparse.ArgumentParser()
    parser.add_argument("freeze", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    freeze = json.loads(args.freeze.read_bytes())
    require(freeze["runtime_authorized"] is True, "frozen root review authorization absent")
    require(freeze["scorer_sha256"] == digest(Path(__file__).read_bytes()), "scorer hash mismatch")
    for path, expected in freeze["source_pins"].items():
        require(digest(Path(path).read_bytes()) == expected, "source hash mismatch: " + path)
    inputs = {}
    for name, member in freeze["inputs"].items():
        raw = Path(member["path"]).read_bytes()
        require(digest(raw) == member["sha256"], "input hash mismatch: " + name)
        inputs[name] = json.loads(raw)
    require(inputs["public_wire"]["domain"] == freeze["domain"], "root-selected domain mismatch")
    result = evaluate(inputs)
    result["freeze_sha256"] = digest(args.freeze.read_bytes())
    result["scorer_sha256"] = freeze["scorer_sha256"]
    usage = resource.getrusage(resource.RUSAGE_SELF)
    result["resource_observation"] = {"wall_seconds": time.monotonic() - started, "user_cpu_seconds": usage.ru_utime, "system_cpu_seconds": usage.ru_stime, "peak_rss_kib_linux": usage.ru_maxrss, "threads": 1}
    require(not args.output.exists(), "result path already exists; frozen evaluation is one-shot")
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "sha256": digest(args.output.read_bytes()), "privacy_qualification": False}))


if __name__ == "__main__":
    main()
