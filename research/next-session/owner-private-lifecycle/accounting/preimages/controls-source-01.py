"""Focused malformed-public-evidence controls for the independent auditor.

The caller supplies the selected real GN3 prefix bytes. Each changed fixture is
explicitly synthetic: refreshing its file pins tests arithmetic/receipt joins
after transport authentication; no changed bytes acquire chain authority.
"""
import copy
import hashlib
import json


def run(audit_module, originals, original_pins):
    def encode(value):
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def digest(raw):
        return hashlib.sha256(raw).hexdigest()

    def mutation(name, change, expected):
        values = {key: audit_module["strict_json"](raw) for key, raw in originals.items()
                  if key != "native-tail"}
        change(values)
        raws = {key: encode(value) for key, value in values.items()}
        raws["native-tail"] = originals["native-tail"]
        # Keep unchanged original bytes, then make the synthetic transport and
        # history pins internally consistent. The financial checks must still
        # reject each named invalid observation.
        for key in values:
            if values[key] == audit_module["strict_json"](originals[key]):
                raws[key] = originals[key]
        values["replay"]["fetch_sha256"] = digest(raws["fetch"])
        values["replay"]["history_sha256"] = digest(raws["history"])
        raws["replay"] = encode(values["replay"])
        pins = {key: digest(raw) for key, raw in raws.items()}
        try:
            audit_module["audit"](raws, pins)
        except ValueError as error:
            if str(error) != expected:
                raise AssertionError(f"{name}: unexpected rejection {error}") from error
            return {"control": name, "rejected": True, "reason": str(error)}
        raise AssertionError(f"{name}: invalid synthetic evidence accepted")

    def set_path(key, path, value):
        def change(data):
            selected = data[key]
            for part in path[:-1]:
                selected = selected[part]
            selected[path[-1]] = value
        return change

    cases = [
        ("canonical-decimal-rejects-bool", "fetch", ["transactions", 0, "accepted_input_contexts", 0,
            "amount_sompi"], True, "canonical-network-decimal"),
        ("canonical-decimal-rejects-leading-zero", "fetch", ["transactions", 0,
            "accepted_input_contexts", 0, "amount_sompi"], "03203807461", "canonical-network-decimal"),
        ("wrong-populated-context-point", "fetch", ["transactions", 0, "accepted_input_contexts", 0,
            "outpoint", "index"], 1, "context-outpoint"),
        ("one-sompi-inflated-source", "fetch", ["transactions", 0, "accepted_input_contexts", 0,
            "amount_sompi"], "3203807462", "accepted-body-native-receipt-fee-join"),
        ("native-replay-false", "replay", ["all_native_Full_and_input_engines_executed"], False,
            "replay-receipt-input-join"),
        ("wrong-observed-fee", "replay", ["transactions", 0, "metrics", "actual_fee_sompi"],
            668901, "accepted-body-native-receipt-fee-join"),
        ("bool-is-not-integer-fee", "replay", ["transactions", 0, "metrics", "actual_fee_sompi"],
            True, "integer-sompi-range"),
        ("insufficient-actual-confirmations", "fetch", ["transactions", 0, "confirmation_policy",
            "actual_blue_score_distance"], "19", "recorded-confirmation-depth"),
        ("wrong-ordinary-change-key", "fetch", ["transactions", 0, "transaction", "outputs", 1,
            "scriptPublicKey"], "000020" + "00"*32 + "ac", "exact-three-owner-GN3-change-and-fee"),
        ("mutated-current-output", "fetch", ["current_view", "queries", 3, "entry", "amount_sompi"],
            "5999999999", "observed-native-output"),
        ("unconfirmed-reserve-disappears", "fetch", ["current_view", "queries", 3, "entry"], None,
            "observed-spent-or-current-output"),
        ("wrong-acquisition-total", "acquisition-ledger", ["mined_source_sompi"],
            9615864284, "acquisition-total-join"),
    ]
    result = [mutation(name, set_path(key, path, value), expected)
              for name, key, path, value, expected in cases]
    def missing_query(data):
        data["fetch"]["current_view"]["queries"].pop(3)
    result.append(mutation("missing-exact-output-query", missing_query, "every-created-pool-output-queried"))
    def inflated_note(data):
        transaction = data["fetch"]["transactions"][0]["transaction"]
        body = bytearray.fromhex(transaction["payload"])
        body[152:160] = (2_000_000_001).to_bytes(8, "little")
        transaction["payload"] = body.hex()
    result.append(mutation("inflated-public-initial-note", inflated_note, "GN3-note-reserve"))
    bad_pins = copy.deepcopy(original_pins)
    bad_pins["fetch"] = "00" * 32
    try:
        audit_module["audit"](originals, bad_pins)
    except ValueError as error:
        assert str(error) == "external-whole-file-pin"
        result.append({"control": "wrong-external-file-pin", "rejected": True, "reason": str(error)})
    else:
        raise AssertionError("wrong file pin accepted")
    try:
        audit_module["audit"](originals, original_pins, require_complete=True)
    except ValueError as error:
        assert str(error) == "full-live-lifecycle-still-incomplete"
        result.append({"control": "GN3-cannot-be-promoted-to-complete", "rejected": True,
                       "reason": str(error)})
    else:
        raise AssertionError("GN3 prefix promoted to complete")
    for name, raw in [("duplicate-json-key", b'{"a":1,"a":2}'), ("nonfinite-json-number", b'{"a":NaN}')]:
        try:
            audit_module["strict_json"](raw)
        except ValueError as error:
            assert str(error) == name
            result.append({"control": name, "rejected": True, "reason": str(error)})
        else:
            raise AssertionError(name + " accepted")
    return {"schema": "kpx8-independent-accounting-malformed-evidence-controls/v1",
            "scope": "SYNTHETIC_MUTATIONS_OF_SELECTED_PUBLIC_GN3_PREFIX",
            "control_count": len(result), "all_rejected": True, "controls": result,
            "funding_or_broadcast_or_private_reads": False,
            "cryptographic_correctness_or_privacy_proven": False}
