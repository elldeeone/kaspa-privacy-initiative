"""Independent arithmetic audit of externally selected public TN10 observations.

This module performs no I/O, native/proof execution, transaction submission or
chain acquisition. A trusted caller must authenticate every input against its
independently selected whole-file SHA256 before passing bytes here. Rechecking
the recorded replay receipt is not independent consensus or cryptography.
"""
import hashlib
import json
import re
import uuid
from fractions import Fraction


DOMAIN = "be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480"
PROFILE = "69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f"
TRIAL = "2a93ba31-0220-47d8-a845-369adadd0c95"
TAIL_SHA = "2e9e00aa4ba7d9a25db4aff5246d58213b336e7a0c7689de8cc36498bcd09bf6"
USEFUL_SOMPI = 2_100_000_000  # Frozen three 5-KAS plus three 2-KAS payments.
MAX_SOMPI = 2_870_000_000_000_000_000
P2PK = re.compile(r"000020[0-9a-f]{64}ac\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def integer(value):
    require(type(value) is int and 0 <= value <= MAX_SOMPI, "integer-sompi-range")
    return value


def decimal(value):
    require(type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value, re.ASCII),
            "canonical-network-decimal")
    return integer(int(value))


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate-json-key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: require(False, "nonfinite-json-number"))


def point(value):
    require(type(value) is dict and set(value) == {"transactionId", "index"}, "outpoint-shape")
    require(type(value["transactionId"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", value["transactionId"]), "transaction-id")
    require(type(value["index"]) is int and 0 <= value["index"] < 2**32, "outpoint-index")
    return value["transactionId"], value["index"]


def point_hex(value):
    return value[0] + value[1].to_bytes(4, "little").hex()


def state(raw):
    require(len(raw) == 112 and raw[:8] == b"KPX8ST01"
            and raw[8:40].hex() == DOMAIN, "state-identity")
    counts = int.from_bytes(raw[72:76], "little"), int.from_bytes(raw[108:112], "little")
    require(1 <= counts[0] <= 2**16 and 1 <= counts[1] <= 2**17, "state-count-bounds")
    return counts


def state_spk(raw, tail):
    state(raw)
    return "0000aa20" + hashlib.blake2b(b"\x4c\x70" + raw + tail, digest_size=32).hexdigest() + "87"


def case_from_network(row):
    """Convert the amount boundary once without executing financial code."""
    transaction = row["transaction"]
    contexts = row["accepted_input_contexts"]
    require(len(transaction["inputs"]) == len(contexts) > 0, "populated-input-context-count")
    inputs = []
    for item, context in zip(transaction["inputs"], contexts):
        require(point(item["previousOutpoint"]) == point(context["outpoint"]), "context-outpoint")
        inputs.append((point(item["previousOutpoint"]), decimal(context["amount_sompi"]),
                       context["script_public_key"]))
    outputs = [(decimal(item["value"]), item["scriptPublicKey"]) for item in transaction["outputs"]]
    require(outputs and all(value > 0 for value, _ in outputs), "positive-native-outputs")
    fee = integer(sum(value for _, value, _ in inputs) - sum(value for value, _ in outputs))
    return transaction, inputs, outputs, fee


def acquisition(raws, ledger):
    rows, spent, source_sum, fee_sum = [], set(), 0, 0
    require(ledger["trial_id"] == TRIAL and len(ledger["owners"]) == 3, "acquisition-trial")
    for index, selected in enumerate(ledger["owners"]):
        raw = raws[f"acquisition-{index}"]
        require(sha(raw) == selected["ordinary_case_sha256"], "acquisition-selected-case")
        case = strict_json(raw)
        transaction, contexts = case["transaction"], case["entries"]
        require(transaction["id"] == selected["ordinary_transaction_id"], "acquisition-transaction")
        require(len(transaction["inputs"]) == len(contexts) == 11
                and len(transaction["outputs"]) == 1, "eleven-coinbases-one-self-output")
        output = transaction["outputs"][0]
        require(P2PK.fullmatch(output["scriptPublicKey"]), "ordinary-self-P2PK")
        value = integer(output["value"])
        source = 0
        for item, context in zip(transaction["inputs"], contexts):
            key = point(item["previousOutpoint"])
            require(key not in spent and context["isCoinbase"] is True
                    and context["covenantId"] is None
                    and context["scriptPublicKey"] == output["scriptPublicKey"],
                    "distinct-own-coinbase-input")
            spent.add(key)
            source += integer(context["amount"])
        fee = integer(source - value)
        require((source, value, fee) == (selected["mined_source_sompi"],
                selected["ordinary_output_sompi"], selected["acquisition_fee_sompi"]),
                "acquisition-ledger-case-join")
        rows.append(((transaction["id"], 0), value, output["scriptPublicKey"]))
        source_sum += source
        fee_sum += fee
    require((source_sum, sum(row[1] for row in rows), fee_sum) ==
            (ledger["mined_source_sompi"], ledger["ordinary_outputs_sompi"],
             ledger["acquisition_fees_sompi"]), "acquisition-total-join")
    return rows, integer(source_sum), integer(fee_sum)


def audit(raws, pins, *, require_complete=False):
    """Audit one recorded prefix; incomplete prefixes cannot become completion.

    Named bytes: acquisition-ledger, acquisition-0/1/2, fetch, replay, history,
    checkpoint, native-tail. At completion also final-scan-0/1/2. No paths or
    owner-private data enter this interface. External pins must cover exactly
    the supplied names; result selection provenance remains the caller's duty.
    """
    require(type(require_complete) is bool and set(raws) == set(pins), "exact-selected-public-inputs")
    for name, raw in raws.items():
        require(type(raw) is bytes and sha(raw) == pins[name], "external-whole-file-pin")
    required = {"acquisition-ledger", "acquisition-0", "acquisition-1", "acquisition-2",
                "fetch", "replay", "history", "checkpoint", "native-tail"}
    require(required <= set(raws), "all-accounting-inputs")
    data = {name: strict_json(raw) for name, raw in raws.items() if name != "native-tail"}
    fetch, replay, history, checkpoint = (data[name] for name in ("fetch", "replay", "history", "checkpoint"))
    tail = raws["native-tail"]
    require(sha(tail) == TAIL_SHA, "selected-immutable-tail")
    require(fetch["network_id"] == "testnet-10" and fetch["financial_profile_sha256"] == PROFILE
            and fetch["descriptor"]["trial_id"] == TRIAL, "selected-TN10-trial-profile")
    require(replay["status"] == "RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS"
            and replay["all_native_Full_and_input_engines_executed"] is True
            and replay["genesis_rederived_from_public_notes_and_native_backing"] is True
            and replay["financial_profile_sha256"] == PROFILE
            and replay["selection_file_sha256"] == fetch["selection_file_sha256"]
            and replay["descriptor_sha256"] == fetch["descriptor_file_sha256"]
            and replay["fetch_sha256"] == pins["fetch"]
            and replay["history_sha256"] == pins["history"]
            and replay["current_checkpoint"] == checkpoint == history["head"], "replay-receipt-input-join")
    require(history["schema"] == "kpx8-owner-private-history/v1"
            and history["domain_hex32"] == DOMAIN, "public-history-identity")
    ordinary, source, acquisition_fees = acquisition(raws, data["acquisition-ledger"])
    accepted = fetch["transactions"]
    require(1 <= len(accepted) <= 12 and len(accepted) == len(replay["transactions"]), "accepted-prefix-length")
    require(len(history["transitions"]) == len(accepted) - 1, "history-prefix-length")
    initial = history["genesis"]
    previous_state = bytes.fromhex(initial["state_hex112"])
    require(state(previous_state) == (3, 1), "initial-three-notes-sentinel-NF")
    reserve = integer(initial["reserve_sompi"])
    head, spent, nfs, fees, payouts, transitions = None, set(), set(), [], [], []
    identities = set()
    accepted_participants = None
    ordinary_change = 0
    queries = ordinary[:]
    for ordinal, (row, verification) in enumerate(zip(accepted, replay["transactions"])):
        transaction, inputs, outputs, fee = case_from_network(row)
        identity = transaction["id"]
        require(identity not in identities, "distinct-observed-transactions")
        identities.add(identity)
        require(verification["transaction_id"] == identity
                and verification["native_full_and_all_input_engines_passed"] is True
                and integer(verification["metrics"]["actual_fee_sompi"]) == fee,
                "accepted-body-native-receipt-fee-join")
        confirmation = row["confirmation_policy"]
        require(confirmation["passes"] is True
                and decimal(confirmation["actual_blue_score_distance"]) >=
                    integer(confirmation["min_confirmation_count"]) >= 20, "recorded-confirmation-depth")
        for key, _, _ in inputs:
            require(key not in spent, "physical-input-used-once")
            spent.add(key)
        body = bytes.fromhex(transaction["payload"])
        if ordinal == 0:
            require(inputs == ordinary and len(outputs) == 4 and len(body) == 1576
                    and body[:8] == b"KPX8GN01" and body[8:40].hex() == PROFILE
                    and body[40:72].hex() == DOMAIN and str(uuid.UUID(bytes=body[72:88])) == TRIAL,
                    "actual-GN3-backing-trial")
            note_values = [int.from_bytes(body[88 + 496*i + 64:88 + 496*i + 72], "little")
                           for i in range(3)]
            require(note_values == [2_000_000_000] * 3 and sum(note_values) == reserve
                    and outputs[0] == (reserve, state_spk(previous_state, tail)), "GN3-note-reserve")
            shares = [fee // 3, fee // 3, fee - 2 * (fee // 3)]
            require(outputs[1:] == [(value - note - share, script)
                    for (_, value, script), note, share in zip(inputs, note_values, shares)],
                    "exact-three-owner-GN3-change-and-fee")
            ordinary_change = sum(value for value, _ in outputs[1:])
            require(initial["outpoint_hex36"] == identity + "00000000", "genesis-outpoint")
            head = identity, 0
            kind = "GN3"
        else:
            kind = "batch" if ordinal <= 2 else "exit"
            require(inputs == [(head, reserve, state_spk(previous_state, tail))]
                    and body[112:148].hex() == point_hex(head)
                    and body[148:260] == previous_state, "exact-current-reserve-state-input")
            old, new = state(body[148:260]), state(body[268:380])
            old_reserve, remaining, body_fee, payout = [int.from_bytes(body[at:at+8], "little")
                                                        for at in (260, 380, 388, 396)]
            require(old_reserve == reserve and body_fee == fee
                    and reserve == remaining + payout + fee, "body-native-money-join")
            new_state = body[268:380]
            if kind == "batch":
                require(len(body) == 10780 and body[:8] == b"KPX8PB01"
                        and new == (old[0] + 6, old[1] + 3) and payout == 0
                        and outputs == [(remaining, state_spk(new_state, tail))], "batch-physical-state-shape")
                spent_nfs = [body[436 + 96*i:468 + 96*i] for i in range(3)]
            else:
                require(len(body) == 1632 and body[:8] == b"KPX8XB01"
                        and new == (old[0], old[1] + 1)
                        and body[188:220] == body[308:340], "exit-state-shape")
                payout_script = body[404:440].hex()
                require(P2PK.fullmatch(payout_script) and outputs[-1] == (payout, payout_script)
                        and outputs == ([(remaining, state_spk(new_state, tail))] if remaining else [])
                            + [(payout, payout_script)], "native-payout-and-continuing-reserve")
                payouts.append({"transaction_id": identity, "output_index": len(outputs)-1,
                                "payout_sompi": payout, "script_public_key": payout_script})
                spent_nfs = [body[440:472]]
            for nf in spent_nfs:
                require(len(nf) == 32 and nf != bytes(32) and nf not in nfs, "distinct-spent-nullifier")
                nfs.add(nf)
            require(body[16:48].hex() == DOMAIN, "transition-domain")
            reserve, previous_state = integer(remaining), new_state
            head = (identity, 0) if reserve else None
            transition = history["transitions"][ordinal - 1]
            require(transition["kind"] == kind
                    and bytes.fromhex(transition["projection_hex"])[-len(body):] == body
                    and transition["successor_outpoint_hex36"] == (point_hex(head) if head else None),
                    "accepted-history-transition-head")
            if kind == "batch":
                roster = transition["session"]["roster"]
                require(type(roster) is list and len(roster) == 3
                        and all(type(member) is str and re.fullmatch(r"[0-9a-f]{64}", member)
                                for member in roster) and len(set(roster)) == 3,
                        "exact-accepted-three-owner-roster")
                if accepted_participants is None:
                    accepted_participants = set(roster)
                else:
                    require(set(roster) == accepted_participants, "same-three-owners-in-both-payment-rounds")
        fees.append(fee)
        transitions.append({"kind": kind, "transaction_id": identity, "fee_sompi": fee})
        queries += [((identity, index), value, script) for index, (value, script) in enumerate(outputs)]
    require(checkpoint == {"outpoint_hex36": point_hex(head) if head else None,
            "reserve_sompi": reserve, "state_hex112": previous_state.hex()}, "final-checkpoint")
    require(integer(replay["observed_total_fee_sompi"]) == sum(fees)
            and replay["payouts"] == payouts, "all-replayed-fees-and-payouts")
    for view in [fetch["current_view"], fetch["current_view"]["final_requery"]]:
        observed = {point(item["outpoint"]): item for item in view["queries"]}
        require(len(observed) == len(view["queries"]), "distinct-exact-current-queries")
        for key, value, script in queries:
            require(key in observed, "every-created-pool-output-queried")
            query = observed[key]
            require(query["queried"] is True and decimal(query["amount_sompi"]) == value
                    and query["script_public_key"] == script, "exact-current-query")
            entry = query["entry"]
            require((entry is None) == (key in spent), "observed-spent-or-current-output")
            if entry is not None:
                require(point(entry["outpoint"]) == key and decimal(entry["amount_sompi"]) == value
                        and entry["script_public_key"] == script and entry["is_coinbase"] is False
                        and entry["covenant_id"] is None, "observed-native-output")
    pool_fees = sum(fees)
    total_fees = integer(acquisition_fees + pool_fees)
    payout_sum = sum(row["payout_sompi"] for row in payouts)
    require(source == ordinary_change + payout_sum + reserve + total_fees, "whole-trial-conservation")
    financial_complete = len(accepted) == 12 and len(payouts) == 9 and reserve == 0
    if financial_complete:
        require(state(previous_state) == (15, 16) and len(nfs) == 15, "terminal-note-nullifier-counts")
    scans_complete = False
    if {"final-scan-0", "final-scan-1", "final-scan-2"} <= set(raws):
        scans = [data[f"final-scan-{i}"] for i in range(3)]
        require(accepted_participants is not None and
                {scan["participant_id_hex32"] for scan in scans} == accepted_participants,
                "terminal-scans-belong-to-accepted-payment-cohort")
        scans_complete = all(scan["schema"] == "kpx8-owner-scan-complete/v1"
            and scan["domain_hex32"] == DOMAIN and scan["history_sha256"] == pins["history"]
            and all(scan[key] is True for key in ("seed_only", "scan_completed", "terminal_reconciled",
                                                    "native_payout_keys_rederived"))
            and scan["private_claims_exported"] is False for scan in scans)
        require(scans_complete and financial_complete, "terminal-seed-scan-reconciliation")
    complete = financial_complete and scans_complete
    require(not require_complete or complete, "full-live-lifecycle-still-incomplete")
    ratio = Fraction(total_fees, USEFUL_SOMPI)
    return {"schema": "kpx8-independent-recorded-live-accounting/v1", "trial_id": TRIAL,
        "scope": "RECORDED_SELECTED_NODE_PREFIX_ARITHMETIC_AND_RECEIPT_JOINS",
        "complete_requested_lifecycle": complete, "financial_chain_terminal": financial_complete,
        "three_original_seed_terminal_scans": scans_complete, "input_sha256": dict(pins),
        "accepted_pool_transaction_count": len(accepted), "ordinary_acquisition_transaction_count": 3,
        "accepted_payment_round_count": min(len(accepted)-1, 2), "confirmed_payout_count": len(payouts),
        "mined_source_sompi": source, "ordinary_GN3_change_sompi": ordinary_change,
        "native_payout_sompi": payout_sum, "remaining_reserve_sompi": reserve,
        "acquisition_fees_sompi": acquisition_fees, "pool_fees_sompi": pool_fees,
        "GN3_fee_sompi": fees[0], "mixed_batch_fees_sompi": fees[1:3],
        "mixed_batch_total_fee_sompi": sum(fees[1:3]),
        "independent_exit_fees_sompi": fees[3:],
        "independent_exit_total_fee_sompi": sum(fees[3:]),
        "complete_fee_sompi_so_far": total_fees, "transactions": transitions, "payouts": payouts,
        "whole_trial_sompi_conservation": True, "fixed_useful_payment_sompi": USEFUL_SOMPI,
        "denominator_is_frozen_workload_not_decrypted_by_auditor": True,
        "fee_ratio_numerator": ratio.numerator, "fee_ratio_denominator": ratio.denominator,
        "two_percent_target_verdict": ("PASS" if total_fees * 100 <= USEFUL_SOMPI * 2 else "FAIL")
            if complete else "INCOMPLETE",
        "independent_consensus_or_crypto_proof_verified": False,
        "privacy_or_separate_administration_qualified": False,
        "original_private_bytes_or_hashes_read": 0}
