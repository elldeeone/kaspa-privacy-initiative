"""New-profile public replay. Only explicitly offline supplied contexts are supported.

Hidden ownership, value conservation and payout-key inequality rely on exact
body/context-bound native evidence selected by trusted client software. Public
parsing cannot infer them from ciphertexts, public roots or a caller's report.
"""
from __future__ import annotations

import hmac

from dependencies import old
from approved_template import approved_policy

CONTEXT = "OFFLINE_SUPPLIED_CONTEXT"


def descriptor_check(descriptor):
    old.need(type(descriptor) is dict and set(descriptor) == old.DESCRIPTOR_FIELDS, "descriptor-fields")
    old.need(descriptor["schema"] == "kpx3-recovery-descriptor/v1"
             and descriptor["network_id"] == "testnet-10" and descriptor["genesis_hash_hex"] == old.GENESIS,
             "descriptor-network-profile")
    domain, vk = old.hx(descriptor["domain_hex32"], 32), old.hx(descriptor["vk_hex328"], 328)
    old.hx(descriptor["birth_start_hash"], 32)
    old.need(old.point(descriptor["founding_outpoint"])[1] == 0, "founding-output-index")
    raw = old.hx(descriptor["initial_redeem_hex"], 24417)
    old.need(raw[:10] == b"\x4c\x70KPX2ST01" and raw[10:42] == domain, "initial-state-frame-domain")
    old.need(raw[114:] == approved_policy(domain, vk), "unapproved-new-policy-semantics")
    old.need(old.h(raw[114:]).hex() == descriptor["immutable_policy_sha256"], "immutable-policy-hash")
    return domain, vk, raw


def private_action(tx, entries, state, current, reserve, payload, sig, proof):
    old.need(len(payload) == 4400 and len(tx["inputs"]) == 1
             and sig == bytes(65) and proof != bytes(128), "private-frame")
    old.need(payload[8:40] == state.domain and payload[40:76] == old.hx(current["transactionId"], 32)
             + old.u32(current["index"]) and payload[76:188] == state.encoded(), "private-auth-context")
    amounts = [old.integer(int.from_bytes(payload[at:at + 8], "little")) for at in (188, 196, 476, 484)]
    old_reserve, fee, remaining, paid = amounts
    destination = payload[492:528]
    old.need(old_reserve == reserve and fee > 0 and remaining == reserve - paid - fee
             and (remaining == 0 or remaining >= old.NOTE_FLOOR), "private-reserve-fee-payout")
    if paid:
        old.need(paid >= old.PAYOUT_FLOOR and destination[:3] == b"\0\0\x20" and destination[-1] == 172,
                 "private-payout-script")
    else:
        old.need(remaining >= old.NOTE_FLOOR and destination == bytes(36), "private-P0-destination")
    # Check every inactive byte before skipping CM work, including both paths.
    if not remaining:
        old.need(paid > 0 and payload[268:332] == bytes(64) and payload[528:1056] == bytes(528)
                 and payload[3376:4400] == bytes(1024), "terminal-inactive-fields")
    old.need(old.h(payload[528:1056]) == payload[332:364], "private-ciphertext-binding")
    old.need(payload[204:236] != payload[236:268], "private-distinct-nfs")
    for slot in range(2):
        state.insert(payload[204 + slot * 32:236 + slot * 32], payload[1056 + slot * 1160:2216 + slot * 1160])
    if remaining:
        old.need(payload[268:300] != payload[300:332], "private-distinct-cms")
        for slot in range(2):
            state.append(payload[268 + slot * 32:300 + slot * 32], payload[528 + slot * 264:792 + slot * 264],
                         payload[3376 + slot * 512:3888 + slot * 512])
    old.need(payload[364:476] == state.encoded(), "private-next-state")
    old.need(len(tx["outputs"]) == int(remaining > 0) + int(paid > 0), "private-output-count")
    payout = None
    if paid:
        index = int(remaining > 0)
        output = tx["outputs"][index]
        old.need(old.integer(output["value"]) == paid and output["scriptPublicKey"] == destination.hex(), "private-native-payout")
        payout = {"transaction_id": tx["id"], "outpoint": old.outpoint(tx, index),
                  "amount_sompi": paid, "script_public_key": destination.hex(), "kind": "PRIVATE_EXIT"}
    return remaining, fee, payout


def admit_action(tx, entries, state, reserve, payload, sig, proof, genesis_note):
    old.need(len(payload) == 1344 and len(tx["inputs"]) == 2
             and sig == bytes(65) and proof == bytes(128), "admit-frame")
    _, cm, cipher, value = old.public_note(payload, state.domain, b"KPX2AD01")
    old.need(payload[1176:] == (genesis_note if len(state.deliveries) == len(state.entries) == 1 else bytes(168)),
             "admit-genesis-opening")
    fee, change = [old.integer(int.from_bytes(payload[at:at + 8], "little")) for at in (1160, 1168)]
    funding = old.integer(entries[1]["amount_sompi"])
    old.need(fee > 0 and funding == value + fee + change and reserve + funding <= old.MAX, "admit-external-conservation")
    old.funding_signature(tx["inputs"][1], entries[1])
    old.need(len(tx["outputs"]) == (2 if change else 1), "admit-change-arity")
    if change:
        old.need(old.integer(tx["outputs"][1]["value"]) == change
                 and tx["outputs"][1]["scriptPublicKey"] == entries[1]["script_public_key"], "admit-change-output")
    state.append(cm, cipher, payload[536:1048])
    old.need(payload[1048:1160] == state.encoded(), "admit-next-state")
    return reserve + value, fee, None


def reveal_action(tx, entries, state, reserve, payload, sig, proof):
    old.need(len(payload) == 2029 and payload[8] == 1 and len(tx["inputs"]) == 1
             and proof == bytes(128) and sig[-1] == 1 and sig[:64] != bytes(64), "reveal-frame")
    position = int.from_bytes(payload[177:181], "little")
    old.need(position < len(state.deliveries), "reveal-position")
    note = payload[9:113] + payload[181:213] + payload[145:177]
    cm = old.h(b"KPX1NOT\0", state.domain, note)
    old.need(cm.hex() == state.deliveries[position]["cm"] and cm == payload[213:245], "reveal-cm")
    key = payload[113:145]
    old.need(old.h(b"KPX1KEY\0", state.domain, key) == payload[181:213], "reveal-key")
    old.need(payload[245:757] == state.cm.path(position), "reveal-current-cm-path")
    nf = hmac.digest(key, b"KPX1NF\0\0" + state.domain + cm + old.u32(position), "sha256")
    old.need(nf == payload[1917:1949], "reveal-original-nf")
    middle = state.insert(nf, payload[757:1917])
    old.need(middle == payload[1949:1981] and state.nf.root == payload[1981:2013], "reveal-next-nf")
    value = old.integer(int.from_bytes(note[64:72], "little"))
    fee, paid = [old.integer(int.from_bytes(payload[at:at + 8], "little")) for at in (2013, 2021)]
    old.need(old.NOTE_FLOOR <= value <= reserve and fee > 0 and paid >= old.PAYOUT_FLOOR
             and value == fee + paid, "reveal-conservation")
    reserve -= value
    old.need(len(tx["outputs"]) == (2 if reserve else 1), "reveal-output-count")
    index = int(reserve > 0)
    output = tx["outputs"][index]
    old.need(old.integer(output["value"]) == paid and output["scriptPublicKey"] == old.p2pk(payload[145:177]), "reveal-native-payout")
    return reserve, fee, {"transaction_id": tx["id"], "outpoint": old.outpoint(tx, index),
                         "amount_sompi": paid, "script_public_key": output["scriptPublicKey"], "kind": "REVEAL"}


def _replay(descriptor, bundle, native_validator, *, context):
    old.need(context == CONTEXT and type(bundle) is dict and set(bundle) == {
        "schema", "context", "network_id", "genesis_hash_hex", "descriptor_sha256", "transactions"}, "offline-bundle-fields")
    domain, _, initial = descriptor_check(descriptor)
    old.need(bundle["schema"] == "kpx3-supplied-context/v1" and bundle["context"] == CONTEXT
             and bundle["network_id"] == descriptor["network_id"] and bundle["genesis_hash_hex"] == old.GENESIS
             and bundle["descriptor_sha256"] == old.digest(descriptor), "offline-descriptor-binding")
    rows, spends, consumed = {}, {}, set()
    for row in bundle["transactions"]:
        old.need(type(row) is dict and set(row) == {"transaction", "input_contexts"}, "offline-row-fields")
        tx = old.canonical(row["transaction"])
        old.need(tx["id"] not in rows, "duplicate-supplied-transaction")
        entries, _ = old.context_entries(tx, row, synthetic=True)
        for entry in entries:
            old.need(set(entry) == {"outpoint", "amount_sompi", "script_public_key", "block_daa_score", "is_coinbase", "covenant_id"},
                     "offline-input-context-fields")
        rows[tx["id"]] = row
        for index, input_ in enumerate(tx["inputs"]):
            at = old.point(input_["previousOutpoint"])
            old.need(at not in consumed, "duplicate-or-competing-supplied-spend")
            consumed.add(at)
            spends.setdefault(at, []).append((tx["id"], index))
    for row in rows.values():
        for entry in row["input_contexts"]:
            txid, index = old.point(entry["outpoint"])
            if txid in rows:
                parent = rows[txid]["transaction"]
                old.need(index < len(parent["outputs"]), "parent-output-index")
                output = parent["outputs"][index]
                old.need(old.integer(entry["amount_sompi"]) == old.integer(output["value"])
                         and entry["script_public_key"] == output["scriptPublicKey"], "parent-output-context")
    founding = old.point(descriptor["founding_outpoint"])
    old.need(founding[0] in rows, "missing-founding-history", incomplete=True)
    row = rows[founding[0]]
    tx = row["transaction"]
    entries, founding_fee = old.context_entries(tx, row, synthetic=True)
    old.need(len(tx["inputs"]) == 1 and len(tx["outputs"]) in (1, 2), "founding-arity")
    old.funding_signature(tx["inputs"][0], entries[0])
    genesis_note, _, cipher, reserve = old.public_note(old.hx(tx["payload"], 536), domain, b"KPX2GN01")
    state = old.State(domain, genesis_note, cipher)
    old.need(initial[2:114] == state.encoded(), "incoherent-founding-state")
    old.need(old.integer(tx["outputs"][0]["value"]) == reserve
             and tx["outputs"][0]["scriptPublicKey"] == old.p2sh(initial), "founding-reserve")
    if len(tx["outputs"]) == 2:
        old.need(tx["outputs"][1]["scriptPublicKey"] == entries[0]["script_public_key"], "founding-change")
    selected = {tx["id"]}
    operations = [{"kind": "FOUNDING", "transaction_id": tx["id"], "reserve_sompi": reserve,
                   "fee_sompi": founding_fee, "state_hex112": state.encoded().hex()}]
    payouts = []
    current, redeem = old.outpoint(tx), initial
    while reserve:
        children = spends.get(old.point(current), [])
        if not children:
            break
        child, input_index = children[0]
        old.need(input_index == 0 and child not in selected, "reserve-input-index-or-cycle")
        row = rows[child]
        tx = row["transaction"]
        entries, actual_fee = old.context_entries(tx, row, synthetic=True)
        old.same_entry(entries[0], {"outpoint": current, "amount_sompi": reserve, "script_public_key": old.p2sh(redeem)})
        sig, proof, actual_redeem = old.pool_witness(tx)
        old.need(actual_redeem == redeem and redeem[2:114] == state.encoded(), "current-policy-state")
        payload = old.hx(tx["payload"])
        magic = payload[:8]
        previous_reserve = reserve
        if magic == b"KPX3AU01":
            reserve, fee, payout = private_action(tx, entries, state, current, reserve, payload, sig, proof)
            kind = "PRIVATE_EXIT" if payout else "PRIVATE_TRANSFER"
        elif magic == b"KPX2AD01":
            reserve, fee, payout = admit_action(tx, entries, state, reserve, payload, sig, proof, genesis_note)
            kind = "ADMIT"
        elif magic == b"KPX2RV01":
            reserve, fee, payout = reveal_action(tx, entries, state, reserve, payload, sig, proof)
            kind = "REVEAL"
        else:
            raise old.Invalid("unsupported-new-pool-operation")
        old.need(fee == actual_fee, "exact-native-fee")
        state.counts()
        if reserve:
            old.need(reserve >= old.NOTE_FLOOR and old.integer(tx["outputs"][0]["value"]) == reserve, "continuing-reserve-floor-value")
            successor = b"\x4c\x70" + state.encoded() + initial[114:]
            old.need(tx["outputs"][0]["scriptPublicKey"] == old.p2sh(successor), "immutable-successor")
        else:
            successor = None
        if payout:
            payouts.append(payout)
        operations.append({"kind": kind, "transaction_id": child, "prior_outpoint": current,
                           "prior_reserve_sompi": previous_reserve, "reserve_sompi": reserve,
                           "fee_sompi": fee, "state_hex112": state.encoded().hex()})
        selected.add(child)
        current, redeem = (old.outpoint(tx), successor) if reserve else (None, None)
    # Include every supplied ancestor, rather than silently trusting external funding.
    pending = list(selected)
    while pending:
        txid = pending.pop()
        for input_ in rows[txid]["transaction"]["inputs"]:
            parent = input_["previousOutpoint"]["transactionId"]
            if parent in rows and parent not in selected:
                selected.add(parent)
                pending.append(parent)
    old.need(selected == set(rows), "unrelated-or-broken-pool-history")
    pool_ids = {op["transaction_id"] for op in operations}
    for txid in selected - pool_ids:
        tx, entries = rows[txid]["transaction"], rows[txid]["input_contexts"]
        old.need(tx["payload"] == "" and len(tx["inputs"]) == 1, "unsupported-ordinary-ancestor")
        old.funding_signature(tx["inputs"][0], entries[0])
        for output in tx["outputs"]:
            key = old.spk(output["scriptPublicKey"])
            old.need(len(key) == 36 and key[2] == 32 and key[-1] == 172, "ordinary-ancestor-output")
    if native_validator is not None:
        for txid in sorted(selected):
            row = rows[txid]
            old.need(native_validator(row["transaction"], row["input_contexts"]) is True, "selected-offline-native-evidence")
    return {"schema": "kpx3-public-replay/v1", "context": CONTEXT, "descriptor_sha256": old.digest(descriptor),
            "domain_hex32": domain.hex(), "deliveries": state.deliveries,
            "nullifiers": [{"value": e["value"].hex(), "next_value": e["next_value"].hex(), "next_index": e["next_index"]} for e in state.entries],
            "operations": operations, "payouts": payouts, "ordinary_ancestors": len(selected - pool_ids),
            "head": {"outpoint": current, "state_hex112": state.encoded().hex(), "reserve_sompi": reserve,
                     "current_redeem_hex": None if redeem is None else redeem.hex(), "current_utxo": None},
            "completeness": {"complete": False, "public_replay_complete": True, "terminal": reserve == 0,
                             "accepted_chain_backing": False, "network_current_view_observed": False,
                             "independent_consensus": False, "durable_data_availability_proved": False},
            "native_evidence_selected": native_validator is not None,
            "groth16_and_signatures": "EXACT_BODY_CONTEXT_BOUND_SELECTED_OFFLINE_EVIDENCE" if native_validator else "UNCHECKED_OFFLINE",
            "sdk_transaction_id_validation": False, "network_fetch_and_wallet_supported": False}


def replay(descriptor, bundle, native_validator=None, *, context=CONTEXT):
    try:
        return _replay(descriptor, bundle, native_validator, context=context)
    except old.Invalid:
        raise
    except (KeyError, TypeError, ValueError, IndexError, OverflowError):
        raise old.Invalid("new-public-replay-schema") from None
