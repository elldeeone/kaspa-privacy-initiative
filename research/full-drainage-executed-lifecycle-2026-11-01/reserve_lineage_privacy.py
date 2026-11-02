#!/usr/bin/env python3
"""Sealed offline observer for actual TN10 reserve ancestry and one merge model."""

from __future__ import annotations

from collections import defaultdict
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
UNIT = 10_000_000
PERMISSION_RENT = 50_000_000
DEPOSIT_TAG = b"KPI-private-deposit-v1\0"
PAYOUT_TAG = b"KPI-native-payout-v1\0"
EDGES = (("A", "M"), ("B", "M"), ("M", "S"), ("A", "S"))
ACTORS = ("A", "B", "M", "S")
PARENT_MANIFEST_SHA256 = "1259c42cb7cde08fac0b9da29176e46cc20dddc963682c680a19958eefd5b88c"

spec = importlib.util.spec_from_file_location("live_correction", HERE / "score_live_correction.py")
correction = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(correction)


def read(path: Path):
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_new(path: Path, value: object) -> None:
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def point(value: dict) -> str:
    return f'{value["transactionId"]}:{value["index"]}'


def accepted_transaction(run: Path, label: str) -> tuple[dict, dict, Path]:
    path = run / f"{label}-accepted.json"
    record = read(path)
    tx = record["transaction"]
    txid = tx["verboseData"]["transactionId"]
    if record["transactionId"] != txid or record["confirmed"] < 10:
        raise ValueError(f"unconfirmed or mismatched accepted transaction: {label}")
    return record, tx, path


def owner_projection(run: Path) -> tuple[dict, dict, dict]:
    known_path = run / "wallet-public/known-owner-evidence.json"
    known = read(known_path)
    exit_by_amount = {}
    operation_shapes = []
    for index in range(1, 11):
        operation = read(run / f"wallet-public/operation-{index:02}.json")
        statement = operation["statement"]
        operation_shapes.append(
            {
                "ordinal": index,
                "kind": statement["kind"],
                "proofBytes": len(operation["proof"]),
                "ciphertextBytes": [len(item["ciphertext"]) for item in operation["deliveries"]],
            }
        )
        if statement["kind"] == 3:
            destination = bytes(statement["exit_destination"]).hex()
            row = {
                "owner": known["exitOwnerByDestination"][destination],
                "amountSompi": statement["exit_value"],
                "destination": destination,
            }
            if row["amountSompi"] in exit_by_amount:
                raise ValueError("observer requires unique exit amounts in this retained run")
            exit_by_amount[row["amountSompi"]] = row
    return known, exit_by_amount, {"path": str(known_path.relative_to(run)), "operationShapes": operation_shapes}


def actual_reserve_lineage(run: Path) -> dict:
    known, exit_by_amount, shapes = owner_projection(run)
    reserves = {}
    deposits = []
    evidence = {}

    # Bind every payout permission to the unique state transition that created
    # it. This is validation only; settlement labels are not supplied to the
    # payment-history enumerator.
    initialize, initialize_tx, _ = accepted_transaction(run, "initialize")
    state_point = f'{initialize["transactionId"]}:0'
    if initialize_tx["outputs"][0]["value"] != 100_000_000:
        raise ValueError("unexpected initial state rent")
    permissions = {}
    for ordinal in range(1, 8):
        label = f"batch-{ordinal:02}-settlement"
        settlement, tx, _ = accepted_transaction(run, label)
        state_inputs = [point(raw["previousOutpoint"]) for raw in tx["inputs"] if point(raw["previousOutpoint"]) == state_point]
        if len(state_inputs) != 1 or tx["outputs"][0]["value"] != 100_000_000:
            raise ValueError(f"broken state lineage: {label}")
        state_point = f'{settlement["transactionId"]}:0'
        if 2 <= ordinal <= 6:
            permission = tx["outputs"][1]
            if permission["value"] != PERMISSION_RENT or permission.get("covenant") is None:
                raise ValueError(f"unexpected payout permission: {label}")
            permissions[f'{settlement["transactionId"]}:1'] = label
    for label in ("deposit-a", "deposit-b"):
        record, tx, path = accepted_transaction(run, label)
        evidence[str(path.relative_to(run))] = sha(path)
        payload = bytes.fromhex(tx["payload"])
        if not payload.startswith(DEPOSIT_TAG) or len(payload) != len(DEPOSIT_TAG) + 36:
            raise ValueError("unexpected accepted deposit payload")
        owner_id = payload[len(DEPOSIT_TAG):len(DEPOSIT_TAG) + 32].hex()
        index = int.from_bytes(payload[-4:], "little")
        output = tx["outputs"][index]
        owner = known["depositOwnerByPublicOwner"][owner_id]
        outpoint = f'{record["transactionId"]}:{index}'
        reserves[outpoint] = {
            "depositTransactionId": record["transactionId"],
            "sourceOwner": owner,
            "valueSompi": output["value"],
            "scriptPublicKey": output["scriptPublicKey"],
        }
        deposits.append({"ownerId": owner_id, "knownOwner": owner, "outpoint": outpoint, "valueSompi": output["value"]})

    payouts = []
    payout_records = []
    for ordinal in range(1, 6):
        label = f"payout-{ordinal:02}"
        record, tx, path = accepted_transaction(run, label)
        evidence[str(path.relative_to(run))] = sha(path)
        if not bytes.fromhex(tx["payload"]).startswith(PAYOUT_TAG):
            raise ValueError("unexpected accepted payout payload")
        payout_records.append((record["header"]["blueScore"], ordinal, record, tx))
    payout_records.sort()

    for _, ordinal, record, tx in payout_records:
        permission_matches = [
            point(raw["previousOutpoint"]) for raw in tx["inputs"]
            if point(raw["previousOutpoint"]) in permissions
        ]
        if len(permission_matches) != 1:
            raise ValueError("payout must consume exactly one tracked permission")
        permission_point = permission_matches[0]
        permissions.pop(permission_point)
        matched = [(index, point(raw["previousOutpoint"])) for index, raw in enumerate(tx["inputs"]) if point(raw["previousOutpoint"]) in reserves]
        if len(matched) != 1:
            raise ValueError("payout must consume exactly one tracked reserve")
        input_index, reserve_point = matched[0]
        reserve = reserves.pop(reserve_point)
        principal = tx["outputs"][0]["value"] - PERMISSION_RENT
        exit_row = exit_by_amount.get(principal)
        if exit_row is None:
            raise ValueError("payout amount does not match one public exit")
        remainder = reserve["valueSompi"] - principal
        if remainder < 0:
            raise ValueError("payout exceeds selected reserve")
        next_point = None
        if remainder:
            changes = [
                (index, output) for index, output in enumerate(tx["outputs"])
                if output["scriptPublicKey"] == reserve["scriptPublicKey"] and output["value"] == remainder
            ]
            if len(changes) != 1:
                raise ValueError("missing or ambiguous reserve change")
            index, _ = changes[0]
            next_point = f'{record["transactionId"]}:{index}'
            reserves[next_point] = {**reserve, "valueSompi": remainder}
        payouts.append(
            {
                "ordinal": ordinal,
                "transactionId": record["transactionId"],
                "blueScore": record["header"]["blueScore"],
                "timestamp": record["header"]["timestamp"],
                "permissionInput": permission_point,
                "reserveInputIndex": input_index,
                "reserveInput": reserve_point,
                "reserveOutput": next_point,
                "principalSompi": principal,
                "publicNativeOutputSompi": tx["outputs"][0]["value"],
                "exitOwner": exit_row["owner"],
                "sourceDepositOwner": reserve["sourceOwner"],
                "sourceDepositTransactionId": reserve["depositTransactionId"],
            }
        )
    if reserves:
        raise ValueError("terminal reserve lineage did not drain")
    if permissions:
        raise ValueError("terminal payout permissions were not all consumed")

    sponsor_addresses = set()
    total_fees = 0
    accepted_times = []
    protocol_labels = [
        "activate", "bootstrap", "initialize", "deposit-a", "deposit-b",
        *[f"publish-{index:02}" for index in range(1, 11)],
        *[f"batch-{index:02}-settlement" for index in range(1, 8)],
        *[f"payout-{index:02}" for index in range(1, 6)],
    ]
    for label in protocol_labels:
        request_path = run / f"{label}-build/request.json"
        transaction_path = run / f"{label}-build/transaction.json"
        accepted_path = run / f"{label}-accepted.json"
        request = read(request_path)
        transaction = read(transaction_path)
        accepted = read(accepted_path)
        sponsor_addresses.add(request["sponsorUtxo"]["address"])
        total_fees += transaction["qualification"]["feeSompi"]
        accepted_times.append(accepted["header"]["timestamp"])
        evidence[str(request_path.relative_to(run))] = sha(request_path)
        evidence[str(transaction_path.relative_to(run))] = sha(transaction_path)
        evidence[str(accepted_path.relative_to(run))] = sha(accepted_path)
    return {
        "deposits": deposits,
        "payouts": payouts,
        "terminalReserveSompi": 0,
        "feeAndTimingEvidence": {
            "protocolTransactions": len(protocol_labels),
            "uniqueSponsorAddresses": len(sponsor_addresses),
            "totalProtocolFeesSompi": total_fees,
            "firstAcceptedTimestamp": min(accepted_times),
            "lastAcceptedTimestamp": max(accepted_times),
            "usedToDiscriminatePaymentHistories": False,
            "networkOrIpOriginMeasured": False,
        },
        "operationEvidence": {**shapes, "usedToDiscriminatePaymentHistories": False},
        "evidenceSha256ByRelativePath": dict(sorted(evidence.items())),
    }


def provenance_executions(initial, terminal_values, steps=3):
    by_sender = defaultdict(list)
    for sender, recipient in EDGES:
        by_sender[sender].append(recipient)
    initial_notes = tuple(sorted((owner, value, owner) for owner, value in initial))
    results = []

    def visit(notes, history):
        if len(history) == steps:
            if sorted(value for _, value, _ in notes) == sorted(terminal_values):
                results.append((tuple(history), tuple(sorted(notes))))
            return
        used = set()
        for index, (sender, value, origin) in enumerate(notes):
            marker = (sender, value, origin)
            if marker in used:
                continue
            used.add(marker)
            for recipient in by_sender[sender]:
                for amount in range(1, value):
                    next_notes = list(notes)
                    next_notes.pop(index)
                    next_notes.extend(((recipient, amount, origin), (sender, value - amount, origin)))
                    visit(tuple(sorted(next_notes)), (*history, (sender, recipient, amount)))

    visit(initial_notes, ())
    return results


def gross(history):
    return tuple(sorted(history))


def histories(executions):
    return sorted({gross(history) for history, _ in executions})


def describe_histories(values):
    rendered = [[{"sender": a, "recipient": b, "amountSompi": amount * UNIT} for a, b, amount in history] for history in values]
    return {"grossHistoryCount": len(values), "grossHistories": rendered}


def own_facts(history, actor):
    return tuple(sorted(fact for fact in history if actor in fact[:2]))


def fact_key(facts):
    return ";".join(f"{a}->{b}:{value * UNIT}" for a, b, value in facts) or "none"


def prediction(run: Path) -> dict:
    parent = correction.verify_parent(run)
    initial, terminal, steps, correction_bindings = correction.public_inputs(run)
    lineage = actual_reserve_lineage(run)
    terminal_values = [value for _, value in terminal]
    executions = provenance_executions(initial, terminal_values, steps)
    chain_histories = histories(executions)
    known_executions = [(history, notes) for history, notes in executions if sorted((owner, value) for owner, value, _ in notes) == sorted(map(tuple, terminal))]
    known_histories = histories(known_executions)

    observed_origins = {
        (row["exitOwner"], row["principalSompi"] // UNIT): row["sourceDepositOwner"]
        for row in lineage["payouts"]
    }
    lineage_executions = [
        (history, notes) for history, notes in known_executions
        if all(observed_origins.get((owner, value)) == origin for owner, value, origin in notes)
    ]
    lineage_histories = histories(lineage_executions)

    participant = {}
    for actor in ACTORS:
        own_terminal = sorted(value for owner, value in terminal if owner == actor)
        own_visible = [(history, notes) for history, notes in executions if sorted(value for owner, value, _ in notes if owner == actor) == own_terminal]
        groups = defaultdict(list)
        for history, notes in own_visible:
            groups[own_facts(gross(history), actor)].append((history, notes))
        participant[actor] = {
            "ownTerminalNotesSompi": [value * UNIT for value in own_terminal],
            "conditionalOnOwnPaymentFacts": {
                fact_key(facts): {"ownPaymentFacts": [[a, b, value * UNIT] for a, b, value in facts], **describe_histories(histories(group))}
                for facts, group in sorted(groups.items())
            },
        }

    common_sources = sorted(item["knownOwner"] for item in lineage["deposits"])
    merge_payouts = [
        {
            "exitOwner": row["exitOwner"],
            "principalSompi": row["principalSompi"],
            "sourceDepositOwnerCandidates": common_sources,
        }
        for row in lineage["payouts"]
    ]
    sparse = correction.legacy.enumerate_sequences(
        (("A", "B"),), lambda notes: tuple(sorted(notes)) == (("A", 6), ("B", 4)), steps=1, initial=(("A", 10),)
    )
    false_m_to_s = [history for history in known_histories if any((a, b) == ("M", "S") for a, b, _ in history)]
    return {
        "schema": "full-drainage-live-reserve-lineage-prediction-v1",
        "selection": "NEXT-PRIVACY-SELECTION.md",
        "parent": parent,
        "correctionEvidenceSha256ByRelativePath": correction_bindings,
        "transactionEvidence": lineage,
        "views": {
            "chainOnly": describe_histories(chain_histories),
            "knownOwnerBalanceOnly": describe_histories(known_histories),
            "knownOwnerPlusReserveLineage": describe_histories(lineage_histories),
            "truthfulParticipant": participant,
        },
        "candidateSyntheticCommonReserve": {
            "classification": "offline counterfactual; not an implemented covenant path",
            "initialReserveSompi": sum(item["valueSompi"] for item in lineage["deposits"]),
            "terminalReserveSompi": 0,
            "payouts": merge_payouts,
            "knownOwnerGrossHistories": describe_histories(known_histories),
            "forcedDelay": False,
            "retainedUserPrincipal": False,
            "mpc": False,
        },
        "controls": {
            "sparseKnownOwnerGrossHistoryCount": len({gross(history) for history in sparse}),
            "falseMToSUniqueGrossHistoryCount": len(false_m_to_s),
            "predictionsReadPrivateTruth": False,
        },
        "frozenHypothesisResultBeforeTruth": {
            "reserveLineageSelectsOneGrossHistory": len(lineage_histories) == 1,
            "balanceCompatibleGrossHistories": len(known_histories),
            "lineageCompatibleGrossHistories": len(lineage_histories),
        },
        "boundary": {
            "reserveLineageIsNativeTransactionEvidence": True,
            "knownOwnerMappingsAreAuxiliaryEvidenceNotChainFacts": True,
            "participantReceivesOnlyOwnTerminalAndPaymentFacts": True,
            "sponsorTimingShapesLoggedButNotUsedAsLikelihoods": True,
            "syntheticMergeDoesNotAuthorizeOrModelARealTransaction": True,
            "publicTransparentExitBalancesRemainUnchanged": True,
            "noGeneralPrivacyOrProductionClaim": True,
        },
    }


def actual_provenance(run: Path, initial):
    truth_path = run / "private/truth.json"
    if truth_path.stat().st_mode & 0o077:
        raise ValueError("private truth permissions")
    truth = read(truth_path)
    notes = [(owner, value, owner) for owner, value in initial]
    history = []
    for sender, recipient, input_sompi, payment_sompi in truth["payments"]:
        input_value = correction.units(input_sompi)
        payment = correction.units(payment_sompi)
        matches = [index for index, note in enumerate(notes) if note[0] == sender and note[1] == input_value]
        if len(matches) != 1:
            raise ValueError("private truth does not identify one provenance note")
        _, value, origin = notes.pop(matches[0])
        notes.extend(((recipient, payment, origin), (sender, value - payment, origin)))
        history.append((sender, recipient, payment))
    return tuple(history), tuple(sorted(notes))


def validation(run: Path, directory: Path) -> dict:
    prediction_path = directory / "PREDICTIONS.json"
    sealed = read(prediction_path)
    if sha(prediction_path) != (directory / "PREDICTIONS.sha256").read_text().strip():
        raise ValueError("prediction seal changed")
    if canonical(prediction(run)) != canonical(sealed):
        raise ValueError("public evidence changed after seal")
    initial, terminal, _, _ = correction.public_inputs(run)
    actual_history, actual_notes = actual_provenance(run, initial)
    actual_gross = gross(actual_history)

    def rendered_histories(path):
        return {
            tuple(sorted((row["sender"], row["recipient"], row["amountSompi"] // UNIT) for row in history))
            for history in path["grossHistories"]
        }

    known = rendered_histories(sealed["views"]["knownOwnerBalanceOnly"])
    lineage = rendered_histories(sealed["views"]["knownOwnerPlusReserveLineage"])
    if actual_gross not in known or actual_gross not in lineage:
        raise ValueError("sealed public candidates exclude execution truth")

    observed = {
        (row["exitOwner"], row["principalSompi"] // UNIT): row["sourceDepositOwner"]
        for row in sealed["transactionEvidence"]["payouts"]
    }
    actual_origin = {(owner, value): origin for owner, value, origin in actual_notes}
    if observed != actual_origin:
        raise ValueError("reserve ancestry differs from actual terminal provenance")

    participant = {}
    for actor in ACTORS:
        actual_facts = own_facts(actual_gross, actor)
        key = fact_key(actual_facts)
        row = sealed["views"]["truthfulParticipant"][actor]["conditionalOnOwnPaymentFacts"].get(key)
        if row is None:
            raise ValueError("sealed participant view omitted actual own facts")
        candidates = rendered_histories(row)
        participant[actor] = {
            "ownFactsKey": key,
            "otherPaymentGrossHistoryCandidates": len(candidates),
            "executionTruthRetained": actual_gross in candidates,
            "otherUsersPrivateFactsSupplied": False,
        }

    false_view = [history for history in known if any((a, b) == ("M", "S") for a, b, _ in history)]
    return {
        "schema": "full-drainage-live-reserve-lineage-validation-v1",
        "sealedPredictionsSha256": sha(prediction_path),
        "privateTruthReadOnlyAfterSeal": True,
        "privateKeysBackupsOrWitnessesRead": False,
        "actualGrossHistoryRetainedByBalanceView": actual_gross in known,
        "actualGrossHistoryRetainedByLineageView": actual_gross in lineage,
        "frozenHypothesisConfirmed": len(lineage) == 1,
        "reserveLineageMatchesActualFundingOrigins": True,
        "reserveLineageGrossHistoryCount": len(lineage),
        "balanceOnlyGrossHistoryCount": len(known),
        "candidateMergeGrossHistoryCount": sealed["candidateSyntheticCommonReserve"]["knownOwnerGrossHistories"]["grossHistoryCount"],
        "fundingOriginCandidatesPerPayout": {
            "baseline": [1 for _ in sealed["transactionEvidence"]["payouts"]],
            "syntheticCommonReserve": [len(row["sourceDepositOwnerCandidates"]) for row in sealed["candidateSyntheticCommonReserve"]["payouts"]],
        },
        "participantViews": participant,
        "controls": {
            "sparseKnownOwnerRemainsUnique": sealed["controls"]["sparseKnownOwnerGrossHistoryCount"] == 1,
            "falseMToSIsUniqueWrong": len(false_view) == 1 and actual_gross not in false_view,
        },
        "decision": {
            "biggestDemonstratedDirectPaymentLeak": "known-owner full-drainage balances reveal B->M 20000000 sompi and constrain A->M to 30000000 or 40000000 sompi",
            "reserveLineageAddsExactFundingOriginLeak": True,
            "reserveLineageReconstructsDirectGrossHistory": len(lineage) == 1,
            "syntheticMergeImprovesFundingOriginAmbiguity": all(
                value > 1 for value in [len(row["sourceDepositOwnerCandidates"]) for row in sealed["candidateSyntheticCommonReserve"]["payouts"]]
            ),
            "syntheticMergeImprovesDirectPaymentHistory": sealed["candidateSyntheticCommonReserve"]["knownOwnerGrossHistories"]["grossHistoryCount"] > len(known),
            "protocolFixReady": False,
            "blocker": "transparent complete withdrawals plus known-owner mappings preserve per-owner net balances; reserve consolidation cannot hide those balances",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("predict", "validate"))
    parser.add_argument("run", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    run = args.run.resolve()
    directory = args.output.resolve()
    if args.stage == "predict":
        result = prediction(run)
        directory.mkdir(parents=True, exist_ok=False)
        write_new(directory / "PREDICTIONS.json", result)
        (directory / "PREDICTIONS.sha256").write_text(sha(directory / "PREDICTIONS.json") + "\n")
        print(json.dumps(result["frozenHypothesisResultBeforeTruth"], sort_keys=True))
    else:
        result = validation(run, directory)
        write_new(directory / "VALIDATION.json", result)
        print(json.dumps(result["decision"], sort_keys=True))


if __name__ == "__main__":
    main()
