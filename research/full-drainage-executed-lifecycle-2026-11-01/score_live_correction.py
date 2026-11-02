#!/usr/bin/env python3
"""Versioned, offline correction; inference never reads private execution truth.

This is the existing finite-grid model, not a new network privacy attack. The
separate validation command checks coupled truth AFTER predictions are sealed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

UNIT = 10_000_000  # Retained grid, not an inferred ordinary-user distribution.
EDGES = (("A", "M"), ("B", "M"), ("M", "S"), ("A", "S"))
PARENT_MANIFEST_SHA256 = "1259c42cb7cde08fac0b9da29176e46cc20dddc963682c680a19958eefd5b88c"
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("retained_live_score", HERE / "score-live-tn10.py")
legacy = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(legacy)


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write_new(path, value):
    with Path(path).open("x") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def units(value):
    if type(value) is not int or not 0 < value < 2**64 or value % UNIT:
        raise ValueError("amount outside retained positive integer-sompi grid")
    return value // UNIT


def gross(sequence):
    return tuple(sorted(sequence))


def candidates(initial, terminal, steps, edges=EDGES):
    initial = tuple(map(tuple, initial))
    terminal = tuple(map(tuple, terminal))
    return legacy.enumerate_sequences(
        edges, lambda notes: tuple(sorted(notes)) == tuple(sorted(terminal)),
        steps=steps, initial=initial,
    )


def condition(sequences, edge):
    # Only knowledge of a relationship is supplied, not the hidden payment value.
    return [s for s in sequences if any((a, b) == tuple(edge) for a, b, _ in s)]


def describe(sequences):
    histories = sorted({gross(s) for s in sequences})
    relationships = sorted({(a, b) for h in histories for a, b, _ in h})
    return {
        "eventSequenceCount": len(sequences),
        "grossHistoryCount": len(histories),
        "grossHistories": [list(map(list, h)) for h in histories],
        "amountUnitSompi": UNIT,
        "paymentFacts": [
            {
                "sender": a, "recipient": b,
                "presentInEveryHistory": all(any((x, y) == (a, b) for x, y, _ in h) for h in histories),
                "amountSompiCandidates": sorted({v * UNIT for h in histories for x, y, v in h if (x, y) == (a, b)}),
            }
            for a, b in relationships
        ],
    }


def assess(sequences, truth, edge=None):
    actual = gross(truth)
    unique = {gross(s) for s in sequences}
    retained = actual in unique
    fact_true = edge is None or any((a, b) == tuple(edge) for a, b, _ in truth)
    if not fact_true:
        status = "contradictory_external_fact_not_a_live_privacy_result"
    elif not retained:
        status = "model_excludes_execution_truth_invalid_result"
    elif len(unique) == 1:
        status = "correct_unique_reconstruction_conditional_on_supplied_fact"
    else:
        status = "truth_retained_with_residual_ambiguity"
    return {
        "externalFactConsistentWithExecution": fact_true,
        "coupledExecutionTruthRetained": retained,
        "candidateCount": len(unique),
        "uniqueWrongPrediction": len(unique) == 1 and not retained,
        "successfulReconstruction": fact_true and retained and len(unique) == 1,
        "status": status,
    }


def verify_parent(run):
    parent = run / "public-result"
    manifest = parent / "MANIFEST.json"
    if sha(manifest) != PARENT_MANIFEST_SHA256:
        raise ValueError("original result manifest changed")
    entries = read(manifest)["entries"]
    for name, expected in entries.items():
        path = parent / name
        if path.parent != parent or path.stat().st_size != expected["bytes"] or sha(path) != expected["sha256"]:
            raise ValueError("original result artifact changed")
    return {"manifestSha256": sha(manifest), "verifiedOriginalFiles": len(entries)}


def public_inputs(run):
    known = read(run / "wallet-public/known-owner-evidence.json")
    operations = [read(run / f"wallet-public/operation-{i:02}.json") for i in range(1, 11)]
    kinds = [op["statement"]["kind"] for op in operations]
    if kinds != [1, 1, 2, 2, 2, 3, 3, 3, 3, 3]:
        raise ValueError("unsupported workload: correction retains the original finite model")
    initial = []
    for i, op in enumerate(operations[:2]):
        st = op["statement"]
        label = known["depositOwnerByPublicOwner"][bytes(st["deposit_owner"]).hex()]
        amount = st["deposit_value"]
        deposit = read(run / f"deposit-{'ab'[i]}-accepted.json")
        if deposit["transaction"]["outputs"][0]["value"] != amount:
            raise ValueError("credit and accepted native deposit amount differ")
        initial.append((label, units(amount)))
    terminal = [
        (known["exitOwnerByDestination"][bytes(op["statement"]["exit_destination"]).hex()], units(op["statement"]["exit_value"]))
        for op in operations[5:]
    ]
    if sum(v for _, v in initial) != sum(v for _, v in terminal):
        raise ValueError("terminal principal conservation differs")
    labels = ["deposit-a", "deposit-b"] + [f"publish-{i:02}" for i in range(1, 11)] + [f"payout-{i:02}" for i in range(1, 6)] + [f"batch-{i:02}-settlement" for i in range(1, 8)]
    bindings = {}
    for label in labels:
        path = run / f"{label}-accepted.json"
        record = read(path)
        if type(record["confirmed"]) is not int or record["confirmed"] < 10:
            raise ValueError("missing retained native confirmation")
        bindings[str(path.relative_to(run))] = sha(path)
    for i in range(1, 11):
        path = run / f"wallet-public/operation-{i:02}.json"
        bindings[str(path.relative_to(run))] = sha(path)
    owner_path = run / "wallet-public/known-owner-evidence.json"
    bindings[str(owner_path.relative_to(run))] = sha(owner_path)
    if len(set(initial)) != len(initial) or len({a for a, _ in initial}) != len(initial):
        raise ValueError("unsupported duplicate funding owner")
    return initial, terminal, kinds.count(2), bindings


def predict(run):
    parent = verify_parent(run)
    initial, terminal, steps, bindings = public_inputs(run)
    seq = candidates(initial, terminal, steps)
    if not seq:
        raise ValueError("no histories fit the retained finite model")
    return {
        "schema": "full-drainage-live-score-correction-v2",
        "parent": parent,
        "evidenceSha256ByRelativePath": bindings,
        "publicEvidenceDerivedModel": {"initialNotes": initial, "terminalNotes": terminal, "transferCount": steps, "amountUnitSompi": UNIT},
        "predictionReadsExecutionTruth": False,
        "plausibleKnownOwner": describe(seq),
        "conditionalRelationshipSensitivities": {
            f"{a}->{b}": {"relationshipAssumedKnown": [a, b], "provenance": "hypothetical additional external knowledge; not measured RPC/network evidence", **describe(condition(seq, (a, b)))}
            for a, b in EDGES
        },
        "oldStrongView": {"relationshipAssumedKnown": ["M", "S"], "retainedForTruthConsistencyValidation": True},
        "boundary": {
            "amountsOwnerMappingsTransferCountAndTerminalNotesConstrainEnumeration": True,
            "contactGraphAndAmountGridAreRetainedWorkloadAssumptions": True,
            "confirmationRecordsAreOfflineEvidenceNotFreshRPCVerification": True,
            "feesTimingSponsorBatchingAndPayloadShapesWereLoggedButNotUsedAsDiscriminatingLikelihoods": True,
            "serviceViewHasNoIndependentlyImplementedNetworkAttributionAttack": True,
            "cryptographicOpacityAssumedNotProved": True,
            "noGeneralAnonymityOrEqualPosteriorClaim": True,
            "nativeOwnerPayoutsAlsoIncludePermissionRentRefunds": True,
            "accountingAppliesOnlyToSuccessfulAttempt06NotEarlierTrials": True,
        },
    }


def private_execution(run, initial, terminal):
    # Only this validation phase may read the private workload. No keys or
    # witnesses are read. Publish validation flags, never this private object.
    path = run / "private/truth.json"
    if path.stat().st_mode & 0o077:
        raise ValueError("private truth permissions are not restricted")
    recorded = read(path)
    notes = list(map(tuple, initial))
    actual = []
    for row in recorded["payments"]:
        sender, recipient, input_sompi, payment_sompi = row
        input_value, payment_value = units(input_sompi), units(payment_sompi)
        if (sender, input_value) not in notes or payment_value >= input_value:
            raise ValueError("recorded payment sequence does not execute from observed deposits")
        notes.remove((sender, input_value))
        notes.extend(((sender, input_value - payment_value), (recipient, payment_value)))
        actual.append((sender, recipient, payment_value))
    if sorted(notes) != sorted(map(tuple, terminal)):
        raise ValueError("recorded payment history does not produce observed owner exits")
    return actual


def validate(run, directory):
    sealed = read(directory / "PREDICTIONS.json")
    if sha(directory / "PREDICTIONS.json") != (directory / "PREDICTIONS.sha256").read_text().strip():
        raise ValueError("prediction seal changed")
    # Recheck the same public-only projection before inspecting private truth.
    if canonical(predict(run)) != canonical(sealed):
        raise ValueError("public prediction inputs changed after seal")
    model = sealed["publicEvidenceDerivedModel"]
    seq = candidates(model["initialNotes"], model["terminalNotes"], model["transferCount"])
    actual = private_execution(run, model["initialNotes"], model["terminalNotes"])
    if len(actual) != model["transferCount"]:
        raise ValueError("recorded transfer count differs")
    baseline = assess(seq, actual)
    if not baseline["coupledExecutionTruthRetained"]:
        raise ValueError("baseline model excludes actual execution")
    return {
        "schema": "full-drainage-live-truth-validation-v2",
        "sealedPredictionsSha256": sha(directory / "PREDICTIONS.json"),
        "privateWorkloadReadOnlyAfterPredictionSeal": True,
        "privatePaymentsExecuteToObservedTerminalNotes": True,
        "truthFileIsRetainedExecutionMetadataNotIndependentlyReprovedWitness": True,
        "privateKeysBackupsOrWitnessesRead": False,
        "plausibleKnownOwner": baseline,
        "conditionalRelationshipSensitivities": {f"{a}->{b}": assess(condition(seq, (a, b)), actual, (a, b)) for a, b in EDGES},
        "priorStrongObserverSuccessClaimWithdrawnForThisRun": not assess(condition(seq, ("M", "S")), actual, ("M", "S"))["successfulReconstruction"],
        "newTruthConsistentSensitivitiesAreNotPrespecifiedAttacks": True,
        "terminalAccounting": read(run / "public-result/FINAL-CHECKPOINT.json")["accounting"],
        "originalEvidenceRecheckedUnchanged": verify_parent(run),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("predict", "validate"))
    parser.add_argument("run", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.stage == "predict":
        result = predict(args.run.resolve())
        args.output.mkdir(parents=True, exist_ok=False)
        write_new(args.output / "PREDICTIONS.json", result)
        with (args.output / "PREDICTIONS.sha256").open("x") as handle:
            handle.write(sha(args.output / "PREDICTIONS.json") + "\n")
        print(json.dumps({"predictionsSealed": True, "grossHistories": result["plausibleKnownOwner"]["grossHistoryCount"]}))
    else:
        result = validate(args.run.resolve(), args.output)
        write_new(args.output / "VALIDATION.json", result)
        print(json.dumps({"baselineTruthRetained": result["plausibleKnownOwner"]["coupledExecutionTruthRetained"], "oldStrongSuccessClaimWithdrawn": result["priorStrongObserverSuccessClaimWithdrawnForThisRun"]}))


if __name__ == "__main__":
    main()
