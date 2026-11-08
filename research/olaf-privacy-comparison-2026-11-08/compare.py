#!/usr/bin/env python3
"""Bounded offline amount-leakage screen for Olaf's published TN10 trial."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
UPSTREAM = "7ffe8353437604322f8bdd6e8d0c4f5b15a55ee1"
PINS = {
    "poc/recovery-tn10/live-2026-10-20/evidence/result.json": "26e13486d15ec2b0947d1bc4eb0f72f8b064a997133f2befb1d6178a304bb164",
    "poc/recovery-tn10/src/wallet.rs": "ad6da512c460fabe8b4d872238a5f32511e14b4be75e124b2a66319e45b5af60",
    "poc/recovery-tn10/live-2026-10-20/README.md": "036097e066519d61de3d39f81e814b68d2b3e7c330f02ac177af933697006d66",
    "poc/private-note-wallet/src/protocol.rs": "2593052d61b4997e5f3d66e768edcaab51b6a4c862afe1368aa19c6d36a5708b",
    "research/note-granularity-privacy-2026-11-08/PREDICTION.json": "d392ea489638af35c0440784e0df8ecb2e277e185a62a15d296571e45d474fc0",
    "research/note-granularity-privacy-2026-11-08/RESULT.json": "971979cd3fecc38f27284c80ba370ee8f01f56942c6bde614298b39310351a48",
    "local:poc/private-note-wallet/src/protocol.rs": "2bf0e6e9d22acc68c61121671beb3b2ff2332e15ff06a0b4b5d75e4a5a0b5526",
}
UPSTREAM_PATHS = {
    "poc/recovery-tn10/live-2026-10-20/evidence/result.json",
    "poc/recovery-tn10/src/wallet.rs",
    "poc/recovery-tn10/live-2026-10-20/README.md",
    "poc/private-note-wallet/src/protocol.rs",
}
SOMPI_PER_KAS = 100_000_000


def source(path, local=False):
    if path in UPSTREAM_PATHS and not local:
        data = subprocess.check_output(["git", "show", f"{UPSTREAM}:{path}"], cwd=ROOT)
    else:
        data = (ROOT / path).read_bytes()
    pin = f"local:{path}" if local else path
    assert hashlib.sha256(data).hexdigest() == PINS[pin], f"changed source: {pin}"
    return data


def full_drain_candidates(deposit, principal_exits, recipient_owner=None):
    """One depositor, one positive transfer, zero fee, two complete exits."""
    assert isinstance(deposit, int) and deposit > 0
    assert len(principal_exits) == 2
    assert all(isinstance(value, int) and value > 0 for value in principal_exits.values())
    assert sum(principal_exits.values()) == deposit, "reserve does not reconcile"
    if recipient_owner is None:
        return sorted(set(principal_exits.values()))
    assert recipient_owner in principal_exits
    return [principal_exits[recipient_owner]]


def public_inputs():
    result = json.loads(source("poc/recovery-tn10/live-2026-10-20/evidence/result.json"))
    protocol = source("poc/private-note-wallet/src/protocol.rs").decode()
    own_protocol = source("poc/private-note-wallet/src/protocol.rs", local=True).decode()
    for body in (protocol, own_protocol):
        assert "pub exit_destination: H" in body
        assert "pub exit_value: u64" in body
        assert "b.extend(self.exit_value.to_le_bytes())" in body
    readback = result["finalNativeReadback"]
    exits = {}
    for owner in ("alice", "bob"):
        principal = readback[f"{owner}PrincipalSompi"]
        rent = readback[f"{owner}PermissionRentRefundSompi"]
        payout = readback[f"{owner}PayoutSompi"]
        assert payout == principal + rent, "rent was included in principal"
        exits[owner] = principal
    assert readback["bothRecipientOutputsPresent"] is True
    assert result["finalCheckpoint"]["accounting"]["reserve_principal"] == 0
    assert result["finalCheckpoint"]["accounting"]["private_liability"] == 0
    accepted = result["nativeAcceptedTransactions"]
    for stage in ("deposit", "publish-alice-payment-transfer", "bob-payout", "alice-payout"):
        assert len(accepted[stage]["transactionId"]) == 64
        assert len(accepted[stage]["acceptedBlock"]) == 64
    assert result["retainedPrivateEvidence"]["ownerReceiveFilesAndPublicInputBodiesPublished"] is False
    return result, exits


def predict():
    result, exits = public_inputs()
    deposit = 10 * SOMPI_PER_KAS  # Fixed in SELECTION; checked against fixture only at score time.
    known = full_drain_candidates(deposit, exits, "bob")
    bare = full_drain_candidates(deposit, exits)
    assert known == [4 * SOMPI_PER_KAS]
    previous = json.loads(source("research/note-granularity-privacy-2026-11-08/PREDICTION.json"))
    prior_exact = previous["baselineWholeKAS"]["exactAmounts"]
    output = {
        "sourceCommit": UPSTREAM,
        "trial": result["trial"],
        "observer": "known depositor, payout owners, single directed contact and full drainage",
        "principalExitsSompi": exits,
        "permissionRentExcludedSompi": {
            owner: result["finalNativeReadback"][f"{owner}PermissionRentRefundSompi"]
            for owner in exits
        },
        "depositSompi": deposit,
        "knownOwnerPaymentCandidatesSompi": known,
        "bareStructuralPaymentCandidatesSompi": bare,
        "knownOwnerExactPayments": 1,
        "knownOwnerPaymentCount": 1,
        "ourMatchedFieldControlCandidatesSompi": known,
        "ourMatchedFieldControlExecuted": False,
        "ourExisting47KASExactPayments": len(prior_exact),
        "ourExisting47KASPaymentCount": 7,
        "ourExisting47KASWorkloadMatched": False,
        "preciseChainOnlyOwnershipScored": False,
    }
    (HERE / "PREDICTION.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


def score():
    prediction_bytes = (HERE / "PREDICTION.json").read_bytes()
    prediction = json.loads(prediction_bytes)
    source("research/note-granularity-privacy-2026-11-08/RESULT.json")
    actual_local = json.loads((ROOT / "research/note-granularity-privacy-2026-11-08/RESULT.json").read_text())
    assert actual_local["truthRetained"] is True
    assert len(actual_local["baselineExactActualAmounts"]) == prediction["ourExisting47KASExactPayments"]
    wallet_source = source("poc/recovery-tn10/src/wallet.rs").decode()
    readme = source("poc/recovery-tn10/live-2026-10-20/README.md").decode()
    match = re.search(r"Note::for_address\(&bob,\s*([0-9_]+)\)", wallet_source)
    assert match, "fixture transfer truth missing"
    truth = int(match.group(1).replace("_", ""))
    assert "Alice's final 6-KAS" in readme and "Bob's 4-KAS" in readme
    assert "st.exit_value = note.value" in wallet_source
    assert "st.exit_destination = chain::destination(&recipient)" in wallet_source
    assert truth in prediction["knownOwnerPaymentCandidatesSompi"]
    assert prediction["knownOwnerPaymentCandidatesSompi"] == [truth]
    assert prediction["ourMatchedFieldControlCandidatesSompi"] == [truth]
    assert prediction["bareStructuralPaymentCandidatesSompi"] == [400_000_000, 600_000_000]
    assert prediction["depositSompi"] == 10 * SOMPI_PER_KAS

    # Controls reject a rent-as-principal mistake, broken conservation and wrong truth.
    failed = 0
    for candidate_deposit, candidate_exits in (
        (prediction["depositSompi"], {"alice": 650_000_000, "bob": 450_000_000}),
        (prediction["depositSompi"], {"alice": 600_000_000, "bob": 300_000_000}),
    ):
        try:
            full_drain_candidates(candidate_deposit, candidate_exits, "bob")
        except AssertionError:
            failed += 1
    assert failed == 2
    assert 500_000_000 not in prediction["knownOwnerPaymentCandidatesSompi"]
    output = {
        "predictionSha256": hashlib.sha256(prediction_bytes).hexdigest(),
        "upstreamFixtureTruthSompi": truth,
        "publishedFixtureAmountKnownFromSource": True,
        "publishedFixtureRelationshipKnownFromSource": True,
        "knownOwnerAmountExact": True,
        "knownOwnerExactOfPayments": "1/1",
        "ourMatchedFieldControlExactOfPayments": "1/1 (counterfactual; no executed matched wallet trial)",
        "ourActual47KASExactOfPayments": "4/7 (different offline wallet workload)",
        "bareChainStructuralCandidatesOnly": prediction["bareStructuralPaymentCandidatesSompi"],
        "chainOnlyOwnershipUnmeasured": True,
        "decisiveComparison": "No demonstrated complete-lifecycle amount-privacy advantage on matched sparse full-drain field model",
        "controlsRejected": failed + 1,
        "truthRetained": True,
        "newNetworkTransaction": False,
        "consensusChange": False,
    }
    (HERE / "RESULT.json").write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    assert len(sys.argv) == 2 and sys.argv[1] in ("predict", "score")
    {"predict": predict, "score": score}[sys.argv[1]]()
