"""Reproduce public ownership and cost results; no private controller inputs."""
from pathlib import Path
import hashlib
import json
from fractions import Fraction
import observe
from check_reuse import check as check_reuse

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = ROOT / "research/payment-set-withdrawal-2026-11-05/run"


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    check_reuse()
    manifest = observe.read(PUBLIC / "MANIFEST.json")
    assert set(p.name for p in PUBLIC.iterdir()) == set(manifest["files"]) | {"MANIFEST.json"}
    for name, item in manifest["files"].items():
        p = (PUBLIC / name).resolve()
        assert p.is_relative_to(PUBLIC.resolve())
        assert p.stat().st_size == item["bytes"] and sha(p) == item["sha256"], name
    freeze = observe.read(PUBLIC / "FREEZE.json")
    for name, expected in freeze["files"].items():
        assert sha(ROOT / name) == expected, f"frozen source changed: {name}"
    seal = observe.read(PUBLIC / "PREDICTION-SEAL.json")
    for name, expected in seal["files"].items():
        assert sha(PUBLIC / name) == expected
    assert sha(Path(__file__).with_name("observe.py")) == seal["observerSha256"]
    baseline = observe.read(PUBLIC / "baseline.json")
    truth = {x["owner"]: x["recipientKey"] for x in baseline["identifiedOutputRegistrations"]}
    counts = {}
    for p in sorted(PUBLIC.glob("*-prediction.json")):
        name = p.name.replace("-prediction.json", "")
        result = observe.predict(observe.read(PUBLIC / f"{name}.json"))
        assert result == observe.read(p)
        assert truth in result["completeOwnershipAssignments"]
        counts[name] = result["assignmentCount"]
    validation = observe.read(PUBLIC / "VALIDATION.json")
    assert validation["predictionSealSha256"] == sha(PUBLIC / "PREDICTION-SEAL.json")
    assert counts == validation["counts"]
    x = observe.read(PUBLIC / "execution.json")
    assert x["finalReservePrincipalSompi"] == x["finalPrivateLiabilitySompi"] == x["finalUnpaidExits"] == 0
    cases = x["native"]["nativeCases"]
    assert len(cases) == 38 and sum(c["accepted"] for c in cases) == 8
    assert all(c["accepted"] == c["expectedAccept"] for c in cases)
    assert x["lifecycle"]["recipientRespend"] and x["lifecycle"]["restoredWalletsDiscoverFinalNotes"] == 3
    c = x["costs"]
    assert c["necessaryProofs"] == 6 and c["usefulPaymentsSompi"] == 3_000_000_000
    assert c["originalVerificationMassPerOperationFloor"] == 177500
    assert c["packedVerificationMassPerOperationFloor"] == 147500
    assert c["packedRouteFeeFloorAt100Sompi"] == 6 * 147500 * 100
    assert c["routeFeeFloorIncludingActualWithdrawalAt100Sompi"] == 48_000_000 + 3 * 147500 * 100
    assert c["routeFeeFloorIncludingActualWithdrawalAt100Sompi"] * 10000 > c["usefulPaymentsSompi"] * 200
    mass = x["native"]["jointMassQuote"]
    # Compute dominates both raw and normalized mass for this exact packet.
    assert mass["computeMass"] > mass["storageMass"]
    assert mass["computeMass"] > (mass["transientMass"] + 1) // 2
    assert mass["withinBlockComponentLimits"]
    assert c["withdrawalQuotedMass"] == mass["computeMass"]
    assert c["actualSyntheticWithdrawalFeeSompi"] >= c["withdrawalQuotedMass"] * 100
    assert 4 * c["packedVerificationMassPerOperationFloor"] > mass["blockComputeLimit"]
    assert not any(x[k] for k in ("newConsensusRules", "chainAcceptance", "fullNodeValidation", "networkPrivacyMeasured"))
    frontier = {
        "schema": "direct-route-cost-floor-frontier-v1",
        "scope": "arithmetic sensitivity only; no complete-route or paid-fee qualification",
        "usefulPaymentsSompi": c["usefulPaymentsSompi"],
        "floorBeforeOtherRouteCostsPercentAt100": float(Fraction(c["routeFeeFloorIncludingActualWithdrawalAt100Sompi"] * 100, c["usefulPaymentsSompi"])),
        "minimumFinalBalanceSompiFor2PercentFloorAt100": (c["routeFeeFloorIncludingActualWithdrawalAt100Sompi"] * 100 + 5) // 6,
        "feeRateFloorSensitivity": [{"sompiPerMass": rate, "sixProofsFeeFloorSompi": 6 * 147500 * rate, "fixedWithdrawalPlusOtherThreeProofsFloorSompi": 48_000_000 + 3 * 147500 * rate} for rate in (1, 10, 100)],
        "fullCostQualified": False,
    }
    assert frontier == observe.read(PUBLIC / "COST-FRONTIER.json")
    print(json.dumps({"ownershipAssignments": counts, "actualWalletAndNativeEvidenceVerified": True, "costFloorPercentAtHistoricalPrice": frontier["floorBeforeOtherRouteCostsPercentAt100"], "completeCostQualified": False}, indent=2))


if __name__ == "__main__":
    main()
