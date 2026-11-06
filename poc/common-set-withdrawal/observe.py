#!/usr/bin/env python3
"""Finite payout-owner inference from one complete, declared observation only.

RSA blindness, Groth16 zero knowledge and independent recipient keys are model
assumptions. This enumerator is not a cryptanalytic attack or network test.
"""
import argparse
from collections import Counter
import hashlib
import itertools
import json
from pathlib import Path

TAG = b"KPI-output-registration-v1\0"
MODE = b"RFC9474-RSABSSA-SHA384-PSS-Randomized"


def require(value, message):
    if not value:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, "duplicate JSON key")
            out[k] = v
        return out
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs)


def predict(view):
    require(set(view) <= {"schema", "observer", "mode", "issuerDer", "issuerFingerprint", "round", "denominationSompi", "owners", "events", "explicitOwnerLinks", "network", "native", "previouslyPublishedIndividualExits", "identifiedOutputRegistrations"}, "unreviewed observation field")
    require(view["schema"] == "common-set-observation-v1", "observation schema")
    require(view["mode"].encode() == MODE, "issuer mode")
    require(digest(MODE + bytes.fromhex(view["issuerDer"])) == view["issuerFingerprint"], "common issuer identity")
    owners = view["owners"]
    require(len(owners) == 3 and len(set(owners)) == 3, "three distinct input owners")
    denomination = view["denominationSompi"]
    require(type(denomination) is int and 0 < denomination < 2**63, "integer sompi")
    issues = [e for e in view["events"] if e["kind"] == "issue"]
    redeems = [e for e in view["events"] if e["kind"] == "redeem"]
    require(len(issues) + len(redeems) == len(view["events"]), "unreviewed event kind")
    require(all(set(e) <= {"kind", "owner", "claim", "context", "tag", "proof", "blindMessage", "blindSignature", "leakedRandomizer"} for e in issues), "unreviewed issuance field")
    require(all(set(e) <= {"kind", "message", "signature", "randomizer", "recipientKey", "valueSompi", "owner"} for e in redeems), "unreviewed redemption field")
    require(len(issues) == len(redeems) == 3, "complete fixed round")
    require({e["owner"] for e in issues} == set(owners), "eligible owners")
    require([e["kind"] for e in view["events"]] == ["issue"] * 3 + ["redeem"] * 3, "round-wide issuance barrier")
    keys = sorted(e["recipientKey"] for e in redeems)
    require(len(set(keys)) == 3, "distinct real recipient keys")
    for e in redeems:
        msg = bytes.fromhex(e["message"])
        expected = TAG + bytes.fromhex(view["round"]) + bytes.fromhex(view["issuerFingerprint"]) + denomination.to_bytes(8, "little") + bytes.fromhex(e["recipientKey"])
        require(msg == expected and e["valueSompi"] == denomination, "redemption context")
    native = view["native"]
    require(set(native) == {"version", "subnetwork", "lockTime", "gas", "payload", "inputs", "outputs", "activePublicClaims", "policyRedeemScript"}, "unreviewed native field")
    require(all(set(i) == {"transactionId", "index", "sequence", "computeBudget", "sigOpCount", "signatureScript"} for i in native["inputs"]), "unreviewed input field")
    require(all(set(o) == {"scriptPublicKey", "valueSompi", "covenant"} for o in native["outputs"]), "unreviewed output field")
    require(all(i["computeBudget"] == 4800 and i["sigOpCount"] is None and i["sequence"] == 0 for i in native["inputs"]), "fixed native compute/sequence profile")
    require(all(o["covenant"] is None for o in native["outputs"]), "unexpected native covenant metadata")
    require(native["payload"] == "" and native["lockTime"] == native["gas"] == 0, "native metadata")
    require(Counter((o["scriptPublicKey"], o["valueSompi"]) for o in native["outputs"]) == Counter(("000020" + k + "ac", denomination) for k in keys), "registered keys must be actual native outputs")
    require({e["claim"] for e in issues} == set(native["activePublicClaims"]), "public input-claim identities")
    links = []
    for item in view.get("identifiedOutputRegistrations", []):
        message=bytes.fromhex(item["message"])
        expected=TAG+bytes.fromhex(view["round"])+bytes.fromhex(view["issuerFingerprint"])+denomination.to_bytes(8,"little")+bytes.fromhex(item["recipientKey"])
        require(message==expected,"identified registration context")
        links.append((item["owner"],item["recipientKey"],"identified output registration API"))
    for item in view.get("explicitOwnerLinks", []):
        links.append((item["owner"], item["recipientKey"], "declared participant/external fact"))
    for item in view.get("previouslyPublishedIndividualExits", []):
        links.append((item["owner"], item["recipientKey"], "earlier public exit"))
    for e in redeems:
        if "owner" in e:
            links.append((e["owner"], e["recipientKey"], "redemption origin echoed"))
    for issue in issues:
        if "leakedRandomizer" in issue:
            matching = [e for e in redeems if e["randomizer"] == issue["leakedRandomizer"]]
            require(len(matching) == 1, "leaked randomizer consistency")
            links.append((issue["owner"], matching[0]["recipientKey"], "identified issuance randomizer"))
    require(all(owner in owners and key in keys for owner, key, _ in links), "unknown owner/output in side information")
    assignments = []
    for values in itertools.permutations(keys):
        mapping = dict(zip(owners, values))
        if all(mapping[owner] == key for owner, key, _ in links):
            assignments.append(mapping)
    require(assignments, "contradictory observations exclude every complete history")
    by_output = {key: sorted({owner for mapping in assignments for owner in owners if mapping[owner] == key}) for key in keys}
    return {
        "schema": "common-set-ownership-prediction-v1",
        "observationSha256": digest(canonical(view)),
        "completeOwnershipAssignments": assignments,
        "assignmentCount": len(assignments),
        "possibleOwnersByActualOutputKey": by_output,
        "uniquelyAttributedOutputs": sum(len(v) == 1 for v in by_output.values()),
        "explicitLinkSources": sorted({source for _, _, source in links}),
        "cryptographicPropertiesAssumed": True,
        "networkAnonymityMeasured": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    parser.add_argument("prediction", type=Path)
    args = parser.parse_args()
    result = predict(read(args.observation))
    with args.prediction.open("x") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
