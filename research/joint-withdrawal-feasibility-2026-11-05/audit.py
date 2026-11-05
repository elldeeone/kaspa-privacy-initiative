#!/usr/bin/env python3
"""Read-only exposure audit of retained public withdrawals, not a new protocol.

No proof/signature verification, native validation, RPC, private truth or wallet
access occurs. The output-permutation control creates no transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE = ROOT / "research/full-drainage-executed-lifecycle-2026-11-01/run/tn10-attempt-06-public"
ARCHIVE_SHA256 = "3bd5d1c2dea949bb043bd94fe65da0a2182ab9e5f8e80ab05706227e08a670da"
OP_TAG = b"KPI-private-operation-v1\0"
PERMISSION_TAG = b"KPI-native-permission-v1\0"
PAYOUT_TAG = b"KPI-native-payout-v1\0"
RENT = 50_000_000
PUBLIC_LEN = 410
SOURCES = (
    "poc/private-note-wallet/src/protocol.rs",
    "poc/private-note-chain/common/src/lib.rs",
    "poc/recovery-native/common/src/lib.rs",
    "poc/recovery-native/common/src/restricted.rs",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def amount(value):
    require(type(value) is int and 0 < value <= (1 << 63) - 1, "positive signed-native-range integer sompi required")
    return value


def verify_archive(archive):
    manifest = archive / "ARCHIVE-MANIFEST.json"
    require(sha(manifest.read_bytes()) == ARCHIVE_SHA256, "archive manifest changed")
    entries = read(manifest)["entries"]
    for name, expected in entries.items():
        path = (archive / name).resolve()
        require(path.is_relative_to(archive.resolve()), "archive path escapes root")
        raw = path.read_bytes()
        require(len(raw) == expected["bytes"] and sha(raw) == expected["sha256"], f"archive file changed: {name}")
    return len(entries)


def transaction(archive, name):
    record = read(archive / name)
    tx = record["transaction"]
    require(record["transactionId"] == tx["verboseData"]["transactionId"], "transaction ID record mismatch")
    require(type(record["confirmed"]) is int and record["confirmed"] >= 10, "insufficient retained confirmations")
    return record["transactionId"], tx


def decode_exit(payload):
    require(payload.startswith(OP_TAG), "operation tag")
    offset = len(OP_TAG)
    require(len(payload) >= offset + 4, "truncated operation length")
    length = int.from_bytes(payload[offset:offset + 4], "little")
    require(length == PUBLIC_LEN + 128 and len(payload) == offset + 4 + length + 32, "EXIT framing/trailing bytes")
    statement = payload[offset + 4:offset + 4 + PUBLIC_LEN]
    require(statement[:2] == b"\x01\x03", "not version-one EXIT")
    key = payload[-32:]
    require(key != bytes(32), "zero native key")
    destination = statement[330:362]
    # vprogs StandardSpk::PubKey byte ABI: variant 0 || x-only key32.
    require(hashlib.sha256(b"\x00" + key).digest() == destination, "native key/destination mismatch")
    principal = amount(int.from_bytes(statement[362:370], "little"))
    amount(principal + RENT)
    intent = sha(b"KPI-intent-v1\0" + statement[2:34] + statement)
    return {
        "intentId": intent,
        "destinationHash": destination.hex(),
        "nativeKey": key.hex(),
        "principalSompi": principal,
        "nativeOutputSompi": principal + RENT,
        "scriptPublicKey": "000020" + key.hex() + "ac",
    }


def match_outputs(requests, outputs):
    """Derive links by public script bytes; amounts confirm, never assign owners."""
    links = {}
    used = set()
    for request in requests:
        matching = [i for i, output in enumerate(outputs)
                    if output["scriptPublicKey"] == request["scriptPublicKey"]]
        require(len(matching) == 1, "missing or ambiguous public recipient script")
        index = matching[0]
        require(index not in used, "reused output assignment")
        used.add(index)
        require(amount(outputs[index]["value"]) == request["nativeOutputSompi"], "retained payout amount/rent mismatch")
        require(request["intentId"] not in links, "duplicate request")
        links[request["intentId"]] = index
    return links


def audit(archive=ARCHIVE):
    checked = verify_archive(archive)
    requests = []
    publishes = {}
    permissions = {}
    payouts = []
    payout_records = []
    paths = []
    payout_inputs = set()
    owners = read(archive / "wallet-public/known-owner-evidence.json")["exitOwnerByDestination"]
    for i in range(5):
        publish_name = f"publish-{i + 6:02}-accepted.json"
        publish_id, publish = transaction(archive, publish_name)
        request = decode_exit(bytes.fromhex(publish["payload"]))
        requests.append(request)
        require(request["intentId"] not in publishes, "duplicate public request")
        publishes[request["intentId"]] = publish_id
    for i in range(5):
        permission_id, permission = transaction(archive, f"batch-{i + 2:02}-settlement-accepted.json")
        payload = bytes.fromhex(permission["payload"])
        require(payload.startswith(PERMISSION_TAG) and len(payload) == len(PERMISSION_TAG) + 32, "permission intent framing")
        intent = payload[len(PERMISSION_TAG):].hex()
        require(intent in publishes and intent not in permissions, "unknown or duplicate permission intent")
        permissions[intent] = {"transactionId": permission_id, "index": 1}
    for i in range(5):
        payout_id, payout = transaction(archive, f"payout-{i + 1:02}-accepted.json")
        require(len(payout["inputs"]) == 3 and len(payout["outputs"]) in (2, 3), "retained single-exit payout shape")
        for item in payout["inputs"]:
            old = item["previousOutpoint"]
            p = (old["transactionId"], old["index"])
            require(p not in payout_inputs, "reused native payout input")
            payout_inputs.add(p)
        payouts.append(payout["outputs"][0])
        payout_records.append((payout_id, payout))
    # Determine assignments by script bytes across the whole set before checking
    # ID tags/outpoints. File order and amount uniqueness supply no assignment.
    base = match_outputs(requests, payouts)
    for request in requests:
        payout_id, payout = payout_records[base[request["intentId"]]]
        point = permissions[request["intentId"]]
        require(bytes.fromhex(payout["payload"]) == PAYOUT_TAG + bytes.fromhex(request["intentId"]), "payout intent ID")
        require(payout["inputs"][0]["previousOutpoint"] == point, "payout spends a different permission")
        paths.append({
            "publicRequestTransactionId": publishes[request["intentId"]],
            "intentId": request["intentId"],
            "permissionOutpoint": point,
            "payoutOutpoint": {"transactionId": payout_id, "index": 0},
            "principalSompi": request["principalSompi"],
            "nativeOutputSompi": request["nativeOutputSompi"],
            "ownerWithSuppliedAuxiliaryMapping": owners.get(request["destinationHash"]),
        })
    require(len({r["intentId"] for r in requests}) == 5, "five distinct exits required")
    permutations_checked = 0
    for permutation in itertools.permutations(payouts):
        links = match_outputs(requests, permutation)
        require(all(permutation[links[r["intentId"]]]["scriptPublicKey"] == payouts[base[r["intentId"]]]["scriptPublicKey"] for r in requests), "permutation changed recipient linkage")
        permutations_checked += 1
    return {
        "schema": "joint-withdrawal-feasibility-audit-v1",
        "baseCommit": "00018b9898ae2f09c9bca59ede632aee54c940ec",
        "decision": "existing-exit-wrapper-fails-exposure-gate",
        "archiveManifestSha256": ARCHIVE_SHA256,
        "archiveFilesVerified": checked,
        "sourceFiles": {name: sha((ROOT / name).read_bytes()) for name in SOURCES},
        "publicRequestToPayoutLinks": len(base),
        "linksWithoutPermissionOrPayoutPayloadTags": len(base),
        "ownersKnownOnlyWithSuppliedMapping": sum(p["ownerWithSuppliedAuxiliaryMapping"] is not None for p in paths),
        "outputPermutationsChecked": permutations_checked,
        "allPermutationsRetainAllPublicRecipientLinks": True,
        "paths": paths,
        "conditionalCompleteLifecycleComparisonRun": False,
        "newCandidateNativeValidationRun": False,
        "cryptographicProofsGeneratedOrReverified": False,
        "limits": [
            "Historical hash-bound evidence; no fresh chain observation or independent consensus replay.",
            "Public request-to-script linkage alone does not identify a human owner.",
            "Output permutations are an exposure control, not valid joint transactions.",
            "No anonymous-registration or replacement common-set proof protocol was implemented.",
            "Failure of this wrapper does not establish impossibility of a redesigned current-L1 application.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="create a new public report; refuses overwrite")
    parser.add_argument("--check", type=Path, help="recompute and compare an existing report")
    args = parser.parse_args()
    require(not (args.output and args.check), "choose output or check")
    report = audit()
    if args.check:
        require(read(args.check) == report, "report differs from fresh public-evidence audit")
        print("Public withdrawal exposure audit: reproduced exactly; candidate comparison not run.")
    elif args.output:
        with args.output.open("x") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
