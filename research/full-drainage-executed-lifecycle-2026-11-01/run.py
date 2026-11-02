#!/usr/bin/env python3
"""Run two fresh wallet worlds through isolated wallet and replaceable relay processes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from cryptography.hazmat.primitives.asymmetric import ec


SELECTION_SHA256 = "3eab9d1f75aafbff8792efefbc47d6e7d12e22f82763112866cd5e3bc5369336"
LABELS = ("A", "B", "M", "S")
DEPOSITS = {"A": 100_000_000, "B": 100_000_000}
EXITS = (("A", 60_000_000), ("B", 80_000_000), ("M", 30_000_000), ("M", 20_000_000), ("S", 10_000_000))
WORLDS = {
    "H1": (
        ("A", "M", 100_000_000, 40_000_000),
        ("B", "M", 100_000_000, 20_000_000),
        ("M", "S", 40_000_000, 10_000_000),
    ),
    "H2": (
        ("A", "M", 100_000_000, 30_000_000),
        ("A", "S", 70_000_000, 10_000_000),
        ("B", "M", 100_000_000, 20_000_000),
    ),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: object, mode: int = 0o644) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(mode)


def run_json(command: list[str]) -> dict:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    if completed.stderr:
        sys.stderr.write(completed.stderr)
    return json.loads(completed.stdout)


class WalletWorker:
    def __init__(self, binary: Path, store: Path, parameters: Path, verifier: str):
        self.process = subprocess.Popen(
            [str(binary), "wallet-worker", str(store), str(parameters), verifier],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.process.stdout is not None
        raw = self.process.stdout.readline()
        if not raw:
            assert self.process.stderr is not None
            raise RuntimeError(self.process.stderr.read())
        self.ready = json.loads(raw)
        if "error" in self.ready:
            raise RuntimeError(self.ready["error"])

    def request(self, value: dict) -> dict:
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps(value, sort_keys=True) + "\n")
        self.process.stdin.flush()
        raw = self.process.stdout.readline()
        if not raw:
            assert self.process.stderr is not None
            raise RuntimeError(self.process.stderr.read())
        result = json.loads(raw)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result

    def stop(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.write("STOP\n")
        self.process.stdin.flush()
        self.process.wait(timeout=10)
        if self.process.returncode:
            assert self.process.stderr is not None
            raise RuntimeError(self.process.stderr.read())


class Relay:
    def __init__(self, script: Path, output: Path, instance: str):
        self.instance = instance
        self.output = output
        self.process = subprocess.Popen(
            [sys.executable, str(script), str(output), instance],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def send(self, operation: dict) -> dict:
        assert self.process.stdin is not None and self.process.stdout is not None
        request = {"relayToken": secrets.token_hex(16), "operation": operation}
        self.process.stdin.write(json.dumps(request, sort_keys=True) + "\n")
        self.process.stdin.flush()
        raw = self.process.stdout.readline()
        if not raw:
            assert self.process.stderr is not None
            raise RuntimeError(self.process.stderr.read())
        return json.loads(raw)

    def stop(self) -> dict:
        assert self.process.stdin is not None
        pid = self.process.pid
        self.process.stdin.close()
        self.process.wait(timeout=10)
        if self.process.returncode:
            assert self.process.stderr is not None
            raise RuntimeError(self.process.stderr.read())
        return {"serviceInstance": self.instance, "pid": pid, "exitCode": self.process.returncode}


def start_workers(binary: Path, stores: Path, parameters: Path, verifier: str) -> dict[str, WalletWorker]:
    workers = {label: WalletWorker(binary, stores / f"{label}.wallet", parameters, verifier) for label in LABELS}
    return workers


def stop_workers(workers: dict[str, WalletWorker]) -> None:
    for worker in workers.values():
        worker.stop()


def event_metadata(result: dict) -> dict:
    operation = result["operation"]
    statement = operation["statement"]
    return {
        "kind": statement["kind"],
        "domain": bytes(statement["domain"]).hex(),
        "verifier": bytes(statement["verifier"]).hex(),
        "anchor": bytes(statement["anchor"]).hex(),
        "nullifier": bytes(statement["nullifier"]).hex(),
        "outputCommitments": [bytes(item).hex() for item in statement["outputs"]],
        "deliveryHashes": [bytes(item).hex() for item in statement["delivery"]],
        "ciphertextBytes": [len(item["ciphertext"]) for item in operation["deliveries"]],
        "proofBytes": len(operation["proof"]),
        "wireBytes": result["wireBytes"],
        "wireSha256": result["wireSha256"],
        "statementId": result["statementId"],
        "exitValueSompi": statement["exit_value"],
        "exitDestination": bytes(statement["exit_destination"]).hex(),
        "feeSompi": statement["fee"],
    }


def run_world(
    world: str,
    alias: str,
    binary: Path,
    native_helper: Path,
    parameters: Path,
    vk: Path,
    verifier: str,
    relay_script: Path,
    public_root: Path,
    private_root: Path,
) -> dict:
    public = public_root / alias
    private = private_root / alias
    public.mkdir(mode=0o755)
    private.mkdir(mode=0o700)
    stores = private / "wallets"
    stores.mkdir(mode=0o700)
    workers = start_workers(binary, stores, parameters, verifier)
    addresses = {label: worker.ready for label, worker in workers.items()}
    ensure_new = all(not value["restored"] for value in addresses.values())
    if not ensure_new:
        raise RuntimeError("fresh wallet worker unexpectedly restored")

    deposit_specs = []
    deposit_owner_map = {}
    for deposit_index, (label, amount) in enumerate(DEPOSITS.items(), 1):
        owner = addresses[label]["owner"]
        native_deposit = public / f"native-deposit-{deposit_index:02}.bin"
        native = run_json(
            [
                str(native_helper),
                "deposit",
                owner,
                str(amount),
                str(0x20 + deposit_index),
                str(native_deposit),
            ]
        )
        deposit_id = native["reference"]
        deposit_specs.append({"id": deposit_id, "amountSompi": amount, "owner": owner})
        deposit_owner_map[owner] = label
    deposits_path = public / "deposits.json"
    write_json(deposits_path, deposit_specs)
    state_index = 0
    ledger = public / f"state-{state_index:02}.bin"
    init_summary = run_json([str(binary), "ledger-init", verifier, str(deposits_path), str(ledger)])

    events = []
    proof_seconds = 0.0
    default_relay = Relay(relay_script, public / "relay-default", "default")

    def apply_result(result: dict, relay: Relay) -> None:
        nonlocal ledger, state_index, proof_seconds
        ordinal = len(events) + 1
        proof_seconds += result["proofSeconds"]
        operation_path = public / f"operation-{ordinal:02}.json"
        write_json(operation_path, result["operation"])
        capture = relay.send(result["operation"])
        state_index += 1
        next_ledger = public / f"state-{state_index:02}.bin"
        application = run_json(
            [str(binary), "ledger-apply", str(vk), verifier, str(ledger), str(operation_path), str(next_ledger)]
        )
        event = {
            "schema": "full-drainage-executed-event-v1",
            "ordinal": ordinal,
            "serviceInstance": relay.instance,
            "serviceCapture": capture["capture"],
            "relayAcceptedMonotonicNs": capture["acceptedByRelayMonotonicNs"],
            "proofSeconds": result["proofSeconds"],
            "operationFile": operation_path.name,
            "application": application,
            "publicMetadata": event_metadata(result),
        }
        write_json(public / f"event-{ordinal:02}.json", event)
        events.append(event)
        ledger = next_ledger

    try:
        for label, deposit in zip(("A", "B"), deposit_specs, strict=True):
            result = workers[label].request(
                {"action": "credit", "ledgerPath": str(ledger), "deposit": deposit["id"], "valueSompi": deposit["amountSompi"]}
            )
            apply_result(result, default_relay)

        output_indices = [secrets.randbelow(2) for _ in range(3)]
        for index, (sender, recipient, input_value, amount) in enumerate(WORLDS[world]):
            result = workers[sender].request(
                {
                    "action": "transfer",
                    "ledgerPath": str(ledger),
                    "inputValueSompi": input_value,
                    "paymentSompi": amount,
                    "paymentOutputIndex": output_indices[index],
                    "recipientOwner": addresses[recipient]["owner"],
                    "recipientIncoming": addresses[recipient]["incoming"],
                }
            )
            apply_result(result, default_relay)
    finally:
        default_stop = default_relay.stop()
        stop_workers(workers)

    payment_state = ledger
    stopped_at = time.monotonic_ns()
    restored = start_workers(binary, stores, parameters, verifier)
    for label in LABELS:
        if not restored[label].ready["restored"]:
            raise RuntimeError("wallet recovery did not restore")
        if restored[label].ready["owner"] != addresses[label]["owner"]:
            raise RuntimeError("wallet recovery address mismatch")

    exit_destinations = []
    prepared_exits = []
    for label, value in EXITS:
        native_key = ec.generate_private_key(ec.SECP256K1())
        native_secret = native_key.private_numbers().private_value.to_bytes(32, "big").hex()
        native_pubkey = native_key.public_key().public_numbers().x.to_bytes(32, "big")
        destination = hashlib.sha256(b"\x00" + native_pubkey).hexdigest()
        exit_destinations.append(
            {
                "destination": destination,
                "nativePubkey": native_pubkey.hex(),
                "owner": label,
                "amountSompi": value,
                "nativeSecret": native_secret,
            }
        )
        prepared_exits.append(
            (
                label,
                value,
                destination,
                native_pubkey.hex(),
                restored[label].request(
                    {
                        "action": "exit",
                        "ledgerPath": str(payment_state),
                        "inputValueSompi": value,
                        "exitDestination": destination,
                    }
                ),
            )
        )

    replacement = Relay(relay_script, public / "relay-replacement", "replacement")
    payout_records = []
    try:
        for label, value, destination, native_pubkey, result in prepared_exits:
            apply_result(result, replacement)
            native_output = secrets.token_hex(32)
            state_index += 1
            next_ledger = public / f"state-{state_index:02}.bin"
            payout = run_json(
                [
                    str(binary),
                    "ledger-payout",
                    str(ledger),
                    result["statementId"],
                    str(value),
                    destination,
                    native_output,
                    str(next_ledger),
                ]
            )
            payout_record = {
                "exitStatementId": result["statementId"],
                "amountSompi": value,
                "destination": destination,
                "nativePubkey": native_pubkey,
                "nativeOutput": native_output,
                "accounting": payout,
            }
            payout_records.append(payout_record)
            write_json(public / f"payout-{len(payout_records):02}.json", payout_record)
            ledger = next_ledger
    finally:
        replacement_stop = replacement.stop()
        stop_workers(restored)

    final_summary = run_json([str(binary), "ledger-summary", str(ledger)])
    for key in ("reserveSompi", "privateLiabilitySompi", "pendingDepositSompi", "unpaidExitSompi"):
        if final_summary[key] != 0:
            raise RuntimeError(f"nonzero final {key}")
    if final_summary["paidNativeOutputs"] != 5:
        raise RuntimeError("not all local payout fixtures confirmed")
    exit_anchor_set = {
        event_metadata(result)["anchor"] for _, _, _, _, result in prepared_exits
    }
    if len(exit_anchor_set) != 1:
        raise RuntimeError("exits were not prepared against one common recovery state")

    identity_evidence = {
        "schema": "full-drainage-known-owner-evidence-v1",
        "depositOwnerByPublicOwner": deposit_owner_map,
        "exitOwnerByDestination": {item["destination"]: item["owner"] for item in exit_destinations},
    }
    write_json(public / "known-owner-evidence.json", identity_evidence)
    write_json(
        public / "native-exits.json",
        [
            {
                "destination": item["destination"],
                "nativePubkey": item["nativePubkey"],
                "amountSompi": item["amountSompi"],
            }
            for item in exit_destinations
        ],
    )
    service_loss = {
        "schema": "full-drainage-service-loss-v1",
        "defaultRelay": default_stop,
        "defaultStoppedBeforeRecoveryMonotonicNs": str(stopped_at),
        "walletWorkersStoppedAfterPayments": True,
        "walletBackupsRestored": 4,
        "allExitProofsPreparedAgainstOnePreExitState": True,
        "commonExitAnchor": next(iter(exit_anchor_set)),
        "replacementRelay": replacement_stop,
        "sameHost": True,
        "independentHostsOrHumans": False,
    }
    write_json(public / "service-loss.json", service_loss)
    receipt = {
        "schema": "full-drainage-executed-world-receipt-v1",
        "alias": alias,
        "verifier": verifier,
        "depth": 4,
        "credits": 2,
        "transfers": 3,
        "exits": 5,
        "confirmedLocalPayoutFixtures": 5,
        "walletProofSeconds": proof_seconds,
        "events": len(events),
        "serviceLoss": service_loss,
        "initialAccounting": init_summary,
        "finalAccounting": final_summary,
        "publicOperationFiles": [event["operationFile"] for event in events],
        "nativeSettlement": False,
        "evidenceBoundary": "genuine wallet proofs and local atomic ledger; authenticated native deposit/payout fixtures only",
    }
    write_json(public / "run-receipt.json", receipt)
    private_truth = {
        "world": world,
        "alias": alias,
        "payments": WORLDS[world],
        "paymentOutputIndices": output_indices,
        "addresses": addresses,
        "exitDestinations": exit_destinations,
    }
    write_json(private / "truth.json", private_truth, 0o600)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--native-helper", required=True, type=Path)
    parser.add_argument("--public-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--setup-public-source", type=Path)
    parser.add_argument("--parameters-source", type=Path)
    args = parser.parse_args()
    selection = Path(__file__).with_name("SELECTION.md")
    if sha256(selection) != SELECTION_SHA256:
        raise SystemExit("selection hash changed")
    if args.public_root.exists() or args.private_root.exists():
        raise SystemExit("run output exists")
    args.public_root.mkdir(mode=0o755, parents=True)
    args.private_root.mkdir(mode=0o700, parents=True)
    common = args.private_root / "common"
    common.mkdir(mode=0o700)
    parameters = common / "parameters.bin"
    vk = args.public_root / "verifying-key.bin"
    vk_uncompressed = args.public_root / "verifying-key-uncompressed.bin"
    if (args.setup_public_source is None) != (args.parameters_source is None):
        raise SystemExit("setup public source and parameters source must be supplied together")
    if args.setup_public_source is not None:
        shutil.copyfile(args.parameters_source, parameters)
        shutil.copyfile(args.setup_public_source / "verifying-key.bin", vk)
        shutil.copyfile(
            args.setup_public_source / "verifying-key-uncompressed.bin", vk_uncompressed
        )
        setup = json.loads((args.setup_public_source / "setup.json").read_text())
    else:
        setup = run_json(
            [str(args.binary), "setup", str(parameters), str(vk), str(vk_uncompressed)]
        )
    write_json(args.public_root / "setup.json", setup)
    verifier = setup["verifier"]
    worlds = list(WORLDS)
    secrets.SystemRandom().shuffle(worlds)
    aliases = [f"trial-{secrets.token_hex(8)}" for _ in worlds]
    mapping = dict(zip(aliases, worlds, strict=True))
    write_json(args.private_root / "world-aliases.json", mapping, 0o600)
    relay_script = Path(__file__).with_name("relay.py")
    receipts = []
    started = time.monotonic()
    for alias, world in mapping.items():
        receipts.append(
            run_world(
                world,
                alias,
                args.binary.resolve(),
                args.native_helper.resolve(),
                parameters.resolve(),
                vk.resolve(),
                verifier,
                relay_script.resolve(),
                args.public_root,
                args.private_root,
            )
        )
    public_summary = {
        "schema": "full-drainage-executed-lifecycle-summary-v1",
        "selectionSha256": SELECTION_SHA256,
        "verifier": verifier,
        "trialAliases": aliases,
        "worldCount": 2,
        "allFinalPrincipalAccountingZero": all(
            all(receipt["finalAccounting"][key] == 0 for key in ("reserveSompi", "privateLiabilitySompi", "pendingDepositSompi", "unpaidExitSompi"))
            for receipt in receipts
        ),
        "allWalletsRestored": all(receipt["serviceLoss"]["walletBackupsRestored"] == 4 for receipt in receipts),
        "allExitsPreparedFromCommonRecoveryState": all(receipt["serviceLoss"]["allExitProofsPreparedAgainstOnePreExitState"] for receipt in receipts),
        "totalWalletProofSeconds": sum(receipt["walletProofSeconds"] for receipt in receipts),
        "wallSeconds": time.monotonic() - started,
        "nativeSettlement": False,
    }
    write_json(args.public_root / "summary.json", public_summary)
    print(json.dumps(public_summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
