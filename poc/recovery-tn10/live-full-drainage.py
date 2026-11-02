#!/usr/bin/env python3
"""Finite local-node orchestration for the depth-four TN10 trial."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
RUN = Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None
if RUN is None or not RUN.is_dir():
    raise SystemExit("usage: live-full-drainage.py ACTION PRIVATE_RUN [ARG]")
TRIAL_DIR = RUN / "trial"
TRIAL_PATH = TRIAL_DIR / "trial.json"
TRIAL = json.loads(TRIAL_PATH.read_text())
SPONSOR = TRIAL["sponsorNative"]["address"]
RECOVERY = ROOT / ".local/ci-target/release/kpi-recovery-tn10"
NATIVE = ROOT / ".local/ci-target/release/kpi-full-drainage-native"
VALIDATOR = ROOT / ".local/ci-target/release/kpi-tn10-integration"
VALIDATOR_SHA = "1e0b13e2f686b86a2f0d3b76fd494e27413b963294bcd10ff7778599f33c5a64"
CHAIN = ROOT / "poc/recovery-tn10/live-chain.mjs"
CAPTURE = ROOT / "poc/tn10-live/capture.mjs"
ADDRESS = ROOT / "poc/recovery-tn10/script-address.mjs"
RUNNER = ROOT / "research/full-drainage-executed-lifecycle-2026-11-01/runner/target/release/full-drainage-executed-lifecycle-runner"
VK = ROOT / "research/full-drainage-executed-lifecycle-2026-11-01/tn10-depth4-preparation/wallet-public/verifying-key.bin"
PARAMETERS = Path("/var/tmp/kpi-tn10-full-drainage-20261101-v3/private/common/parameters.bin")
SOURCE_PRIVATE = Path("/var/tmp/kpi-tn10-full-drainage-20261101-v3/private/trial-a23e64a6a381f127")
PROGRAM = RUN / "guest/guest.program.bin"
RISC0_CARGO = Path("/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/risc0-rust/bin/cargo")
R0VM_DIR = Path("/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools")
LANE_KEY = "e94e9720ed1aaca48f921aa5b15e4ebb02abc181a0149f57a2cf361e521ab86b"
VERIFIER = "97ef3a85e5d03956150f9802d42697a8dcbb338a32a30efc811d1b3898157e32"
ZERO = "00" * 32


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read(path: Path) -> dict:
    return json.loads(path.read_text())


def write(path: Path, value: object, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    os.fsync(directory)
    os.close(directory)


def command(*args: object, capture_output: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        text=True,
        capture_output=capture_output,
    )
    if result.returncode:
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        raise RuntimeError(f"command failed: {args[0]}")
    return result


def command_json(*args: object) -> dict:
    result = command(*args)
    if result.stderr:
        sys.stderr.write(result.stderr)
    return json.loads(result.stdout)


def query(label: str, addresses: list[str]) -> dict:
    return command_json("node", CHAIN, "query", RUN, label, json.dumps(addresses))


def block(label: str, block_hash: str) -> dict:
    return command_json("node", CHAIN, "block", RUN, label, block_hash)


def output_address(record: Path, index: int) -> str:
    return command("node", ADDRESS, record, index).stdout.strip()


def sponsor(snapshot: dict) -> dict:
    candidates = [
        entry
        for entry in snapshot["utxos"]["entries"]
        if entry["address"] == SPONSOR and entry["utxoEntry"]["covenantId"] is None
    ]
    if not candidates:
        raise RuntimeError("fresh sponsor has no ordinary fee UTXO")
    return max(candidates, key=lambda entry: int(entry["utxoEntry"]["amount"]))


def build(label: str, kind: str, fields: dict, addresses: list[str] | None = None) -> Path:
    snapshot = query(label, [SPONSOR, *(addresses or [])])
    request = {
        "trial": TRIAL["trial"],
        "kind": kind,
        "server": snapshot["server"],
        "sponsorUtxo": sponsor(snapshot),
        "feeRateSompiPerGram": 100,
        **fields,
    }
    request_path = RUN / f"{label}-request.json"
    write(request_path, request)
    output = RUN / f"{label}-build"
    command(RECOVERY, "build", TRIAL_PATH, request_path, TRIAL_DIR / "sponsor/native.key", output)
    return output


def submit(label: str, output: Path) -> dict:
    record = read(output / "transaction.json")
    request = read(output / "request.json")
    supplied = {
        (value["outpoint"]["transactionId"], value["outpoint"]["index"]): value
        for key, value in request.items()
        if key.endswith("Utxo")
    }
    entries = [
        supplied[(item["previousOutpoint"]["transactionId"], item["previousOutpoint"]["index"])]
        for item in record["transaction"]["inputs"]
    ]
    envelope = RUN / f"{label}-submit.json"
    write(envelope, {"record": record, "entries": entries, "qualification": record["qualification"]})
    command("node", CHAIN, "submit", RUN, label, envelope, capture_output=False)
    return read(RUN / f"{label}-accepted.json")


def capture(label: str, start: str | None = None, end: str | None = None) -> Path:
    output = RUN / f"{label}-capture.json"
    args: list[object] = ["node", "--max-old-space-size=16384", CAPTURE, output, LANE_KEY, 50]
    if start is not None:
        if end is None:
            raise RuntimeError("fixed capture needs an end")
        args.extend([start, end])
    result = command(*args)
    if result.stdout:
        print(result.stdout.strip())
    return output


def freeze(stage: str, checkpoint: Path, accepted: dict) -> Path:
    capture_path = capture(stage, read(checkpoint)["nextCaptureStart"], accepted["header"]["hash"])
    output = RUN / stage
    command(RECOVERY, "freeze", VALIDATOR, VALIDATOR_SHA, PROGRAM, stage, capture_path, checkpoint, output)
    return output


def current_wallet_state() -> tuple[int, Path]:
    states = sorted((RUN / "wallet-public").glob("state-*.bin"))
    if not states:
        raise RuntimeError("wallet mirror not initialized")
    latest = states[-1]
    return int(latest.stem.split("-")[1]), latest


class WalletWorker:
    def __init__(self, label: str):
        self.label = label
        self.process = subprocess.Popen(
            [str(RUNNER), "wallet-worker", str(RUN / f"private/wallets/{label}.wallet"), str(PARAMETERS), VERIFIER],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        assert self.process.stdout is not None
        self.ready = json.loads(self.process.stdout.readline())
        expected = TRIAL["wallets"][label]
        if self.ready.get("owner") != expected["owner"] or self.ready.get("incoming") != expected["incoming"]:
            raise RuntimeError(f"wallet {label} identity mismatch")

    def prove(self, request: dict) -> dict:
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.write(json.dumps(request, sort_keys=True) + "\n")
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        if "error" in response:
            raise RuntimeError(response["error"])
        return response

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


def publish_operation(ordinal: int, worker: WalletWorker, request: dict, native_pubkey: str = ZERO) -> dict:
    public = RUN / "wallet-public"
    state_index, ledger = current_wallet_state()
    request = {**request, "ledgerPath": str(ledger)}
    result = worker.prove(request)
    operation = public / f"operation-{ordinal:02}.json"
    write(operation, result["operation"])
    write(public / f"operation-{ordinal:02}-proof.json", {key: value for key, value in result.items() if key != "operation"})
    payload = public / f"operation-{ordinal:02}-payload.json"
    command(NATIVE, "encode-operation", operation, native_pubkey, payload)
    output = build(f"publish-{ordinal:02}", "publish", {"operationPayloadHex": read(payload)["operationPayloadHex"]})
    accepted = submit(f"publish-{ordinal:02}", output)
    next_ledger = public / f"state-{state_index + 1:02}.bin"
    application = command_json(RUNNER, "ledger-apply", VK, VERIFIER, ledger, operation, next_ledger)
    write(public / f"operation-{ordinal:02}-application.json", application)
    return accepted


def reconcile_wallet_payout(ordinal: int, transaction_id: str) -> None:
    public = RUN / "wallet-public"
    operation = read(public / f"operation-{ordinal:02}.json")
    statement = operation["statement"]
    exit_id = read(public / f"operation-{ordinal:02}-payload.json")["operationId"]
    native = command_json(NATIVE, "deposit-reference", transaction_id, 0)["reference"]
    state_index, ledger = current_wallet_state()
    next_ledger = public / f"state-{state_index + 1:02}.bin"
    report = command_json(
        RUNNER,
        "ledger-payout",
        ledger,
        exit_id,
        statement["exit_value"],
        bytes(statement["exit_destination"]).hex(),
        native,
        next_ledger,
    )
    write(public / f"payout-{ordinal - 5:02}-application.json", report)


def settlement(stage: str) -> dict:
    number = int(stage.split("-")[1])
    target_dir = RUN / stage
    target_path = target_dir / "target.json"
    target = read(target_path)
    previous_record = RUN / ("initialize-build" if number == 1 else f"batch-{number - 1:02}-settlement-build") / "transaction.json"
    state_address = output_address(previous_record, 0)
    snapshot = query(f"{stage}-settlement-state", [state_address])
    state_point = target["stateOutpoint"]
    state_utxo = next(entry for entry in snapshot["utxos"]["entries"] if entry["outpoint"] == state_point)
    anchor = block(f"{stage}-anchor", target["endBlock"])
    fields = {
        "targetPath": str(target_path),
        "targetSha256": sha256(target_path),
        "receiptPath": str(target_dir / "receipt/receipt.bin"),
        "stateUtxo": state_utxo,
        "anchorBlock": anchor,
        "selectedParentBlock": snapshot["sinkBlock"],
    }
    output = build(f"{stage}-settlement", "settlement", fields, [state_address])
    accepted = submit(f"{stage}-settlement", output)
    acceptance = capture(f"{stage}-settlement-acceptance", target["endBlock"], accepted["header"]["hash"])
    checkpoint = RUN / f"{stage}-checkpoint"
    command(RECOVERY, "checkpoint", VALIDATOR, VALIDATOR_SHA, acceptance, output / "transaction.json", target_path, checkpoint)
    return accepted


def payout(exit_ordinal: int) -> dict:
    stage_number = exit_ordinal + 1
    stage = f"batch-{stage_number:02}"
    state_path = RUN / stage / "state.bin"
    inspected = command_json(RECOVERY, "inspect-state", state_path)
    if len(inspected["unpaidExits"]) != 1:
        raise RuntimeError("payout requires one open exit")
    exit_row = inspected["unpaidExits"][0]
    permission_record = RUN / f"{stage}-settlement-build/transaction.json"
    permission_address = output_address(permission_record, 1)
    reserve_record = RUN / "deposit-a-build/transaction.json"
    reserve_address = output_address(reserve_record, 0)
    snapshot = query(f"payout-{exit_ordinal:02}-inputs", [permission_address, reserve_address])
    entries = snapshot["utxos"]["entries"]
    permission_point = read(permission_record)["transactionId"]
    permission = next(entry for entry in entries if entry["outpoint"] == {"transactionId": permission_point, "index": 1})
    reserve = next(entry for entry in entries if entry["outpoint"] == exit_row["reserveOutpoint"])
    fields = {
        "publicStatePath": str(state_path),
        "exitId": exit_row["exitId"],
        "permissionTransactionPath": str(permission_record),
        "permissionUtxo": permission,
        "reserveUtxo": reserve,
    }
    output = build(f"payout-{exit_ordinal:02}", "payout", fields, [permission_address, reserve_address])
    accepted = submit(f"payout-{exit_ordinal:02}", output)
    reconcile_wallet_payout(exit_ordinal + 5, read(output / "transaction.json")["transactionId"])
    return accepted


def setup() -> None:
    os.chmod(RUN, 0o700)
    private = RUN / "private"
    wallets = private / "wallets"
    public = RUN / "wallet-public"
    private.mkdir(mode=0o700)
    wallets.mkdir(mode=0o700)
    public.mkdir(mode=0o700)
    for label in ("A", "B", "M", "S"):
        target = wallets / f"{label}.wallet"
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write((SOURCE_PRIVATE / f"wallets/{label}.wallet").read_bytes())
    truth = read(SOURCE_PRIVATE / "truth.json")
    if any(
        truth["addresses"][label][field] != TRIAL["wallets"][label][field]
        for label in ("A", "B", "M", "S")
        for field in ("owner", "incoming")
    ):
        raise RuntimeError("fresh trial participants differ from retained wallet backups")
    write(private / "truth.json", truth)
    write(
        RUN / "live-config.json",
        {
            "trial": TRIAL["trial"],
            "verifier": VERIFIER,
            "parametersSha256": sha256(PARAMETERS),
            "validatorSha256": sha256(VALIDATOR),
            "recoveryBinarySha256": sha256(RECOVERY),
            "nativeHelperSha256": sha256(NATIVE),
            "runnerSha256": sha256(RUNNER),
            "walletBackupSource": str(SOURCE_PRIVATE),
            "testnetOnly": True,
        },
    )


def observer_evidence() -> None:
    truth = read(RUN / "private/truth.json")
    write(
        RUN / "wallet-public/known-owner-evidence.json",
        {
            "schema": "full-drainage-known-owner-evidence-v1",
            "depositOwnerByPublicOwner": {
                TRIAL["wallets"][label]["owner"]: label for label in ("A", "B")
            },
            "exitOwnerByDestination": {
                item["destination"]: item["owner"] for item in truth["exitDestinations"]
            },
            "scope": "frozen known-owner observer input; no wallet secrets",
        },
    )


def initialize_wallet_mirror() -> None:
    deposits = []
    for label in ("A", "B"):
        record = read(RUN / f"deposit-{label.lower()}-build/transaction.json")
        reference = command_json(NATIVE, "deposit-reference", record["transactionId"], 0)["reference"]
        deposits.append({"id": reference, "amountSompi": 100_000_000, "owner": TRIAL["wallets"][label]["owner"]})
    public = RUN / "wallet-public"
    write(public / "deposits.json", deposits)
    command(RUNNER, "ledger-init", VERIFIER, public / "deposits.json", public / "state-00.bin")


def deposit(label: str) -> dict:
    initialize_record = RUN / "initialize-build/transaction.json"
    state_address = output_address(initialize_record, 0)
    snapshot = query(f"deposit-{label.lower()}-state", [state_address])
    transaction_id = read(initialize_record)["transactionId"]
    state_utxo = next(entry for entry in snapshot["utxos"]["entries"] if entry["outpoint"] == {"transactionId": transaction_id, "index": 0})
    output = build(
        f"deposit-{label.lower()}",
        "deposit",
        {
            "covenantId": read(initialize_record)["details"]["covenantId"],
            "checkpointPath": str(RUN / "initialize-checkpoint/checkpoint.json"),
            "stateUtxo": state_utxo,
            "depositLabel": label,
            "depositAmountSompi": 100_000_000,
        },
        [state_address],
    )
    return submit(f"deposit-{label.lower()}", output)


def prove(stage: str) -> None:
    target = RUN / stage / "target.json"
    output = RUN / stage / "receipt"
    prover_binary = R0VM_DIR / ("r0vm-cuda" if stage in {f"batch-{number:02d}" for number in range(1, 7)} else "r0vm")
    if not prover_binary.is_file():
        raise RuntimeError("selected local prover is unavailable")
    prover_path = RUN / f"private/{prover_binary.name}-bin"
    prover_path.mkdir(mode=0o700, exist_ok=True)
    launcher = prover_path / "r0vm"
    if not launcher.exists():
        launcher.symlink_to(prover_binary)
    if launcher.resolve() != prover_binary.resolve():
        raise RuntimeError("prover launcher mismatch")
    environment = os.environ.copy()
    environment["RISC0_PROVER"] = "ipc"
    environment["PATH"] = f"{prover_path}:{environment['PATH']}"
    result = subprocess.run(
        [str(RECOVERY), "prove", str(target), sha256(target), str(output)],
        cwd=ROOT,
        env=environment,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(f"proof failed for {stage}")
    command(RECOVERY, "verify", target, sha256(target), output / "receipt.bin", RUN / stage / "verification")


def build_guest() -> None:
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(ROOT / ".local/ci-target")
    environment["KPI_RISC0_CARGO"] = str(RISC0_CARGO)
    environment["RUSTC"] = str(RISC0_CARGO.with_name("rustc"))
    result = subprocess.run(
        ["bash", str(ROOT / "poc/recovery-native/build_guest.sh"), str(RUN / "guest"), "tn10-full-drainage-depth-4"],
        cwd=ROOT,
        env=environment,
        text=True,
    )
    if result.returncode:
        raise RuntimeError("guest build failed")
    if sha256(PROGRAM) != "f03e520e76f4fd8d756b7659da6dd7d8075fbf7ecc675dbbd41d15e8c8f8e5bc":
        raise RuntimeError("guest program hash mismatch")


def activation() -> None:
    output = build("activate", "activate", {})
    submit("activate", output)


def seed() -> None:
    source = capture("seed")
    command(RECOVERY, "seed", VALIDATOR, VALIDATOR_SHA, source, RUN / "seed.json")


def bootstrap() -> None:
    seed_path = RUN / "seed.json"
    output = build("bootstrap", "bootstrap", {"seedPath": str(seed_path), "seedSha256": sha256(seed_path)})
    submit("bootstrap", output)


def initialize() -> None:
    bootstrap_record = RUN / "bootstrap-build/transaction.json"
    address = output_address(bootstrap_record, 0)
    snapshot = query("initialize-state", [address])
    transaction_id = read(bootstrap_record)["transactionId"]
    state_utxo = next(entry for entry in snapshot["utxos"]["entries"] if entry["outpoint"] == {"transactionId": transaction_id, "index": 0})
    output = build("initialize", "initialize", {"bootstrapPath": str(bootstrap_record), "stateUtxo": state_utxo}, [address])
    accepted = submit("initialize", output)
    acceptance = capture("initialize-acceptance", read(RUN / "seed.json")["endBlock"], accepted["header"]["hash"])
    command(RECOVERY, "checkpoint", VALIDATOR, VALIDATOR_SHA, acceptance, output / "transaction.json", bootstrap_record, RUN / "initialize-checkpoint")


def batch_one() -> None:
    deposit("A")
    deposit("B")
    initialize_wallet_mirror()
    workers = {label: WalletWorker(label) for label in ("A", "B")}
    try:
        accepted = publish_operation(1, workers["A"], {"action": "credit", "deposit": read(RUN / "wallet-public/deposits.json")[0]["id"], "valueSompi": 100_000_000})
        accepted = publish_operation(2, workers["B"], {"action": "credit", "deposit": read(RUN / "wallet-public/deposits.json")[1]["id"], "valueSompi": 100_000_000})
        accepted = publish_operation(3, workers["A"], {"action": "transfer", "inputValueSompi": 100_000_000, "paymentSompi": 30_000_000, "paymentOutputIndex": 0, "recipientOwner": TRIAL["wallets"]["M"]["owner"], "recipientIncoming": TRIAL["wallets"]["M"]["incoming"]})
    finally:
        for worker in workers.values():
            worker.stop()
    freeze("batch-01", RUN / "initialize-checkpoint/checkpoint.json", accepted)


def batch_two() -> None:
    workers = {label: WalletWorker(label) for label in ("A", "B")}
    started = time.monotonic_ns()
    try:
        accepted = publish_operation(4, workers["A"], {"action": "transfer", "inputValueSompi": 70_000_000, "paymentSompi": 10_000_000, "paymentOutputIndex": 0, "recipientOwner": TRIAL["wallets"]["S"]["owner"], "recipientIncoming": TRIAL["wallets"]["S"]["incoming"]})
        accepted = publish_operation(5, workers["B"], {"action": "transfer", "inputValueSompi": 100_000_000, "paymentSompi": 20_000_000, "paymentOutputIndex": 1, "recipientOwner": TRIAL["wallets"]["M"]["owner"], "recipientIncoming": TRIAL["wallets"]["M"]["incoming"]})
    finally:
        for worker in workers.values():
            worker.stop()
    stopped = time.monotonic_ns()
    write(RUN / "service-loss.json", {"walletWorkersStopped": True, "beforeExitProofs": True, "startedMonotonicNs": str(started), "stoppedMonotonicNs": str(stopped)})
    worker = WalletWorker("A")
    try:
        write(RUN / "wallet-recovery-01.json", worker.ready)
        accepted = publish_operation(6, worker, {"action": "exit", "inputValueSompi": 60_000_000, "exitDestination": read(RUN / "private/truth.json")["exitDestinations"][0]["destination"]}, read(RUN / "private/truth.json")["exitDestinations"][0]["nativePubkey"])
    finally:
        worker.stop()
    freeze("batch-02", RUN / "batch-01-checkpoint/checkpoint.json", accepted)


def next_payout_and_exit(exit_ordinal: int) -> None:
    accepted = payout(exit_ordinal)
    if exit_ordinal == 5:
        freeze("batch-07", RUN / "batch-06-checkpoint/checkpoint.json", accepted)
        return
    truth = read(RUN / "private/truth.json")["exitDestinations"][exit_ordinal]
    label = truth["owner"]
    worker = WalletWorker(label)
    try:
        write(RUN / f"wallet-recovery-{exit_ordinal + 1:02}.json", worker.ready)
        accepted = publish_operation(
            exit_ordinal + 6,
            worker,
            {"action": "exit", "inputValueSompi": truth["amountSompi"], "exitDestination": truth["destination"]},
            truth["nativePubkey"],
        )
    finally:
        worker.stop()
    freeze(f"batch-{exit_ordinal + 2:02}", RUN / f"batch-{exit_ordinal + 1:02}-checkpoint/checkpoint.json", accepted)


action = sys.argv[1]
if action == "setup":
    setup()
elif action == "build-guest":
    build_guest()
elif action == "observer-evidence":
    observer_evidence()
elif action == "activate":
    activation()
elif action == "seed":
    seed()
elif action == "bootstrap":
    bootstrap()
elif action == "initialize":
    initialize()
elif action == "batch-01":
    batch_one()
elif action == "batch-02":
    batch_two()
elif action == "prove":
    prove(sys.argv[3])
elif action == "settle":
    settlement(sys.argv[3])
elif action == "payout-exit":
    next_payout_and_exit(int(sys.argv[3]))
else:
    raise SystemExit("unknown action")
