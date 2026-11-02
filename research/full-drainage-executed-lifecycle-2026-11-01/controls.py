#!/usr/bin/env python3
"""Adversarial controls over preserved executed artifacts and private wallet stores."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess


def load(path: Path):
    return json.loads(path.read_text())


def write_private(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject(command: list[str], output: Path | None = None) -> dict:
    before_exists = output.exists() if output else False
    completed = subprocess.run(command, capture_output=True, text=True)
    after_exists = output.exists() if output else False
    if completed.returncode == 0 or (output and (before_exists or after_exists)):
        raise RuntimeError(f"control unexpectedly accepted: {command}")
    return {"exitCode": completed.returncode, "stderr": completed.stderr.strip(), "outputCreated": after_exists}


def wrong_owner(binary: Path, store: Path, parameters: Path, verifier: str, ledger: Path) -> dict:
    process = subprocess.Popen(
        [str(binary), "wallet-worker", str(store), str(parameters), verifier],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    ready = json.loads(process.stdout.readline())
    process.stdin.write(
        json.dumps(
            {
                "action": "exit",
                "ledgerPath": str(ledger),
                "inputValueSompi": 60_000_000,
                "exitDestination": secrets.token_hex(32),
            },
            sort_keys=True,
        )
        + "\n"
    )
    process.stdin.flush()
    response = json.loads(process.stdout.readline())
    process.stdin.write("STOP\n")
    process.stdin.flush()
    process.wait(timeout=10)
    if "error" not in response or process.returncode != 0:
        raise RuntimeError("unauthorized wallet control did not reject cleanly")
    return {"ready": ready, "response": response, "exitCode": process.returncode}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--public-root", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("output exists")
    private_controls = args.private_root / "controls"
    private_controls.mkdir(mode=0o700)
    summary = load(args.public_root / "summary.json")
    verifier = summary["verifier"]
    alias = summary["trialAliases"][0]
    trial = args.public_root / alias
    source_state = trial / "state-02.bin"
    operation = load(trial / "operation-03.json")
    original_state_hash = digest(source_state)
    mutations = {}
    for name, field in (("wrong-domain", "domain"), ("wrong-root", "anchor")):
        changed = json.loads(json.dumps(operation))
        changed["statement"][field][0] ^= 1
        operation_path = private_controls / f"{name}.json"
        output_path = private_controls / f"{name}-state.bin"
        write_private(operation_path, changed)
        mutations[name] = reject(
            [
                str(args.binary),
                "ledger-apply",
                str(args.public_root / "verifying-key.bin"),
                verifier,
                str(source_state),
                str(operation_path),
                str(output_path),
            ],
            output_path,
        )
    if digest(source_state) != original_state_hash:
        raise RuntimeError("mutation control changed source state")

    first_exit_event = load(trial / "event-06.json")
    exit_meta = first_exit_event["publicMetadata"]
    unpaid_state = trial / "state-06.bin"
    underpaid_output = private_controls / "underpaid-state.bin"
    diverted_output = private_controls / "diverted-state.bin"
    underpaid = reject(
        [
            str(args.binary),
            "ledger-payout",
            str(unpaid_state),
            exit_meta["statementId"],
            str(exit_meta["exitValueSompi"] - 1),
            exit_meta["exitDestination"],
            secrets.token_hex(32),
            str(underpaid_output),
        ],
        underpaid_output,
    )
    diverted = reject(
        [
            str(args.binary),
            "ledger-payout",
            str(unpaid_state),
            exit_meta["statementId"],
            str(exit_meta["exitValueSompi"]),
            secrets.token_hex(32),
            secrets.token_hex(32),
            str(diverted_output),
        ],
        diverted_output,
    )
    replay_output = private_controls / "replay-state.bin"
    replay = reject(
        [
            str(args.binary),
            "ledger-apply",
            str(args.public_root / "verifying-key.bin"),
            verifier,
            str(trial / "state-15.bin"),
            str(trial / "operation-06.json"),
            str(replay_output),
        ],
        replay_output,
    )
    unauthorized = wrong_owner(
        args.binary.resolve(),
        args.private_root / alias / "wallets" / "S.wallet",
        args.private_root / "common" / "parameters.bin",
        verifier,
        (trial / "state-05.bin").resolve(),
    )
    result = {
        "schema": "full-drainage-executed-controls-v1",
        "trialAlias": alias,
        "wrongDomain": mutations["wrong-domain"],
        "wrongRoot": mutations["wrong-root"],
        "acceptedExitReplay": replay,
        "underpaidPayout": underpaid,
        "divertedPayout": diverted,
        "unauthorizedWalletDiscoveryAndExit": unauthorized,
        "sourceStateUnchanged": digest(source_state) == original_state_hash,
        "allRejected": True,
        "sameHost": True,
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"allRejected": True, "controls": 6}, sort_keys=True))


if __name__ == "__main__":
    main()
