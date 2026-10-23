"""Run only the new private LOCAL archive checker, no proof/native/RPC calls.

Trial path is an argument; secrets are only read from each own seed-only backup.
Every request/verdict is written0600 inside the private trial, never into Git.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
CHECKER = ROOT / "poc/future-testnet/recovery_check.py"
CHECKER_SHA = "c9091b52c8562e30fa567095c2070a8c8845cfdb5c9578e5357aca156fe0677b"


def write(path, value):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), "w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    if hashlib.sha256(CHECKER.read_bytes()).hexdigest() != CHECKER_SHA:
        raise ValueError("private LOCAL checker source pin")
    trial = Path(sys.argv[1]).resolve(strict=True)
    identity_path = trial / "public/recovery-identity.json"
    identity = json.loads(identity_path.read_bytes())
    archive_path = trial / "local-archive.json"
    archive = json.loads(archive_path.read_bytes())
    if archive["oracle_stage"] != "LOCAL_SUPPLIED_CONTEXT" or "secrets" in identity:
        raise ValueError("expected private LOCAL public records only")
    destination = trial / "recovery-checks"
    destination.mkdir(mode=0o700, exist_ok=False)
    bridge = ROOT.parent / "recipient-target/debug/kpi-future-recipient-crypto"
    results = []
    for label in ("bob", "charlie"):
        request = {"oracle_stage": "LOCAL_SUPPLIED_CONTEXT", "identity_path": str(identity_path),
                   "backup_path": str(trial / "backups" / (label + ".json")),
                   "archive_path": str(archive_path), "crypto_path": str(bridge),
                   "crypto_sha256": identity["runtime_pins"]["bridge_sha256"], "label": label}
        write(destination / (label + "-request.json"), request)
        result = subprocess.run([sys.executable, "-B", str(CHECKER)], input=json.dumps(request),
                                capture_output=True, text=True, check=False)
        try:
            verdict = json.loads(result.stdout)
        except ValueError:
            verdict = {"passed": False, "error": "CHECKER_OUTPUT_NOT_JSON"}
        write(destination / (label + "-verdict.json"), verdict)
        if result.returncode or verdict.get("passed") is not True:
            print(json.dumps({"passed": False, "label": label, "error": verdict.get("error", "CHECKER_REJECTED")}))
            return 1
        results.append({key: verdict[key] for key in ("label", "operations_checked", "actual_received_note_sompi",
                       "terminal_zero", "owned_unspent_sompi", "both_payout_outputs_checked",
                       "both_payout_utxos_reobserved", "confirmed_with_trusted_node")})
    write(destination / "results.json", {"passed": True, "oracle_stage": "LOCAL_SUPPLIED_CONTEXT",
          "network_contacted": False, "prover_or_native_rerun": False, "results": results})
    print(json.dumps({"passed": True, "oracle_stage": "LOCAL_SUPPLIED_CONTEXT", "results": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
