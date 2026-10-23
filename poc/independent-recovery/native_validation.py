"""Optional public-data native validator; no factory, PK, signer or RPC calls."""
from pathlib import Path
import hashlib
import json
import os
import subprocess

from replay import Incomplete, Invalid, integer


def native_case(transaction, entries):
    """Convert decimal strings losslessly to the official native serde shape."""
    tx = {"version": transaction["version"], "id": transaction["id"],
        "inputs": [{"previousOutpoint": item["previousOutpoint"],
            "signatureScript": item["signatureScript"],
            "sequence": integer(item["sequence"], (1 << 64) - 1),
            "computeBudget": integer(item["computeBudget"], 65535)} for item in transaction["inputs"]],
        "outputs": [{"value": integer(item["value"]), "scriptPublicKey": item["scriptPublicKey"],
                     "covenant": None} for item in transaction["outputs"]],
        "lockTime": integer(transaction["lockTime"], (1 << 64) - 1),
        "subnetworkId": transaction["subnetworkId"], "gas": integer(transaction["gas"], (1 << 64) - 1),
        "payload": transaction["payload"], "mass": integer(transaction["storageMass"], (1 << 64) - 1)}
    return {"transaction": tx, "entries": [{"amount": integer(item["amount_sompi"]),
        "scriptPublicKey": item["script_public_key"],
        "blockDaaScore": integer(item["block_daa_score"], (1 << 64) - 1),
        "isCoinbase": item["is_coinbase"], "covenantId": item["covenant_id"]} for item in entries]}


class NativeValidator:
    """The installed caller selects code; descriptor/RPC data never select it.

    This authenticates local software identity and validates supplied public
    contexts, not chain inclusion or honest-node consensus. The independently
    selected executable is assumed immutable on the trusted client filesystem.
    """
    def __init__(self, executable, expected_sha256, output):
        self.executable = Path(executable).resolve(strict=True)
        self.expected_sha256 = expected_sha256
        self.output = Path(output)
        if self.output.exists():
            raise Invalid("fresh-native-validation-output-required")
        self.output.mkdir(mode=0o700, parents=True)
        self.reports = []
        self.check_binary()

    def check_binary(self):
        if (not os.access(self.executable, os.X_OK)
                or hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.expected_sha256):
            raise Invalid("native-validator-software-identity")

    def __call__(self, transaction, entries):
        self.check_binary()
        index = len(self.reports)
        case = self.output / (f"{index:05d}-case.json")
        raw = (json.dumps(native_case(transaction, entries), separators=(",", ":")) + '\n').encode()
        with case.open('xb') as file:
            file.write(raw)
        result = self.output / f"{index:05d}"
        try:
            process = subprocess.run([str(self.executable), "validate-transaction", str(case), str(result)],
                                     capture_output=True, text=True)
        except OSError:
            raise Incomplete("native-validation-unavailable") from None
        report_file = result / "native-validation.json"
        if process.returncode or not report_file.is_file():
            raise Incomplete("native-validation-execution-failed")
        report = json.loads(report_file.read_bytes())
        verdict = (report.get("isolation") == "PASS" and report.get("Full", {}).get("accepted") is True
            and report.get("all_input_engines_accepted") is True
            and len(report.get("per_input_ScriptEngine", [])) == len(transaction["inputs"])
            and all(row.get("accepted") is True for row in report["per_input_ScriptEngine"]))
        self.reports.append({"transaction_id": transaction["id"], "accepted": verdict,
            "public_case_sha256": hashlib.sha256(raw).hexdigest(),
            "native_report_sha256": hashlib.sha256(report_file.read_bytes()).hexdigest(),
            "native_report_path": str(report_file), "executable_sha256": self.expected_sha256})
        return verdict
