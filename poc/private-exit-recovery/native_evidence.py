"""Finite trusted-client evidence reuse, not verification of arbitrary proofs.

The installed software pins a manifest of already independently reviewed public
native runs. Matching reports/self hashes supplied by an untrusted caller are
never admitted. Version1 transaction IDs alone cannot authenticate witnesses.
"""
import hashlib
import json
from pathlib import Path

from dependencies import ROOT, old, native
from selected_identities import EVIDENCE_SHA

HERE = Path(__file__).resolve().parent


def checked(item, *, json_value=True):
    path = ROOT / item["path"]
    raw = path.read_bytes()
    old.need(len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"], "preselected-native-artifact-identity")
    return json.loads(raw) if json_value else raw


class ExistingNativeResults:
    """No selectable manifest path, executable override, subprocess or RPC."""
    def __init__(self):
        raw = (HERE / "native-evidence.json").read_bytes()
        old.need(hashlib.sha256(raw).hexdigest() == EVIDENCE_SHA, "preselected-native-evidence-authority")
        manifest = json.loads(raw)
        old.need(manifest["schema"] == "kpx3-preselected-offline-native-evidence/v1"
                 and manifest["native_binary_sha256"] == "077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061",
                 "preselected-native-software-authority")
        source = checked(manifest["native_source_freeze"])
        for item in source["files"]:
            checked(item, json_value=False)
        closed = checked(manifest["root_closed_main_result"])
        old.need(closed["complete_supplied_context_native_sequence_passed"] is True
                 and closed["native_Full_operations"] == 7, "preselected-mainline-result")
        self.cases, self.calls = {}, []
        for record in manifest["records"]:
            case, report = checked(record["native_case"]), checked(record["native_report"])
            old.need(report["isolation"] == "PASS" and report["Full"]["accepted"] is True
                     and report["all_input_engines_accepted"] is True
                     and len(report["per_input_ScriptEngine"]) == len(case["transaction"]["inputs"])
                     and all(row["accepted"] is True for row in report["per_input_ScriptEngine"]), "preselected-native-verdict")
            self.cases[old.digest(case)] = record

    def __call__(self, transaction, entries):
        identity = old.digest(native.native_case(transaction, entries))
        self.calls.append({"transaction_id": transaction["id"], "exact_case_identity": identity,
                           "matched": identity in self.cases})
        return identity in self.cases
