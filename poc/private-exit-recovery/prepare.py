#!/usr/bin/env python3
"""Prepare only public bodies/context/previous-Full evidence; no replay or VM."""
import hashlib
import json
from pathlib import Path

import build_template
from dependencies import ROOT, old

HERE = Path(__file__).resolve().parent
BASE = ROOT / "research/next-session/privacy-recovery"
PREFIX = BASE / "lifecycle/prefix-execution-01"
MAIN = BASE / "lifecycle/main-execution-01"
OUT = BASE / "compatibility/fixtures-01"
STAGES = [(PREFIX, name) for name in ("funding-prep", "founding", "admit")]
STAGES += [(MAIN, name) for name in ("spend", "bob-partial", "bob-full", "charlie-terminal")]


def pin(path):
    path = path.resolve(strict=True)
    raw = path.read_bytes()
    return {"path": str(path.relative_to(ROOT)), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def save(path, value):
    with path.open("x") as file:
        json.dump(value, file, indent=2, sort_keys=True)
        file.write("\n")


def main():
    OUT.mkdir(parents=True, exist_ok=False)
    build_template.main()
    slots = json.loads((HERE / "kpx3-policy-template.json").read_bytes())
    rows, attestations = [], []
    for parent, stage in STAGES:
        case_path, report_path = parent / stage / "validation-case.json", parent / stage / "native-validation.json"
        case, report = [json.loads(path.read_bytes()) for path in (case_path, report_path)]
        if not (report["isolation"] == "PASS" and report["Full"]["accepted"] is True
                and report["all_input_engines_accepted"] is True
                and len(report["per_input_ScriptEngine"]) == len(case["transaction"]["inputs"])
                and all(item["accepted"] is True for item in report["per_input_ScriptEngine"])):
            raise ValueError("selected native result not accepted")
        tx = dict(case["transaction"])
        tx["storageMass"] = tx.pop("mass")
        entries = [{"outpoint": tx["inputs"][i]["previousOutpoint"], "amount_sompi": item["amount"],
                    "script_public_key": item["scriptPublicKey"], "block_daa_score": item["blockDaaScore"],
                    "is_coinbase": item["isCoinbase"], "covenant_id": item["covenantId"]}
                   for i, item in enumerate(case["entries"])]
        rows.append({"transaction": tx, "input_contexts": entries})
        attestations.append({"native_case": pin(case_path), "native_report": pin(report_path),
                             "transaction_id": tx["id"]})
    initial = bytes.fromhex(rows[2]["transaction"]["inputs"][0]["signatureScript"])[199:]
    domain = initial[10:42]
    vk_slot = next(slot for slot in slots["patch_slots"] if slot["kind"] == "vk")
    at = 114 + vk_slot["data_offset"]
    vk = initial[at:at + 328]
    expected = bytearray((HERE / "kpx3-policy-template.bin").read_bytes())
    for slot in slots["patch_slots"]:
        value = domain if slot["kind"] == "domain" else vk
        expected[slot["data_offset"]:slot["data_offset"] + len(value)] = value
    if initial[114:] != expected or len(initial) != 24417:
        raise ValueError("actual new program/template conformance")
    descriptor = {"schema": "kpx3-recovery-descriptor/v1", "network_id": "testnet-10", "genesis_hash_hex": old.GENESIS,
        "domain_hex32": domain.hex(), "founding_outpoint": old.outpoint(rows[1]["transaction"]),
        "birth_start_hash": "00" * 32, "initial_redeem_hex": initial.hex(), "vk_hex328": vk.hex(),
        "immutable_policy_sha256": old.h(initial[114:]).hex()}
    bundle = {"schema": "kpx3-supplied-context/v1", "context": "OFFLINE_SUPPLIED_CONTEXT", "network_id": "testnet-10",
              "genesis_hash_hex": old.GENESIS, "descriptor_sha256": old.digest(descriptor), "transactions": rows}
    save(OUT / "descriptor.json", descriptor)
    save(OUT / "supplied-public-bodies.json", bundle)
    evidence = {"schema": "kpx3-preselected-offline-native-evidence/v1", "classification": "PUBLIC_SYNTHETIC_DO_NOT_FUND",
        "authority": "Installed client pins these previously root/reviewer-closed native artifacts. Caller data never select evidence.",
        "native_binary_sha256": "077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061",
        "native_source_freeze": pin(BASE / "native/private-native-source-02/SOURCE-FREEZE.json"),
        "root_closed_main_result": pin(MAIN / "RESULTS.json"), "records": attestations,
        "new_native_or_proof_execution": False, "accepted_chain_backing": False}
    save(HERE / "native-evidence.json", evidence)
    constants = "# Generated from selected public source/artifact preparation; no secrets.\n"
    for variable, filename in (("TEMPLATE_SHA", "kpx3-policy-template.bin"), ("TEMPLATE_MANIFEST_SHA", "kpx3-policy-template.json"),
                               ("EVIDENCE_SHA", "native-evidence.json")):
        constants += variable + " = " + repr(hashlib.sha256((HERE / filename).read_bytes()).hexdigest()) + "\n"
    with (HERE / "selected_identities.py").open("x") as file:
        file.write(constants)
    save(OUT / "PREPARATION.json", {"classification": "PUBLIC_SYNTHETIC_DO_NOT_FUND", "public_bodies": 7,
        "template_conforms_to_actual_program": True, "native_VM_or_decoder_replay_executed": False,
        "seed_private_witness_PK_prover_read": False, "descriptor": pin(OUT / "descriptor.json"),
        "supplied_bodies": pin(OUT / "supplied-public-bodies.json"), "selected_evidence": pin(HERE / "native-evidence.json")})
    print(json.dumps({"prepared_public_bodies": 7, "decoder_or_VM_executed": False}))


if __name__ == "__main__":
    main()
