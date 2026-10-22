#!/usr/bin/env python3
"""Independent accounting checks for the fixed public native-budget screen."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

import public_native_observation as public

EXPECTED_DESCRIPTOR = "d02c36cd87db7bfd43f6f85a425539a90f8f39224a20ac5ef860ae0f54be3a8b"
BASELINE = public.HERE / "evidence/2026-10-22-public-native-observation/attempt-01"
OBSERVATION_BINARY_SHA256 = "39e3343487938afb2e7450cf653ced8cc87b52245e384633b32d01ca87a84999"
SOURCES = ("src/bin/kpi-native-budget-screen.rs", "verify_native_budget_screen.py",
           "src/native.rs", "src/two_input/mod.rs", "src/two_input/covenant.rs",
           "src/protocol.rs", "Cargo.toml", "Cargo.lock", "public_native_observation.py")


def file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    with path.open("x") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


def check(report, original_native, input_sha256):
    need = public.require
    need(report.get("schema") == "kpi-public-native-budget-screen-v1" and report.get("passed") is True,
         "budget report schema/pass")
    need(report["input_sha256"] == input_sha256, "budget input identity")
    need(report["classifier_controls"] == ["typed_direct_underbudget","wrong_limit_rejected",
                                           "same_display_wrong_type_rejected","unrelated_proof_integrity_rejected"],
         "exact error classifier controls")
    need(len(report["baselines"]) == len(report["candidate1600"]) == 13
         and len(report["focused_boundaries"]) == 9, "budget case coverage")
    for i, (baseline, candidate) in enumerate(zip(report["baselines"], report["candidate1600"], strict=True)):
        need(type(baseline["ordinal"]) is int and baseline["ordinal"] == i
             and type(candidate["ordinal"]) is int and candidate["ordinal"] == i, "budget ordinal")
        need(baseline["reserve_budget"] == 3000 and candidate["reserve_budget"] == 1600, "budget values")
        known = original_native["baseline"]["records"][i + 1]
        for row in (baseline, candidate):
            need(row["original_transaction_id"] == row["candidate_transaction_id"] == known["transaction_id"]
                 and row["original_full_hash"] == known["full_hash"], "original native identity changed")
            need(row["full_native"]["passed"] is True and row["reserve_input"]["passed"] is True,
                 "full native candidate did not pass")
            need(row["original_fee_sompi"] == row["full_native"]["fee_sompi"] == "40000000", "original fee changed")
        need(baseline["candidate_full_hash"] == baseline["original_full_hash"]
             and candidate["candidate_full_hash"] != candidate["original_full_hash"], "full hash budget binding")
        need(candidate["full_native"]["per_input_units"] == baseline["full_native"]["per_input_units"], "per-input units changed")
    all_rows = report["baselines"] + report["candidate1600"] + report["focused_boundaries"]
    for row in all_rows:
        budget = public.integer(row["reserve_budget"], 65535, "reserve budget")
        need(row["allowed_reserve_units"] == budget * 10_000 + 9_999, "budget conversion")
        for flag in ("transaction_id_unchanged", "sig_hash_all_unchanged", "proof_authorization_ciphertexts_outputs_signatures_unchanged"):
            need(row[flag] is True, "mutated protected field: " + flag)
        if row["expected_pass"] is True:
            need(row["reserve_input"]["passed"] is True and row["full_native"]["passed"] is True, "expected native pass missing")
            used = public.integer(row["reserve_input"]["used_units"], 2**64-1, "VM units")
            need(used <= row["allowed_reserve_units"], "successful VM exceeds budget")
        else:
            need(row["expected_pass"] is False and row["reserve_input"]["passed"] is False
                 and row["full_native"]["passed"] is False, "expected native rejection missing")
            error = row["reserve_input"]["error"]
            need(error["cause_variant"] == "ExceededCommittedScriptUnits" and error["typed_outer_match"] is True
                 and error["inner_message_matches_generated_typed_meter_error"] is True,
                 "wrong VM rejection variant")
            need(error["limit_units"] == row["allowed_reserve_units"]
                 and type(error["attempted_used_units"]) is int
                 and error["attempted_used_units"] > error["limit_units"], "VM rejection units")
            exact = f'script units exceeded the amount committed in the input: used={error["attempted_used_units"]}, limit={error["limit_units"]}'
            if error["outer_variant"] == "ZkIntegrity":
                need(error["cause_is_serialized"] is True, "ZK cost-wrapper representation")
                exact = "ZK Integrity: Kaspa txscript error: " + exact
            else:
                need(error["outer_variant"] == "ExceededCommittedScriptUnits"
                     and error["cause_is_serialized"] is False, "direct VM underbudget variant")
            need(error["display"] == exact and exact in row["full_native"]["error"], "full/native VM rejection attribution")
        mining = public.integer(row["metrics"]["mining_mass"], 2**64-1, "mining mass")
        relay = public.integer(row["metrics"]["relay_mass"], 2**64-1, "relay mass")
        need([x["sompi_per_gram"] for x in row["fee_quotes"]] == [100,200,500], "fee quote rate coverage")
        for quote in row["fee_quotes"]:
            rate = public.integer(quote["sompi_per_gram"], 500, "fee rate")
            amount = public.Sompi.parse(quote["necessary_fee_sompi"]).value
            need(amount == mining * rate and quote["relay_only_fee_sompi"] == str(relay * rate), "fee quote arithmetic")
            need(quote["original_fee_covers"] is (amount <= 40_000_000)
                 and quote["minimum_note_covers_fee"] is (amount <= 60_000_000), "fee coverage flags")
            need(quote["minimum_claim_for_payout_floor_sompi"] == str(amount + 10_000_000), "payout floor arithmetic")
    expected = [(0,1500,True),(0,1497,True),(0,1496,False),(0,1474,False),
                (4,1500,True),(4,1497,True),(4,1496,True),(4,1495,False),(4,1474,False)]
    need([(x["ordinal"],x["reserve_budget"],x["expected_pass"]) for x in report["focused_boundaries"]] == expected,
         "frozen focused boundary matrix")
    maximum = max(r["metrics"]["mining_mass"] for r in report["candidate1600"])
    summary = report["summary"]
    need(summary["maximum_candidate_mining_mass"] == maximum
         and summary["maximum_2x_necessary_fee_sompi"] == str(maximum * 200)
         and summary["maximum_5x_necessary_fee_sompi"] == str(maximum * 500)
         and summary["original_fee_covers_all_2x"] is (maximum * 200 <= 40_000_000)
         and summary["minimum_note_covers_worst_5x_fee"] is (maximum * 500 <= 60_000_000)
         and summary["minimum_claim_for_worst_5x_payout_floor_sompi"] == str(maximum * 500 + 10_000_000),
         "budget summary arithmetic")
    return dict(passed=True, checked_transactions=13, checked_native_cases=len(all_rows),
                independent_fee_quotes=len(all_rows)*3, summary=summary)


def run(binary, expected_sha256, observation_binary, output):
    start = time.time()
    binary, observation_binary = binary.resolve(strict=True), observation_binary.resolve(strict=True)
    public.unhex(expected_sha256, 32, "expected budget executable digest")
    public.require(file_sha(binary) == expected_sha256, "budget executable identity")
    public.require(file_sha(observation_binary) == OBSERVATION_BINARY_SHA256, "observation baseline executable changed")
    baseline_manifest = public.unique_json((BASELINE / "MANIFEST.json").read_bytes())
    baseline_hashes = {name:file_sha(BASELINE/name) for name in baseline_manifest["artifacts"]}
    public.require(all(baseline_hashes[name] == entry["sha256"] for name,entry in baseline_manifest["artifacts"].items()),
                   "observation baseline artifact drift")
    source = {name:file_sha(public.HERE/name) for name in SOURCES}
    raw = public.load_public_rehearsal()
    public.extract(raw,13,EXPECTED_DESCRIPTOR)
    data = public.canonical(public.select_prefix(raw,13))
    public.require(data == (BASELINE/"selected-public-input.json").read_bytes(), "budget input differs from verified observation baseline")
    output.mkdir(parents=True,exist_ok=False)
    input_path = output/"selected-public-input.json"
    input_path.write_bytes(data)
    command=["/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv",
             "--ro-bind","/usr","/usr","--symlink","usr/bin","/bin","--symlink","usr/lib","/lib",
             "--symlink","usr/lib64","/lib64","--proc","/proc","--dev","/dev","--tmpfs","/tmp",
             "--ro-bind",str(binary),"/budget-check","--ro-bind",str(input_path),"/input.json",
             "--chdir","/tmp","/budget-check","/input.json"]
    process=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240,check=False)
    (output/"native.stdout.json").write_bytes(process.stdout)
    (output/"native.stderr.txt").write_bytes(process.stderr)
    public.require(process.returncode==0 and not process.stderr,"native budget screen failed: "+process.stderr.decode(errors="replace"))
    report=public.unique_json(process.stdout)
    validation=check(report,public.unique_json((BASELINE/"native.stdout.json").read_bytes()),public.sha(data).hex())
    public.require(source=={name:file_sha(public.HERE/name) for name in SOURCES},"budget source changed during execution")
    public.require(baseline_hashes=={name:file_sha(BASELINE/name) for name in baseline_hashes}
                   and file_sha(observation_binary)==OBSERVATION_BINARY_SHA256,"observation baseline changed during budget screen")
    public.require(file_sha(binary)==expected_sha256,"budget binary changed")
    save(output/"validation.json",dict(schema="kpi-public-native-budget-validation-v1",**validation,
                                      elapsed_seconds=time.time()-start,command=command,returncode=process.returncode,
                                      observation_baseline_preserved=True,chain_acceptance_verified=False,
                                      runtime_resource_scope="whole-job resources belong to the coordinator's systemd cgroup receipt"))
    save(output/"MANIFEST.json",dict(schema="kpi-public-native-budget-manifest-v1",source_sha256=source,
                                   source_base_commit="ec6aa15d586bcc8a90f7232b433fd48d8c73d509",
                                   input_sha256=public.sha(data).hex(),binary_sha256=expected_sha256,
                                   observation_baseline_manifest_sha256=file_sha(BASELINE/"MANIFEST.json"),
                                   observation_baseline_artifact_sha256=baseline_hashes,
                                   artifacts={p.name:dict(bytes=p.stat().st_size,sha256=file_sha(p)) for p in sorted(output.iterdir())},
                                   boundary="unchanged genuine public proofs/auth/outputs/signatures/fees; isolated original contexts; no network/keys/new proofs/broadcast/default change"))
    print(json.dumps(validation))


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-binary",type=Path,required=True)
    parser.add_argument("--expected-native-sha256",required=True)
    parser.add_argument("--observation-binary",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    args=parser.parse_args()
    try:
        run(args.native_binary,args.expected_native_sha256,args.observation_binary,args.output_dir.resolve())
    except (public.ObservationError,OSError,KeyError,json.JSONDecodeError,subprocess.TimeoutExpired) as error:
        print("native budget verification: "+str(error),file=sys.stderr)
        sys.exit(1)
