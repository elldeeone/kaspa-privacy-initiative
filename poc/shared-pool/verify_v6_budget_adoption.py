#!/usr/bin/env python3
"""Freeze factory1600 replay regression and independently compare public bodies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
HISTORICAL = HERE / "evidence/2026-10-22-public-native-budget/attempt-03"
INPUT_SHA = "7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1"
BUDGET_REPORT_SHA = "5e9a33282ae88b21f43310c91eebf55040398a9601c2be2e35ae70b86a3a48a6"
SOURCES = ["Cargo.toml", "Cargo.lock", "verify_v6_budget_adoption.py"]
SOURCES += sorted(str(p.relative_to(HERE)) for p in (HERE/"src").rglob("*.rs")
                  if "bin" not in p.relative_to(HERE/"src").parts
                  or p.name == "kpi-v6-budget-adoption-check.rs")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def save(path, value):
    path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+"\n")


def check(report, public, old_budget):
    require(report["schema"] == "kpi-v6-budget-adoption-v1" and report["passed"] is True
            and report["input_sha256"] == INPUT_SHA and report["case_count"] == 13,
            "adoption report identity/coverage")
    for name in ["historical_replay_passed","factory_replay_passed","replay_preserves_declared_v1_budget",
                 "full_native_validation_mandatory","replay_native_mass_limits_mandatory",
                 "factory_policy_checks_passed","same_final_public_state","same_integer_accounting",
                 "other_version_budgets_unchanged"]:
        require(report[name] is True,"required actual check: "+name)
    require(report["factory_default_budget"] == 1600 and report["historical_retained_budget"] == 3000
            and report["chain_acceptance_verified"] is False,"default/historical scope")
    records = report["cases"]
    require(len(records) == 13 and [row["ordinal"] for row in records] == list(range(13)),
            "thirteen newly constructed factory operations")
    by_id = {body["id"]:body for body in public["parents"]+public["lineage"]}
    for ordinal, row in enumerate(records):
        original = public["lineage"][ordinal+1]
        candidate = row["factory_transaction"]
        expected = unique_json(canonical(original))
        expected["inputs"][0]["computeBudget"] = 1600
        require(candidate["storageMass"] == original["storageMass"],"unchanged contextual storage mass")
        require(canonical(candidate) == canonical(expected),"budget-only full factory body: "+str(ordinal))
        require(original["inputs"][0]["computeBudget"] == row["historical_budget"] == 3000
                and candidate["inputs"][0]["computeBudget"] == row["factory_budget"] == 1600,
                "historical and factory values")
        signature = bytes.fromhex(candidate["inputs"][0]["signatureScript"])
        require(len(signature) == 24709 and signature == bytes.fromhex(original["inputs"][0]["signatureScript"])
                and row["redeem_script_sha256"] == sha(signature[133:]),"immutable proof/redeem bytes")
        parent_point = original["inputs"][0]["previousOutpoint"]
        prior_output = by_id[parent_point["transactionId"]]["outputs"][parent_point["index"]]
        require(row["reserve_spk_hex"] == prior_output["scriptPublicKey"],"unchanged actual reserve SPK")
        historical = old_budget["candidate1600"][ordinal]
        require(row["transaction_id"] == original["id"] == candidate["id"]
                and row["historical_full_hash"] == historical["original_full_hash"]
                and row["factory_full_hash"] == historical["candidate_full_hash"]
                and row["historical_full_hash"] != row["factory_full_hash"],
                "independently retained native ID/full-hash vectors")
        require(row["historical_sig_hash_all"] == row["factory_sig_hash_all"]
                and len(row["factory_sig_hash_all"]) == len(original["inputs"])
                and all(type(x) is str and len(bytes.fromhex(x)) == 32 for x in row["factory_sig_hash_all"]),
                "actual native SIG_HASH_ALL values")
        require(row["per_input_units"] == historical["full_native"]["per_input_units"],
                "retained native meter vectors")
        for flag in ["full_native_historical","full_native_factory","native_policy_historical",
                     "native_policy_factory","all_other_fields_exact"]:
            require(row[flag] is True,"factory check: "+flag)
        metrics = row["factory_metrics"]
        require(type(metrics["compute_mass"]) is int and metrics["compute_mass"] <= 500_000
                and type(metrics["storage_mass"]) is int and metrics["storage_mass"] <= 500_000
                and type(metrics["transient_mass"]) is int and metrics["transient_mass"] <= 1_000_000,
                "native mass-cap evidence")
    old, new = report["historical_summary"], report["factory_summary"]
    require(canonical(old["state"]) == canonical(new["state"])
            and canonical(old["accounting"]) == canonical(new["accounting"])
            and old["chain_acceptance_verified"] is new["chain_acceptance_verified"] is False,
            "replay final state/accounting equality")
    controls = report["controls"]
    require([x["name"] for x in controls] == ["underbudget_native_rejection","unexpected_fee",
            "unexpected_output","wrong_genuine_proof","excessive_budget_mass"]
            and all(x["rejected"] is True for x in controls),"five meaningful replay controls")
    old_low = next(x for x in old_budget["focused_boundaries"] if x["ordinal"] == 0 and x["reserve_budget"] == 1474)
    meter = controls[0]["typed_meter_cause"]
    require(meter["typed_outer_variant"] == "ZkIntegrity"
            and meter["serialized_inner_variant"] == "ExceededCommittedScriptUnits"
            and meter["limit_units"] == 14_749_999
            and meter["used_units"] == old_low["reserve_input"]["error"]["attempted_used_units"]
            and meter["display"] == old_low["reserve_input"]["error"]["display"],
            "precise independently retained underbudget native cause")
    require(controls[1]["error"] == controls[2]["error"] == "public state/transaction reconstruction mismatch"
            and controls[3]["error"] == "pool native validation: failed to verify the signature script: ZK Integrity: Groth16 verification failed"
            and controls[4]["error"] == "pool native mass: native block mass limit", "exact control layers")
    return {"passed":True,"new_factory_cases":13,"historical_and_factory_replay_passed":True,
            "canonical_bodies_compared":13,"retained_native_hash_and_meter_vectors_compared":13,
            "negative_controls":5,"default_budget":1600,"other_version_budgets_unchanged":True,
            "chain_acceptance_verified":False,"minimum_note_5x_fee_problem_fixed":False}


def run(binary, expected_sha, output):
    start = time.time()
    binary = binary.resolve(strict=True)
    require(sha(binary.read_bytes()) == expected_sha,"adoption executable identity")
    raw = (HISTORICAL/"selected-public-input.json").read_bytes()
    budget = (HISTORICAL/"native.stdout.json").read_bytes()
    require(sha(raw) == INPUT_SHA and sha(budget) == BUDGET_REPORT_SHA,"historical evidence preserved")
    source = {name:sha((HERE/name).read_bytes()) for name in SOURCES}
    output.mkdir(parents=True,exist_ok=False)
    (output/"selected-public-input.json").write_bytes(raw)
    command=["/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv",
             "--ro-bind","/usr","/usr","--symlink","usr/bin","/bin","--symlink","usr/lib","/lib",
             "--symlink","usr/lib64","/lib64","--proc","/proc","--dev","/dev","--tmpfs","/tmp",
             "--ro-bind",str(binary),"/adoption-check","--ro-bind",str(output/"selected-public-input.json"),"/input.json",
             "--chdir","/tmp","/adoption-check","/input.json"]
    save(output/"freeze.json",{"schema":"kpi-v6-budget-adoption-freeze-v1","source_sha256":source,
         "input_sha256":INPUT_SHA,"binary_sha256":expected_sha,"command":command,
         "frozen_case_count":13,"frozen_control_names":["underbudget_native_rejection","unexpected_fee",
         "unexpected_output","wrong_genuine_proof","excessive_budget_mass"],"default_budget":1600,
         "historical_fixture_budget":3000,"minimum_note_5x_fee_problem_fixed":False})
    process=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1100,check=False)
    (output/"native.stdout.json").write_bytes(process.stdout)
    (output/"native.stderr.txt").write_bytes(process.stderr)
    require(process.returncode == 0 and not process.stderr,"adoption native check failed: "+process.stderr.decode(errors="replace"))
    checked=check(unique_json(process.stdout),unique_json(raw),unique_json(budget))
    require(source == {name:sha((HERE/name).read_bytes()) for name in SOURCES},"adoption source changed during execution")
    require(sha(binary.read_bytes()) == expected_sha and sha((HISTORICAL/"selected-public-input.json").read_bytes()) == INPUT_SHA
            and sha((HISTORICAL/"native.stdout.json").read_bytes()) == BUDGET_REPORT_SHA,"binary/historical evidence drift")
    checked.update(elapsed_seconds=time.time()-start,returncode=process.returncode)
    save(output/"validation.json",checked)
    save(output/"MANIFEST.json",{"schema":"kpi-v6-budget-adoption-manifest-v1","source_sha256":source,
        "input_sha256":INPUT_SHA,"binary_sha256":expected_sha,"historical_native_budget_report_sha256":BUDGET_REPORT_SHA,
        "artifacts":{p.name:{"bytes":p.stat().st_size,"sha256":sha(p.read_bytes())} for p in sorted(output.iterdir())}})
    print(json.dumps(checked,sort_keys=True))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-binary",type=Path,required=True)
    parser.add_argument("--expected-native-sha256",required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    args=parser.parse_args()
    try:
        run(args.native_binary,args.expected_native_sha256,args.output_dir.resolve())
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        raise SystemExit("v6 budget adoption verification: "+str(error))
