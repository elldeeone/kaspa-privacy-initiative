#!/usr/bin/env python3
"""Freeze/run a public-only native boundary checker and independently fold paths.

No wallet, setup, proving parameter, network client or private fixture is opened.
Every synthetic supplied context remains explicitly unauthenticated by a chain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
INPUT_SHA = "7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1"
BASELINE = HERE / "evidence/2026-10-22-public-native-budget/attempt-03/selected-public-input.json"
SOURCES = ["Cargo.toml", "Cargo.lock", "verify_native_budget_boundaries.py"]
SOURCES += sorted(str(p.relative_to(HERE)) for p in (HERE / "src").rglob("*.rs")
                  if "bin" not in p.relative_to(HERE / "src").parts
                  or p.name == "kpi-public-native-budget-boundaries.rs")
LIMBS = [(0, 7), (7, 14), (14, 21), (21, 28), (28, 32)]


def sha(data):
    return hashlib.sha256(data).digest()


def file_sha(path):
    return sha(path.read_bytes()).hex()


def require(test, message):
    if not test:
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
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def integer(value, label):
    require(type(value) is int and value >= 0, label + " requires nonnegative integer")
    return value


def amount(value):
    require(type(value) is str and str(int(value)) == value and int(value) >= 0,
            "canonical integer sompi")
    return int(value)


def u32(data):
    require(len(data) == 4, "u32 size")
    return int.from_bytes(data, "little")


def fold(leaf, index, path):
    require(len(leaf) == 32 and len(path) % 32 == 0, "Merkle framing")
    for level in range(len(path) // 32):
        sibling = path[level*32:(level+1)*32]
        leaf = sha(b"\x01" + (sibling + leaf if index & (1 << level) else leaf + sibling))
    return leaf


def limb_vector(a, b):
    return ["eq" if a[lo:hi] == b[lo:hi] else
            "lt" if int.from_bytes(a[lo:hi], "little") < int.from_bytes(b[lo:hi], "little") else "gt"
            for lo, hi in LIMBS]


def validate(report, input_value):
    require(report["schema"] == "kpi-public-native-budget-boundaries-v1"
            and report["passed"] is True and report["input_sha256"] == INPUT_SHA,
            "native report identity")
    require(report["chain_acceptance_verified"] is False and report["backing_verified"] is False
            and report["default_changed"] is False and report["new_setup_or_proof"] is False,
            "native report scope")
    shapes = ["sentinel_first", "tail_end", "middle_bracket", "limb_0", "limb_1", "limb_2",
              "limb_3", "limb_4", "mixed_all_limbs", "index_127_128", "index_32767_32768", "near_capacity"]
    expected_names = {f"row{row}_{shape}_{terminal}"
                      for row, terminal in [(4, "continuing"), (5, "continuing"),
                                            (7, "continuing"), (7, "terminal")]
                      for shape in shapes}
    cases = report["cases"]
    require(len(cases) == 48 and len({row["name"] for row in cases}) == 48
            and {row["name"] for row in cases} == expected_names, "frozen 48-case matrix")
    maximum = 0
    folds = 0
    branch_vectors = set()
    sentinel, tail, middle = 0, 0, 0
    for case in cases:
        name, shape = case["name"], case["shape"]
        row = int(name.split("_")[0][3:])
        source = input_value["lineage"][row+1]
        source_payload = bytes.fromhex(source["payload"])
        source_signature = bytes.fromhex(source["inputs"][0]["signatureScript"])
        tx = case["budget1600_transaction"]
        payload = bytes.fromhex(tx["payload"])
        signature = bytes.fromhex(tx["inputs"][0]["signatureScript"])
        require(payload[8:385] == source_payload[8:385]
                and payload[385:755] == source_payload[385:755]
                and signature[2:130] == source_signature[2:130], name + " genuine proof/auth/cipher")
        require(len(payload) == 5228 and len(signature) == 24709
                and tx["inputs"][0]["computeBudget"] == 1600, name + " fixed native shape")
        auth = payload[8:385]
        count, anchor = u32(auth[40:44]), auth[44:76]
        mode = auth[204]
        require(case["genuine_anchor_count"] == count and bytes.fromhex(case["genuine_anchor_hex"]) == anchor,
                name + " anchor record")
        require(case["genuine_authorization_sha256"] == sha(auth).hex()
                and case["genuine_proof_sha256"] == sha(signature[2:130]).hex()
                and case["genuine_ciphertexts_sha256"] == sha(payload[385:755]).hex(), name + " public identities")
        state = bytes.fromhex(case["prior_state_hex"])
        next_state = bytes.fromhex(case["next_state_hex"])
        require(len(state) == 105 and len(next_state) == 105 and state[0] == next_state[0] == 6,
                name + " compact states")
        cm, nf = u32(state[1:5]), u32(state[5:9])
        require(cm == case["prior_cm_count"] and nf == case["prior_nf_count"]
                and cm % 2 == 1 and 0 < cm < 65536 and nf % 2 == 0 and nf <= 2*cm,
                name + " prior count bounds")
        require(u32(next_state[5:9]) == nf+2 and u32(next_state[1:5]) == cm+(2 if mode == 1 else 0)
                and u32(next_state[5:9]) <= 2*u32(next_state[1:5]), name + " next count bounds")
        require(case["synthetic_context"] is True and case["chain_acceptance_verified"] is False
                and case["backing_verified"] is False, name + " synthetic supplied context flag")
        # Directly read the P2SH redeem's immutable 105-byte state literal.
        redeem = signature[133:]
        require(len(redeem) == 24576 and redeem[36:141] == state, name + " supplied reserve state literal")
        witness = payload[860:]
        require(fold(sha(b"\x03" + auth[40:76]), (count-1)//2, witness[:512]) == state[73:105],
                name + " genuine historical anchor path")
        folds += 1
        nf_root = state[41:73]
        for slot in range(2):
            base = 512+slot*1160
            pred_index = u32(witness[base:base+4])
            old_leaf = witness[base+4:base+72]
            pred_path = witness[base+72:base+616]
            append_path = witness[base+616:base+1160]
            value, successor = old_leaf[:32], old_leaf[36:68]
            nullifier = auth[76+slot*32:108+slot*32]
            require(int.from_bytes(value, "little") < int.from_bytes(nullifier, "little")
                    and (successor == bytes(32)
                         or int.from_bytes(nullifier, "little") < int.from_bytes(successor, "little")),
                    name + " independent LE predecessor comparison")
            require(fold(sha(b"\x02" + old_leaf), pred_index, pred_path) == nf_root,
                    name + " old NF predecessor path")
            index = nf+slot+1
            changed_leaf = value+index.to_bytes(4, "little")+nullifier
            changed_root = fold(sha(b"\x02"+changed_leaf), pred_index, pred_path)
            require(fold(bytes(32), index, append_path) == changed_root, name + " NF append emptiness")
            new_leaf = nullifier + old_leaf[32:68]
            nf_root = fold(sha(b"\x02"+new_leaf), index, append_path)
            folds += 4
            recorded = case["predecessors"][slot]
            require(recorded["predecessor_index"] == pred_index
                    and recorded["predecessor_hex"] == value.hex()
                    and recorded["next_index"] == u32(old_leaf[32:36])
                    and recorded["next_hex"] == successor.hex()
                    and recorded["predecessor_limb_comparisons"] == limb_vector(value, nullifier)
                    and recorded["successor_limb_comparisons"] ==
                    (None if successor == bytes(32) else limb_vector(nullifier, successor)),
                    name + " independent comparator vectors")
            branch_vectors.add(tuple(limb_vector(value, nullifier)))
            if successor != bytes(32):
                branch_vectors.add(tuple(limb_vector(nullifier, successor)))
            sentinel += pred_index == 0
            tail += successor == bytes(32)
            middle += pred_index != 0 and successor != bytes(32)
            if shape.startswith("index_") or shape == "near_capacity":
                expected = {"index_127_128": [127,128], "index_32767_32768": [32767,32768],
                            "near_capacity": [nf-1,nf]}[shape][slot]
                require(pred_index == expected, name + " requested predecessor physical index")
        require(nf_root == next_state[41:73], name + " independently reconstructed NF root")
        cm_root = state[9:41]
        if mode == 1:
            for slot in range(2):
                path = witness[2832+slot*512:2832+(slot+1)*512]
                require(fold(bytes(32), cm+slot, path) == cm_root, name + " CM append emptiness")
                cm_root = fold(sha(b"\x00"+auth[140+slot*32:172+slot*32]), cm+slot, path)
                folds += 2
            require(cm_root == next_state[9:41], name + " independently reconstructed CM root")
            history_path = witness[3856:4368]
            require(fold(bytes(32), (cm+1)//2, history_path) == state[73:105], name + " history append emptiness")
            require(fold(sha(b"\x03"+(cm+2).to_bytes(4,"little")+cm_root), (cm+1)//2,
                         history_path) == next_state[73:105], name + " independently reconstructed history root")
            folds += 2
        else:
            require(witness[2832:] == bytes(1536) and next_state[9:41] == cm_root
                    and next_state[73:105] == state[73:105], name + " DRAIN fixed zero/nonappend path")
        terminal = name.endswith("_terminal")
        require(payload[755:860] == (bytes(105) if terminal else next_state), name + " final state payload")
        reserve = amount(case["supplied_utxo"]["amount"])
        payout = int.from_bytes(auth[205:213],"little")
        fee = int.from_bytes(auth[213:221],"little")
        require(reserve == payout+fee+(0 if terminal else 2_000_000_000)
                and sum(amount(o["value"]) for o in tx["outputs"]) == reserve-fee, name + " integer native accounting")
        if terminal:
            require(mode == 2 and len(tx["outputs"]) == 1, name + " terminal DRAIN shape")
        units = integer(case["used_units_budget1600"], "metered units")
        require(units == case["used_units_budget3000"] and units <= 15_857_502
                and case["allowance_budget1600"] == 16_009_999
                and case["margin_units"] == 16_009_999-units
                and case["native_full_validation_budget3000"] is True
                and case["native_full_validation_budget1600"] is True, name + " native budget outcomes")
        control = case["native_bad_anchor_path_control"]
        require(control == {"rejected":True,"typed_variant":"VerifyError",
                            "error":"script ran, but verification failed"}, name + " precise native negative")
        maximum = max(maximum,units)
    require(sentinel > 0 and tail > 0 and middle > 0, "predecessor branch coverage")
    # Every one-limb difference with other limbs equal and all five limbs
    # unequal must appear in independently reconstructed public witnesses.
    for limb in range(5):
        require(any(v[limb] == "lt" and all(v[j] == "eq" for j in range(5) if j != limb)
                    for v in branch_vectors), "limb equality/unequal coverage")
    require(any(all(x != "eq" for x in v) for v in branch_vectors), "all-limbs-unequal coverage")
    require(report["maximum_units"] == maximum and report["minimum_budget1600_margin"] == 16_009_999-maximum,
            "maximum/margin recount")
    return {"passed":True,"native_cases":48,"full_native_positive_executions":96,
            "typed_native_negative_controls":48,"independent_merkle_folds":folds,
            "maximum_units":maximum,"minimum_budget1600_margin":16_009_999-maximum,
            "maximum_cm_count":max(c["prior_cm_count"] for c in cases),
            "maximum_nf_count":max(c["prior_nf_count"] for c in cases),
            "predecessor_observations":{"sentinel":sentinel,"tail":tail,"middle":middle},
            "distinct_limb_vectors":[list(v) for v in sorted(branch_vectors)],
            "chain_acceptance_verified":False,"backing_verified":False,"default_changed":False}


def run(binary, expected_sha, output):
    start = time.time()
    binary = binary.resolve(strict=True)
    require(file_sha(binary) == expected_sha, "boundary executable SHA")
    data = BASELINE.read_bytes()
    require(sha(data).hex() == INPUT_SHA, "allowlisted public baseline SHA")
    source = {name:file_sha(HERE/name) for name in SOURCES}
    output.mkdir(parents=True,exist_ok=False)
    (output/"selected-public-input.json").write_bytes(data)
    command = ["/usr/bin/bwrap","--unshare-all","--die-with-parent","--new-session","--clearenv",
               "--ro-bind","/usr","/usr","--symlink","usr/bin","/bin","--symlink","usr/lib","/lib",
               "--symlink","usr/lib64","/lib64","--proc","/proc","--dev","/dev","--tmpfs","/tmp",
               "--ro-bind",str(binary),"/boundary-check","--ro-bind",str(output/"selected-public-input.json"),"/input.json",
               "--chdir","/tmp","/boundary-check","/input.json"]
    save(output/"freeze.json",{"schema":"kpi-native-boundaries-execution-freeze-v1",
        "source_sha256":source,"input_sha256":INPUT_SHA,"binary_sha256":expected_sha,
        "command":command,"frozen_case_count":48,"budgets":[3000,1600],
        "frozen_maximum_units":15_857_502,"maximum_cm_count":65535,"maximum_prior_nf_count":131068,
        "scope":"unchanged genuine public proof/auth/cipher, synthetic supplied state and unfunded reserve context"})
    process = subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1100,check=False)
    (output/"native.stdout.json").write_bytes(process.stdout)
    (output/"native.stderr.txt").write_bytes(process.stderr)
    require(process.returncode == 0 and not process.stderr,
            "native boundary checker failed: " + process.stderr.decode(errors="replace"))
    checked = validate(unique_json(process.stdout),unique_json(data))
    require(source == {name:file_sha(HERE/name) for name in SOURCES}, "source changed during execution")
    require(file_sha(binary) == expected_sha and sha(BASELINE.read_bytes()).hex() == INPUT_SHA,
            "binary/input changed during execution")
    checked.update(elapsed_seconds=time.time()-start,returncode=process.returncode,
                   runtime_resource_scope="coordinator-owned systemd cgroup")
    save(output/"validation.json",checked)
    save(output/"MANIFEST.json",{"schema":"kpi-native-boundaries-artifact-manifest-v1",
        "source_sha256":source,"input_sha256":INPUT_SHA,"binary_sha256":expected_sha,
        "artifacts":{p.name:{"bytes":p.stat().st_size,"sha256":file_sha(p)} for p in sorted(output.iterdir())}})
    print(json.dumps(checked,sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-binary",type=Path,required=True)
    parser.add_argument("--expected-native-sha256",required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    args = parser.parse_args()
    try:
        run(args.native_binary,args.expected_native_sha256,args.output_dir.resolve())
    except (ValueError,KeyError,OSError,subprocess.TimeoutExpired) as error:
        raise SystemExit("native budget boundaries: " + str(error))
