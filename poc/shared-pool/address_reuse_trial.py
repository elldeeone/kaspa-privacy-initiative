#!/usr/bin/env python3
"""Fresh, offline native address-reuse diagnostic; never connects or broadcasts.

Creates seven genuine proofs using the unchanged wallet/lifecycle binaries.
Observers and publication are separate: this driver never opens private wallets
from an older run, and never invokes an observer with both counterfactual arms.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CANDIDATE = "dbf4dace0fe6d992c9add46e6b4cd8a8f8b7309b"
SOURCES = ("address_reuse_trial.py", "address_reuse_observer.py", "address_reuse_evaluate.py",
           "two-input-lifecycle.py", "early_privacy_surface.py", "population_privacy_model.py",
           "population_privacy_index.py", "two_input_privacy_observer.py", "two_input_privacy_z3.py",
           "ADDRESS-REUSE-SPEC.md", "Cargo.toml", "Cargo.lock")
PUBLIC_FILES = ("descriptor.json", "vk.bin", "lineage.json", "parents.json", "head.json",
                "checked.json", "funding_owner_directory.json")


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    with Path(path).open("x") as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")


def freeze(root, wallet, helper):
    source = {str(p.relative_to(REPO)): p for p in [HERE / name for name in SOURCES]}
    source.update({str(p.relative_to(REPO)): p for p in sorted((HERE / "src").rglob("*.rs"))})
    source.update({"binary/wallet": wallet, "binary/lifecycle": helper})
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    if commit != CANDIDATE:
        raise ValueError("unexpected checkpoint commit")
    software = root / "software"
    software.mkdir(mode=0o700)
    frozen = {}
    for name, path in source.items():
        destination = software / ("bin" if name.startswith("binary/") else "code") / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o500 if name.startswith("binary/") else 0o400)
        digest = sha(path)
        if sha(destination) != digest:
            raise ValueError("freeze source changed during copy: " + name)
        frozen[name] = dict(sha256=digest, bytes=path.stat().st_size,
                            copy=str(destination.relative_to(root)))
    before = dict(schema="kpi-address-reuse-source-pins-v1", candidate=commit, files=frozen,
                  runtime_trust="Same host/system runtime; copied binaries and source identities are pinned")
    save(root / "candidate-hashes-before.json", before)
    return before, source


def verify_frozen(root, before, sources):
    checked = {}
    for name, entry in before["files"].items():
        current, copied = sha(sources[name]), sha(root / entry["copy"])
        if current != entry["sha256"] or copied != entry["sha256"]:
            raise ValueError("source/binary changed during trial: " + name)
        checked[name] = current
    save(root / "candidate-hashes-after.json", dict(unchanged=True, files=checked))


def helper_module(root, before):
    path = root / before["files"]["poc/shared-pool/two-input-lifecycle.py"]["copy"]
    spec = importlib.util.spec_from_file_location("address_reuse_lifecycle", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def public_directory(snapshot, admission):
    lineage = read(snapshot / "lineage.json")
    founder_point = lineage[0]["inputs"][0]["previousOutpoint"]
    joining_point = admission["transaction"]["inputs"][1]["previousOutpoint"]
    return dict(schema="kpi-address-reuse-funding-owners-v1", entries=[
        dict(transaction_id=point["transactionId"], index=point["index"], owner=owner)
        for owner, point in enumerate((founder_point, joining_point))])


def selected_script(snapshot, entry):
    parents = {tx["id"]: tx for tx in read(snapshot / "parents.json")}
    return parents[entry["transaction_id"]]["outputs"][entry["index"]]["scriptPublicKey"]


def run(args):
    os.umask(0o077)
    args.output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = args.output_parent / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    (root / "private").mkdir(mode=0o700)
    print("Private experiment directory: " + str(root), flush=True)
    before, sources = freeze(root, args.wallet_binary.resolve(), args.helper_binary.resolve())
    lifecycle = helper_module(root, before)
    params = args.params.resolve()
    if ((params / "pk.bin").stat().st_size != lifecycle.PIN["bytes"]
            or sha(params / "pk.bin") != lifecycle.PIN["sha256"]
            or sha(params / "vk.bin") != lifecycle.VK_SHA256):
        raise ValueError("retained public proving/verification parameter mismatch")
    save(root / "parameters.json", dict(proving_key=lifecycle.PIN,
         verification_key_sha256=lifecycle.VK_SHA256, setup_generated=False))
    wallet = root / before["files"]["binary/wallet"]["copy"]
    helper = root / before["files"]["binary/lifecycle"]["copy"]
    experiment = lifecycle.Experiment(root, params, wallet, helper)
    operations, arms = [], []
    started = time.monotonic()

    def proof(worker, snapshot, action, label):
        result = worker.request(snapshot, action)
        operations.append(dict(label=label, proof_ms=result["proof_ms"],
                               preparation_ms=result["preparation_ms"],
                               native_validation_ms=result["native_validation_ms"],
                               metrics=result["metrics"]))
        print(f"Validated proof {len(operations)}/7: {label}.", flush=True)
        return result

    try:
        experiment.run("founder", helper,
            [(params / "vk.bin", "/vk.bin"), (experiment.pin, "/pin.json"),
             (root, "/destination", "rw")],
            ["founder", "/vk.bin", "/pin.json", "/destination/founder"])
        initial = experiment.snapshot("00-founded")
        a_backup = root / "founder/backup.json"
        a_receive = read(root / "founder/receive.json")
        a = experiment.worker("A", a_backup)
        bootstrap = proof(a, initial, dict(action="pay", positions=[0], recipient=a_receive,
                                           amount_sompi="1960000000"), "shared-bootstrap")
        shared = experiment.snapshot("01-bootstrap", initial, bootstrap["transaction"])
        b_backup, b_receive = experiment.create("B", shared)
        b = experiment.worker("B", b_backup)
        founder_parent = read(root / "founder/synthetic-parent.json")
        for name, key_index, expected_match in (("matched", 3, True), ("different-index", 0, False)):
            funding = experiment.run(name + "-funding-info", wallet, experiment.mounts(b_backup),
                ["funding", "/backup.json", "/public/01-bootstrap/descriptor.json", str(key_index)])
            parent = experiment.run(name + "-synthetic-parent", helper, [],
                                    ["fund", funding["script_public_key"]])
            save(root / "private" / (name + "-synthetic-parent.json"), parent)
            joining = experiment.snapshot(name + "-00-parent", shared, parent=parent["transaction"])
            wrong = dict(action="admit", txid=parent["transaction"]["id"], index=0,
                         native_key_index=0 if key_index == 3 else 3)
            b.request(joining, wrong, False)
            admission = proof(b, joining, dict(action="admit", txid=parent["transaction"]["id"],
                index=0, native_key_index=key_index), name + "-admission")
            admitted = experiment.snapshot(name + "-01-admitted", joining, admission["transaction"])
            payment = proof(a, admitted, dict(action="pay", positions=[1], recipient=b_receive,
                amount_sompi="1920000000"), name + "-payment")
            paid = experiment.snapshot(name + "-02-payment", admitted, payment["transaction"])
            owned = experiment.inspect(name + "-B-received", b_backup, paid)
            assert owned["balance_sompi"] == "3080000000"
            assert {(row["position"], row["value_sompi"]) for row in owned["notes"] if not row["spent"]} == {
                (3, "1160000000"), (5, "1920000000")}
            b.request(paid, dict(action="exit", positions=[3, 5], native_key_index=0), False)
            exit_tx = proof(b, paid, dict(action="exit", positions=[3, 5], native_key_index=3), name + "-exit")
            final = experiment.snapshot(name + "-03-drained", paid, exit_tx["transaction"])
            checked = read(final / "checked.json")["replay"]
            accounting = checked["accounting"]
            assert checked["drained"] is True
            for field, expected in {"initial_reserve_sompi": "2000000000", "admitted_sompi": "1200000000",
                    "paid_sompi": "3040000000", "pool_fees_sompi": "160000000", "remaining_reserve_sompi": "0"}.items():
                assert accounting[field] == expected, field
            directory = public_directory(final, admission)
            save(final / "funding_owner_directory.json", directory)
            payout = exit_tx["transaction"]["outputs"]
            assert len(payout) == 1 and payout[0]["value"] == "3040000000"
            b_script = selected_script(final, directory["entries"][1])
            a_script = selected_script(final, directory["entries"][0])
            assert (b_script == payout[0]["scriptPublicKey"]) is expected_match
            assert a_script != payout[0]["scriptPublicKey"] and a_script != b_script
            assert sha(final / "descriptor.json") == sha(shared / "descriptor.json")
            truth = dict(schema="kpi-address-reuse-truth-v1",
                values=[2000000000, 1960000000, 0, 1160000000, 0, 1920000000, 0],
                owners=[0, 0, None, 1, None, 1, None],
                inputs={"0": [0], "1": [], "2": [1], "3": [3, 5]},
                payment=dict(sender=0, recipient=1, amount=1920000000),
                expected_script_match=expected_match)
            truth_path = root / "private" / (name + "-truth.json")
            save(truth_path, truth)
            arms.append(dict(name=name, public_dir=str(final.relative_to(root)),
                truth_file=str(truth_path.relative_to(root)), truth_sha256=sha(truth_path),
                public_files={filename: sha(final / filename) for filename in PUBLIC_FILES},
                replay=checked, expected_script_match=expected_match,
                wrong_owner_script_differs=True,
                ordinary_parent_fees_sompi=str(int(founder_parent["ordinary_fee_sompi"])
                                              + int(parent["ordinary_fee_sompi"])),
                founding_fee_sompi=accounting["founding_fee_sompi"]))
            print(name + ": complete native replay, accounting and script controls passed.", flush=True)
        experiment.finish()
        assert len(operations) == 7 and len(experiment.workers) == 2
        verify_frozen(root, before, sources)
        if sha(params / "pk.bin") != lifecycle.PIN["sha256"] or sha(params / "vk.bin") != lifecycle.VK_SHA256:
            raise ValueError("public parameters changed during trial")
        result = dict(complete=True, arms=arms, proof_count=7, operations=operations,
            chain_acceptance_verified=False, genuine_groth16_proofs=True,
            controls=experiment.controls, isolation=experiment.audits,
            elapsed_seconds=time.monotonic() - started,
            provenance_before="candidate-hashes-before.json", provenance_after="candidate-hashes-after.json",
            scope="Offline synthetic ancestry, same-key counterfactual arms; observers must see one arm only")
        save(root / "native-result.json", result)
        print("Native phase complete: " + str(root / "native-result.json"), flush=True)
    except BaseException as failure:
        save(root / "failure.json", dict(error=str(failure), completed_proofs=len(operations)))
        raise
    finally:
        experiment.finish()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--params", type=Path, required=True)
    parser.add_argument("--wallet-binary", type=Path, default=HERE / "target/release/kpi-two-input-wallet")
    parser.add_argument("--helper-binary", type=Path, default=HERE / "target/release/kpi-two-input-lifecycle")
    parser.add_argument("--output-parent", type=Path, default=Path("/home/luke/kpi-private/address-reuse"))
    run(parser.parse_args())


if __name__ == "__main__":
    main()
