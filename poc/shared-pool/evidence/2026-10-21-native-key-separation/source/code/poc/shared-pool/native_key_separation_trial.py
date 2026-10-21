#!/usr/bin/env python3
"""Fresh offline funding-key separation retest; never connects or broadcasts.

Creates ten genuine proofs with purpose-separated v2 and compatible v1 backups.
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
CANDIDATE = "b62cfd1910d77f9962882b1088d6cc718e7df1b2"
LEGACY_WALLET_SHA256 = "1b95101d84434d2f8598d6bdd4c2a15964f7fa25fb54da313344dd5cf0d514ed"
OBSERVER_SHA256 = "e157540aef57153909dd2558c853b8381a2bb1260d9e7fdc3ba613618a05a9a9"
PROFILES = {
    "v1": ("kpi-v6-wallet-backup-v1", "KPI/payout-key/v2"),
    "v2": ("kpi-v6-wallet-backup-v2", "KPI/funding-key/v1+KPI/payout-key/v2"),
}
SOURCES = ("native_key_separation_trial.py", "address_reuse_observer.py", "native_key_separation_evaluate.py",
           "two-input-lifecycle.py", "early_privacy_surface.py", "population_privacy_model.py",
           "population_privacy_index.py", "two_input_privacy_observer.py", "two_input_privacy_z3.py",
           "ADDRESS-KEY-SEPARATION-SPEC.md", "Cargo.toml", "Cargo.lock")
DOCUMENTS = ("docs/adr/0030-separate-funding-and-exit-keys.md",
             "docs/rfc/0013-coherent-v6-lifecycle.md",
             "research/shielded-kas-native-key-separation-2026-10-21.md")
PUBLIC_FILES = ("descriptor.json", "vk.bin", "lineage.json", "parents.json", "head.json",
                "checked.json", "funding_owner_directory.json")
EVALUATION_SOURCES = set(SOURCES) - {"two-input-lifecycle.py", "Cargo.toml", "Cargo.lock"}

if not __debug__:
    raise RuntimeError("run without Python optimization so experiment assertions remain enabled")


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


def check_evaluation(path):
    frozen = read(path / "freeze.json")
    preparation = read(path / "preparation.json")
    if (frozen["schema"] != "kpi-native-key-separation-evaluation-freeze-v1"
            or set(frozen["sources"]) != EVALUATION_SOURCES
            or preparation["prepared"] is not True
            or preparation["controls_passed"] is not True
            or preparation["historical_positive_passed"] is not True
            or preparation["freeze_sha256"] != sha(path / "freeze.json")):
        raise ValueError("evaluator must be frozen and prepared before fresh wallet creation")
    for name, digest in frozen["sources"].items():
        if sha(HERE / name) != digest or sha(path / "code" / name) != digest:
            raise ValueError("evaluator/native source mismatch: " + name)
    if frozen["sources"]["address_reuse_observer.py"] != OBSERVER_SHA256:
        raise ValueError("historical observer changed")
    for key, relative in (
        ("controls_result_sha256", "runs/controls/result.json"),
        ("historical_positive_result_sha256", "runs/historical-positive-observe/result.json"),
        ("historical_replay_sha256", "historical-positive-replay.json"),
    ):
        if preparation[key] != sha(path / relative):
            raise ValueError("evaluation preparation evidence changed: " + key)
    return dict(freeze_sha256=sha(path / "freeze.json"),
                preparation_sha256=sha(path / "preparation.json"),
                prepared_utc=preparation["prepared_utc"])


def freeze(root, wallet, helper, legacy):
    source = {str(p.relative_to(REPO)): p for p in [HERE / name for name in SOURCES]}
    source.update({str(p.relative_to(REPO)): p for p in sorted((HERE / "src").rglob("*.rs"))})
    source.update({name: REPO / name for name in DOCUMENTS})
    source.update({"binary/wallet": wallet, "binary/lifecycle": helper, "binary/legacy-wallet": legacy})
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    if commit != CANDIDATE:
        raise ValueError("unexpected base checkpoint commit")
    if sha(legacy) != LEGACY_WALLET_SHA256 or sha(HERE / "address_reuse_observer.py") != OBSERVER_SHA256:
        raise ValueError("historical binary/observer identity mismatch")
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
    # Untracked new files are covered by the complete manifest, not by git diff.
    tracked_paths = [name for name in source if not name.startswith("binary/")]
    patch = subprocess.check_output(["git", "diff", "--binary", CANDIDATE, "--", *tracked_paths], cwd=REPO)
    (root / "tracked-source.patch").write_bytes(patch)
    before = dict(schema="kpi-native-key-separation-source-pins-v1", base_commit=commit,
                  tested_revision="base commit plus exact copied source manifest; fix is uncommitted",
                  tracked_patch_sha256=sha(root / "tracked-source.patch"), files=frozen,
                  source_manifest_sha256=hashlib.sha256(json.dumps(frozen, sort_keys=True).encode()).hexdigest(),
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
    tracked_paths = [name for name in sources if not name.startswith("binary/")]
    patch = subprocess.check_output(["git", "diff", "--binary", CANDIDATE, "--", *tracked_paths], cwd=REPO)
    if hashlib.sha256(patch).hexdigest() != before["tracked_patch_sha256"]:
        raise ValueError("tracked source patch changed during trial")
    save(root / "candidate-hashes-after.json", dict(unchanged=True, files=checked,
         tracked_patch_sha256=before["tracked_patch_sha256"]))


def backup_profile(path, expected):
    # Fresh experiment backups only. Return public format metadata, never keys.
    backup = read(path)
    profile = (backup["format"], backup["native_derivation"])
    if profile != PROFILES[expected]:
        raise ValueError("unexpected newly created backup profile")
    return dict(format=profile[0], native_derivation=profile[1])


def legacy_create(experiment, binary, snapshot):
    out = experiment.root / "B-legacy"
    out.mkdir(mode=0o700)
    experiment.run("initialize-fresh-legacy-B", binary,
        [(snapshot, "/public"), (experiment.pin, "/pin.json"), (out, "/destination", "rw")],
        ["create", "/public/descriptor.json", "/public/vk.bin", "/pin.json", "/destination/wallet"])
    return out / "wallet/backup.json", read(out / "wallet/receive.json")


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
    evaluation = check_evaluation(args.evaluation.resolve())
    args.output_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = args.output_parent / str(uuid.uuid4())
    root.mkdir(mode=0o700)
    (root / "private").mkdir(mode=0o700)
    print("Private experiment directory: " + str(root), flush=True)
    before, sources = freeze(root, args.wallet_binary.resolve(), args.helper_binary.resolve(),
                             args.legacy_wallet_binary.resolve())
    save(root / "evaluation-preparation.json", evaluation)
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
    legacy = root / before["files"]["binary/legacy-wallet"]["copy"]
    experiment = lifecycle.Experiment(root, params, wallet, helper)
    operations, arms = [], []
    started = time.monotonic()

    def proof(worker, snapshot, action, label):
        result = worker.request(snapshot, action)
        operations.append(dict(label=label, proof_ms=result["proof_ms"],
                               preparation_ms=result["preparation_ms"],
                               native_validation_ms=result["native_validation_ms"],
                               metrics=result["metrics"]))
        print(f"Validated proof {len(operations)}/10: {label}.", flush=True)
        return result

    try:
        experiment.run("founder", helper,
            [(params / "vk.bin", "/vk.bin"), (experiment.pin, "/pin.json"),
             (root, "/destination", "rw")],
            ["founder", "/vk.bin", "/pin.json", "/destination/founder"])
        initial = experiment.snapshot("00-founded")
        a_backup = root / "founder/backup.json"
        a_profile = backup_profile(a_backup, "v2")
        a_hash = sha(a_backup)
        a_receive = read(root / "founder/receive.json")
        a = experiment.worker("A-bootstrap", a_backup)
        bootstrap = proof(a, initial, dict(action="pay", positions=[0], recipient=a_receive,
                                           amount_sompi="1960000000"), "shared-bootstrap")
        # Retain only this worker for the first arm's payment, then stop it
        # before recovery. This saves one parameter load without sharing a
        # recovery process or mounting another wallet's backup.
        shared = experiment.snapshot("01-bootstrap", initial, bootstrap["transaction"])
        v2_backup, v2_receive = experiment.create("B-v2", shared)
        v1_backup, v1_receive = legacy_create(experiment, legacy, shared)
        profiles = {"v2": backup_profile(v2_backup, "v2"), "v1": backup_profile(v1_backup, "v1")}
        backup_hashes = {"v2": sha(v2_backup), "v1": sha(v1_backup)}
        founder_parent = read(root / "founder/synthetic-parent.json")
        schedule = (("v2-same-index", 3, False, "v2", v2_backup, v2_receive),
                    ("v2-different-index", 0, False, "v2", v2_backup, v2_receive),
                    ("legacy-v1-same-index", 3, True, "v1", v1_backup, v1_receive))
        for name, key_index, expected_match, version, b_backup, b_receive in schedule:
            funding_args = ["funding", "/backup.json", "/public/01-bootstrap/descriptor.json", str(key_index)]
            funding = experiment.run(name + "-funding-info", wallet, experiment.mounts(b_backup), funding_args)
            legacy_funding_equal = None
            if version == "v1":
                old_funding = experiment.run(name + "-old-cli-funding", legacy,
                                             experiment.mounts(b_backup), funding_args)
                assert funding == old_funding, "legacy funding output changed under new software"
                legacy_funding_equal = True
            parent = experiment.run(name + "-synthetic-parent", helper, [],
                                    ["fund", funding["script_public_key"]])
            save(root / "private" / (name + "-synthetic-parent.json"), parent)
            joining = experiment.snapshot(name + "-00-parent", shared, parent=parent["transaction"])
            b = experiment.worker(name + "-admission", b_backup)
            b.request(joining, dict(action="admit", txid=parent["transaction"]["id"], index=0,
                         native_key_index=0 if key_index == 3 else 3), False)
            admission = proof(b, joining, dict(action="admit", txid=parent["transaction"]["id"],
                index=0, native_key_index=key_index), name + "-admission")
            b.stop()
            admitted = experiment.snapshot(name + "-01-admitted", joining, admission["transaction"])
            if name != "v2-same-index":
                a = experiment.worker(name + "-payment-author", a_backup)
            payment = proof(a, admitted, dict(action="pay", positions=[1], recipient=b_receive,
                amount_sompi="1920000000"), name + "-payment")
            a.stop()
            paid = experiment.snapshot(name + "-02-payment", admitted, payment["transaction"])
            assert sha(b_backup) == backup_hashes[version]
            owned = experiment.inspect(name + "-fresh-recovery-scan", b_backup, paid)
            assert owned["balance_sompi"] == "3080000000"
            assert {(row["position"], row["value_sompi"]) for row in owned["notes"] if not row["spent"]} == {
                (3, "1160000000"), (5, "1920000000")}
            restored = experiment.worker(name + "-fresh-recovery-exit", b_backup)
            assert restored.process is not b.process and b.stopped and a.stopped
            restored.request(paid, dict(action="exit", positions=[3, 5], native_key_index=0), False)
            exit_tx = proof(restored, paid, dict(action="exit", positions=[3, 5], native_key_index=3), name + "-exit")
            restored.stop()
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
            save(final / "terminal-payout.json", exit_tx["transaction"])
            signed = experiment.run(name + "-restored-native-payout-spend", helper,
                [(b_backup, "/backup.json"), (final, "/public")],
                ["payout-spend", "/backup.json", "/public/descriptor.json", "/public/terminal-payout.json", "3"])
            assert signed["native_validation_passed"] is True and signed["chain_acceptance_verified"] is False
            save(root / "private" / (name + "-payout-spend.json"), signed)
            if version == "v2":
                # A separate synthetic parent controlled by this wallet's EXIT key
                # must not be accepted as v2 funding, even at the same index.
                bad_parent = experiment.run(name + "-exit-purpose-parent", helper, [],
                                            ["fund", payout[0]["scriptPublicKey"]])
                wrong_purpose = experiment.snapshot(name + "-wrong-purpose-parent", shared,
                                                    parent=bad_parent["transaction"])
                action = root / "private" / (name + "-wrong-purpose.json")
                save(action, dict(action="admit", txid=bad_parent["transaction"]["id"], index=0,
                                  native_key_index=3))
                experiment.run(name + "-reject-exit-purpose-funding", helper,
                    [(b_backup, "/backup.json"), (wrong_purpose, "/public"), (action, "/action.json")],
                    ["prepare-check", "/backup.json", "/public", "/action.json"], False)
            assert sha(b_backup) == backup_hashes[version] and sha(a_backup) == a_hash
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
                backup_profile=profiles[version], original_backup_sha256=backup_hashes[version],
                original_backup_unchanged=True, recovery_fresh_process=True,
                terminal_payout_spend_native_validated=True, native_payout_discovery="known index 3 supplied",
                payout_spend_sha256=sha(root / "private" / (name + "-payout-spend.json")),
                legacy_old_new_funding_equal=legacy_funding_equal,
                exit_purpose_funding_rejected=version == "v2", wrong_owner_script_differs=True,
                ordinary_parent_fees_sompi=str(int(founder_parent["ordinary_fee_sompi"])
                                              + int(parent["ordinary_fee_sompi"])),
                founding_fee_sompi=accounting["founding_fee_sompi"]))
            print(name + ": native replay, original-backup recovery and payout spend passed.", flush=True)
        experiment.finish()
        assert len(operations) == 10 and len(experiment.workers) == 9
        verify_frozen(root, before, sources)
        if check_evaluation(args.evaluation.resolve()) != evaluation:
            raise ValueError("evaluation preparation changed during native trial")
        if sha(params / "pk.bin") != lifecycle.PIN["sha256"] or sha(params / "vk.bin") != lifecycle.VK_SHA256:
            raise ValueError("public parameters changed during trial")
        result = dict(schema="kpi-native-key-separation-result-v1", complete=True, arms=arms,
            proof_count=10, operations=operations, founder_backup_profile=a_profile,
            founder_original_backup_unchanged=sha(a_backup) == a_hash,
            evaluation_freeze_sha256=evaluation["freeze_sha256"],
            evaluation_preparation_sha256=evaluation["preparation_sha256"],
            chain_acceptance_verified=False, genuine_groth16_proofs=True,
            controls=experiment.controls, isolation=experiment.audits,
            elapsed_seconds=time.monotonic() - started,
            provenance_before="candidate-hashes-before.json", provenance_after="candidate-hashes-after.json",
            scope="Offline synthetic ancestry; original backup plus supplied public head; known-index native payout spend")
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
    parser.add_argument("--evaluation", type=Path, required=True)
    parser.add_argument("--legacy-wallet-binary", type=Path, required=True)
    parser.add_argument("--wallet-binary", type=Path, default=HERE / "target/release/kpi-two-input-wallet")
    parser.add_argument("--helper-binary", type=Path, default=HERE / "target/release/kpi-two-input-lifecycle")
    parser.add_argument("--output-parent", type=Path, default=Path("/home/luke/kpi-private/native-key-separation"))
    run(parser.parse_args())


if __name__ == "__main__":
    main()
