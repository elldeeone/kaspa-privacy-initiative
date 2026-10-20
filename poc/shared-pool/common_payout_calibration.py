#!/usr/bin/env python3
"""Validate H17 genuine bodies and export only the chosen fresh public branch."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from two_input_privacy_native import project, normalized


def read(path):
    return json.loads(path.read_text())


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024*1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write(path, data):
    with path.open("x") as out:
        json.dump(data, out, indent=2)
        out.write("\n")


def run(root, params, executable):
    """Fresh private identity only; preserve any existing run on collision."""
    here = Path(__file__).resolve().parent
    binary = root / "kpi-two-input"
    with executable.open("rb") as source, binary.open("xb") as target:
        shutil.copyfileobj(source, target)
    binary.chmod(0o700)
    write(root / "native-pins.json", dict(
        freeze="71d2aca", binary_sha256=sha(binary),
        params={n: sha(params / n) for n in ("pk.bin", "vk.bin", "setup.json")},
        plan_sha256=sha(root / "a0-s0/plan.json"), rayon_threads=4,
        sources={str(p.relative_to(here)): sha(p) for p in sorted((here / "src").rglob("*.rs"))},
        cargo_lock_sha256=sha(here / "Cargo.lock")))
    with (root / "native.log").open("x") as log:
        subprocess.run(["/usr/bin/time", "-v", "-o", str(root / "native-resource.txt"),
                        str(binary), "common-study", str(params), str(root / "a0-s0/plan.json"),
                        str(root / "native")], env=dict(os.environ, RAYON_NUM_THREADS="4"),
                       stdout=log, stderr=log, check=True)


def check(root):
    native = root / "native"
    binary = root / "kpi-two-input"
    pins = read(root / "native-pins.json")
    if sha(binary) != pins["binary_sha256"]:
        raise ValueError("native binary changed")
    summary = read(native / "summary.json")
    assert all(summary[k] for k in ("offline_only", "synthetic_utxos", "real_groth16_proofs"))
    assert summary["common_payout_sompi"] == 200_000_000
    assert len(summary["proofs"]) == 34
    choices = summary["optional_exit_checks"]
    assert len(choices) == 4 and {c["owner"] for c in choices} == {0, 1, 2, 3}
    for c in choices:
        assert all(c[k] for k in ("saved_before_partial", "unchanged_authorization", "isolated",
                                  "full_wins_partial_rejected", "partial_wins_full_rejected"))
        assert not c["wallet_keys_mounted"] and not c["proving_key_available"]
    expected = read(root / "a0-s0/public.json")
    plan = read(root / "a0-s0/plan.json")
    assert sha(root / "a0-s0/plan.json") == pins["plan_sha256"]
    comparisons = {}
    for arm in ("fresh", "saved"):
        model = copy.deepcopy(expected)
        if arm == "saved":
            for event, note in zip(model["events"][16:], plan["drains"], strict=True):
                event["anchor_count"] = note["born"]
        raw = native / f"{arm}-native-private.json"
        public = project(read(raw))
        if normalized(public) != normalized(model):
            raise ValueError(f"{arm} native/model projection differs")
        a = summary["arms"][arm]
        assert a["operations"] == 23 and a["reserve_remaining"] == 0
        assert a["fees_sompi"] == sum(e["fee"] for e in public["events"]) == 920_000_000
        assert a["payout_sompi"] == sum(e["payout"] for e in public["events"])
        assert a["funding_sompi"] == a["payout_sompi"] + a["fees_sompi"]
        assert len(a["checks"]) == 7 and all(p > 0 for p in a["wallet_exit_payouts_sompi"])
        for c in a["checks"]:
            assert all(c[k] for k in ("unchanged_authorization", "isolated",
                                      "alternate_rejected", "replay_rejected"))
            assert not c["proving_key_available"] and not c["wallet_keys_mounted"]
        replay = native / f"{arm}-replay.json"
        output = root / f"replay-{arm}"
        output.mkdir(mode=0o700)
        # A separate public-body verifier receives no private plan, wallet or PK.
        subprocess.run(["bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                        "--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/lib", "/lib",
                        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
                        "--ro-bind", str(binary), "/verify", "--ro-bind", str(raw), "/public.json",
                        "--bind", str(output), "/output", "--", "/verify", "verify-study",
                        "/public.json", "/output/replay.json"], check=True)
        shutil.copyfile(output / "replay.json", replay)
        verified = read(replay)
        assert verified["transactions"] == 23 and verified["reserve_remaining"] == 0
        assert verified["fee_sompi"] == a["fees_sompi"] and verified["payout_sompi"] == a["payout_sompi"]
        comparisons[arm] = dict(exact_normalized_projection_match=True,
                                private_trace_sha256=sha(raw), public_replay_sha256=sha(replay),
                                transactions=23)
    write(root / "calibration-check.json", dict(
        comparisons=comparisons, validator_sha256=sha(Path(__file__)),
        projector_sha256=sha(Path(__file__).with_name("two_input_privacy_native.py")),
        complete=True, native_summary_sha256=sha(native / "summary.json")))
    print("Both genuine traces match the model and pass public-body verification.")


def export(root, dest):
    check_receipt = read(root / "calibration-check.json")
    assert check_receipt["complete"]
    assert check_receipt["validator_sha256"] == sha(Path(__file__))
    assert check_receipt["projector_sha256"] == sha(Path(__file__).with_name("two_input_privacy_native.py"))
    native = root / "native"
    assert check_receipt["native_summary_sha256"] == sha(native / "summary.json")
    for arm in ("fresh", "saved"):
        assert check_receipt["comparisons"][arm]["private_trace_sha256"] == sha(native / f"{arm}-native-private.json")
    prepared = read(root / "preparation.json")["files"]
    for case in ("a0-s0", "a0-s1", "a1-s0", "a1-s1"):
        public = root / case / "public.json"
        assert sha(public) == prepared[f"{case}/public.json"]
        # Public amounts, ordering and opaque chain labels; no private matching.
        write(dest / case / "public.json", read(public))
    # Directly allowlisted public receipt; old/fresh alternative capability bodies
    # and raw optional-choice requests never leave the private directory.
    summary = read(native / "summary.json")
    summary["optional_exit_checks"] = [
        {k: v for k, v in row.items() if k not in ("owner", "original_position")}
        for row in summary["optional_exit_checks"]]
    for name, value in (
        ("calibration.json", summary),
        ("calibration-check.json", check_receipt),
        ("native-pins.json", read(root / "native-pins.json")),
        ("fresh-native.json", read(native / "fresh-native-private.json")),
        ("fresh-replay.json", read(native / "fresh-replay.json")),
        ("saved-replay.json", read(native / "saved-replay.json")),
    ):
        write(dest / name, value)
    resource = (root / "native-resource.txt").read_text()
    maximum = next(int(l.split(":")[-1]) for l in resource.splitlines() if "Maximum resident set size" in l)
    write(dest / "native-resources.json", dict(
        peak_rss_kib=maximum, meaning="proof process and children, not concurrent observers",
        actual_tkas_spent=0, rayon_threads=4))
    hashes = {str(p.relative_to(dest)): sha(p) for p in sorted(dest.rglob("*"))
              if p.is_file() and p.name != "SHA256SUMS.json"}
    manifest = dest / "SHA256SUMS.json"
    # This is the combined export's only replaceable file; immutable evidence
    # is first created by the observer exporter and extended before commit.
    manifest.write_text(json.dumps(hashes, indent=2)+"\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("run", "check", "export"))
    parser.add_argument("root", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--params", type=Path)
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    if args.command == "run":
        if args.params is None or args.binary is None:
            parser.error("run requires --params and --binary")
        run(args.root.resolve(), args.params.resolve(), args.binary.resolve())
    elif args.command == "check":
        check(args.root)
    else:
        export(args.root, args.destination)
