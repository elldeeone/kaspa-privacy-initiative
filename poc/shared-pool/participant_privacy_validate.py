"""Post-observation H16 audit, including the complete original integer witness.

This private-side process may read plans/truth only after all predictions and
main scoring finish. It never produces attack predictions.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import time

from participant_privacy_observer import ParticipantModel, prefix_view
from participant_privacy_view import ledger

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h16_controller", HERE / "participant-privacy.py")
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
read, sha, save = controller.read, controller.sha, controller.save


def validate(root, earlier):
    start = time.monotonic()
    config = controller.freeze()
    summary = read(root / "summary.json")
    if summary["completed_observations"] != 64 or not summary["all_truth_survives"]:
        raise ValueError("private witness audit requires completed observations and scoring")
    pins = read(root / "execution-pins.json")
    if any(sha(HERE / name) != digest for name, digest in pins["sources"].items()):
        raise ValueError("executed source changed")
    checked = 0
    for case in config["cases"]:
        plan, truth = [read(root / case / f"{name}.json") for name in ("plan", "truth")]
        notes, events = ledger(plan)
        if any(truth[str(i)]["inputs"] != e["inputs"] for i, e in enumerate(events) if e["inputs"]):
            raise ValueError("plan/ground-truth graph mismatch")
        for arm in config["arms"]:
            data = read(root / case / f"{arm}.json")
            for participant in config["participants"]:
                view = read(root / case / f"{arm}-participant-{participant}.json")
                for profile in config["profiles"]:
                    for end in range(len(data["events"])):
                        prefix = dict(data, events=data["events"][:end + 1])
                        model = ParticipantModel(prefix, prefix_view(data, view, end), profile)
                        for p, value in enumerate(model.values):
                            model.model.add(value == notes[p]["value"])
                        fixed = {i: e["inputs"] for i, e in enumerate(events)
                                 if i <= end and e["inputs"]}
                        if not model.check(fixed=fixed):
                            raise ValueError(f"complete integer witness excluded: {case}/{arm}/{participant}/{profile}/{end}")
                        checked += 1
    isolation = [read(p) for p in root.glob("*/*/isolation.json")]
    if len(isolation) != 64 or not all(
            p["nested_user_namespace_denied"] and p["interfaces"] == ["lo"]
            and {"/proc/1/cmdline", "/proc/self/mountinfo"} <= set(p["inaccessible"])
            for p in isolation):
        raise ValueError("missing corrected isolation receipt")
    old_pins = read(earlier / "execution-pins.json")
    for name in controller.OBSERVER_FILES:
        if old_pins["sources"][name] != pins["sources"][name]:
            raise ValueError("observer equations changed between attempts")
    if (read(root / "private-provenance.json")["projected_views_sha256"]
            != read(earlier / "private-provenance.json")["projected_views_sha256"]):
        raise ValueError("participant views changed between attempts")
    compared, incomplete = 0, []
    for previous in earlier.glob("*/*/predictions.json"):
        try:
            old = read(previous)
        except json.JSONDecodeError:
            incomplete.append(str(previous.relative_to(earlier)))
            continue
        current = read(root / previous.relative_to(earlier))
        if old["rows"] != current["rows"]:
            raise ValueError("isolation correction changed a candidate result")
        compared += 1
    for name, digest in config["private_source_hashes"].items():
        if sha(root / name) != digest:
            raise ValueError("original private input changed")
    receipt = dict(
        complete_original_value_and_input_witness_prefix_checks=checked,
        corrected_isolation_receipts=len(isolation),
        repeated_complete_predictions_identical=compared, incomplete_earlier_files=incomplete,
        all_projected_views_identical=True, observer_equations_unchanged=True,
        baseline_source_and_evidence_hashes_valid=True,
        seconds=time.monotonic() - start, validator_sha256=sha(Path(__file__)),
        final_execution_pins_sha256=sha(root / "execution-pins.json"))
    save(root / "validation.json", receipt)
    print(json.dumps(receipt))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("earlier", type=Path)
    args = parser.parse_args()
    validate(args.root, args.earlier)
