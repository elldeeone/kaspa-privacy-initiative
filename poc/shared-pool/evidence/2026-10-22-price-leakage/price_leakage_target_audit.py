#!/usr/bin/env python3
"""Additive post-completion semantic recount; no generation or new inference.

Run only after all predictions, original scoring and public export complete.
Mount the closed seed-free score-inputs at /data; cases, result, process,
isolation and inputs JSON at /score; and completion/export receipts plus the
export manifest at /terminal. Only an
aggregate audit receipt is written. No original scorer/model/observer imports.
"""
import argparse
from datetime import datetime
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import socket

PROFILES = ("C+D", "pooled")
BASE = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported",
        "partial_tail", "split_tail", "receipt_timing", "cash_inverse", "colluder_tags",
        "bridge_ancestry", "combined")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
AMOUNTS = ("amount_within_10pct", "amount_exact")
CONTRASTS = ("public_minus_price", "pooled_minus_price", "pooled_minus_public")
SOURCES = ("working_balance_trial.py", "working_balance_trial_tests.py", "working_balance_model.py",
           "working_balance_model_tests.py", "working_balance_observer.py", "working_balance_observer_tests.py",
           "working_balance_validate.py", "working_balance_validator_tests.py", "price_leakage_trial.py",
           "price_leakage_trial_tests.py", "price_leakage_score.py", "price_leakage_score_tests.py", "PRICE-LEAKAGE-SPEC.md")
BOUNDARY = "finite arithmetic hypotheses; not exhaustive inference or native evidence"


def need(ok, label):
    if not ok:
        raise ValueError("target-audit: " + label)


def integer(value, low=0, high=2**64-1):
    need(type(value) is int and low <= value <= high, "integer")
    return value


def fields(value, names, label):
    need(type(value) is dict and set(value) == set(names), label)


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def plain(path, directory=False):
    path = Path(path).absolute()
    need(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "unsafe path")
    need(path.is_dir() if directory else path.is_file(), "missing artifact")
    return path


def parse(blob):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("target-audit: nonfinite JSON")
    return json.loads(blob, object_pairs_hook=pairs, parse_constant=invalid)


def read(root, name, pin=None):
    need(type(name) is str and name and not Path(name).is_absolute() and ".." not in Path(name).parts, "relative path")
    blob = plain(Path(root)/name).read_bytes()
    if pin is not None:
        need(digest(blob) == pin, "artifact digest")
    return parse(blob)


def sha(path):
    return digest(plain(path).read_bytes())


def ratio(value):
    return dict(numerator=value.numerator, denominator=value.denominator)


def timestamp(value):
    result = datetime.fromisoformat(value)
    need(result.tzinfo is not None, "timestamp timezone")
    return result


def isolation(mode):
    return dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
                mode=mode, mounts={"controls": [], "generate": ["/seed.json"],
                    "observe": ["/public.json", "/directory.json", "/view.json", "/targets.json"],
                    "score": ["/data"]}[mode], truth_mounted=mode == "score", seed_mounted=mode == "generate")


def paths(case):
    return {k: ("private/" if k == "truth" else "public/")+case+"-"+k+".json"
            for k in ("public", "directory", "cost", "truth", "C", "pooled")}


def derived_targets(public, truth):
    """Derive PAY targets from economic obligations and actual event outputs.

    Preparatory admission/merge events can share an obligation. They are never
    substituted for its actual payment. Declared truth.targets is checked last.
    """
    need(truth["schema"] == "kpi-working-balance-truth-v1" and truth["cell"] == "sparse-independent"
         and truth["arm"] == "partial", "truth scope")
    payments, hidden = truth["plan"]["payments"], truth["events"]
    need(type(payments) is list and len(payments) == 64 and len(hidden) == len(public["events"]), "economic roster")
    by_obligation = {}
    for index, (event, record) in enumerate(zip(public["events"], hidden, strict=True)):
        need(type(event["event"]) is int and type(record["event"]) is int
             and event["event"] == record["event"] == index, "actual event alignment")
        if record["kind"] != "pay":
            continue
        obligation = integer(record["obligation"], 0, 63)
        need(obligation not in by_obligation and record["phase"] == "payment"
             and type(event["mode"]) is int and event["mode"] == 1
             and type(event["payout"]) is int and event["payout"] == 0, "unique actual PAY")
        by_obligation[obligation] = index
    need(set(by_obligation) == set(range(64)), "complete actual payment obligations")
    targets = []
    for obligation, payment in enumerate(payments):
        need(type(payment["obligation"]) is int and payment["obligation"] == obligation, "ordered payment plan")
        sender, recipient = integer(payment["sender"], 0, 31), integer(payment["recipient"], 0, 31)
        amount = integer(payment["amount"], 1)
        integer(payment["minute"])
        need(sender != recipient, "economic payment roles")
        event = by_obligation[obligation]
        record, observed = hidden[event], public["events"][event]
        need(type(record["owner"]) is int and record["owner"] == sender
             and type(observed["minute"]) is int and observed["minute"] == payment["minute"], "payment owner/time")
        outputs = record["outputs"]
        need(type(outputs) is list and len(outputs) == 2 and [out["position"] for out in outputs] == observed["new"], "payment output positions")
        need(type(outputs[0]["value"]) is int and outputs[0]["value"] == amount
             and type(outputs[0]["recipient"]) is int and outputs[0]["recipient"] == recipient, "economic payment output")
        change = integer(outputs[1]["value"])
        need(outputs[1]["recipient"] == (sender if change else None), "actual sender change owner")
        targets.append(dict(obligation=obligation, event=event, sender=sender, recipient=recipient, amount=amount))
    need(canonical(targets) == canonical(truth["targets"]), "declared target disagreement")
    return [target for target in targets if target["sender"] >= 8 and target["recipient"] >= 8]


def check_prediction(prediction, public, directory, view, profile):
    fields(prediction, ("schema", "complete", "profile", "through_event", "public_sha256", "directory_sha256",
                       "view_sha256", "target_events_sha256", "rows", "boundary"), "prediction schema")
    need(prediction["schema"] == "kpi-working-balance-predictions-v1" and prediction["complete"] is True
         and prediction["profile"] == profile and prediction["boundary"] == BOUNDARY
         and type(prediction["through_event"]) is int and prediction["through_event"] == len(public["events"])-1, "prediction scope")
    targets = [e["event"] for e in public["events"] if e["mode"] == 1 and e["payout"] == 0]
    for key, value in (("public", public), ("directory", directory), ("view", view), ("target_events", targets)):
        need(prediction[key+"_sha256"] == canonical(value), "prediction input binding")
    need(type(prediction["rows"]) is list and [r["event"] for r in prediction["rows"]] == targets, "all observable targets")
    names = BASE if profile == "C+D" else BASE+tuple("C_"+n for n in BASE)
    result = {}
    for row in prediction["rows"]:
        fields(row, ("event", "event_id", "guesses"), "prediction row")
        event = integer(row["event"], 0, len(public["events"])-1)
        need(row["event_id"] == public["events"][event]["event_id"], "prediction event identity")
        fields(row["guesses"], names, "attack roster")
        for guess in row["guesses"].values():
            fields(guess, ("sender", "recipient", "amount", "relationship_rank"), "guess schema")
            integer(guess["sender"], 0, 31); integer(guess["recipient"], 0, 31); integer(guess["amount"])
            need(type(guess["relationship_rank"]) is list and len(guess["relationship_rank"]) == 4, "rank shape")
            for value in guess["relationship_rank"]:
                integer(value, -(2**63)+1, 2**63-1)
        result[event] = row["guesses"]
    return result, targets


def outcomes(guess, target):
    sender, recipient = guess["sender"] == target["sender"], guess["recipient"] == target["recipient"]
    return dict(sender=sender, recipient=recipient, relationship=sender and recipient,
                amount_within_10pct=abs(guess["amount"]-target["amount"])*10 <= target["amount"],
                amount_exact=guess["amount"] == target["amount"])


def case_counts(public, truth, predictions):
    targets = derived_targets(public, truth)
    need(bool(targets), "empty protected population")
    baseline = {"amount_within_10pct": [abs(4_500_000_000-t["amount"])*10 <= t["amount"] for t in targets],
                "amount_exact": [t["amount"] == 1_000_000_000 for t in targets]}
    vectors = {p: {m: [] for m in METRICS} for p in PROFILES}
    for target in targets:
        for profile in PROFILES:
            guesses = predictions[profile][target["event"]]
            need(guesses["prior"]["amount"] == 4_500_000_000, "protected prior action")
            for metric, value in outcomes(guesses["split_tail"], target).items():
                vectors[profile][metric].append(value)
    pairs = {}
    for name, left, right in zip(CONTRASTS, (vectors["C+D"], vectors["pooled"], vectors["pooled"]),
                               (baseline, baseline, vectors["C+D"]), strict=True):
        pairs[name] = {}
        for metric in AMOUNTS:
            a, b = left[metric], right[metric]
            gains = sum(x and not y for x, y in zip(a, b, strict=True))
            losses = sum(y and not x for x, y in zip(a, b, strict=True))
            pairs[name][metric] = dict(gains=gains, losses=losses, eligible=len(targets),
                                       difference=ratio(Fraction(sum(a)-sum(b), len(targets))))
    return dict(eligible_targets=len(targets), observable_targets=sum(e["mode"] == 1 and e["payout"] == 0 for e in public["events"]),
                price_baseline={m: sum(v) for m, v in baseline.items()},
                profiles={p: {m: sum(v) for m, v in metrics.items()} for p, metrics in vectors.items()}, paired=pairs)


def compare_case(recount, saved):
    need(saved["schema"] == "kpi-price-leakage-case-v1" and saved["complete"] is True
         and saved["cell"] == "sparse-independent" and saved["arm"] == "partial", "saved case scope")
    need(type(saved["eligible_targets"]) is int and recount["eligible_targets"] == saved["eligible_targets"]
         and type(saved["observable_targets"]) is int and recount["observable_targets"] == saved["observable_targets"]
         and canonical(recount["price_baseline"]) == canonical(saved["price_baseline"])
         and canonical(recount["paired"]) == canonical(saved["paired"]), "per-ledger semantic recount")
    for profile in PROFILES:
        need(canonical(recount["profiles"][profile]) == canonical(saved["profiles"][profile]["variants"]["split_tail"]), "fixed-attack target recount")


def compare_aggregate(recounts, saved):
    count = len(recounts); total = sum(c["eligible_targets"] for c in recounts)
    need(saved["complete"] is True and saved["qualification_pass"] is False and saved["inferential_attack"] == "split_tail"
         and saved["independent_ledgers"] == count and saved["eligible_targets"] == total
         and saved["observable_targets"] == sum(c["observable_targets"] for c in recounts), "terminal summary scope")
    def rates(values):
        return dict(correct=sum(values), eligible=total, pooled_rate=ratio(Fraction(sum(values), total)),
                    equal_ledger_rate=ratio(sum((Fraction(v, c["eligible_targets"]) for v, c in zip(values, recounts, strict=True)), Fraction())/count))
    for metric in AMOUNTS:
        need(canonical(rates([c["price_baseline"][metric] for c in recounts])) == canonical(saved["price_baseline"][metric]), "aggregate baseline recount")
    for profile in PROFILES:
        for metric in METRICS:
            need(canonical(rates([c["profiles"][profile][metric] for c in recounts])) == canonical(saved["profiles"][profile]["variants"]["split_tail"][metric]), "aggregate fixed-attack recount")
    for contrast in CONTRASTS:
        for metric in AMOUNTS:
            pairs = [c["paired"][contrast][metric] for c in recounts]
            gains, losses = sum(p["gains"] for p in pairs), sum(p["losses"] for p in pairs)
            expected = dict(gains=gains, losses=losses, eligible=total,
                            pooled_difference=ratio(Fraction(gains-losses, total)),
                            equal_ledger_difference=ratio(sum((Fraction(p["difference"]["numerator"], p["difference"]["denominator"]) for p in pairs), Fraction())/count))
            need(all(canonical(saved["contrasts"][contrast]["metrics"][metric][k]) == canonical(v) for k, v in expected.items()), "aggregate paired recount")
    return total


def audit(data, score, terminal, design_freeze, public_rehearsal=False):
    """Default accepts512 held-out ledgers; explicit public rehearsal accepts4."""
    need(type(public_rehearsal) is bool, "audit mode")
    ledger_count = 4 if public_rehearsal else 512
    job_count = 2*ledger_count
    data, score, terminal = (plain(p, directory=True) for p in (data, score, terminal))
    for folder, expected in ((score, {n+".json" for n in ("cases", "result", "process", "isolation", "inputs")}),
                             (terminal, {"completion.json", "export-receipt.json", "manifest.json"})):
        need({p.name for p in folder.iterdir()} == expected and all(p.is_file() and not p.is_symlink() for p in folder.iterdir()), "closed audit auxiliary mounts")
    design = parse(plain(design_freeze).read_bytes())
    need(design["schema"] == "kpi-price-target-audit-design-v1" and design["sources"][Path(__file__).name] == sha(__file__), "audit source freeze")
    need(not Path("/home").exists() and not Path("/proc").exists()
         and [name for _, name in socket.if_nameindex()] == ["lo"], "run inside isolated seed-free audit sandbox")
    freeze, generation, batch, predictions = (read(data, n) for n in ("freeze.json", "generation.json", "prediction-batch.json", "predictions.json"))
    completion, exported, manifest = (read(terminal, n) for n in ("completion.json", "export-receipt.json", "manifest.json"))
    cases, summary = read(score, "cases.json"), read(score, "result.json")
    need(freeze["schema"] == "kpi-price-leakage-freeze-v1" and type(freeze["rehearsal"]) is bool
         and freeze["rehearsal"] == public_rehearsal and freeze["ledgers"] == ledger_count
         and freeze["profiles"] == list(PROFILES) and freeze["cell"] == "sparse-independent" and freeze["arm"] == "partial"
         and freeze["horizon"] == "final" and freeze["qualification_pass"] is False and set(freeze["sources"]) == set(SOURCES), "frozen evaluation scope")
    need(all(freeze["sources"][name] == pin for name, pin in design["reference_sources"].items()), "reviewed semantic source identities")
    need(summary["schema"] == "kpi-price-leakage-summary-v1" and type(summary["rehearsal"]) is bool
         and summary["rehearsal"] == public_rehearsal and summary["development_only"] == public_rehearsal,
         "summary evaluation/rehearsal mode")
    freeze_pin, generation_pin, batch_pin = (sha(data/n) for n in ("freeze.json", "generation.json", "prediction-batch.json"))
    need(completion["complete"] is True and completion["qualification_pass"] is False
         and type(completion["rehearsal"]) is bool and completion["rehearsal"] == public_rehearsal
         and completion["ledgers"] == ledger_count
         and completion["freeze_sha256"] == freeze_pin and completion["prediction_batch_sha256"] == batch_pin
         and completion["score_sha256"] == sha(score/"result.json"), "terminal completion identity")
    need(exported["complete"] is True and exported["freeze_sha256"] == freeze_pin
         and exported["completion_sha256"] == sha(terminal/"completion.json") and exported["manifest_sha256"] == sha(terminal/"manifest.json")
         and manifest["schema"] == "kpi-price-leakage-export-v1" and manifest["freeze_sha256"] == freeze_pin
         and timestamp(completion["completed_utc"]) <= timestamp(exported["completed_utc"]), "verified export receipt identity")
    need(generation["complete"] is True and generation["freeze_sha256"] == freeze_pin
         and batch["complete"] is True and batch["freeze_sha256"] == freeze_pin and batch["generation_sha256"] == generation_pin
         and batch["predictions_sha256"] == sha(data/"predictions.json"), "complete public barrier")
    score_process = read(score, "process.json", completion["score_process_sha256"])
    need(read(score, "isolation.json", completion["score_isolation_sha256"]) == isolation("score")
         and read(score, "inputs.json") == {"/data": "closed-score-tree"}
         and type(score_process["returncode"]) is int and score_process["returncode"] == 0
         and timestamp(batch["sealed_utc"]) <= timestamp(score_process["started_utc"])
         <= timestamp(score_process["ended_utc"]) <= timestamp(completion["completed_utc"]), "original score after full barrier")
    ids = ["ledger-"+str(i).zfill(4) for i in range(ledger_count)]
    matrix = [(case, profile) for case in ids for profile in PROFILES]
    need([r["case"] for r in generation["records"]] == ids and len(cases) == ledger_count
         and [(r["case"], r["profile"]) for r in batch["records"]] == matrix
         and [(r["case"], r["profile"]) for r in predictions] == matrix, "complete ledger/job roster")
    need(len({r["pins"][paths(r["case"])["public"]] for r in generation["records"]}) == ledger_count, "distinct complete public ledgers")
    public_names = {"freeze.json", "controls.json", "seed-commitment.json", "generation.json", "predictions.json", "prediction-batch.json"}
    public_names |= {"runs/"+mode+"/"+name+".json" for mode in ("controls", "generate") for name in ("result", "process", "isolation", "inputs")}
    truth_names = set()
    for case, record in zip(ids, generation["records"], strict=True):
        expected = paths(case)
        need(record["files"] == expected and set(record["pins"]) == set(expected.values()), "closed generated paths")
        public_names.update(n for k, n in expected.items() if k != "truth")
        public_names.add("inputs/"+case+"-targets.json"); truth_names.add(expected["truth"])
    public_names |= {"runs/observe-"+str(i).zfill(4)+"/"+n+".json" for i in range(job_count) for n in ("result", "process", "isolation", "inputs", "seal")}
    actual = set()
    for path in data.rglob("*"):
        need(not path.is_symlink(), "staged symlink")
        if path.is_file(): actual.add(str(path.relative_to(data)))
    need(actual == public_names | truth_names and not any("seed.json" in Path(n).parts for n in actual), "closed seed-free staged tree")
    export_names = public_names | {"completion.json"} | {"runs/score/"+n+".json" for n in ("result", "cases", "process", "isolation", "inputs")} | {"code/"+n for n in SOURCES}
    need(set(manifest["files"]) == export_names and exported["files"] == len(export_names), "closed public export roster")
    for name in public_names:
        need(sha(data/name) == manifest["files"][name]["sha256"], "export/stage public digest")
    for name in ("cases", "result", "process", "isolation", "inputs"):
        need(sha(score/(name+".json")) == manifest["files"]["runs/score/"+name+".json"]["sha256"], "export/score digest")
    need(sha(terminal/"completion.json") == manifest["files"]["completion.json"]["sha256"], "export/completion digest")
    for name, pin in freeze["sources"].items():
        need(manifest["files"]["code/"+name]["sha256"] == pin, "frozen source export identity")
    controls, seed_commit = read(data, "controls.json"), read(data, "seed-commitment.json")
    need(controls["passed"] is True and controls["freeze_sha256"] == freeze_pin and seed_commit["freeze_sha256"] == freeze_pin
         and seed_commit["controls_sha256"] == sha(data/"controls.json") and seed_commit["ledgers"] == ledger_count
         and type(seed_commit["public_seed"]) is bool and seed_commit["public_seed"] == public_rehearsal
         and generation["seed_commitment_sha256"] == sha(data/"seed-commitment.json"), "pre-sampling public provenance")
    for mode, receipt in (("controls", controls), ("generate", generation)):
        prefix = "runs/"+mode+"/"
        process = read(data, prefix+"process.json", receipt["process_sha256"])
        lower = freeze["frozen_utc"] if mode == "controls" else seed_commit["sampled_utc"]
        need(type(process["returncode"]) is int and process["returncode"] == 0
             and read(data, prefix+"isolation.json", receipt["isolation_sha256"]) == isolation(mode)
             and read(data, prefix+"inputs.json") == ({} if mode == "controls" else {"/seed.json": seed_commit["seed_sha256"]})
             and timestamp(lower) <= timestamp(process["started_utc"]) <= timestamp(process["ended_utc"])
             <= timestamp(receipt["completed_utc"]), "generator/control isolation and chronology")
    need(timestamp(controls["completed_utc"]) <= timestamp(seed_commit["sampled_utc"])
         <= timestamp(generation["completed_utc"]), "controls before sampling")
    controls_result = read(data, "runs/controls/result.json", controls["result_sha256"])
    need(controls_result["passed"] is True and type(controls_result["tests"]) is int and controls_result["tests"] > 0, "successful pre-sampling controls")
    need(read(data, "runs/generate/result.json", generation["result_sha256"]) == dict(complete=True, records=generation["records"]), "generated artifact origin")
    authorized = []
    for index, record in enumerate(generation["records"]):
        case = ids[index]; files = record["files"]
        # Public sealed predictions are verified before this case's truth opens.
        bundle = {k: read(data, files[k], record["pins"][files[k]]) for k in ("public", "directory", "C", "pooled")}
        checked = {}
        for offset, profile in enumerate(PROFILES):
            serial = 2*index+offset; prefix = "runs/observe-"+str(serial).zfill(4)+"/"
            seal_record, entry = batch["records"][serial], predictions[serial]
            need(seal_record["seal"] == prefix+"seal.json", "closed observer seal")
            seal = read(data, prefix+"seal.json", seal_record["seal_sha256"])
            need(seal["freeze_sha256"] == freeze_pin and seal["generation_sha256"] == generation_pin and seal["prediction_file"] == prefix+"result.json", "observer seal identity")
            prediction = read(data, prefix+"result.json", seal["prediction_sha256"])
            need(canonical(prediction) == canonical(entry["prediction"]), "sealed prediction copy")
            view_name = "C" if profile == "C+D" else "pooled"
            checked[profile], observed_targets = check_prediction(prediction, bundle["public"], bundle["directory"], bundle[view_name], profile)
            target_name = "inputs/"+case+"-targets.json"
            mounts = {"/public.json": files["public"], "/directory.json": files["directory"], "/view.json": files[view_name], "/targets.json": target_name}
            need(set(seal["inputs"]) == set(mounts.values()) and read(data, target_name) == observed_targets, "public observer input roster")
            need(all(sha(data/name) == seal["inputs"][name] for name in mounts.values()), "observer input digest")
            process = read(data, prefix+"process.json", seal["process_sha256"])
            need(type(process["returncode"]) is int and process["returncode"] == 0
                 and read(data, prefix+"isolation.json", seal["isolation_sha256"]) == isolation("observe")
                 and read(data, prefix+"inputs.json", seal["input_manifest_sha256"]) == {mount: seal["inputs"][name] for mount, name in mounts.items()}
                 and timestamp(generation["completed_utc"]) <= timestamp(process["started_utc"]) <= timestamp(process["ended_utc"])
                 <= timestamp(seal["sealed_utc"]) <= timestamp(batch["sealed_utc"]), "sealed observer execution")
        need(all(canonical(g) == canonical(checked["pooled"][event]["C_"+name]) for event, row in checked["C+D"].items() for name, g in row.items()), "public-copy equality")
        authorized.append((bundle, checked))
    # Every public job's seal, permitted inputs and process passes first.
    # This second pass is the first point at which any truth bytes are read.
    recounted = []
    for index, (record, (bundle, checked)) in enumerate(zip(generation["records"], authorized, strict=True)):
        files = record["files"]
        truth = read(data, files["truth"], record["pins"][files["truth"]])
        # Independently corroborate permitted disclosures against actual events.
        for profile, members in (("C+D", []), ("pooled", list(range(8)))):
            view = bundle["C" if profile == "C+D" else "pooled"]
            expected = dict(schema="kpi-working-balance-view-v1", members=members,
                authored=[{k: r[k] for k in ("event", "owner", "inputs", "outputs")} for r in truth["events"] if r["owner"] in members],
                receipts=[dict(position=o["position"], value=o["value"], owner=o["recipient"]) for r in truth["events"] for o in r["outputs"] if o["value"] > 0 and o["recipient"] in members])
            need(canonical(view) == canonical(expected), "actual participant disclosure scope")
        recount = case_counts(bundle["public"], truth, checked)
        compare_case(recount, cases[index])
        expected_binding = dict(public=canonical(bundle["public"]), directory=canonical(bundle["directory"]),
            views={p: canonical(bundle["C" if p == "C+D" else "pooled"]) for p in PROFILES},
            predictions={p: canonical(predictions[2*index+o]["prediction"]) for o, p in enumerate(PROFILES)})
        need(canonical(cases[index]["input_sha256"]) == canonical(expected_binding), "case input identities")
        recounted.append(recount)
    total = compare_aggregate(recounted, summary)
    return dict(schema="kpi-price-target-audit-receipt-v1", complete=True, additive_verification_only=True,
                public_rehearsal=public_rehearsal, ledgers_checked=ledger_count,
                sealed_observer_jobs=job_count, eligible_targets_checked=total,
                target_derivation="economic payment obligations and actual PAY outputs; declared targets cross-checked afterward",
                checked_attack="split_tail", checked_metrics=list(METRICS), checked_baselines="45-tKAS approximate; 10-tKAS exact",
                every_case_selected_metrics_match=True, aggregate_counts_and_paired_rates_match=True,
                input_sha256=dict(audit_design=sha(design_freeze), freeze=freeze_pin, prediction_batch=batch_pin,
                                  completion=sha(terminal/"completion.json"), export_manifest=sha(terminal/"manifest.json"),
                                  score_cases=sha(score/"cases.json"), score_result=sha(score/"result.json")),
                seed_opened=False, histories_regenerated=False, attacks_executed=False, original_verdict_changed=False,
                limits=["Semantic recount of existing frozen outcomes, not a new experiment or privacy criterion.",
                        "Does not establish independent sampling, source correctness, native acceptance or privacy qualification.",
                        "Exact e-values and descriptive other attacks are covered by the separate aggregate recount."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--score", type=Path, required=True)
    parser.add_argument("--terminal", type=Path, required=True)
    parser.add_argument("--design-freeze", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--public-rehearsal", action="store_true", help="accept only the completed4-ledger public-seed rehearsal")
    args = parser.parse_args()
    result = audit(args.data, args.score, args.terminal, args.design_freeze, args.public_rehearsal)
    with args.receipt.open("x") as stream:
        json.dump(result, stream, indent=2, allow_nan=False); stream.write("\n")
    print(json.dumps(dict(complete=True, ledgers_checked=result["ledgers_checked"], receipt_sha256=sha(args.receipt))))


if __name__ == "__main__":
    main()
