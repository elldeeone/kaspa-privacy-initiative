#!/usr/bin/env python3
"""Freeze, generate and isolate the first modeled 32-role falsification stage.

No wallet secrets, native transaction construction, proof generation or network.
Private seeds and truth live outside Git; observers receive one declared view.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import early_privacy_surface as surface
from early_privacy_surface import dependency_manifest, need, read, sandbox, save, sha

HERE = Path(__file__).resolve().parent
SPEC = "POPULATION-PRIVACY-SPEC.md"
SOURCES = ("population_privacy_trial.py", "population_privacy_model.py",
           "population_privacy_workload.py", "two_input_privacy_observer.py",
           "two_input_privacy_z3.py", "early_privacy_surface.py")
CANDIDATE = "aa6ed4947f7c25db128cd5d89b7c021d6b8fe690"
CALIBRATION = "evidence/2026-10-20-early-privacy/attempts/method-04"
VENV = Path("/home/luke/.local/share/kpi-shared-pool-tools")
REGIMES = ("overlap", "overlap", "sparse", "sparse")


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def prepare(output, venv):
    need(not output.is_relative_to(HERE.parents[1]), "private experiment must be outside Git")
    output.mkdir(mode=0o700)
    for directory in ("code", "private", "public", "runs"):
        (output / directory).mkdir(mode=0o700)
    for name in SOURCES + (SPEC,):
        shutil.copyfile(HERE / name, output / "code" / name)
    # This manifest exists before seed sampling, history generation or inference.
    save(output / "freeze.json", dict(
        schema="kpi-population-freeze-v1", candidate=CANDIDATE,
        sources={name: sha(output / "code" / name) for name in SOURCES + (SPEC,)},
        dependency_root=str(venv), dependencies=dependency_manifest(venv),
        calibration={name: sha(HERE / CALIBRATION / name) for name in
                     ("public-input.json", "observer-infer/result.json", "completion.json")},
        ordered_regimes=list(REGIMES),
        scope="Modeled owner-aware falsification; no new native validation or statistical qualification",
        runtime_trust="Author-written code, host OS and system runtime; isolation is not an independent audit",
    ))
    return dict(prepared=True, generated=False, freeze_sha256=sha(output / "freeze.json"))


def check(output):
    frozen = read(output / "freeze.json")
    need(sha(Path(__file__).resolve()) == frozen["sources"]["population_privacy_trial.py"],
         "runner differs from frozen source")
    need(sha(Path(surface.__file__).resolve()) == frozen["sources"]["early_privacy_surface.py"],
         "loaded host helper differs from frozen source")
    for name, expected in frozen["sources"].items():
        need(sha(output / "code" / name) == expected, "changed frozen source: " + name)
    need(dependency_manifest(Path(frozen["dependency_root"])) == frozen["dependencies"],
         "changed dependency bytes")
    return frozen


def command(output, frozen, destination, inputs):
    args = sandbox() + ["--ro-bind", frozen["dependency_root"], "/venv",
                        "--bind", str(destination), "/output"]
    for name in SOURCES:
        args += ["--ro-bind", str(output / "code" / name), "/" + name]
    for local, mount in inputs:
        args += ["--ro-bind", str(local), mount]
    return args


def isolated(output, frozen, name, mode, inputs=()):
    destination = output / "runs" / name
    destination.mkdir(mode=0o700)
    args = command(output, frozen, destination, inputs)
    mounts = [mount for _, mount in inputs]
    probe = (
        "import pathlib,json;"
        "assert not pathlib.Path('/home').exists();"
        "interfaces=[x.split(':')[0].strip() for x in "
        "pathlib.Path('/proc/net/dev').read_text().splitlines() if ':' in x];"
        "assert interfaces==['lo'];"
        "print(json.dumps({'interfaces':interfaces,'home_accessible':False}))"
    )
    audit = subprocess.run(args + ["--", "/venv/bin/python", "-c", probe],
                           capture_output=True, text=True, check=True)
    isolation = json.loads(audit.stdout)
    isolation.update(inputs=mounts, mode=mode, private_truth_mounted="/truth.json" in mounts)
    if mode in ("_observe", "_controls"):
        need(not isolation["private_truth_mounted"] and "/seeds.json" not in mounts,
             "private input in observer")
    save(destination / "isolation.json", isolation)
    save(destination / "inputs.json", {mount: sha(local) for local, mount in inputs})
    with (destination / "stdout.log").open("x") as stdout, (destination / "stderr.log").open("x") as stderr:
        status = subprocess.run(args + ["--", "/venv/bin/python", "/population_privacy_trial.py", mode],
                                stdout=stdout, stderr=stderr)
    save(destination / "process.json", dict(returncode=status.returncode))
    need(status.returncode == 0, "isolated process failed; preserve " + str(destination))
    return destination, read(destination / "result.json")


def controls(output):
    frozen = check(output)
    directory, result = isolated(output, frozen, "controls", "_controls")
    need(result["model"]["passed"] and result["model"]["complete"]
         and result["workload"]["passed"], "controls failed")
    check(output)
    save(output / "controls.json", dict(passed=True, result_sha256=sha(directory / "result.json"),
                                       result=result))
    return result


def generate(output):
    frozen = check(output)
    control = read(output / "controls.json")
    need(control["passed"] and control["result_sha256"] == sha(output / "runs/controls/result.json"),
         "controls must pass before sampling")
    need(not any((output / "private").iterdir()) and not any((output / "public").iterdir()),
         "fresh generation only; preserve used identities")
    bundles = [dict(requests=secrets.token_hex(32), opaque=secrets.token_hex(32)) for _ in REGIMES]
    save(output / "private/seeds.json", bundles)
    save(output / "seed-commitments.json", dict(
        freeze_sha256=sha(output / "freeze.json"),
        commitments=[canonical(bundle) for bundle in bundles],
        meaning="Four independent request sets, each with two matched arms; seeds withheld"))
    # Generation is a separate process, allowed to read seeds and write truth.
    with (output / "private/generation.log").open("x") as log:
        status = subprocess.run([str(Path(frozen["dependency_root"]) / "bin/python"),
                                 "-B", str(output / "code/population_privacy_trial.py"),
                                 "_generate", str(output)],
                                stdout=log, stderr=log,
                                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                                     "PYTHONPYCACHEPREFIX": str(output / "private/unused-pycache")})
    need(status.returncode == 0, "generation failed; preserve seeds, prefixes and private log")
    check(output)
    result = read(output / "generation.json")
    need(result["complete"], "incomplete generated history; do not resample")
    return result


def generate_private(output):
    import population_privacy_workload as workload
    bundles = read(output / "private/seeds.json")
    need([canonical(b) for b in bundles] == read(output / "seed-commitments.json")["commitments"],
         "seed commitments changed")
    cases = []
    for index, (bundle, regime) in enumerate(zip(bundles, REGIMES, strict=True), 1):
        arms = workload.generate(bundle, regime)
        for arm, history in arms.items():
            name = f"set-{index:02}-{arm}"
            directory = output / "public" / name
            directory.mkdir(mode=0o700)
            public, truth = history["public"], history["truth"]
            need("payout_owners" not in public, "payout-owner links are development controls only")
            save(directory / "public.json", public)
            save(output / "private" / (name + ".json"), truth)
            for view_name, members in [("C", []), ("pooled", list(range(8)))] + [
                    (f"P-{role}", [role]) for role in range(8)]:
                save(directory / (view_name + ".json"), workload.make_view(public, truth, members))
            cases.append(dict(name=name, regime=regime, arm=arm,
                              complete=history["complete"], error=history["error"],
                              events=len(public["algebra"]["events"]),
                              ordinary_payments=sum(e["kind"] == "payment" for e in truth["events"]),
                              pins={p.name: sha(p) for p in sorted(directory.glob("*.json"))},
                              truth_sha256=sha(output / "private" / (name + ".json")),
                              accounting={key: value for key, value in truth["accounting"].items()
                                          if not key.startswith("role_")}))
    save(output / "generation.json", dict(complete=all(c["complete"] for c in cases), cases=cases,
                                         independent_request_sets=len(bundles),
                                         seed_commitments_sha256=sha(output / "seed-commitments.json")))


def score(public, view, prediction, truth):
    import population_privacy_model as model
    import population_privacy_workload as workload
    need(prediction["public_sha256"] == model.digest(public) and
         prediction["view_sha256"] == model.digest(view), "prediction input identity")
    final = len(public["algebra"]["events"]) - 1
    expected = [dict(event=i, through_event=final) for i, event in
                enumerate(public["algebra"]["events"]) if i > 0 and event["mode"] == 1]
    need(prediction["requested_targets"] == expected, "changed requested target coverage")
    actual_targets = [dict(event=r["event"], through_event=r["through_event"])
                      for r in prediction["rows"]]
    need(actual_targets == expected[:len(actual_targets)], "missing/duplicate/reordered target rows")
    need(not prediction["complete"] or actual_targets == expected, "incomplete target set")
    need(workload.accounting(public, truth["values"], truth["owners"], truth["inputs"],
                             truth["events"]) == truth["accounting"], "truth accounting changed")
    consistency = model.validate_truth(public, view, truth)
    need(consistency["complete"] and consistency["cp_sat"] == consistency["z3"] == "SAT",
         "actual generated truth excluded by observer model")
    members, adversaries = set(view["members"]), set(public["adversaries"])
    authors = {r["event"] for r in view["authored"]}
    received = {r["position"] for r in view["receipts"]}
    admitted = {public["funding_owners"][public["algebra"]["initial"]["funding_group"]]}
    all_admitted = {}
    for i, e in enumerate(public["algebra"]["events"]):
        if e["mode"] == 0:
            admitted.add(public["funding_owners"][e["funding_group"]])
        all_admitted[i] = len(admitted) == len(public["roles"])
    rows = []
    for row in prediction["rows"]:
        i = row["event"]
        hidden, event = truth["events"][i], public["algebra"]["events"][i]
        need(hidden["kind"] == "payment", "nonpayment prediction")
        actual = {key: hidden[key] for key in ("sender", "recipient", "amount")}
        need(actual["amount"] == truth["values"][event["new"][0]] and
             actual["recipient"] == truth["owners"][event["new"][0]] and
             all(truth["owners"][p] == actual["sender"] for p in truth["inputs"][str(i)]),
             "hidden event inconsistent with concrete note history")
        endpoints = {actual["sender"], actual["recipient"]}
        primary = all_admitted[i] and not endpoints.intersection(adversaries | members)
        direct = dict(sender=i in authors,
                      recipient=i in authors or event["new"][0] in received,
                      amount=i in authors or event["new"][0] in received)
        forced = {}
        for field in actual:
            proposition = row[field]
            forced[field] = proposition["forced"]
            if forced[field]:
                need(proposition["candidate"] == actual[field], "forced fact contradicts actual truth")
                need(all(proposition["certificates"][engine] == {
                    "candidate": "SAT", "different": "UNSAT"} for engine in ("cp_sat", "z3")),
                    "missing dual-solver forced certificate")
        rows.append(dict(event=i, through_event=row["through_event"], primary_eligible=primary,
                         startup=not all_admitted[i], adversary_endpoint=bool(endpoints & adversaries),
                         directly_known=direct, forced=forced,
                         undisclosed_forced={k: forced[k] and not direct[k] for k in forced}))
    primary = [r for r in rows if r["primary_eligible"]]
    failures = [r for r in primary if any(r["undisclosed_forced"].values())]
    return dict(complete=prediction["complete"], truth_consistency=consistency,
                arm=truth["arm"], rows=rows, tested_primary_targets=len(primary),
                forced_primary_disclosures=failures,
                persistent_counterexample_requires_review=truth["arm"] == "persistent" and bool(failures),
                qualification_pass=False,
                limit="Exact conditional disclosures only; no real-world anonymity or rate qualification")


def run(output, case_name, view_name):
    frozen = check(output)
    generation = read(output / "generation.json")
    need(generation["complete"], "generation incomplete")
    case = next((c for c in generation["cases"] if c["name"] == case_name), None)
    need(case is not None, "unknown case")
    truth_path = output / "private" / (case_name + ".json")
    need(sha(truth_path) == case["truth_sha256"], "changed generated truth")
    directory = output / "public" / case_name
    need("payout_owners" not in read(directory / "public.json"),
         "undeclared payout-owner side information")
    for name, expected in case["pins"].items():
        need(sha(directory / name) == expected, "changed public/view file")
    need(view_name + ".json" in case["pins"] and view_name != "public", "unknown participant view")
    selected = [(directory / "public.json", "/public.json"),
                (directory / (view_name + ".json"), "/view.json")]
    label = case_name + "-" + view_name + "-final"
    observed, prediction = isolated(output, frozen, label, "_observe", selected)
    seal = dict(prediction_sha256=sha(observed / "result.json"),
                public_sha256=sha(directory / "public.json"),
                view_sha256=sha(directory / (view_name + ".json")),
                truth_sha256=case["truth_sha256"],
                freeze_sha256=sha(output / "freeze.json"))
    save(observed / "prediction-seal.json", seal)
    # Truth enters only this separate scorer, after all predictions are sealed.
    scored, result = isolated(output, frozen, label + "-score", "_score", selected + [
        (observed / "result.json", "/prediction.json"),
        (truth_path, "/truth.json")])
    need(sha(observed / "result.json") == seal["prediction_sha256"], "predictions changed during scoring")
    need(sha(truth_path) == case["truth_sha256"], "truth changed during scoring")
    check(output)
    save(observed / "completion.json", dict(
        complete=result["complete"], prediction_seal=seal, score_sha256=sha(scored / "result.json"),
        qualification_pass=False, scope="One case and view at final horizon only",
        persistent_counterexample_requires_review=result["persistent_counterexample_requires_review"]))
    return dict(case=case_name, view=view_name, complete=result["complete"],
                tested_primary_targets=result["tested_primary_targets"],
                forced_primary_disclosures=result["forced_primary_disclosures"],
                qualification_pass=False)


def main():
    os.umask(0o077)
    if len(sys.argv) > 1 and sys.argv[1].startswith("_"):
        mode = sys.argv[1]
        if mode == "_generate":
            generate_private(Path(sys.argv[2]))
            return
        if mode == "_controls":
            import population_privacy_model as model
            import population_privacy_workload as workload
            result = dict(model=model.controls(), workload=workload.controls())
        elif mode == "_observe":
            import population_privacy_model as model
            result = model.analyze(read(Path("/public.json")), read(Path("/view.json")))
        else:
            need(mode == "_score", "unknown internal command")
            result = score(*(read(Path("/" + name + ".json")) for name in
                             ("public", "view", "prediction", "truth")))
        save(Path("/output/result.json"), result)
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "controls", "generate", "run"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--venv", type=Path, default=VENV)
    parser.add_argument("--case", default="set-01-persistent")
    parser.add_argument("--view", default="pooled")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.command == "prepare":
        result = prepare(output, args.venv.resolve())
    elif args.command == "controls":
        result = controls(output)
    elif args.command == "generate":
        result = generate(output)
    else:
        result = run(output, args.case, args.view)
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
