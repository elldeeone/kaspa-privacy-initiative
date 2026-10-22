#!/usr/bin/env python3
"""Frozen sparse-ledger price-baseline test; seal every attack before truth.

Only arithmetic fixtures are generated. No native proofs, funds, keys, RPC,
network access, broadcast, fitted attacks or optional stopping occur here.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import working_balance_trial as base

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUNNER = "price_leakage_trial.py"
SPEC = "PRICE-LEAKAGE-SPEC.md"
COUNT = 512
REHEARSAL_COUNT = 4
PROFILES = ("C+D", "pooled")
CELL = "sparse-independent"
ARM = "partial"
SOURCES = tuple(dict.fromkeys((*base.SOURCES, RUNNER, "price_leakage_trial_tests.py",
    "price_leakage_score.py", "price_leakage_score_tests.py")))
PYTHON = base.PYTHON
need, now, sha, digest, canonical = base.need, base.now, base.sha, base.digest, base.canonical
load, save, plain, relative = base.load, base.save, base.plain, base.relative


def ledger_ids(count):
    need(type(count) is int and count in (COUNT, REHEARSAL_COUNT), "fixed ledger count")
    return [f"ledger-{i:04d}" for i in range(count)]


def paths(case):
    need(case in ledger_ids(COUNT), "closed ledger identity")
    return {key: ("private/" if key == "truth" else "public/") + case + "-" + key + ".json"
            for key in ("public", "directory", "cost", "truth", "C", "pooled")}


def expected_matrix(frozen):
    return [(case, profile) for case in ledger_ids(frozen["ledgers"]) for profile in PROFILES]


def prepare(root, rehearsal=False, rehearsal_root=None):
    root = Path(root).absolute()
    need(not root.is_relative_to(ROOT) and not root.exists() and ".." not in root.parts,
         "new private attempt outside Git required")
    plain(root.parent, directory=True)
    source_pins = {name: sha(plain(HERE/name)) for name in (*SOURCES, SPEC)}
    runtime = base.runtime_manifest()
    receipt = None
    if not rehearsal:
        need(rehearsal_root is not None, "complete public rehearsal required before private prepare")
        previous = plain(rehearsal_root, directory=True)
        frozen = load(relative(previous, "freeze.json"))
        completed = load(relative(previous, "completion.json"))
        need(frozen["rehearsal"] is True and frozen["ledgers"] == REHEARSAL_COUNT
             and frozen["sources"] == source_pins and frozen["runtime"] == runtime,
             "rehearsal must exercise exact frozen sources, spec and runtime")
        need(completed["complete"] is True and completed["rehearsal"] is True
             and completed["freeze_sha256"] == sha(previous/"freeze.json")
             and completed["score_sha256"] == sha(relative(previous, "runs/score/result.json"))
             and completed["prediction_batch_sha256"] == sha(relative(previous, "prediction-batch.json")),
             "complete rehearsal receipt")
        verify_completion(previous, frozen)
        exported = load(relative(previous, "export-receipt.json"))
        destination = plain(exported["destination"], directory=True)
        verified = verify_export(destination)
        manifest = load(relative(destination, "manifest.json"))
        need(exported["freeze_sha256"] == sha(previous/"freeze.json")
             and exported["completion_sha256"] == sha(previous/"completion.json")
             and exported["manifest_sha256"] == sha(destination/"manifest.json")
             and exported["files"] == verified["files"]
             and manifest["files"]["freeze.json"]["sha256"] == sha(previous/"freeze.json")
             and manifest["files"]["completion.json"]["sha256"] == sha(previous/"completion.json")
             and manifest["files"]["runs/score/result.json"]["sha256"] == completed["score_sha256"]
             and base.timestamp(completed["completed_utc"]) <= base.timestamp(exported["completed_utc"]),
             "complete matching public rehearsal export required")
        receipt = dict(completed_utc=completed["completed_utc"],
                       freeze_sha256=sha(previous/"freeze.json"),
                       completion_sha256=sha(previous/"completion.json"),
                       score_sha256=completed["score_sha256"],
                       export_manifest_sha256=exported["manifest_sha256"],
                       export_receipt_sha256=sha(previous/"export-receipt.json"),
                       ledgers=REHEARSAL_COUNT, public_seed=True)
    else:
        need(rehearsal_root is None, "rehearsal cannot inherit another rehearsal")
    root.mkdir(mode=0o700)
    for name in ("code", "private", "public", "runs", "inputs"):
        (root/name).mkdir(mode=0o700)
    for name in (*SOURCES, SPEC):
        shutil.copyfile(plain(HERE/name), root/"code"/name)
    frozen = dict(schema="kpi-price-leakage-freeze-v1", frozen_utc=now(),
        base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        sources=source_pins, runtime=runtime, rehearsal=bool(rehearsal),
        ledgers=REHEARSAL_COUNT if rehearsal else COUNT, profiles=list(PROFILES),
        cell=CELL, arm=ARM, horizon="final", qualification_pass=False,
        rehearsal_receipt=receipt,
        barrier="All ledger/profile predictions sealed and verified before any truth mount")
    save(root/"freeze.json", frozen)
    return dict(prepared=True, sampled=False, rehearsal=bool(rehearsal),
                ledgers=frozen["ledgers"], freeze_sha256=sha(root/"freeze.json"),
                run_command=[str(PYTHON), "-B", str(root/"code"/RUNNER), "run", str(root)])


def check(root, entry=True):
    root = plain(root, directory=True)
    if entry:
        need(Path(__file__).absolute() == root/"code"/RUNNER, "execute frozen controller")
    frozen = load(relative(root, "freeze.json"))
    need(frozen["schema"] == "kpi-price-leakage-freeze-v1"
         and set(frozen["sources"]) == set((*SOURCES, SPEC)), "freeze source roster")
    need(type(frozen["rehearsal"]) is bool and frozen["ledgers"] ==
         (REHEARSAL_COUNT if frozen["rehearsal"] else COUNT)
         and frozen["profiles"] == list(PROFILES) and frozen["cell"] == CELL
         and frozen["arm"] == ARM and frozen["horizon"] == "final"
         and frozen["qualification_pass"] is False, "frozen design drift")
    need(frozen["rehearsal"] or frozen["rehearsal_receipt"] is not None,
         "missing prior rehearsal")
    for name, pin in frozen["sources"].items():
        need(sha(relative(root, "code/"+name)) == pin, "frozen source drift")
    need(base.runtime_manifest() == frozen["runtime"], "frozen runtime drift")
    return frozen


ISOLATION_PROBE = ("import pathlib,socket,subprocess,json;"
    "assert not pathlib.Path('/home').exists();assert not pathlib.Path('/proc').exists();"
    "assert [n for _,n in socket.if_nameindex()]==['lo'];"
    "assert subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True).returncode!=0;"
    "print(json.dumps({'no_home':True,'no_proc':True,'interfaces':['lo'],'nested_userns_denied':True}))")


def isolated(root, label, mode, inputs):
    allow = {"controls": (), "generate": ("/seed.json",),
        "observe": ("/public.json", "/directory.json", "/view.json", "/targets.json"),
        "score": ("/data",)}
    need(mode in allow and tuple(mount for _, mount in inputs) == allow[mode],
         "closed isolation input allowlist")
    folder = root/"runs"/label
    folder.mkdir(mode=0o700)
    source_names = (("working_balance_observer.py",) if mode == "observe" else
                    (RUNNER, "working_balance_trial.py", "working_balance_model.py") if mode == "generate" else
                    SOURCES if mode == "controls" else
                    (RUNNER, "working_balance_trial.py", "working_balance_validate.py", "price_leakage_score.py"))
    command = base.sandbox()+["--dir", "/code", "--bind", str(folder), "/output"]
    for name in source_names:
        command += ["--ro-bind", str(relative(root, "code/"+name)), "/code/"+name]
    for path, mount in inputs:
        command += ["--ro-bind", str(plain(path, directory=mount == "/data")), mount]
    probe = base.sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", ISOLATION_PROBE],
                             capture_output=True, text=True, check=True)
    save(folder/"isolation.json", dict(**json.loads(probe.stdout), mode=mode,
        mounts=[mount for _, mount in inputs], truth_mounted=mode == "score", seed_mounted=mode == "generate"))
    save(folder/"inputs.json", {mount: "closed-score-tree" if mount == "/data" else sha(path)
                              for path, mount in inputs})
    if mode == "observe":
        script = ("import sys,json;sys.path.insert(0,'/code');import working_balance_observer as a;"
            "p,d,v,t=[json.load(open('/'+n+'.json')) for n in ('public','directory','view','targets')];"
            "r=a.observe(p,d,v,len(p['events'])-1,target_events=t);"
            "f=open('/output/result.json','x');json.dump(r,f,indent=2,allow_nan=False);f.write('\\n');f.close()")
    else:
        script = "import sys;sys.path.insert(0,'/code');import price_leakage_trial as t;t.internal("+repr(mode)+")"
    started = now()
    with (folder/"stdout.log").open("x") as out, (folder/"stderr.log").open("x") as err:
        process = base.sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", script], stdout=out, stderr=err)
    save(folder/"process.json", dict(started_utc=started, ended_utc=now(), returncode=process.returncode))
    need(process.returncode == 0, "isolated stage failed; preserve all inputs and inspect stderr")
    return folder, load(plain(folder/"result.json"))


def generation_sources(root, generation, frozen):
    need(generation["complete"] is True and [r["case"] for r in generation["records"]]
         == ledger_ids(frozen["ledgers"]), "complete fixed generation roster")
    result = {}
    for record in generation["records"]:
        expected = paths(record["case"])
        need(record["files"] == expected and set(record["pins"]) == set(expected.values()),
             "closed generated artifact paths")
        for pin in record["pins"].values():
            need(type(pin) is str and len(pin) == 64 and all(c in "0123456789abcdef" for c in pin), "artifact pin")
        # Deliberately do not open or hash truth: its opaque generator pin suffices.
        result[record["case"]] = {key: base.pinned_json(root, name, record["pins"][name])
                                  for key, name in expected.items() if key != "truth"}
    return result


def isolation_receipt(mode):
    return dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
        mode=mode, mounts={"controls": [], "generate": ["/seed.json"],
            "observe": ["/public.json", "/directory.json", "/view.json", "/targets.json"],
            "score": ["/data"]}[mode], truth_mounted=mode == "score", seed_mounted=mode == "generate")


def verify_lifecycle(root, generation, frozen):
    controls = load(relative(root, "controls.json")); seed = load(relative(root, "seed-commitment.json"))
    need(controls["passed"] is True and controls["freeze_sha256"] == sha(root/"freeze.json")
         and seed["freeze_sha256"] == sha(root/"freeze.json")
         and seed["controls_sha256"] == sha(root/"controls.json")
         and seed["ledgers"] == frozen["ledgers"] and seed["public_seed"] == frozen["rehearsal"]
         and generation["seed_commitment_sha256"] == sha(root/"seed-commitment.json"), "preseed provenance")
    outcome = base.pinned_json(root, "runs/controls/result.json", controls["result_sha256"])
    need(outcome["passed"] is True and type(outcome["tests"]) is int and outcome["tests"] > 0,
         "controls must pass before sampling")
    for mode, receipt in (("controls", controls), ("generate", generation)):
        prefix = "runs/"+mode+"/"
        process = base.pinned_json(root, prefix+"process.json", receipt["process_sha256"])
        isolation = base.pinned_json(root, prefix+"isolation.json", receipt["isolation_sha256"])
        need(process["returncode"] == 0 and type(process["returncode"]) is int
             and isolation == isolation_receipt(mode), "lifecycle isolation/process")
        need(load(relative(root, prefix+"inputs.json")) ==
             ({} if mode == "controls" else {"/seed.json": seed["seed_sha256"]}), "mounted seed identity")
        lower = frozen["frozen_utc"] if mode == "controls" else seed["sampled_utc"]
        need(base.timestamp(lower) <= base.timestamp(process["started_utc"])
             <= base.timestamp(process["ended_utc"]) <= base.timestamp(receipt["completed_utc"]), "lifecycle chronology")
    need(base.timestamp(controls["completed_utc"]) <= base.timestamp(seed["sampled_utc"])
         <= base.timestamp(generation["completed_utc"]), "sample after controls")
    need(base.pinned_json(root, "runs/generate/result.json", generation["result_sha256"])
         == {"complete": True, "records": generation["records"]}, "generation origin")


def observer_inputs(root, case, profile):
    mapping = paths(case)
    return [(root/mapping["public"], "/public.json"), (root/mapping["directory"], "/directory.json"),
            (root/mapping["C" if profile == "C+D" else "pooled"], "/view.json"),
            (root/"inputs"/(case+"-targets.json"), "/targets.json")]


def verify_batch(root, frozen=None):
    frozen = load(relative(root, "freeze.json")) if frozen is None else frozen
    generation = load(relative(root, "generation.json")); batch = load(relative(root, "prediction-batch.json"))
    predictions = load(relative(root, "predictions.json"))
    need(generation["freeze_sha256"] == sha(root/"freeze.json") and batch["complete"] is True
         and batch["freeze_sha256"] == sha(root/"freeze.json")
         and batch["generation_sha256"] == sha(root/"generation.json")
         and batch["predictions_sha256"] == sha(root/"predictions.json"), "batch identity")
    verify_lifecycle(root, generation, frozen)
    sources = generation_sources(root, generation, frozen)
    expected = expected_matrix(frozen)
    need([(r["case"], r["profile"]) for r in batch["records"]] == expected
         and [(r["case"], r["profile"]) for r in predictions] == expected, "complete sealed prediction matrix")
    generated_at, sealed_at = base.timestamp(generation["completed_utc"]), base.timestamp(batch["sealed_utc"])
    public_guesses = {}
    for serial, (record, entry, (case, profile)) in enumerate(zip(batch["records"], predictions, expected, strict=True)):
        prefix = f"runs/observe-{serial:04d}/"
        need(record["seal"] == prefix+"seal.json", "closed seal path")
        seal = base.pinned_json(root, record["seal"], record["seal_sha256"])
        need(seal["freeze_sha256"] == sha(root/"freeze.json")
             and seal["generation_sha256"] == sha(root/"generation.json")
             and seal["prediction_file"] == prefix+"result.json", "sealed source identity")
        prediction = base.pinned_json(root, prefix+"result.json", seal["prediction_sha256"])
        need(prediction == entry["prediction"], "prediction drift")
        inputs = observer_inputs(root, case, profile)
        expected_names = {str(path.relative_to(root)) for path, _ in inputs}
        need(set(seal["inputs"]) == expected_names, "closed observer input path set")
        values = [base.pinned_json(root, str(path.relative_to(root)), seal["inputs"][str(path.relative_to(root))])
                  for path, _ in inputs]
        public, directory, view, targets = values
        source = sources[case]
        need(public == source["public"] and directory == source["directory"]
             and view == source["C" if profile == "C+D" else "pooled"]
             and targets == list(base.horizons(public)), "observer allowed disclosures and all targets")
        base.validate_prediction(prediction, public, profile, len(public["events"])-1, directory, view, targets)
        process = base.pinned_json(root, prefix+"process.json", seal["process_sha256"])
        isolation = base.pinned_json(root, prefix+"isolation.json", seal["isolation_sha256"])
        mounted = base.pinned_json(root, prefix+"inputs.json", seal["input_manifest_sha256"])
        need(type(process["returncode"]) is int and process["returncode"] == 0
             and isolation == isolation_receipt("observe")
             and mounted == {mount: seal["inputs"][str(path.relative_to(root))] for path, mount in inputs},
             "observer process and isolated inputs")
        need(generated_at <= base.timestamp(process["started_utc"]) <= base.timestamp(process["ended_utc"])
             <= base.timestamp(seal["sealed_utc"]) <= sealed_at, "prediction seal chronology")
        guesses = {r["event"]: r["guesses"] for r in prediction["rows"]}
        if profile == "C+D":
            public_guesses[case] = guesses
        else:
            need(all(guesses[event]["C_"+name] == guess[name]
                     for event, guess in public_guesses[case].items() for name in base.BASE_VARIANTS),
                 "pooled public strategy copies changed")
    return batch, predictions


def public_artifacts(generation, batch):
    names = ["freeze.json", "controls.json", "seed-commitment.json", "generation.json", "predictions.json", "prediction-batch.json"]
    for mode in ("controls", "generate"):
        names += ["runs/"+mode+"/"+name+".json" for name in ("result", "process", "isolation", "inputs")]
    for record in generation["records"]:
        names += [name for key, name in record["files"].items() if key != "truth"]
        names.append("inputs/"+record["case"]+"-targets.json")
    for serial in range(len(batch["records"])):
        names += [f"runs/observe-{serial:04d}/"+name+".json" for name in ("result", "process", "isolation", "inputs", "seal")]
    return names


def stage_score_inputs(root, frozen):
    batch, _ = verify_batch(root, frozen)  # All predictions complete BEFORE any truth link.
    generation = load(root/"generation.json")
    names = public_artifacts(generation, batch) + [r["files"]["truth"] for r in generation["records"]]
    stage = root/"score-inputs"; stage.mkdir(mode=0o700)
    for name in names:
        target = stage/name; target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.link(relative(root, name), target)
    need(not (stage/"private/seed.json").exists(), "seed must not reach scorer")
    return stage


def run(root, workers=12, resume=False):
    need(type(workers) is int and 1 <= workers <= 12, "operational workers between one and twelve")
    frozen = check(root)
    if resume:
        need((root/"generation.json").is_file() and not (root/"prediction-batch.json").exists()
             and not (root/"completion.json").exists(), "resume only incomplete observation of committed generation")
        verify_lifecycle(root, load(root/"generation.json"), frozen)
    else:
        folder, controls = isolated(root, "controls", "controls", [])
        need(controls["passed"] is True, "public controls failed before sampling")
        save(root/"controls.json", dict(passed=True, completed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
            result_sha256=sha(folder/"result.json"), process_sha256=sha(folder/"process.json"), isolation_sha256=sha(folder/"isolation.json")))
        check(root)
        seeds = ([digest(("PUBLIC-PRICE-LEAKAGE-REHEARSAL-"+str(i)).encode()) for i in range(REHEARSAL_COUNT)]
                 if frozen["rehearsal"] else [secrets.token_hex(32) for _ in range(COUNT)])
        need(len(seeds) == len(set(seeds)), "independent seed collision; do not resample")
        save(root/"private/seed.json", dict(rehearsal=frozen["rehearsal"], seeds=seeds))
        del seeds
        save(root/"seed-commitment.json", dict(sampled_utc=now(), freeze_sha256=sha(root/"freeze.json"),
            controls_sha256=sha(root/"controls.json"), seed_sha256=sha(root/"private/seed.json"),
            ledgers=frozen["ledgers"], public_seed=frozen["rehearsal"]))
        generated, generation = isolated(root, "generate", "generate", [(root/"private/seed.json", "/seed.json")])
        need(generation["complete"] is True, "generation complete")
        for directory in ("private", "public"):
            for path in (generated/directory).iterdir():
                need(not (root/directory/path.name).exists(), "create-only generation destination")
                path.rename(root/directory/path.name)  # No controller truth read.
        save(root/"generation.json", {**generation, "freeze_sha256": sha(root/"freeze.json"), "completed_utc": now(),
            "seed_commitment_sha256": sha(root/"seed-commitment.json"), "result_sha256": sha(generated/"result.json"),
            "process_sha256": sha(generated/"process.json"), "isolation_sha256": sha(generated/"isolation.json")})
    sources = generation_sources(root, load(root/"generation.json"), frozen)
    for case, source in sources.items():
        target_path = root/"inputs"/(case+"-targets.json")
        targets = list(base.horizons(source["public"]))
        if target_path.exists():
            need(resume and load(plain(target_path)) == targets, "retained target input drift")
        else:
            save(target_path, targets)
    def observe(item):
        serial, (case, profile) = item
        label = f"observe-{serial:04d}"
        inputs = observer_inputs(root, case, profile)
        existing = root/"runs"/label
        if existing.exists():
            need(resume, "create-only observer output")
            if (existing/"seal.json").is_file():
                # Full pin, isolation, chronology and C-copy checks occur at
                # the complete batch barrier before any scoring/truth mount.
                prediction = load(plain(existing/"result.json"))
                return (dict(case=case, profile=profile, seal=str((existing/"seal.json").relative_to(root)),
                             seal_sha256=sha(existing/"seal.json")), dict(case=case, profile=profile, prediction=prediction))
            expected_inputs = {mount: sha(path) for path, mount in inputs}
            if (existing/"inputs.json").exists():
                need(load(plain(existing/"inputs.json")) == expected_inputs, "retry input drift")
            failed = root/"operational-failures"; failed.mkdir(mode=0o700, exist_ok=True)
            index = 0
            while (failed/(label+f"-{index:04d}")).exists(): index += 1
            # Preserve failed outputs; repeat only deterministic observation
            # with the exact frozen command, input paths and input bytes.
            existing.rename(failed/(label+f"-{index:04d}"))
        folder, prediction = isolated(root, label, "observe", inputs)
        source = sources[case]
        base.validate_prediction(prediction, source["public"], profile, len(source["public"]["events"])-1,
            source["directory"], source["C" if profile == "C+D" else "pooled"], list(base.horizons(source["public"])))
        seal = dict(sealed_utc=now(), freeze_sha256=sha(root/"freeze.json"), generation_sha256=sha(root/"generation.json"),
            prediction_file=str((folder/"result.json").relative_to(root)), prediction_sha256=sha(folder/"result.json"),
            process_sha256=sha(folder/"process.json"), isolation_sha256=sha(folder/"isolation.json"),
            input_manifest_sha256=sha(folder/"inputs.json"),
            inputs={str(path.relative_to(root)): sha(path) for path, _ in inputs})
        save(folder/"seal.json", seal)
        return (dict(case=case, profile=profile, seal=str((folder/"seal.json").relative_to(root)), seal_sha256=sha(folder/"seal.json")),
                dict(case=case, profile=profile, prediction=prediction))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        observations = list(pool.map(observe, enumerate(expected_matrix(frozen))))
    records, predictions = map(list, zip(*observations, strict=True))
    check(root)
    save(root/"predictions.json", predictions)
    save(root/"prediction-batch.json", dict(complete=True, sealed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        generation_sha256=sha(root/"generation.json"), predictions_sha256=sha(root/"predictions.json"), records=records))
    stage = stage_score_inputs(root, frozen)
    scored, score = isolated(root, "score", "score", [(stage, "/data")])
    need(score["complete"] is True and score["qualification_pass"] is False, "bounded arithmetic score")
    verify_batch(root, frozen); check(root)
    save(root/"completion.json", dict(complete=True, completed_utc=now(), rehearsal=frozen["rehearsal"],
        ledgers=frozen["ledgers"], freeze_sha256=sha(root/"freeze.json"),
        prediction_batch_sha256=sha(root/"prediction-batch.json"), score_sha256=sha(scored/"result.json"),
        score_process_sha256=sha(scored/"process.json"), score_isolation_sha256=sha(scored/"isolation.json"), qualification_pass=False))
    return load(root/"completion.json")


def internal(mode):
    if mode == "controls":
        import unittest
        suite = unittest.defaultTestLoader.loadTestsFromNames([name[:-3] for name in SOURCES if name.endswith("_tests.py")])
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        save("/output/result.json", dict(passed=result.wasSuccessful(), tests=result.testsRun))
    elif mode == "generate":
        import working_balance_model as model
        sampled = load("/seed.json")
        count = REHEARSAL_COUNT if sampled["rehearsal"] else COUNT
        need(type(sampled["rehearsal"]) is bool and len(sampled["seeds"]) == count
             and len(set(sampled["seeds"])) == count, "frozen seed roster")
        for directory in ("private", "public"):
            Path("/output", directory).mkdir(mode=0o700)
        records = []
        for case, text in zip(ledger_ids(count), sampled["seeds"], strict=True):
            need(type(text) is str and len(text) == 64, "32-byte ledger seed")
            seed = bytes.fromhex(text)
            work = model.plan(seed, CELL)
            bundle = model.replay(seed, CELL, ARM, work)
            record = dict(case=case, files=paths(case), pins={})
            for key, name in record["files"].items():
                value = bundle["views"]["C+D" if key == "C" else "pooled"] if key in ("C", "pooled") else bundle[key]
                save(Path("/output")/name, value); record["pins"][name] = sha(Path("/output")/name)
            records.append(record)
        save("/output/result.json", dict(complete=True, records=records))
    elif mode == "score":
        import price_leakage_score as scorer
        root = Path("/data")
        frozen = load(root/"freeze.json")
        _, predictions = verify_batch(root, frozen)
        generation = load(root/"generation.json")
        indexed = {(entry["case"], entry["profile"]): entry["prediction"] for entry in predictions}
        cases = []
        for record in generation["records"]:
            mapping = record["files"]
            bundle = {key: base.pinned_json(root, mapping[key], record["pins"][mapping[key]])
                      for key in ("public", "directory", "cost", "truth")}
            bundle["views"] = {profile: base.pinned_json(root, mapping["C" if profile == "C+D" else "pooled"],
                record["pins"][mapping["C" if profile == "C+D" else "pooled"]]) for profile in PROFILES}
            cases.append(scorer.score_case(bundle, {profile: indexed[record["case"], profile] for profile in PROFILES}))
        result = scorer.aggregate(cases, expected_ledgers=frozen["ledgers"])
        result.update(complete=True, rehearsal=frozen["rehearsal"], qualification_pass=False)
        save("/output/cases.json", cases)
        save("/output/result.json", result)
    else:
        raise ValueError("unknown internal mode")


def verify_completion(root, frozen):
    completed = load(relative(root, "completion.json"))
    need(completed["complete"] is True and completed["freeze_sha256"] == sha(root/"freeze.json")
         and completed["score_sha256"] == sha(relative(root, "runs/score/result.json"))
         and completed["prediction_batch_sha256"] == sha(relative(root, "prediction-batch.json"))
         and completed["rehearsal"] == frozen["rehearsal"] and completed["ledgers"] == frozen["ledgers"]
         and completed["qualification_pass"] is False, "completed arithmetic run")
    score = load(relative(root, "runs/score/result.json"))
    need(score["complete"] is True and score["qualification_pass"] is False
         and score["rehearsal"] == frozen["rehearsal"], "complete bounded score")
    process = base.pinned_json(root, "runs/score/process.json", completed["score_process_sha256"])
    isolation = base.pinned_json(root, "runs/score/isolation.json", completed["score_isolation_sha256"])
    batch, _ = verify_batch(root, frozen)
    need(type(process["returncode"]) is int and process["returncode"] == 0 and isolation == isolation_receipt("score")
         and base.timestamp(batch["sealed_utc"]) <= base.timestamp(process["started_utc"])
         <= base.timestamp(process["ended_utc"]) <= base.timestamp(completed["completed_utc"]), "score after barrier")
    return completed, batch


def export(root, destination):
    frozen = check(root)
    completed, batch = verify_completion(root, frozen)
    destination = Path(destination).absolute()
    need(not destination.exists() and not destination.is_relative_to(root), "new public export destination")
    plain(destination.parent, directory=True); destination.mkdir()
    names = public_artifacts(load(root/"generation.json"), batch) + ["completion.json", "runs/score/result.json",
        "runs/score/cases.json", "runs/score/process.json", "runs/score/isolation.json", "runs/score/inputs.json"]
    names += ["code/"+name for name in (*SOURCES, SPEC)]
    manifest = {}
    for name in names:
        need(not name.startswith("private/") and "seed.json" not in Path(name).parts, "no private export")
        blob = relative(root, name).read_bytes(); compressed = len(blob) >= 65_536
        storage = name+".gz" if compressed else name
        stored = gzip.compress(blob, compresslevel=9, mtime=0) if compressed else blob
        target = destination/storage; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(stored)
        manifest[name] = dict(path=storage, encoding="gzip" if compressed else "identity", bytes=len(blob),
            sha256=digest(blob), stored_bytes=len(stored), stored_sha256=digest(stored))
    save(destination/"manifest.json", dict(schema="kpi-price-leakage-export-v1", files=manifest,
        freeze_sha256=sha(root/"freeze.json"), qualification_pass=False,
        scope="All frozen sources, public observations, predictions, seals and aggregate counts; truth and seeds excluded."))
    verified = verify_export(destination)
    save(root/"export-receipt.json", dict(complete=True, completed_utc=now(), destination=str(destination),
        manifest_sha256=sha(destination/"manifest.json"), freeze_sha256=sha(root/"freeze.json"),
        completion_sha256=sha(root/"completion.json"), files=verified["files"]))
    return dict(exported=True, files=len(names), bytes=sum(row["stored_bytes"] for row in manifest.values()), qualification_pass=False)


def verify_export(destination):
    """Verify the closed public roster and every logical/compressed byte pin."""
    manifest = load(relative(destination, "manifest.json"))
    need(manifest["schema"] == "kpi-price-leakage-export-v1" and manifest["qualification_pass"] is False,
         "public export schema")
    metadata = {}
    for name, row in manifest["files"].items():
        need(type(name) is str and not name.startswith(("private/", "score-inputs/"))
             and "seed.json" not in Path(name).parts and not Path(name).is_absolute()
             and ".." not in Path(name).parts and row["encoding"] in ("identity", "gzip")
             and row["path"] == name+(".gz" if row["encoding"] == "gzip" else ""), "closed public export paths")
        stored = relative(destination, row["path"]).read_bytes()
        need(len(stored) == row["stored_bytes"] and digest(stored) == row["stored_sha256"], "stored export drift")
        blob = gzip.decompress(stored) if row["encoding"] == "gzip" else stored
        need(len(blob) == row["bytes"] and digest(blob) == row["sha256"], "logical export drift")
        if name in ("freeze.json", "generation.json", "prediction-batch.json", "completion.json"):
            metadata[name] = base.parse_json(blob)
    need(set(metadata) == {"freeze.json", "generation.json", "prediction-batch.json", "completion.json"}, "export metadata roster")
    expected = public_artifacts(metadata["generation.json"], metadata["prediction-batch.json"]) + ["completion.json",
        "runs/score/result.json", "runs/score/cases.json", "runs/score/process.json", "runs/score/isolation.json", "runs/score/inputs.json"]
    expected += ["code/"+name for name in (*SOURCES, SPEC)]
    need(set(manifest["files"]) == set(expected), "complete public export roster")
    actual = set()
    for path in Path(destination).rglob("*"):
        need(not path.is_symlink(), "public export symlink")
        if path.is_file(): actual.add(str(path.relative_to(destination)))
    need(actual == {"manifest.json"} | {row["path"] for row in manifest["files"].values()},
         "unexpected public export file")
    frozen = metadata["freeze.json"]
    need(set(frozen["sources"]) == set((*SOURCES, SPEC))
         and manifest["files"]["freeze.json"]["sha256"] == manifest["freeze_sha256"]
         == metadata["completion.json"]["freeze_sha256"]
         and all(manifest["files"]["code/"+name]["sha256"] == pin for name, pin in frozen["sources"].items()),
         "export frozen source identity")
    return dict(storage_verified=True, files=len(manifest["files"]), qualification_pass=False)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("root", type=Path); p.add_argument("--rehearsal", action="store_true")
    p.add_argument("--rehearsal-root", type=Path)
    p = sub.add_parser("run"); p.add_argument("root", type=Path); p.add_argument("--workers", type=int, default=12)
    p.add_argument("--resume", action="store_true", help="reuse sealed observations after an operational interruption; never resample")
    p = sub.add_parser("export"); p.add_argument("root", type=Path); p.add_argument("destination", type=Path)
    args = parser.parse_args(); root = args.root.absolute()
    if args.command != "prepare" and Path(__file__).absolute() != root/"code"/RUNNER:
        frozen = load(relative(root, "freeze.json")); source = relative(root, "code/"+RUNNER)
        need(sha(source) == frozen["sources"][RUNNER], "frozen entry drift")
        os.execv(str(PYTHON), [str(PYTHON), "-B", str(source), *sys.argv[1:]])
    result = (prepare(root, args.rehearsal, args.rehearsal_root) if args.command == "prepare" else
              run(root, args.workers, args.resume) if args.command == "run" else export(root, args.destination))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
