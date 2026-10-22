#!/usr/bin/env python3
"""Create-only post-hoc diagnosis: verify public traces before opening old truth.

No generation, seed access, new observer decisions, proofs or network requests.
Detailed truth joins stay in the new private attempt. Only result.json is an
aggregate candidate for publication; source/process checks are not attestation.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUNNER = "working_balance_sparse_diagnosis.py"
SPEC = "WORKING-BALANCE-SPARSE-DIAGNOSIS-SPEC.md"
SOURCES = (RUNNER, "working_balance_sparse_diagnosis_tests.py",
           "working_balance_sparse_trace.py", "working_balance_sparse_trace_tests.py",
           "working_balance_sparse_classify.py", "working_balance_sparse_classify_tests.py", SPEC)
ARMS, PROFILES = ("whole", "partial"), ("C+D", "pooled")
CELL = "sparse-independent"
BASE = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported",
        "partial_tail", "split_tail", "receipt_timing", "cash_inverse", "colluder_tags",
        "bridge_ancestry", "combined")
OLD_FREEZE_SHA = "e7e591090ce4d510abdae6988ec84d7663bdd3a5ecccc7e7eb9a745a95a92f3f"
OLD_SCORE_SHA = "d2723f2a875d5d3df1e16348197e72a4c4b9e6ebc9623fbe8cca50c6e1a648f9"
OLD_SOURCES = {
    "working_balance_trial.py": "d8c73c52929743641c7180565f6e3af4abcfc8f55e53ce0902de8235eec0aa65",
    "working_balance_trial_tests.py": "ea56a131495832d1e0aa7f4bad221a971ba8204d5f2f627165dd78e195ab0130",
    "working_balance_model.py": "a1a8c3989d85f2309dcd726cd2d076c77c4ea77e407a7dfbd8c05f975dafbe00",
    "working_balance_model_tests.py": "d4c6a36f18909d46f6bdd8a0ab4efcc32c951460f4815ba4d4dd02b58caa9ab5",
    "working_balance_observer.py": "b492d5a2e63836751f51f5151c002c3ec6492c224b518846c45eca23f3ea7495",
    "working_balance_observer_tests.py": "0f2ac35622e23dfafa960e8877b743118500c3530015eaa9b59b49c208d38147",
    "working_balance_validate.py": "407c1abeebc913b8112754d70705eae41a36f86cf954aa946dfa565abef3eb14",
    "working_balance_validator_tests.py": "833b7082a67a0ce0f9e98e94f896d64cb5eb6b0bfddc7882485a8f7320c13218",
    "WORKING-BALANCE-PRIVACY-SPEC.md": "16f9c5669e68731db787c84e28857fef3024601daacff86ed2c1a625a76c87d6",
}
OLD_METADATA = ("freeze.json", "generation.json", "prediction-batch.json", "predictions.json",
                "completion.json", "runs/score/result.json")
PYTHON = Path("/usr/bin/python3").resolve()


def need(ok, label):
    if not ok:
        raise ValueError(label)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(plain(path).read_bytes())


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def parse(data):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite JSON")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def load(path):
    return parse(plain(path).read_bytes())


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def plain(path, directory=False):
    path = Path(path).absolute()
    need(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         "unsafe artifact path")
    need(path.is_dir() if directory else path.is_file(), "missing regular artifact")
    return path


def copy_pinned(source, destination, pin):
    data = plain(source).read_bytes()
    need(digest(data) == pin, "artifact drift")
    with Path(destination).open("xb") as stream:
        stream.write(data)


def old_module(root):
    path = plain(Path(root)/"original-code"/"working_balance_trial.py")
    need(sha(path) == OLD_SOURCES[path.name], "old controller drift")
    spec = importlib.util.spec_from_file_location("sparse_diagnosis_original_trial", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata_identity(old):
    identity = {name: sha(old/name) for name in OLD_METADATA}
    need(identity["freeze.json"] == OLD_FREEZE_SHA and identity["runs/score/result.json"] == OLD_SCORE_SHA,
         "wrong original experiment identity")
    frozen = load(old/"freeze.json")
    need(frozen["sources"] == OLD_SOURCES, "old nine-source roster")
    for name, pin in OLD_SOURCES.items():
        need(sha(old/"code"/name) == pin, "old frozen source drift")
    completion = load(old/"completion.json")
    need(completion["complete"] is True and completion["freeze_sha256"] == OLD_FREEZE_SHA
         and completion["prediction_batch_sha256"] == identity["prediction-batch.json"]
         and completion["score_sha256"] == OLD_SCORE_SHA
         and completion["qualification_pass"] is False, "old completion identity")
    return identity


def verify_old_public(root, frozen):
    """Original complete public seal audit; generation's truth pins remain opaque."""
    old = plain(frozen["old_attempt"], directory=True)
    need(metadata_identity(old) == frozen["old_metadata"], "old metadata drift")
    trial = old_module(root)
    generation = load(old/"generation.json")
    batch, predictions = trial.verify_batch(old, generation)
    need(len(batch["records"]) == len(predictions) == 1506, "old complete 1506-job barrier")
    need(sha(old/"runs/score/result.json") == OLD_SCORE_SHA, "original score drift")
    return trial, generation, predictions


def prepare(old, root):
    old = plain(old, directory=True)
    root = Path(root).absolute()
    need(".." not in root.parts and not root.exists() and not root.is_symlink()
         and not root.is_relative_to(ROOT) and not root.is_relative_to(old),
         "new private diagnosis directory outside repository and old attempt required")
    plain(root.parent, directory=True)
    root.mkdir(mode=0o700)
    for name in ("code", "original-code", "public-data", "runs"):
        (root/name).mkdir(mode=0o700)
    for name in SOURCES:
        copy_pinned(HERE/name, root/"code"/name, sha(HERE/name))
    published = HERE/"evidence"/"2026-10-21-working-balance"
    need(sha(published/"freeze.json") == OLD_FREEZE_SHA
         and sha(published/"summary.json") == OLD_SCORE_SHA, "published original identity drift")
    old_metadata = metadata_identity(old)
    for name, pin in OLD_SOURCES.items():
        copy_pinned(old/"code"/name, root/"original-code"/name, pin)
    # Pin all new bytes before the old public audit, and before any truth access.
    frozen = dict(schema="kpi-working-balance-sparse-diagnosis-freeze-v1", frozen_utc=now(),
                  source_directory=str(HERE), old_attempt=str(old), old_metadata=old_metadata,
                  old_sources=OLD_SOURCES, sources={n: sha(root/"code"/n) for n in SOURCES},
                  original_score_sha256=OLD_SCORE_SHA, cell=CELL, arms=list(ARMS), profiles=list(PROFILES),
                  public_jobs=4, old_public_jobs=1506, truth_before_public_seal=False,
                  qualification_pass=False)
    frozen["runtime"] = old_module(root).runtime_manifest()
    save(root/"freeze.json", frozen)
    trial, generation, _ = verify_old_public(root, frozen)
    public_pins = {}
    for record in generation["records"]:
        if record["case"] != CELL:
            continue
        arm = record["arm"]
        for key in ("public", "directory", "cost"):
            name = arm+"-"+key+".json"
            copy_pinned(old/record[key], root/"public-data"/name, record["pins"][record[key]])
            public_pins[name] = sha(root/"public-data"/name)
        for profile, path in record["views"].items():
            name = arm+"-"+("C" if profile == "C+D" else "pooled")+".json"
            copy_pinned(old/path, root/"public-data"/name, record["pins"][path])
            public_pins[name] = sha(root/"public-data"/name)
    copy_pinned(old/"runs/score/result.json", root/"public-data"/"original-summary.json", OLD_SCORE_SHA)
    public_pins["original-summary.json"] = OLD_SCORE_SHA
    save(root/"prepared.json", dict(complete=True, completed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
                                   original_public_jobs=1506, public_files=public_pins,
                                   truth_opened=False, seed_opened=False))
    return dict(prepared=True, truth_opened=False, freeze_sha256=sha(root/"freeze.json"),
                run_command=[str(PYTHON), "-B", str(root/"code"/RUNNER), "run", str(root)])


def check(root):
    root = plain(root, directory=True)
    frozen = load(root/"freeze.json")
    need(frozen["schema"] == "kpi-working-balance-sparse-diagnosis-freeze-v1"
         and set(frozen["sources"]) == set(SOURCES) and frozen["old_sources"] == OLD_SOURCES
         and frozen["cell"] == CELL and frozen["arms"] == list(ARMS) and frozen["profiles"] == list(PROFILES)
         and frozen["public_jobs"] == 4 and frozen["old_public_jobs"] == 1506
         and frozen["truth_before_public_seal"] is False and frozen["qualification_pass"] is False,
         "diagnostic freeze drift")
    for name, pin in frozen["sources"].items():
        need(sha(root/"code"/name) == pin
             and sha(Path(frozen["source_directory"])/name) == pin, "new source drift")
    for name, pin in OLD_SOURCES.items():
        need(sha(root/"original-code"/name) == pin, "old source snapshot drift")
    need(old_module(root).runtime_manifest() == frozen["runtime"], "runtime drift")
    prepared = load(root/"prepared.json")
    need(prepared["complete"] is True and prepared["freeze_sha256"] == sha(root/"freeze.json")
         and prepared["original_public_jobs"] == 1506
         and prepared["truth_opened"] is False and prepared["seed_opened"] is False,
         "prepared public barrier")
    for name, pin in prepared["public_files"].items():
        need(name in public_names() and sha(root/"public-data"/name) == pin, "prepared public drift")
    need(set(prepared["public_files"]) == set(public_names()), "prepared public file roster")
    return frozen


def public_names():
    return [a+"-"+part+".json" for a in ARMS for part in ("public", "directory", "cost", "C", "pooled")]+["original-summary.json"]


def sandbox_stage(root, label, mode, inputs, code, script):
    """Run with closed data mounts, no home/proc/network/seed or attempt mount."""
    trial = old_module(root)
    folder = root/"runs"/label
    folder.mkdir(mode=0o700)
    need(mode in ("trace", "classify"), "sandbox mode")
    expected = ("/public.json", "/directory.json", "/view.json") if mode == "trace" else ("/data",)
    need(tuple(mount for _, mount in inputs) == expected, "sandbox input allowlist")
    command = trial.sandbox()+["--dir", "/code", "--bind", str(folder), "/output"]
    for path in code:
        command += ["--ro-bind", str(plain(path)), "/code/"+path.name]
    for path, mount in inputs:
        if mount == "/data":
            verify_stage(path)
        command += ["--ro-bind", str(plain(path, directory=mount == "/data")), mount]
    probe = ("import pathlib,socket,subprocess,json;assert not pathlib.Path('/home').exists();"
             "assert not pathlib.Path('/proc').exists();assert [n for _,n in socket.if_nameindex()]==['lo'];"
             "assert subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True).returncode!=0;"
             "print(json.dumps({'no_home':True,'no_proc':True,'interfaces':['lo'],'nested_userns_denied':True}))")
    probed = trial.sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", probe],
                               capture_output=True, text=True, check=True)
    save(folder/"isolation.json", dict(**parse(probed.stdout), mode=mode, mounts=list(expected),
                                      truth_mounted=mode == "classify", seed_mounted=False))
    save(folder/"inputs.json", {mount: sha(path) if mount != "/data" else load(path/"manifest.json") for path, mount in inputs})
    start = now()
    with (folder/"stdout.log").open("x") as out, (folder/"stderr.log").open("x") as err:
        process = trial.sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", script], stdout=out, stderr=err)
    save(folder/"process.json", dict(started_utc=start, ended_utc=now(), returncode=process.returncode))
    need(process.returncode == 0, "sandbox stage failed; preserve diagnosis")
    return folder, load(folder/"result.json")


def verify_trace(rows, prediction, public):
    targets = [e["event"] for e in public["events"] if e["mode"] == 1 and e["payout"] == 0]
    need(type(rows) is list and [r["event"] for r in rows] == targets, "all public trace targets")
    expected = {r["event"]: r for r in prediction["rows"]}
    need(set(expected) == set(targets), "original final target roster")
    for row in rows:
        old = expected[row["event"]]
        need(row["event_id"] == old["event_id"] and set(row["all_guesses"]) == set(BASE)
             and canonical(row["all_guesses"]) == canonical({v: old["guesses"][v] for v in BASE})
             and canonical(row["guess"]) == canonical(old["guesses"]["split_tail"])
             and row["full_book_verified"] is True, "trace changed frozen guesses or ranks")


def verify_public_barrier(root):
    frozen = check(root)
    seal = load(root/"public-seal.json")
    need(seal["complete"] is True and seal["freeze_sha256"] == sha(root/"freeze.json")
         and seal["truth_opened"] is False and seal["seed_opened"] is False
         and [(r["arm"], r["profile"]) for r in seal["records"]] == [(a,p) for a in ARMS for p in PROFILES],
         "four public trace seal barrier")
    for index, record in enumerate(seal["records"]):
        folder = root/"runs"/f"trace-{index}"
        need(record["files"] == {name: sha(folder/name) for name in ("result.json", "process.json", "isolation.json", "inputs.json")},
             "public trace seal drift")
        need(load(folder/"process.json")["returncode"] == 0
             and load(folder/"isolation.json") == dict(no_home=True, no_proc=True, interfaces=["lo"],
                nested_userns_denied=True, mode="trace", mounts=["/public.json", "/directory.json", "/view.json"],
                truth_mounted=False, seed_mounted=False), "public process/isolation receipt")
    return frozen, seal


def stage_classification(root):
    # This check finishes before a truth path is opened or hashed.
    frozen, seal = verify_public_barrier(root)
    _, generation, _ = verify_old_public(root, frozen)
    old = Path(frozen["old_attempt"])
    stage = root/"classification-inputs"
    stage.mkdir(mode=0o700)
    files = {}
    for name in public_names():
        pin = sha(root/"public-data"/name)
        copy_pinned(root/"public-data"/name, stage/name, pin)
        files[name] = pin
    for index, record in enumerate(seal["records"]):
        name = record["arm"]+"-"+("C" if record["profile"] == "C+D" else "pooled")+"-trace.json"
        copy_pinned(root/"runs"/f"trace-{index}"/"result.json", stage/name, record["files"]["result.json"])
        files[name] = sha(stage/name)
    # Only these two generation-bound truth files are opened, after the barrier.
    for record in generation["records"]:
        if record["case"] == CELL:
            expected = "private/"+CELL+"-"+record["arm"]+"-truth.json"
            need(record["truth"] == expected, "closed truth path")
            name = record["arm"]+"-truth.json"
            copy_pinned(old/expected, stage/name, record["pins"][expected])
            files[name] = sha(stage/name)
    need(set(files) == set(public_names()) | {a+"-truth.json" for a in ARMS}
         | {a+"-"+p+"-trace.json" for a in ARMS for p in ("C", "pooled")}, "classification input roster")
    save(stage/"manifest.json", dict(files=files, public_seal_sha256=sha(root/"public-seal.json"), seed_included=False))
    verify_stage(stage)
    return stage


def verify_stage(stage):
    stage = plain(stage,directory=True)
    manifest = load(stage/"manifest.json")
    expected = set(public_names()) | {a+"-truth.json" for a in ARMS} | {
        a+"-"+p+"-trace.json" for a in ARMS for p in ("C", "pooled")}
    need(set(manifest) == {"files", "public_seal_sha256", "seed_included"}
         and manifest["seed_included"] is False and set(manifest["files"]) == expected
         and {p.name for p in stage.iterdir()} == expected | {"manifest.json"}, "closed classification stage")
    for name,pin in manifest["files"].items():
        need(sha(stage/name) == pin, "classification stage drift")


def trace_script():
    return ("import sys,json;sys.path.insert(0,'/code');import working_balance_observer as o;"
              "import working_balance_sparse_trace as t;"
              "p,d,v=[json.load(open('/'+n+'.json')) for n in ('public','directory','view')];"
              "p,d,v=o.prefix_inputs(p,d,v);targets=[e['event'] for e in p['events'] if e['mode']==1 and not e['payout']];"
              "engine=o.Engine(p,d,v,min(targets) if targets else len(p['events']));"
              "rows=[t.trace_split_tail(engine,target) for target in targets];"
              "f=open('/output/result.json','x');json.dump({'rows':rows},f,indent=2,allow_nan=False);print(file=f);f.close()")


def classify_script():
    return ("import sys,json;sys.path.insert(0,'/code');import working_balance_sparse_classify as c;"
        "load=lambda n:json.load(open('/data/'+n+'.json'));"
        "bundles={a:{**{k:load(a+'-'+k) for k in ('public','directory','cost','truth')},"
        "'views':{p:load(a+'-'+v) for p,v in [('C+D','C'),('pooled','pooled')]}} for a in ('whole','partial')};"
        "traces={a:{p:load(a+'-'+v+'-trace')['rows'] for p,v in [('C+D','C'),('pooled','pooled')]} for a in ('whole','partial')};"
        "aggregate,detail=c.classify_all(bundles,traces,load('original-summary'));"
        "f=open('/output/result.json','x');json.dump(aggregate,f,indent=2,allow_nan=False);print(file=f);f.close();"
        "f=open('/output/private-detail.json','x');json.dump(detail,f,indent=2,allow_nan=False);print(file=f);f.close()")


def run(root):
    root = plain(root, directory=True)
    need(Path(__file__).absolute() == root/"code"/RUNNER, "execute frozen diagnostic controller")
    frozen = check(root)
    save(root/"run-start.json", dict(started_utc=now(), freeze_sha256=sha(root/"freeze.json")))
    _, _, predictions = verify_old_public(root, frozen)
    records, traces = [], {a: {} for a in ARMS}
    for arm in ARMS:
        public = load(root/"public-data"/(arm+"-public.json"))
        for profile in PROFILES:
            check(root)
            view = "C" if profile == "C+D" else "pooled"
            folder, result = sandbox_stage(root, f"trace-{len(records)}", "trace",
                [(root/"public-data"/(arm+"-public.json"), "/public.json"),
                 (root/"public-data"/(arm+"-directory.json"), "/directory.json"),
                 (root/"public-data"/(arm+"-"+view+".json"), "/view.json")],
                [root/"original-code"/"working_balance_observer.py", root/"code"/"working_balance_sparse_trace.py"], trace_script())
            original = next(p["prediction"] for p in predictions if (p["case"],p["arm"],p["profile"],p["through_event"])
                            == (CELL,arm,profile,len(public["events"])-1))
            need(set(result) == {"rows"}, "closed trace result")
            verify_trace(result["rows"], original, public)
            if profile == "pooled":
                public_rows = {r["event"]: r["all_guesses"] for r in traces[arm]["C+D"]}
                need(all(canonical(public_rows[row["event"]][v]) == canonical(row["guesses"]["C_"+v])
                         for row in original["rows"] for v in BASE), "pooled C_ strategy drift")
            traces[arm][profile] = result["rows"]
            records.append(dict(arm=arm, profile=profile, public_targets=len(result["rows"]),
                files={name: sha(folder/name) for name in ("result.json", "process.json", "isolation.json", "inputs.json")}))
    check(root)
    save(root/"public-seal.json", dict(complete=True, sealed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
                                     records=records, truth_opened=False, seed_opened=False))
    stage = stage_classification(root)
    folder, _ = sandbox_stage(root, "classify", "classify", [(stage,"/data")],
                             [root/"code"/"working_balance_sparse_classify.py",
                              root/"original-code"/"working_balance_validate.py"], classify_script())
    check(root)
    verify_public_barrier(root)
    save(root/"completion.json", dict(complete=True, completed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        public_seal_sha256=sha(root/"public-seal.json"), aggregate_sha256=sha(folder/"result.json"),
        private_detail_sha256=sha(folder/"private-detail.json"),
        classification_process_sha256=sha(folder/"process.json"),
        classification_isolation_sha256=sha(folder/"isolation.json"),
        original_score_sha256=OLD_SCORE_SHA, original_result_changed=False, qualification_pass=False))
    return dict(complete=True, aggregate=str(folder/"result.json"), private_details_published=False,
                original_result_changed=False, qualification_pass=False)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prep = commands.add_parser("prepare"); prep.add_argument("old",type=Path); prep.add_argument("new",type=Path)
    execute = commands.add_parser("run"); execute.add_argument("root",type=Path)
    args = parser.parse_args()
    result = prepare(args.old,args.new) if args.command == "prepare" else run(args.root)
    print(json.dumps(result,indent=2,allow_nan=False))


if __name__ == "__main__":
    main()
