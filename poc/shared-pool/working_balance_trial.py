#!/usr/bin/env python3
"""Frozen stdlib arithmetic comparison: isolate, seal all predictions, then score.

No native proofs, keys, network clients or broadcasts. Private attempt paths are
create-only and outside Git. Observers never receive seed, truth, generator,
case labels or the other arm. Four cases are descriptive, not a qualification.
"""
import argparse
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import gzip
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RUNNER = "working_balance_trial.py"
SPEC = "WORKING-BALANCE-PRIVACY-SPEC.md"
CELLS = ("overlap-independent", "sparse-independent", "overlap-correlated", "sparse-correlated")
ARMS = ("whole", "partial")
PROFILES = ("C+D", "pooled")
HORIZONS = ("creation", "next_payout", "final")
BASE_VARIANTS = ("prior", "residual", "coinput", "split", "subset_nearest", "subset_supported",
                 "partial_tail", "split_tail", "receipt_timing", "cash_inverse", "colluder_tags",
                 "bridge_ancestry", "combined")
METRICS = ("sender", "recipient", "relationship", "amount_within_10pct", "amount_exact")
SOURCES = (RUNNER, "working_balance_trial_tests.py", "working_balance_model.py",
           "working_balance_model_tests.py", "working_balance_observer.py", "working_balance_observer_tests.py",
           "working_balance_validate.py", "working_balance_validator_tests.py")
PYTHON = Path("/usr/bin/python3").resolve()


def need(ok, label="working balance invariant"):
    if not ok:
        raise ValueError(label)


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def canonical(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode())


def load(path):
    return parse_json(Path(path).read_bytes())


def parse_json(blob):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite JSON")
    return json.loads(blob, object_pairs_hook=pairs, parse_constant=invalid)


def save(path, value):
    with Path(path).open("x", encoding="utf-8") as output:
        json.dump(value, output, indent=2, allow_nan=False)
        output.write("\n")


def plain(path, directory=False):
    path = Path(path).absolute()
    need(".." not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), "unsafe artifact path")
    need(path.is_dir() if directory else path.is_file(), "missing regular artifact")
    return path


def relative(root, name):
    need(type(name) is str and name and not Path(name).is_absolute() and ".." not in Path(name).parts,
         "unsafe relative path")
    return plain(Path(root) / name)


def integer(value, low=0, high=2**64-1):
    need(type(value) is int and low <= value <= high, "integer range")
    return value


def variants(profile):
    need(profile in PROFILES, "unknown profile")
    return BASE_VARIANTS if profile == "C+D" else BASE_VARIANTS + tuple("C_"+v for v in BASE_VARIANTS)


def horizons(public):
    events = public["events"]
    final = len(events)-1
    return {i: dict(creation=i, next_payout=next((j for j in range(i+1, len(events))
                       if events[j]["payout"] > 0), final), final=final)
            for i, event in enumerate(events) if event["mode"] == 1 and event["payout"] == 0}


def points(public):
    return sorted({end for cutoffs in horizons(public).values() for end in cutoffs.values()})


def targets_at(public, end):
    return sorted(event for event, cutoffs in horizons(public).items() if end in cutoffs.values())


def cut(public, directory, view, end):
    integer(end, 0, len(public["events"])-1)
    events = public["events"][:end+1]
    count = events[-1]["count_before"] + len(events[-1]["new"])
    groups = {event["funding_group"] for event in events if event["funding_group"]}
    return ({**public, "events": events, "commitments": public["commitments"][:count]},
            {**directory, "initial_funding_owners": {k: v for k, v in directory["initial_funding_owners"].items() if k in groups}},
            {**view, "authored": [row for row in view["authored"] if row["event"] <= end],
             "receipts": [row for row in view["receipts"] if row["position"] < count]})


def validate_prediction(prediction, public, profile, end, directory=None, view=None, targets=None):
    need(set(prediction) == {"schema", "complete", "profile", "through_event", "public_sha256",
         "directory_sha256", "view_sha256", "target_events_sha256", "rows", "boundary"}, "prediction fields")
    need(prediction["schema"] == "kpi-working-balance-predictions-v1" and prediction["complete"] is True
         and prediction["profile"] == profile and type(prediction["through_event"]) is int
         and prediction["through_event"] == end, "prediction scope")
    prefix = {**public, "events": public["events"][:end+1],
              "commitments": public["commitments"][:public["events"][end]["count_before"]+len(public["events"][end]["new"])]}
    need(prediction["public_sha256"] == canonical(prefix), "prediction public prefix hash")
    if directory is not None:
        need(prediction["directory_sha256"] == canonical(directory) and prediction["view_sha256"] == canonical(view),
             "prediction disclosure hashes")
    need(prediction["boundary"] == "finite arithmetic hypotheses; not exhaustive inference or native evidence", "prediction boundary")
    expected = [i for i in horizons(public) if i <= end] if targets is None else targets
    need(prediction["target_events_sha256"] == canonical(expected), "prediction target selection hash")
    need(type(prediction["rows"]) is list and [row["event"] for row in prediction["rows"]] == expected,
         "prediction target coverage")
    for row in prediction["rows"]:
        need(set(row) == {"event", "event_id", "guesses"}, "prediction row fields")
        need(type(row["event"]) is int and row["event_id"] == public["events"][row["event"]]["event_id"], "target identity")
        need(set(row["guesses"]) == set(variants(profile)), "strategy coverage")
        for guess in row["guesses"].values():
            need(set(guess) == {"sender", "recipient", "amount", "relationship_rank"}, "guess fields")
            integer(guess["sender"], 0, 31); integer(guess["recipient"], 0, 31); integer(guess["amount"])
            need(type(guess["relationship_rank"]) is list and len(guess["relationship_rank"]) == 4,
                 "rank fields")
            for number in guess["relationship_rank"]:
                integer(number, -(2**63)+1, 2**63-1)


def sealed_batch_complete(expected, records):
    keys = [(row["case"], row["arm"], row["profile"], row["through_event"]) for row in records]
    need(len(keys) == len(set(keys)) and set(keys) == set(expected), "complete sealed observation matrix")


def selected_guesses(indexed, profile, event, ends, horizon):
    result = dict(indexed[profile, ends[horizon]][event])
    if horizon == "final":
        for earlier in ("creation", "next_payout"):
            result.update({earlier+"__"+name: guess for name, guess in indexed[profile, ends[earlier]][event].items()})
    return result


def fraction(numerator, denominator):
    if denominator == 0:
        return None
    value = Fraction(numerator, denominator)
    return dict(numerator=value.numerator, denominator=value.denominator)


def gate_row(whole, partial, primary=True):
    n = whole["targets"]
    need(type(n) is int and n > 0 and partial["targets"] == n, "matched nonempty primary denominator")
    w, p = whole["family_max"], partial["family_max"]
    reduction = Fraction(w["amount_within_10pct"]-p["amount_within_10pct"], n)
    advantage = Fraction(p["amount_within_10pct"]-partial["prior"]["amount_within_10pct"], n)
    regressions = {m: Fraction(p[m]-w[m], n) for m in ("sender", "recipient", "relationship")}
    conditions = dict(amount_reduction=(not primary or reduction >= Fraction(1, 20)),
                      prior_advantage=(not primary or advantage <= Fraction(1, 20)),
                      relationship_nonregression=all(v <= Fraction(1, 20) for v in regressions.values()))
    return dict(**conditions, passed=all(conditions.values()),
                amount_reduction_rate=fraction(reduction.numerator, reduction.denominator),
                partial_prior_advantage=fraction(advantage.numerator, advantage.denominator),
                identity_regression={k: fraction(v.numerator, v.denominator) for k, v in regressions.items()})


def outcomes(guess, target):
    sender, recipient = guess["sender"] == target["sender"], guess["recipient"] == target["recipient"]
    return dict(sender=sender, recipient=recipient, relationship=sender and recipient,
                amount_exact=guess["amount"] == target["amount"],
                amount_within_10pct=10*abs(guess["amount"]-target["amount"]) <= target["amount"])


def validate_bundle(public, directory, truth, cost):
    from working_balance_validate import validate_bundle as independent
    return independent(public, directory, truth, cost)


def validate_views(truth, views):
    """Reconstruct only disclosures permitted to each profile after the barrier."""
    need(set(views) == set(PROFILES), "disclosure profile roster")
    for profile in PROFILES:
        members = [] if profile == "C+D" else list(range(8))
        expected = dict(schema="kpi-working-balance-view-v1", members=members,
            authored=[{key: row[key] for key in ("event", "owner", "inputs", "outputs")}
                      for row in truth["events"] if row["owner"] in members],
            receipts=[dict(position=out["position"], value=out["value"], owner=out["recipient"])
                      for row in truth["events"] for out in row["outputs"] if out["value"] > 0 and out["recipient"] in members])
        need(canonical(expected) == canonical(views[profile]), "permitted disclosure completeness")


def score_arm(public, truth, predictions):
    targets = [target for target in truth["targets"] if target["sender"] >= 8 and target["recipient"] >= 8]
    need(targets and len({t["obligation"] for t in targets}) == len(targets), "primary target identity")
    ends = horizons(public)
    indexed = {(entry["profile"], entry["through_event"]):
               {row["event"]: row["guesses"] for row in entry["prediction"]["rows"]} for entry in predictions}
    profiles, private_correct = {}, {}
    for profile in PROFILES:
        profiles[profile], private_correct[profile] = {}, {}
        for horizon in HORIZONS:
            names = list(variants(profile))
            if horizon == "final":
                names += [h+"__"+v for h in ("creation", "next_payout") for v in variants(profile)]
            correct = {name: {metric: [] for metric in METRICS} for name in names}
            for target in targets:
                guesses = selected_guesses(indexed, profile, target["event"], ends[target["event"]], horizon)
                need(set(guesses) == set(names), "selected strategy roster")
                for name, guess in guesses.items():
                    for metric, value in outcomes(guess, target).items():
                        correct[name][metric].append(value)
            counters = {name: {m: dict(correct=sum(values), eligible=len(values), rate=fraction(sum(values), len(values)))
                               for m, values in metrics.items()} for name, metrics in correct.items()}
            strongest = {m: max(sum(correct[name][m]) for name in names) for m in METRICS}
            prior = {m: sum(correct["prior"][m]) for m in METRICS}
            profiles[profile][horizon] = dict(targets=len(targets), variants=counters, family_max=strongest, prior=prior,
                absolute_target_exceedances={m: Fraction(strongest[m], len(targets)) > cap for m, cap in
                    (("sender", Fraction(1, 10)), ("recipient", Fraction(1, 10)), ("amount_within_10pct", Fraction(1, 5)))})
            private_correct[profile][horizon] = correct
    return profiles, private_correct, [target["obligation"] for target in targets]


def score_all(bundles, predictions):
    reports, gates, checked = {}, {}, {}
    for cell in CELLS:
        whole, partial = bundles[cell]["whole"], bundles[cell]["partial"]
        need(whole["truth"]["plan"] == partial["truth"]["plan"], "paired economic plan changed")
        arms, correctness, target_ids = {}, {}, {}
        for arm in ARMS:
            bundle = bundles[cell][arm]
            need(bundle["truth"]["cell"] == cell and bundle["truth"]["arm"] == arm, "truth case and arm binding")
            checked[cell+"/"+arm] = validate_bundle(bundle["public"], bundle["directory"], bundle["truth"], bundle["cost"])
            if "views" in bundle:
                validate_views(bundle["truth"], bundle["views"])
            chosen = [entry for entry in predictions if entry["case"] == cell and entry["arm"] == arm]
            arms[arm], correctness[arm], target_ids[arm] = score_arm(bundle["public"], bundle["truth"], chosen)
        need(target_ids["whole"] == target_ids["partial"], "paired primary obligations changed")
        paired, decisions = {}, {}
        for profile in PROFILES:
            paired[profile], decisions[profile] = {}, {}
            for horizon in HORIZONS:
                paired[profile][horizon] = {}
                for variant, metrics in correctness["whole"][profile][horizon].items():
                    paired[profile][horizon][variant] = {}
                    for metric, old in metrics.items():
                        new = correctness["partial"][profile][horizon][variant][metric]
                        paired[profile][horizon][variant][metric] = dict(
                            eligible=len(old), gains=sum(not a and b for a, b in zip(old, new, strict=True)),
                            losses=sum(a and not b for a, b in zip(old, new, strict=True)))
                if horizon != "creation":
                    decisions[profile][horizon] = gate_row(arms["whole"][profile][horizon], arms["partial"][profile][horizon],
                                                         primary=cell.endswith("-independent"))
        costs = {arm: bundles[cell][arm]["cost"] for arm in ARMS}
        fees = {}
        for arm in ARMS:
            invoices = bundles[cell][arm]["truth"]["plan"]["payments"]
            fee = 40_000_000
            fees[arm] = dict(original_invoices=len(invoices),
                ordinary_fee_above_1pct_invoices=sum(100*fee > p["amount"] for p in invoices),
                ordinary_fee_max_fraction=max((fraction(fee, p["amount"]) for p in invoices),
                                              key=lambda f: Fraction(f["numerator"], f["denominator"])),
                lifecycle_fees_sompi=costs[arm]["pool_fees"]+costs[arm]["bridge_fees"],
                capital_normalized_lifecycle_fee_diagnostic=fraction(costs[arm]["pool_fees"]+costs[arm]["bridge_fees"],
                                                                     checked[cell+"/"+arm]["initial_injected_sompi"]),
                per_payment_lifecycle_fee_qualification=False)
        reports[cell] = dict(arms=arms, paired=paired, cost=costs, fee_diagnostics=fees)
        gates[cell] = decisions
    passed = all(row["passed"] for cell in gates.values() for profile in cell.values() for row in profile.values())
    return dict(schema="kpi-working-balance-score-v1", complete=True, directional_pass=passed,
                status="directional-screen-pass" if passed else "candidate-rejected-by-arithmetic-screen",
                qualification_pass=False, paired_histories=4, cases=reports, decisions=gates, validation=checked,
                limits=["Four descriptive paired histories; no statistical or privacy qualification.",
                        "Arithmetic model with ideal hiding labels; no native construction, proof or recovery evidence.",
                        "Family maxima select an aggregate fixed strategy, never a truth-selected per-target guess.",
                        "Lifecycle fees divided by initial capital are diagnostic and do not qualify the 2% per-payment lifecycle target."])


def runtime_manifest():
    library = Path(subprocess.check_output([str(PYTHON), "-I", "-S", "-c", "import sysconfig;print(sysconfig.get_path('stdlib'))"], text=True).strip())
    files = {str(p.relative_to(library)): sha(p) for p in sorted(library.rglob("*"))
             if p.is_file() and "__pycache__" not in p.parts and "site-packages" not in p.parts and "dist-packages" not in p.parts}
    return dict(python=str(PYTHON), python_sha256=sha(PYTHON), stdlib=str(library), stdlib_sha256=canonical(files),
                bwrap_sha256=sha(shutil.which("bwrap")))


def prepare(root):
    root = Path(root).absolute()
    need(not root.is_relative_to(ROOT) and not root.exists() and ".." not in root.parts, "new private attempt outside Git required")
    plain(root.parent, directory=True)
    root.mkdir(mode=0o700)
    for folder in ("code", "private", "public", "runs", "inputs"):
        (root/folder).mkdir(mode=0o700)
    for name in (*SOURCES, SPEC):
        shutil.copyfile(plain(HERE/name), root/"code"/name)
    frozen = dict(schema="kpi-working-balance-freeze-v1", frozen_utc=now(),
        base_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        sources={name: sha(root/"code"/name) for name in (*SOURCES, SPEC)}, runtime=runtime_manifest(),
        cells=list(CELLS), arms=list(ARMS), profiles=list(PROFILES), horizons=list(HORIZONS),
        variants={profile: list(variants(profile)) for profile in PROFILES}, qualification_pass=False,
        barrier="Complete all predictions and seal the batch before opening any truth")
    save(root/"freeze.json", frozen)
    return dict(prepared=True, sampled=False, freeze_sha256=sha(root/"freeze.json"))


def check(root):
    root = plain(root, directory=True)
    need(Path(__file__).absolute() == root/"code"/RUNNER, "execute frozen controller")
    frozen = load(plain(root/"freeze.json"))
    need(frozen["schema"] == "kpi-working-balance-freeze-v1"
         and set(frozen["sources"]) == set((*SOURCES, SPEC)), "freeze roster")
    need(frozen["cells"] == list(CELLS) and frozen["arms"] == list(ARMS)
         and frozen["profiles"] == list(PROFILES) and frozen["horizons"] == list(HORIZONS)
         and frozen["variants"] == {p: list(variants(p)) for p in PROFILES}
         and frozen["qualification_pass"] is False, "freeze design drift")
    for name, pin in frozen["sources"].items():
        need(sha(plain(root/"code"/name)) == pin, "source drift")
    need(runtime_manifest() == frozen["runtime"], "runtime drift")
    return frozen


def sandbox():
    return ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
            "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/lib64", "/lib64", "--dev", "/dev", "--tmpfs", "/tmp",
            "--unshare-user", "--as-pid-1", "--disable-userns", "--cap-drop", "ALL",
            "--setenv", "PATH", "/usr/bin:/bin"]


def isolated(root, label, mode, inputs):
    allowed = {"controls": (), "generate": ("/seed.json",),
               "observe": ("/public.json", "/directory.json", "/view.json", "/targets.json"),
               "score": ("/generation.json", "/prediction-batch.json", "/predictions.json", "/data")}
    need(mode in allowed and tuple(mount for _, mount in inputs) == allowed[mode], "isolated input allowlist")
    folder = root/"runs"/label; folder.mkdir(mode=0o700)
    source_names = ("working_balance_observer.py",) if mode == "observe" else (
        (RUNNER, "working_balance_model.py") if mode == "generate" else SOURCES if mode == "controls" else (RUNNER, "working_balance_validate.py"))
    command = sandbox() + ["--dir", "/code", "--bind", str(folder), "/output"]
    for name in source_names:
        command += ["--ro-bind", str(root/"code"/name), "/code/"+name]
    for path, mount in inputs:
        if mount == "/data":
            # Never mount the attempt directory: it contains the retained seed.
            # A closed hard-link tree avoids bwrap's 9000-argument limit while
            # retaining the exact file allowlist; it is mounted read-only.
            stage = stage_score_inputs(root)
            command += ["--ro-bind", str(stage), "/data"]
        else:
            command += ["--ro-bind", str(plain(path)), mount]
    probe = "import pathlib,socket,subprocess,json;assert not pathlib.Path('/home').exists();assert not pathlib.Path('/proc').exists();assert [n for _,n in socket.if_nameindex()]==['lo'];assert subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True).returncode!=0;print(json.dumps({'no_home':True,'no_proc':True,'interfaces':['lo'],'nested_userns_denied':True}))"
    checked = sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", probe], capture_output=True, text=True, check=True)
    save(folder/"isolation.json", dict(**json.loads(checked.stdout), mode=mode, mounts=[mount for _, mount in inputs],
        truth_mounted=mode == "score", seed_mounted=mode == "generate"))
    save(folder/"inputs.json", {mount: ("directory" if mount == "/data" else sha(path)) for path, mount in inputs})
    if mode == "observe":
        script = "import sys,json;sys.path.insert(0,'/code');import working_balance_observer as a;p,d,v,t=[json.load(open('/'+n+'.json')) for n in ('public','directory','view','targets')];r=a.observe(p,d,v,len(p['events'])-1,target_events=t);f=open('/output/result.json','x');json.dump(r,f,indent=2,allow_nan=False);f.write('\\n');f.close()"
    else:
        script = "import sys;sys.path.insert(0,'/code');import working_balance_trial as t;t.internal("+repr(mode)+")"
    start = now()
    with (folder/"stdout.log").open("x") as out, (folder/"stderr.log").open("x") as err:
        process = sandbox_run(command+["--", str(PYTHON), "-I", "-S", "-B", "-c", script], stdout=out, stderr=err)
    save(folder/"process.json", dict(started_utc=start, ended_utc=now(), returncode=process.returncode))
    need(process.returncode == 0, "isolated stage failed; preserve attempt")
    return folder, load(plain(folder/"result.json"))


def sandbox_run(command, **kwargs):
    # Per-file score mounts can exceed exec's argv byte limit on a long history.
    # bwrap consumes its own NUL-delimited arguments from an anonymous fd.
    fd = os.memfd_create("working-balance-sandbox", flags=0)
    try:
        split = command.index("--")
        os.write(fd, b"\0".join(arg.encode() for arg in command[1:split])+b"\0")
        os.lseek(fd, 0, os.SEEK_SET)
        return subprocess.run([command[0], "--args", str(fd), *command[split:]], pass_fds=(fd,), **kwargs)
    finally:
        os.close(fd)


def timestamp(value):
    need(type(value) is str, "timestamp type")
    result = datetime.fromisoformat(value)
    need(result.tzinfo is not None, "timezone required")
    return result


def pinned_json(root, name, pin):
    blob = relative(root, name).read_bytes()
    need(digest(blob) == pin, "artifact drift")
    return parse_json(blob)


def verify_lifecycle(root, generation):
    """Public receipts establish controls -> fresh sampling -> generation."""
    frozen, controls, seed = (load(root/name) for name in ("freeze.json", "controls.json", "seed-commitment.json"))
    freeze_hash = sha(root/"freeze.json")
    need(controls["passed"] is True and controls["freeze_sha256"] == freeze_hash
         and seed["freeze_sha256"] == freeze_hash and seed["controls_sha256"] == sha(root/"controls.json")
         and generation["seed_commitment_sha256"] == sha(root/"seed-commitment.json"), "preseed provenance")
    outcome = pinned_json(root, "runs/controls/result.json", controls["result_sha256"])
    need(outcome["passed"] is True and type(outcome["tests"]) is int and outcome["tests"] > 0, "preseed controls")
    for stage, receipt in (("controls", controls), ("generate", generation)):
        process = pinned_json(root, "runs/"+stage+"/process.json", receipt["process_sha256"])
        isolation = pinned_json(root, "runs/"+stage+"/isolation.json", receipt["isolation_sha256"])
        need(type(process["returncode"]) is int and process["returncode"] == 0, "lifecycle process failed")
        start, end = timestamp(process["started_utc"]), timestamp(process["ended_utc"])
        lower = timestamp(frozen["frozen_utc"] if stage == "controls" else seed["sampled_utc"])
        need(lower <= start <= end <= timestamp(receipt["completed_utc"]), "lifecycle process chronology")
        need(isolation == dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
             mode=stage, mounts=[] if stage == "controls" else ["/seed.json"],
             truth_mounted=False, seed_mounted=stage == "generate"), "lifecycle isolation")
        need(load(relative(root, "runs/"+stage+"/inputs.json")) == ({} if stage == "controls" else {"/seed.json": seed["seed_sha256"]}),
             "committed seed mount identity")
    need(timestamp(controls["completed_utc"]) <= timestamp(seed["sampled_utc"])
         <= timestamp(generation["completed_utc"]), "sample after controls")
    origin = pinned_json(root, "runs/generate/result.json", generation["result_sha256"])
    need(origin == {"complete": True, "records": generation["records"]}, "generation origin")


def generation_sources(root, generation):
    """Validate all paths before reading anything; truth pins remain opaque."""
    need(generation["complete"] is True and [(r["case"], r["arm"]) for r in generation["records"]]
         == [(c, a) for c in CELLS for a in ARMS], "generation matrix")
    for record in generation["records"]:
        prefix = record["case"]+"-"+record["arm"]
        expected = {k: ("private/" if k == "truth" else "public/")+prefix+"-"+k+".json"
                    for k in ("public", "directory", "cost", "truth")}
        views = {p: "public/"+prefix+"-"+("C" if p == "C+D" else "pooled")+".json" for p in PROFILES}
        need(all(record[k] == name for k, name in expected.items()) and record["views"] == views,
             "closed generation path allowlist")
        need(set(record["pins"]) == set(expected.values()) | set(views.values()), "generation pin roster")
        for pin in record["pins"].values():
            need(type(pin) is str and len(pin) == 64 and all(c in "0123456789abcdef" for c in pin), "artifact hash")
    result = {}
    for record in generation["records"]:
        bundle = {key: pinned_json(root, record[key], record["pins"][record[key]]) for key in ("public", "directory", "cost")}
        bundle["views"] = {p: pinned_json(root, name, record["pins"][name]) for p, name in record["views"].items()}
        result[record["case"], record["arm"]] = bundle
    return result


def expected_matrix(root, generation):
    sources = generation_sources(root, generation)
    return [(c, a, p, end) for c in CELLS for a in ARMS for end in points(sources[c, a]["public"]) for p in PROFILES]


def verify_batch(root, generation):
    root = Path(root)
    batch, predictions = load(plain(root/"prediction-batch.json")), load(plain(root/"predictions.json"))
    freeze_hash, generation_hash = sha(root/"freeze.json"), sha(root/"generation.json")
    need(generation == load(root/"generation.json") and generation["freeze_sha256"] == freeze_hash,
         "generation identity")
    need(batch["complete"] is True and batch["freeze_sha256"] == freeze_hash
         and batch["generation_sha256"] == sha(root/"generation.json")
         and batch["predictions_sha256"] == sha(root/"predictions.json"), "batch identity")
    verify_lifecycle(root, generation)
    sources = generation_sources(root, generation)
    expected = [(c, a, p, end) for c in CELLS for a in ARMS for end in points(sources[c, a]["public"]) for p in PROFILES]
    sealed_batch_complete(expected, batch["records"]); sealed_batch_complete(expected, predictions)
    need(len(batch["records"]) == len(predictions), "prediction count")
    frozen_at = timestamp(load(root/"freeze.json")["frozen_utc"])
    generated_at, batch_at = timestamp(generation["completed_utc"]), timestamp(batch["sealed_utc"])
    need(frozen_at <= generated_at <= batch_at, "batch chronology")
    public_guesses = {}
    for serial, (record, prediction, identity) in enumerate(zip(batch["records"], predictions, expected, strict=True)):
        keys = ("case", "arm", "profile", "through_event")
        need(tuple(record[k] for k in keys) == tuple(prediction[k] for k in keys) == identity, "seal ordering")
        label = f"observe-{serial:04d}"
        need(record["seal"] == "runs/"+label+"/seal.json", "closed seal path")
        seal_path = relative(root, record["seal"])
        need(sha(seal_path) == record["seal_sha256"], "seal drift")
        seal = load(seal_path)
        need(seal["freeze_sha256"] == freeze_hash and seal["generation_sha256"] == generation_hash,
             "seal source identity")
        need(seal["prediction_file"] == "runs/"+label+"/result.json", "closed prediction path")
        names = ["inputs/"+label+"/"+key+".json" for key in ("public", "directory", "view", "targets")]
        # Reject path substitution BEFORE hashing any path supplied by a seal.
        need(set(seal["inputs"]) == set(names), "closed observer input paths")
        need(pinned_json(root, seal["prediction_file"], seal["prediction_sha256"]) == prediction["prediction"], "prediction drift")
        c, a, profile, end = identity
        bundle = sources[c, a]
        expected_values = (*cut(bundle["public"], bundle["directory"], bundle["views"][profile], end), targets_at(bundle["public"], end))
        for path, value in zip(names, expected_values, strict=True):
            need(canonical(pinned_json(root, path, seal["inputs"][path])) == canonical(value), "wrong observer prefix")
        validate_prediction(prediction["prediction"], expected_values[0], profile, end, *expected_values[1:])
        folder = "runs/"+label+"/"
        process = pinned_json(root, folder+"process.json", seal["process_sha256"])
        isolation = pinned_json(root, folder+"isolation.json", seal["isolation_sha256"])
        inputs = pinned_json(root, folder+"inputs.json", seal["input_manifest_sha256"])
        need(type(process["returncode"]) is int and process["returncode"] == 0, "observer process failure")
        need(generated_at <= timestamp(process["started_utc"]) <= timestamp(process["ended_utc"])
             <= timestamp(seal["sealed_utc"]) <= batch_at, "prediction chronology")
        need(isolation == dict(no_home=True, no_proc=True, interfaces=["lo"], nested_userns_denied=True,
             mode="observe", mounts=["/public.json", "/directory.json", "/view.json", "/targets.json"], truth_mounted=False, seed_mounted=False),
             "observer isolation receipt")
        need(inputs == {"/"+Path(name).name: seal["inputs"][name] for name in names}, "mounted input identities")
        guesses = {row["event"]: row["guesses"] for row in prediction["prediction"]["rows"]}
        if profile == "C+D":
            public_guesses[c, a, end] = guesses
        else:
            need(all(canonical(guesses[event]["C_"+v]) == canonical(guess[v])
                     for event, guess in public_guesses[c, a, end].items() for v in BASE_VARIANTS), "pooled public strategy changed")
    return batch, predictions


def public_artifacts(generation, batch):
    names = ["freeze.json", "controls.json", "seed-commitment.json", "generation.json", "prediction-batch.json",
             "predictions.json", "runs/controls/result.json", "runs/controls/process.json", "runs/controls/isolation.json",
             "runs/controls/inputs.json", "runs/generate/result.json", "runs/generate/process.json", "runs/generate/isolation.json",
             "runs/generate/inputs.json"]
    for record in generation["records"]:
        names.extend([record["public"], record["directory"], record["cost"], *record["views"].values()])
    for serial in range(len(batch["records"])):
        label = f"observe-{serial:04d}"
        names.extend("runs/"+label+"/"+n+".json" for n in ("seal", "result", "process", "isolation", "inputs"))
        names.extend("inputs/"+label+"/"+n+".json" for n in ("public", "directory", "view", "targets"))
    return names


def score_mounts(root):
    generation = load(root/"generation.json")
    batch, _ = verify_batch(root, generation)
    return public_artifacts(generation, batch)+[r["truth"] for r in generation["records"]]


def stage_score_inputs(root):
    names = score_mounts(root)  # Completes the public barrier before truth links.
    stage = root/"score-inputs"
    stage.mkdir(mode=0o700)
    for name in names:
        target = stage/name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.link(relative(root, name), target)
    return stage


def run(root):
    frozen = check(root)
    controls_folder, controls = isolated(root, "controls", "controls", [])
    need(controls["passed"] is True, "controls before seed")
    save(root/"controls.json", dict(passed=True, completed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        result_sha256=sha(controls_folder/"result.json"), process_sha256=sha(controls_folder/"process.json"),
        isolation_sha256=sha(controls_folder/"isolation.json")))
    check(root)
    save(root/"private/seed.json", dict(seed=secrets.token_hex(32)))
    save(root/"seed-commitment.json", dict(sampled_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        controls_sha256=sha(root/"controls.json"), seed_sha256=sha(root/"private/seed.json")))
    generated, generation = isolated(root, "generate", "generate", [(root/"private/seed.json", "/seed.json")])
    need(generation["complete"] is True, "generation complete")
    # Generator alone opened its truth. Move exact output files without reading
    # their bytes; observer/controller only use the public generation manifest.
    for directory in ("private", "public"):
        for path in (generated/directory).iterdir():
            path.rename(root/directory/path.name)
    save(root/"generation.json", {**generation, "freeze_sha256": sha(root/"freeze.json"), "completed_utc": now(),
        "seed_commitment_sha256": sha(root/"seed-commitment.json"), "result_sha256": sha(generated/"result.json"),
        "process_sha256": sha(generated/"process.json"), "isolation_sha256": sha(generated/"isolation.json")})
    generation = load(root/"generation.json")
    records, predictions = [], []
    serial = 0
    for source in generation["records"]:
        public = load(relative(root, source["public"])); directory = load(relative(root, source["directory"]))
        for end in points(public):
            for profile in PROFILES:
                label = f"observe-{serial:04d}"; serial += 1
                inputs = root/"inputs"/label; inputs.mkdir(mode=0o700)
                view = load(relative(root, source["views"][profile]))
                values = cut(public, directory, view, end)
                for name, value in zip(("public", "directory", "view"), values, strict=True):
                    save(inputs/(name+".json"), value)
                targets = targets_at(public, end)
                save(inputs/"targets.json", targets)
                folder, prediction = isolated(root, label, "observe", [(inputs/(n+".json"), "/"+n+".json") for n in ("public", "directory", "view", "targets")])
                validate_prediction(prediction, public, profile, end, values[1], values[2], targets)
                seal = dict(sealed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
                    generation_sha256=sha(root/"generation.json"), prediction_file=str((folder/"result.json").relative_to(root)),
                    prediction_sha256=sha(folder/"result.json"),
                    process_sha256=sha(folder/"process.json"), isolation_sha256=sha(folder/"isolation.json"),
                    input_manifest_sha256=sha(folder/"inputs.json"),
                    inputs={str(path.relative_to(root)): sha(path) for path in sorted(inputs.iterdir())})
                save(folder/"seal.json", seal)
                identity = dict(case=source["case"], arm=source["arm"], profile=profile, through_event=end)
                records.append(dict(**identity, seal=str((folder/"seal.json").relative_to(root)), seal_sha256=sha(folder/"seal.json")))
                predictions.append(dict(**identity, prediction=prediction))
    check(root)
    save(root/"predictions.json", predictions)
    save(root/"prediction-batch.json", dict(complete=True, sealed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        generation_sha256=sha(root/"generation.json"), predictions_sha256=sha(root/"predictions.json"), records=records))
    verify_batch(root, generation)
    # No private read or score mount can occur above this complete batch barrier.
    score_folder, score = isolated(root, "score", "score", [(root/"generation.json", "/generation.json"),
        (root/"prediction-batch.json", "/prediction-batch.json"), (root/"predictions.json", "/predictions.json"), (root, "/data")])
    need(score["complete"] is True and score["qualification_pass"] is False, "scoring scope")
    verify_batch(root, generation); check(root)
    save(root/"completion.json", dict(complete=True, completed_utc=now(), freeze_sha256=sha(root/"freeze.json"),
        prediction_batch_sha256=sha(root/"prediction-batch.json"), score_sha256=sha(score_folder/"result.json"),
        score_process_sha256=sha(score_folder/"process.json"), score_isolation_sha256=sha(score_folder/"isolation.json"),
        directional_pass=score["directional_pass"], status=score["status"], qualification_pass=False))
    return load(root/"completion.json")


def internal(mode):
    if mode == "controls":
        import unittest
        modules = [name[:-3] for name in SOURCES if name.endswith("_tests.py")]
        suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
        result = unittest.TextTestRunner(verbosity=1).run(suite)
        save("/output/result.json", dict(passed=result.wasSuccessful(), tests=result.testsRun))
    elif mode == "generate":
        import working_balance_model as model
        data = model.generate(bytes.fromhex(load("/seed.json")["seed"]))
        need(set(data) == set(CELLS), "generated cell roster")
        for directory in ("private", "public"):
            Path("/output", directory).mkdir(mode=0o700)
        records = []
        for case in CELLS:
            need(set(data[case]) == set(ARMS), "generated arm roster")
            for arm in ARMS:
                bundle = data[case][arm]; prefix = case+"-"+arm
                record = dict(case=case, arm=arm, views={}, pins={})
                for key in ("public", "directory", "cost", "truth"):
                    name = ("private/" if key == "truth" else "public/")+prefix+"-"+key+".json"
                    save(Path("/output")/name, bundle[key]); record[key] = name
                    record["pins"][name] = sha(Path("/output")/name)
                for profile in PROFILES:
                    name = "public/"+prefix+"-"+("C" if profile == "C+D" else "pooled")+".json"
                    save(Path("/output")/name, bundle["views"][profile]); record["views"][profile] = name
                    record["pins"][name] = sha(Path("/output")/name)
                records.append(record)
        save("/output/result.json", dict(complete=True, records=records))
    elif mode == "score":
        generation = load("/generation.json")
        batch = load("/prediction-batch.json")
        need(batch["complete"] is True and batch["generation_sha256"] == sha("/generation.json")
             and batch["predictions_sha256"] == sha("/predictions.json"), "score batch barrier")
        verify_batch(Path("/data"), generation)
        bundles = {case: {} for case in CELLS}
        for record in generation["records"]:
            bundle = {}
            for key in ("public", "directory", "cost", "truth"):
                path = relative(Path("/data"), record[key])
                blob = path.read_bytes()
                need(digest(blob) == record["pins"][record[key]], "scorer artifact drift")
                bundle[key] = parse_json(blob)
            bundle["views"] = {profile: pinned_json(Path("/data"), name, record["pins"][name]) for profile, name in record["views"].items()}
            bundles[record["case"]][record["arm"]] = bundle
        save("/output/result.json", score_all(bundles, load("/predictions.json")))
    else:
        raise ValueError("unknown internal mode")


def export(root, destination):
    check(root)
    completion = load(plain(root/"completion.json"))
    need(completion["complete"] is True and completion["qualification_pass"] is False
         and completion["score_sha256"] == sha(root/"runs/score/result.json")
         and completion["freeze_sha256"] == sha(root/"freeze.json")
         and completion["prediction_batch_sha256"] == sha(root/"prediction-batch.json"), "completed export")
    process = pinned_json(root, "runs/score/process.json", completion["score_process_sha256"])
    isolation = pinned_json(root, "runs/score/isolation.json", completion["score_isolation_sha256"])
    need(type(process["returncode"]) is int and process["returncode"] == 0
         and isolation["truth_mounted"] is True and isolation["seed_mounted"] is False, "score execution")
    generation = load(root/"generation.json"); batch, _ = verify_batch(root, generation)
    need(timestamp(batch["sealed_utc"]) <= timestamp(process["started_utc"]) <= timestamp(process["ended_utc"])
         <= timestamp(completion["completed_utc"]), "score follows complete predictions")
    destination = Path(destination).absolute()
    need(not destination.exists() and not destination.is_relative_to(root), "new public export destination")
    plain(destination.parent, directory=True); destination.mkdir()
    names = public_artifacts(generation, batch)+["completion.json", "runs/score/result.json", "runs/score/process.json", "runs/score/isolation.json"]
    names.extend("code/"+name for name in (*SOURCES, SPEC))
    manifest = {}
    for name in names:
        need(not name.startswith("private/"), "private export rejected")
        blob = relative(root, name).read_bytes()
        compressed = len(blob) >= 65_536
        storage = name+".gz" if compressed else name
        stored = gzip.compress(blob, compresslevel=9, mtime=0) if compressed else blob
        target = destination/storage; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(stored)
        manifest[name] = dict(path=storage, encoding="gzip" if compressed else "identity", bytes=len(blob),
                              sha256=digest(blob), stored_bytes=len(stored), stored_sha256=digest(stored))
    save(destination/"manifest.json", dict(schema="kpi-working-balance-export-v1", files=manifest,
        freeze_sha256=sha(root/"freeze.json"), qualification_pass=False,
        scope="All public inputs, predictions, seals, controls and aggregate scoring; private truth and seed excluded."))
    verify_export(destination)
    return dict(exported=True, files=len(names), bytes=sum(r["stored_bytes"] for r in manifest.values()), qualification_pass=False)


def verify_export(destination):
    """Verify stored bytes and roster, not a standalone semantic seal audit.

    For the latter, unpack logical paths and call verify_batch; it never needs
    truth. export() already performs that full public audit before packaging.
    """
    manifest = load(relative(destination, "manifest.json"))
    need(manifest["schema"] == "kpi-working-balance-export-v1" and manifest["qualification_pass"] is False, "export schema")
    metadata = {}
    for name, row in manifest["files"].items():
        need(not name.startswith("private/") and row["encoding"] in ("identity", "gzip")
             and row["path"] == name+(".gz" if row["encoding"] == "gzip" else ""), "export storage mapping")
        stored = relative(destination, row["path"]).read_bytes()
        need(len(stored) == row["stored_bytes"] and digest(stored) == row["stored_sha256"], "stored export drift")
        blob = gzip.decompress(stored) if row["encoding"] == "gzip" else stored
        need(len(blob) == row["bytes"] and digest(blob) == row["sha256"], "logical export drift")
        if name in ("generation.json", "prediction-batch.json"):
            metadata[name] = parse_json(blob)
    need(set(metadata) == {"generation.json", "prediction-batch.json"}, "missing export metadata")
    expected = public_artifacts(metadata["generation.json"], metadata["prediction-batch.json"])+[
        "completion.json", "runs/score/result.json", "runs/score/process.json", "runs/score/isolation.json"]
    expected.extend("code/"+name for name in (*SOURCES, SPEC))
    need(set(manifest["files"]) == set(expected), "incomplete export roster")
    return dict(storage_verified=True, files=len(manifest["files"]), qualification_pass=False)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "run", "export"):
        command = sub.add_parser(name); command.add_argument("root", type=Path)
        if name == "export": command.add_argument("destination", type=Path)
    args = parser.parse_args(); root = args.root.absolute()
    if args.command != "prepare" and Path(__file__).absolute() != root/"code"/RUNNER:
        frozen = load(plain(root/"freeze.json")); source = plain(root/"code"/RUNNER)
        need(sha(source) == frozen["sources"][RUNNER], "frozen entry drift")
        os.execv(str(PYTHON), [str(PYTHON), "-B", str(source), *sys.argv[1:]])
    result = prepare(root) if args.command == "prepare" else run(root) if args.command == "run" else export(root, args.destination)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
