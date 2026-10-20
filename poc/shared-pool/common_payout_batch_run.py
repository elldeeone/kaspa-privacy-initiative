#!/usr/bin/env python3
"""Run an equivalent batch observer on unchanged inputs, without scoring truth."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h17", HERE / "common-payout.py")
h17 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h17)


def run(root, source, case, participant):
    h17.freeze()
    root.mkdir(mode=0o700)
    sources = (*h17.OBSERVER_FILES, "common_payout_batch_observer.py")
    pins = dict(freeze=h17.FREEZE, sources={n: h17.sha(HERE / n) for n in sources},
                controller_sources={n: h17.sha(HERE / n) for n in
                                    ("common_payout_batch_run.py", "common_payout_batch_tests.py")},
                case=case, observer=f"participant-{participant}",
                engine="bounded-batch", scoring_started=False)
    for original, name in ((source / case / "public.json", "input.json"),
                           (source / case / f"view-{participant}.json", "view.json")):
        shutil.copyfile(original, root / name)
        pins[f"{name.split('.')[0]}_sha256"] = h17.sha(root / name)
    output = root / "output"
    output.mkdir(mode=0o700)
    with (root / "controls.log").open("x") as log:
        subprocess.run([str(h17.h16.h14.VENV / "bin/python"), "-m", "unittest",
                        "common_payout_batch_tests", "-v"], cwd=HERE,
                       stdout=log, stderr=log, check=True)
    command = h17.h16.sandbox() + ["--ro-bind", str(h17.h16.h14.VENV), "/venv"]
    for name in sources:
        command += ["--ro-bind", str(HERE / name), f"/{name}"]
    command += ["--ro-bind", str(root / "input.json"), "/input.json",
                "--ro-bind", str(root / "view.json"), "/view.json",
                "--bind", str(output), "/output"]
    # Case and observer labels stay in the controller's receipt, outside the
    # mount. Only generic source/input hashes enter the observed directory.
    h17.save(root / "execution-pins.json", pins)
    h17.save(output / "pins.json", {k: pins[k] for k in
                                  ("sources", "input_sha256", "view_sha256")})
    probe = (
        "import pathlib,json,socket,subprocess;"
        "paths=['/home','/plan.json','/truth.json','/claims.json','/other-view.json',"
        "'/common_payout_generate.py','/common_payout_score.py','/controller.py',"
        "'/proc/1/cmdline','/proc/self/mountinfo'];"
        "denied=[p for p in paths if not pathlib.Path(p).exists()];assert denied==paths;"
        "net=[n for _,n in socket.if_nameindex()];assert net==['lo'];"
        "u=subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True);"
        "assert u.returncode!=0;"
        "print(json.dumps(dict(inaccessible=denied,interfaces=net,nested_user_namespace_denied=True)))"
    )
    receipt = subprocess.run(command + ["--", "/usr/bin/python3", "-c", probe],
                             capture_output=True, text=True, check=True)
    h17.save(output / "isolation.json", json.loads(receipt.stdout))
    with (output / "observer.log").open("x") as log:
        subprocess.run(command + ["--", "/venv/bin/python", "/common_payout_batch_observer.py",
                                  "/input.json", "/view.json", "/output/predictions.json"],
                       stdout=log, stderr=log, check=True)
    prediction = h17.read(output / "predictions.json")
    for field in ("input_sha256", "view_sha256"):
        if prediction[field] != pins[field]:
            raise ValueError("batch input identity changed")
    print(json.dumps(dict(case=case, participant=participant,
                          seconds=prediction["seconds"], queries=prediction["queries"])), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("root", type=Path)
    p.add_argument("source", type=Path)
    p.add_argument("case")
    p.add_argument("participant", type=int, choices=range(4))
    a = p.parse_args()
    run(a.root.resolve(), a.source.resolve(), a.case, a.participant)
