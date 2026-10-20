#!/usr/bin/env python3
"""Recover the sole missing H18 prediction, preserving all completed attempts."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("h18", HERE / "scheduled-payout.py")
h18 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h18)


def replay(root):
    cfg = h18.freeze()
    pins = h18.read(root / "execution-pins.json")
    for name, digest in pins["sources"].items():
        assert h18.sha(HERE / name) == digest == h18.sha(root / "source" / name)
    for name, digest in h18.read(root / "preparation.json")["files"].items():
        assert h18.sha(root / name) == digest
    pending = [(name, arm, who) for name, arm, who in h18.jobs(cfg)
               if not (root / name / arm / h18.observer_name(who) / "predictions.json").exists()]
    assert len(pending) == 1, "replay only the single incomplete observation"
    name, arm, who = pending[0]
    folder = root / name / arm
    old = folder / h18.observer_name(who)
    out = folder / (h18.observer_name(who) + "-single-worker")
    out.mkdir(mode=0o700)
    shutil.copyfile(old / "pins.json", out / "pins.json")
    wrapper = HERE / "scheduled_payout_single_worker.py"
    shutil.copyfile(wrapper, out / wrapper.name)
    cmd = h18.h16.sandbox() + ["--ro-bind", str(h18.h16.h14.VENV), "/venv"]
    for n in h18.OBSERVERS:
        cmd += ["--ro-bind", str(root / "source" / n), "/" + n]
    cmd += ["--ro-bind", str(out / wrapper.name), "/replay.py",
            "--ro-bind", str(folder / "public.json"), "/input.json",
            "--bind", str(out), "/output"]
    if who is not None:
        cmd += ["--ro-bind", str(folder / f"view-{who}.json"), "/view.json"]
    probe = (
        "import pathlib,json,socket,subprocess;"
        "paths=['/home','/private.json','/master-seed.bin','/generator.py','/other-view.json',"
        "'/scheduled_payout_generate.py','/controller.py','/proc/1/cmdline','/proc/self/mountinfo'];"
        "denied=[p for p in paths if not pathlib.Path(p).exists()];assert denied==paths;"
        "net=[n for i,n in socket.if_nameindex()];assert net==['lo'];"
        "u=subprocess.run(['/usr/bin/unshare','--user','--map-root-user','true'],capture_output=True);"
        "assert u.returncode!=0;"
        "print(json.dumps(dict(inaccessible=denied,interfaces=net,nested_user_namespace_denied=True)))"
    )
    checked = subprocess.run(cmd + ["--", "/usr/bin/python3", "-c", probe],
                             capture_output=True, text=True, check=True)
    h18.save(out / "isolation.json", json.loads(checked.stdout))
    receipt = dict(case=name, arm=arm, observer=h18.observer_name(who), solver_workers=1,
                   wrapper_sha256=h18.sha(wrapper), runner_sha256=h18.sha(Path(__file__)),
                   original_sources_unchanged=True, prepared_inputs_unchanged=True,
                   completed_predictions_reused=True, reason="incomplete two-worker OOM run")
    h18.save(root / "single-worker-replay-start.json", receipt)
    start = time.monotonic()
    with (out / "observer.log").open("x") as log:
        result = subprocess.run(cmd + [
            "--", "/usr/bin/time", "-v", "/venv/bin/python", "/replay.py", "/input.json",
            "/view.json" if who is not None else "-", "/output/predictions.json"],
            stdout=log, stderr=log)
    receipt.update(returncode=result.returncode, elapsed_seconds=time.monotonic() - start)
    h18.save(root / "single-worker-replay.json", receipt)
    if result.returncode:
        raise SystemExit(result.returncode)
    prediction = h18.read(out / "predictions.json")
    assert prediction["input_sha256"] == h18.sha(folder / "public.json")
    assert prediction["view_sha256"] == (
        h18.sha(folder / f"view-{who}.json") if who is not None else None)
    old.rename(folder / (h18.observer_name(who) + "-failed-original"))
    out.rename(old)
    print("Missing observation completed; all earlier attempts retained. No truth scored.", flush=True)


if __name__ == "__main__":
    replay(Path(sys.argv[1]).resolve())
