import subprocess,pathlib,json,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-native-20261022T1431')
t=time.monotonic()
r=subprocess.run(json.loads((p/"command.json").read_text()))
(p/"result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t,"scope":"initial native prefix only; no owner workflow"},indent=2)+"\n")
raise SystemExit(r.returncode)
