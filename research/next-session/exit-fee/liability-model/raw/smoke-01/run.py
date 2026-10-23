import pathlib,json,subprocess,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/exit-model-runtime/smoke-01')
t=time.monotonic()
r=subprocess.run(json.loads((p/"command.json").read_text()))
(p/"process-result.json").write_text(json.dumps({"exit_code":r.returncode,"wall_seconds":time.monotonic()-t},indent=2)+"\n")
raise SystemExit(r.returncode)
