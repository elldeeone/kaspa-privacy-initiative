import pathlib,subprocess,json,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/boundary-runtime/s7-tests-01');t=time.monotonic();r=subprocess.run(json.loads((p/"command.json").read_text()))
(p/"result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t,"public_fixtures_only":True,"proof_generation":False},indent=2)+"\n")
raise SystemExit(r.returncode)
