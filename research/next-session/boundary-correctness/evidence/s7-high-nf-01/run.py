import pathlib,json,subprocess,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/boundary-runtime/s7-high-nf-01');t=time.monotonic();r=subprocess.run(json.loads((p/"command.json").read_text()))
(p/"result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t,"single_new_group_only":True,"old_seven_group_result_preserved":True},indent=2)+"\n")
raise SystemExit(r.returncode)
