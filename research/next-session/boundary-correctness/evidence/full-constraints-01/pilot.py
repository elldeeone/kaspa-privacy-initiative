import pathlib,json,subprocess,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/boundary-runtime/full-constraints-01');prefix=json.loads((p/"command-prefix.json").read_text());case=p/"baseline-two-real";case.mkdir()
t=time.monotonic()
with (case/"stdout.jsonl").open("x") as out,(case/"stderr.log").open("x") as err:
 r=subprocess.run(["/usr/bin/time","-v","-o",str(case/"resources.txt"),*prefix,"check","baseline-two-real"],stdout=out,stderr=err)
report={"case":"baseline-two-real","exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t}
(p/"pilot-result.json").write_text(json.dumps(report,indent=2)+"\n")
raise SystemExit(r.returncode)
