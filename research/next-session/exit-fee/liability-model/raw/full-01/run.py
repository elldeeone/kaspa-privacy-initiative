import pathlib,json,subprocess,time
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/exit-model-runtime/full-01')
t=time.monotonic();results=[]
for name,command in json.loads((p/"commands.json").read_text()):
 print(json.dumps({"phase":name,"started":True}),flush=True)
 q=time.monotonic();r=subprocess.run(command)
 results.append({"phase":name,"exit_code":r.returncode,"wall_seconds":time.monotonic()-q})
 (p/"orchestration-progress.json").write_text(json.dumps(results,indent=2)+"\n")
 if r.returncode:break
(p/"process-result.json").write_text(json.dumps({"phases":results,"wall_seconds":time.monotonic()-t},indent=2)+"\n")
raise SystemExit(results[-1]["exit_code"])
