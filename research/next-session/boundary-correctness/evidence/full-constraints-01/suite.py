import pathlib,json,subprocess,time,hashlib
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/boundary-runtime/full-constraints-01');prefix=json.loads((p/"command-prefix.json").read_text());manifest=json.loads((p/"case-manifest.json").read_text())
assert hashlib.sha256((p/"case-manifest.json").read_bytes()).hexdigest()=="8111d4f26d92343496d0fb066e2ae04403d06034a634ceee89626d39da224c61"
start=time.monotonic();outcomes=[]
first=json.loads((p/"baseline-two-real/stdout.jsonl").read_text());outcomes.append({"case":"baseline-two-real","pilot_reused_without_reexecution":True,"result":first,"exit_code":0,"passed":True})
for entry in manifest["cases"]:
 name=entry["id"]
 if name=="baseline-two-real":continue
 case=p/name;case.mkdir();t=time.monotonic()
 with (case/"stdout.jsonl").open("x") as out,(case/"stderr.log").open("x") as err:
  child=subprocess.run(["/usr/bin/time","-v","-o",str(case/"resources.txt"),*prefix,"check",name],stdout=out,stderr=err)
 result=None;parse_error=None
 try:result=json.loads((case/"stdout.jsonl").read_text())
 except Exception as e:parse_error=str(e)
 passed=child.returncode==0 and result is not None and result.get("passed") is True and result.get("expected")==entry["expected"] and result.get("actual")==entry["expected"]
 outcome={"case":name,"expected":entry["expected"],"result":result,"exit_code":child.returncode,"elapsed_seconds":time.monotonic()-t,"passed":passed,"parse_error":parse_error}
 (case/"outcome.json").write_text(json.dumps(outcome,indent=2)+"\n");outcomes.append(outcome)
 (p/"progress.json").write_text(json.dumps({"completed":len(outcomes),"total":len(manifest["cases"]),"last_case":name,"failures":[x["case"] for x in outcomes if not x["passed"]],"elapsed_seconds":time.monotonic()-start},indent=2)+"\n")
 print(json.dumps({"completed":len(outcomes),"case":name,"passed":passed,"exit_code":child.returncode,"seconds":outcome["elapsed_seconds"]}),flush=True)
summary={"case_manifest_sha256":hashlib.sha256((p/"case-manifest.json").read_bytes()).hexdigest(),"cases":outcomes,"total":len(outcomes),"passed":sum(x["passed"] for x in outcomes),"failed":sum(not x["passed"] for x in outcomes),"elapsed_seconds_excluding_pilot":time.monotonic()-start,"full_constraint_cases":sum(x["result"] is not None and x["result"].get("constraints")==4372824 for x in outcomes),"setup_or_proof_performed":False}
(p/"suite-result.json").write_text(json.dumps(summary,indent=2)+"\n")
raise SystemExit(0 if summary["failed"]==0 else 1)
