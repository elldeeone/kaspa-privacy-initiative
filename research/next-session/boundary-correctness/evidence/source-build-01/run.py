import pathlib,subprocess,time,json,hashlib,os
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/boundary-runtime/source-build-01');t=time.monotonic()
r=subprocess.run(["/bin/bash",str(p/"build-warm.sh"),"kpi_v6_boundary_check"])
(p/"result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t},indent=2)+"\n")
if r.returncode==0:
 b=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/v6-boundary-target/x86_64-unknown-linux-gnu/release/kpi_v6_boundary_check');v=b.read_bytes()
 with (p/"selected-checker").open("xb") as f:f.write(v);f.flush();os.fsync(f.fileno())
 (p/"selected-checker").chmod(0o555)
 (p/"binary-identity.json").write_text(json.dumps({"source_path":str(b),"selected_path":str(p/"selected-checker"),"bytes":len(v),"sha256":hashlib.sha256(v).hexdigest()},indent=2)+"\n")
raise SystemExit(r.returncode)
