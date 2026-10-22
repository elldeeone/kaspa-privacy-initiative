import pathlib,subprocess,json,time,hashlib
ev=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/finalize-initial-source-build-20261022T1430')
t=time.monotonic()
r=subprocess.run(["/bin/bash",str(ev/"build-warm.sh"),"kpi_s7_lifecycle_fixture"])
(ev/"result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t},indent=2)+"\n")
if r.returncode==0:
 b=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle-producer-target/x86_64-unknown-linux-gnu/release/kpi_s7_lifecycle_fixture')
 data=b.read_bytes()
 with (ev/"selected-finalizer").open("xb") as f:f.write(data);f.flush();__import__("os").fsync(f.fileno())
 (ev/"selected-finalizer").chmod(0o555)
 (ev/"binary-identity.json").write_text(json.dumps({"original_path":str(b),"selected_path":str(ev/"selected-finalizer"),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()},indent=2)+"\n")
raise SystemExit(r.returncode)
