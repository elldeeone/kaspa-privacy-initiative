import pathlib,subprocess,json,time,hashlib
ev=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/producer-source-build-warm-20261022T1419')
t=time.monotonic()
r=subprocess.run(["/bin/bash",'/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/producer-source-build-warm-20261022T1419/build-warm.sh',"kpi_s7_lifecycle_fixture"])
assert r.returncode==0,"source build failed"
b=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle-producer-target/x86_64-unknown-linux-gnu/release/kpi_s7_lifecycle_fixture')
(ev/"binary-identity.json").write_text(json.dumps({"path":str(b),"sha256":hashlib.sha256(b.read_bytes()).hexdigest(),"bytes":b.stat().st_size},indent=2)+"\n")
r=subprocess.run(['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--ro-bind', '/home/luke/projects/kpi-intensive-2026-10-22/lifecycle-producer-target/x86_64-unknown-linux-gnu/release/kpi_s7_lifecycle_fixture', '/producer', '--bind', '/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts', '/outputs', '--chdir', '/tmp', '/producer', 'prepare', '/outputs/initial-four-public-fixture-20261022T1415'])
(ev/"result.json").write_text(json.dumps({"prepare_exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t,"output":'/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/initial-four-public-fixture-20261022T1415'},indent=2)+"\n")
raise SystemExit(r.returncode)
