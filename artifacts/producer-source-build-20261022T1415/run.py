import pathlib,subprocess,json,time,hashlib
ev=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/producer-source-build-20261022T1415')
t=time.monotonic()
r=subprocess.run(['/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo', 'build', '--frozen', '--offline', '--release', '--target', 'x86_64-unknown-linux-gnu', '--manifest-path', '/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/poc/shared-pool/Cargo.toml', '--bin', 'kpi_s7_lifecycle_fixture', '-j2'])
assert r.returncode==0,"source build failed"
b=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/lifecycle-producer-target/x86_64-unknown-linux-gnu/release/kpi_s7_lifecycle_fixture')
(ev/"binary-identity.json").write_text(json.dumps({"path":str(b),"sha256":hashlib.sha256(b.read_bytes()).hexdigest(),"bytes":b.stat().st_size},indent=2)+"\n")
r=subprocess.run([str(b),"prepare",'/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/initial-four-public-fixture-20261022T1415'])
(ev/"result.json").write_text(json.dumps({"prepare_exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t,"output":'/home/luke/projects/kpi-intensive-2026-10-22/lifecycle/artifacts/initial-four-public-fixture-20261022T1415'},indent=2)+"\n")
raise SystemExit(r.returncode)
