import subprocess,time,json,pathlib
p=pathlib.Path('/home/luke/projects/kpi-intensive-2026-10-22/integration/poc/two-v6-state/common/evidence/host-checks')
t=time.monotonic()
r=subprocess.run(['/home/luke/.rustup/toolchains/1.97.1-x86_64-unknown-linux-gnu/bin/cargo', 'test', '--locked', '--offline', '--manifest-path', '/home/luke/projects/kpi-intensive-2026-10-22/integration/poc/two-v6-state/common/Cargo.toml', '--target', 'x86_64-unknown-linux-gnu', '--release', '-j2', '--', '--test-threads=1'])
(p/"run-result.json").write_text(json.dumps({"exit_code":r.returncode,"elapsed_seconds":time.monotonic()-t},indent=2)+"\n")
raise SystemExit(r.returncode)
