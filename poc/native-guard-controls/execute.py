"""Enforce finite own-unit execution. No cgroup/global-controller mutation."""
import json, os, subprocess, sys, time, tomllib
from pathlib import Path
lane=Path(sys.argv[1]).resolve(); phase=sys.argv[2]
pkg=lane/"worktree/poc/native-guard-controls"; output=lane/"outputs"
assert phase in ("baseline","controls")
path=Path("/sys/fs/cgroup")/Path("/proc/self/cgroup").read_text().strip().split("::",1)[1].lstrip("/")
def read(name): return (path/name).read_text().strip()
limits={x:read(x) for x in ("memory.max","memory.swap.max","cpu.max","pids.max")}
assert limits["memory.max"]==str(512*1024**2) and limits["memory.swap.max"]=="0"
q,p=map(int,limits["cpu.max"].split()); assert q/p==4
assert os.sched_getaffinity(0)=={8,9,10,11} and limits["pids.max"]=="64"
with (output/(phase+"-unit.json")).open("x") as f: json.dump(dict(cgroup=str(path),limits=limits,affinity=sorted(os.sched_getaffinity(0)),started_epoch=time.time()),f,indent=2)
if phase=="baseline":
    with (output/"deadline.json").open("x") as f: json.dump({"epoch_seconds":time.time()+1200},f)
    env=os.environ.copy(); env["CARGO_TARGET_DIR"]=str(lane/"adapter-target"); env["CARGO_BUILD_JOBS"]="1"
    command=[str(Path.home()/".cargo/bin/cargo"),"+1.95.0"]
    subprocess.run(command+["generate-lockfile","--offline","--manifest-path",str(pkg/"Cargo.toml")],check=True,env=env,timeout=60)
    original=tomllib.loads((lane/"worktree/poc/shared-pool/Cargo.lock").read_text())
    child=tomllib.loads((pkg/"Cargo.lock").read_text())
    identities={(p["name"],p["version"],p.get("checksum")) for p in original["package"]}
    assert all((p["name"],p["version"],p.get("checksum")) in identities for p in child["package"] if p["name"]!="kpi-native-guard-id"), "adapter dependency drift from pinned root lock"
    subprocess.run(command+["build","--release","--locked","--offline","--jobs","1","--manifest-path",str(pkg/"Cargo.toml")],check=True,env=env,timeout=300)
subprocess.run(["/usr/bin/python3","-I","-B",str(pkg/"controls.py"),str(lane),phase],check=True,timeout=600)
with (output/(phase+"-cgroup-final.json")).open("x") as f:
    json.dump({x:read(x) for x in ("memory.peak","memory.events","memory.swap.current","cpu.stat","pids.current")},f,indent=2)
