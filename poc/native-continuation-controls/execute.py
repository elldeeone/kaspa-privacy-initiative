"""Enforce own low-priority cgroup and one absolute 20-minute attempt budget."""
import json,os,subprocess,sys,time
from pathlib import Path
lane=Path(sys.argv[1]).resolve(); phase=sys.argv[2]
assert phase in ("baselines","controls")
output=lane/"outputs"; pkg=lane/"worktree/poc/native-continuation-controls"
cg=Path("/sys/fs/cgroup")/Path("/proc/self/cgroup").read_text().strip().split("::",1)[1].lstrip("/")
def read(n):return(cg/n).read_text().strip()
limits={n:read(n) for n in ("cpu.max","cpu.weight","memory.max","memory.swap.max","pids.max")}
assert limits=={"cpu.max":"100000 100000","cpu.weight":"10","memory.max":"536870912","memory.swap.max":"0","pids.max":"64"},limits
assert os.sched_getaffinity(0)=={13} and os.getpriority(os.PRIO_PROCESS,0)==10
with(output/(phase+"-unit.json")).open("x") as f:json.dump(dict(cgroup=str(cg),limits=limits,affinity=[13],nice=10,started_epoch=time.time()),f,indent=2)
if phase=="baselines":
    with(output/"deadline.json").open("x") as f:json.dump({"epoch_seconds":time.time()+1200},f)
subprocess.run(["/usr/bin/python3","-I","-B",str(pkg/"controls.py"),str(lane),phase],check=True,timeout=600)
with(output/(phase+"-cgroup-final.json")).open("x") as f:json.dump({n:read(n) for n in ("memory.peak","memory.events","memory.swap.current","cpu.stat","pids.current")},f,indent=2)
