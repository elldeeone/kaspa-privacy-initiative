from pathlib import Path
import json,subprocess,time
base=Path(__file__).parent
cg=next(x[3:]for x in Path('/proc/self/cgroup').read_text().splitlines()if x.startswith('0::'))
control=Path('/sys/fs/cgroup')/cg.lstrip('/')
caps={x:(control/x).read_text().strip()for x in ['cpu.max','memory.max','memory.swap.max']}
(base/'ACTIVE-CAPS.json').write_text(json.dumps(caps,sort_keys=True)+'\n')
command=json.loads((base/'COMMAND.json').read_bytes())
start=time.monotonic()
r=subprocess.run(['/usr/bin/time','-v','-o',str(base/'resources.txt'),*command],capture_output=True,text=True)
(base/'stdout.log').write_text(r.stdout);(base/'stderr.log').write_text(r.stderr)
(base/'EXECUTION.json').write_text(json.dumps({'returncode':r.returncode,'wall_seconds':time.monotonic()-start},sort_keys=True)+'\n')
raise SystemExit(r.returncode)
