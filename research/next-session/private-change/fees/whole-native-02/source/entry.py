"""Public resource receipt then the one reviewed network-off native screen."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

plan=json.loads(Path(sys.argv[1]).read_bytes())
for row in plan['pins']:
    raw=Path(row['path']).read_bytes()
    if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:
        raise ValueError('public-runtime-input-pin')
output=Path(plan['controller_output'])
caps={'requested':plan['requested_limits'],'observed':None}
try:
    membership=next(row[3:] for row in Path('/proc/self/cgroup').read_text().splitlines() if row.startswith('0::'))
    group=Path('/sys/fs/cgroup')/membership.lstrip('/')
    caps['observed']={name:(group/name).read_text().strip() for name in ('cpu.max','memory.max','memory.swap.max')}
except (OSError,StopIteration) as error:caps['observation_error']=type(error).__name__
with (output/'ACTIVE-CAPS.json').open('x') as file:json.dump(caps,file,sort_keys=True,indent=2);file.write('\n')
started=time.monotonic()
completed=subprocess.run(plan['command'],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC'},capture_output=True,text=True)
(output/'stdout.log').write_text(completed.stdout);(output/'stderr.log').write_text(completed.stderr)
with (output/'EXECUTION.json').open('x') as file:
    json.dump({'returncode':completed.returncode,'wall_seconds':time.monotonic()-started,
        'network_off':True,'ordinary_readonly_executables':True,
        'setup_PK_seed_keys_funding_RPC':0,'native_G16_uses_invalid_zeroProof128_only':True},file,sort_keys=True,indent=2);file.write('\n')
raise SystemExit(completed.returncode)
