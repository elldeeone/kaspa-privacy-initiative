"""Non-blocking live resource observation in the launched unit, before bwrap."""
from pathlib import Path
import json
import os
import sys

result = {'telemetry_only': True, 'pid': os.getpid(), 'observation_stage': 'before_bwrap'}
try:
    membership = Path('/proc/self/cgroup').read_text().splitlines()
    relative = next(row[3:] for row in membership if row.startswith('0::'))
    cgroup = Path('/sys/fs/cgroup') / relative.lstrip('/')
    result['cgroup_path'] = relative
    result['observed'] = {name: (cgroup / name).read_text().strip() for name in
                          ('cpu.max', 'memory.max', 'memory.swap.max', 'pids.current')}
except Exception as error:
    result['observation_error_type'] = type(error).__name__
Path(sys.argv[1], 'active-cgroup.json').write_text(json.dumps(result, indent=2) + '\n')
