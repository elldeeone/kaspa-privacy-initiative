"""Read this process's own Linux cgroup before the unit can be unloaded."""
from pathlib import Path


def capture():
    result={'schema':'kpx-owned-job-cgroup-resources/v1','units':'bytes except cpu.stat microseconds and event counts'}
    try:
        row=next(line for line in Path('/proc/self/cgroup').read_text().splitlines() if line.startswith('0::'))
        relative=row.split('::',1)[1]
        directory=Path('/sys/fs/cgroup')/relative.lstrip('/')
    except (OSError,StopIteration):
        result['available']=False
        return result
    result['available']=True
    for name in ('memory.peak','memory.current','memory.swap.peak','memory.swap.current','pids.current','pids.peak'):
        try:
            raw=(directory/name).read_text().strip();result[name]=int(raw) if raw.isdecimal() else raw
        except OSError:result[name]=None
    for name in ('cpu.stat','memory.events'):
        try:result[name]={key:int(value) for key,value in (line.split() for line in (directory/name).read_text().splitlines())}
        except (OSError,ValueError):result[name]=None
    return result
