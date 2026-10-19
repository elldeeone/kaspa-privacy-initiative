#!/usr/bin/env python3
"""Mount only a confirmed chain transcript and observer software. No trial root."""
import argparse
import json
from pathlib import Path
import subprocess
p=argparse.ArgumentParser();p.add_argument('chain',type=Path);p.add_argument('output',type=Path);p.add_argument('--venv',type=Path,default=Path('/home/luke/.local/share/kpi-shared-pool-tools'));p.add_argument('--amounts',action='store_true');a=p.parse_args()
a.output.mkdir(mode=0o700,exist_ok=False)
base=['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--ro-bind',str(a.venv.resolve()),'/venv','--ro-bind',str(Path(__file__).with_name('observe.py').resolve()),'/observe.py','--ro-bind',str(a.chain.resolve()),'/chain.json','--bind',str(a.output.resolve()),'/result','--chdir','/result']
if a.amounts:base+=['--ro-bind',str(Path(__file__).with_name('amounts.py').resolve()),'/amounts.py']
audit="import pathlib,json; assert not pathlib.Path('/home/luke').exists(); print(json.dumps({'hostHomeAccessible':False,'inputFiles':['/chain.json'],'privateTruthMounted':False,'network':pathlib.Path('/proc/net/dev').read_text(),'mounts':pathlib.Path('/proc/mounts').read_text()}))"
r=subprocess.run(base+['--','/venv/bin/python','-c',audit],check=True,capture_output=True)
(a.output/'namespace.json').write_bytes(r.stdout)
with (a.output/'stdout.json').open('x') as out,(a.output/'stderr.log').open('x') as err:
    subprocess.run(['/usr/bin/time','-v','-o',str(a.output/'resources.txt')]+base+['--','/venv/bin/python','/amounts.py' if a.amounts else '/observe.py','/chain.json','/result/amounts.json' if a.amounts else '/result/observer.json'],stdout=out,stderr=err,check=True)
print((a.output/'stdout.json').read_text())
