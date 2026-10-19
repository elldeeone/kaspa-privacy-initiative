#!/usr/bin/env python3
"""Run an exit with only one user's key, public state/parameters and the binary.

No source checkout, other wallet, network, or operator process is exposed.
Output is public transaction/proof evidence; secret key bytes are never logged.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time

parser=argparse.ArgumentParser()
parser.add_argument('binary',type=Path)
parser.add_argument('public',type=Path)
parser.add_argument('wallet',type=Path)
parser.add_argument('prior')
parser.add_argument('label')
parser.add_argument('output',type=Path)
args=parser.parse_args()
args.output.mkdir(mode=0o700,exist_ok=False)
base=['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
      '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
      '--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
      '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
      '--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4',
      '--dir','/software','--ro-bind',str(args.binary.resolve()),'/software/kpi-self-funded',
      '--ro-bind',str(args.public.resolve()),'/public',
      '--ro-bind',str(args.wallet.resolve()),'/wallet.json',
      '--bind',str(args.output.resolve()),'/output','--chdir','/output']
audit='''import json,pathlib
assert not pathlib.Path('/home/luke').exists()
print(json.dumps({'hostHomeAccessible':False,'networkDevices':pathlib.Path('/proc/net/dev').read_text(),
'mounts':pathlib.Path('/proc/mounts').read_text(),'processes':[p.name for p in pathlib.Path('/proc').iterdir() if p.name.isdigit()]}))
'''
checked=subprocess.run(base+['--','python3','-c',audit],capture_output=True,check=True)
(args.output/'namespace.json').write_bytes(checked.stdout)
started=time.monotonic()
command=base+['--','/software/kpi-self-funded','exit','/public','/wallet.json',args.prior,args.label,'/output']
with (args.output/'stdout.json').open('xb') as out,(args.output/'stderr.log').open('xb') as err:
    result=subprocess.run(command,stdout=out,stderr=err)
report={'label':args.label,'exitCode':result.returncode,'seconds':time.monotonic()-started,
        'publicDirectory':str(args.public.resolve()),'privateInputCount':1,'otherWalletsMounted':False,
        'networkUnshared':True,'pidNamespaceUnshared':True,'sourceCheckoutMounted':False}
(args.output/'isolation.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
raise SystemExit(result.returncode)
