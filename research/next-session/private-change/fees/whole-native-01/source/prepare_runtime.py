"""Create an exact public runtime plan; this command launches no native job."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

root=Path(__file__).resolve().parents[2]
out=Path(sys.argv[1]).resolve()
out.mkdir();(out/'client-output').mkdir()
source=out/'source';shutil.copytree(Path(__file__).resolve().parent,source,
    ignore=shutil.ignore_patterns('__pycache__','target'))
keys=root/'research/next-session/private-change/fees/whole-source-controls-01/public-placeholder-keys.json'
shutil.copyfile(keys,out/'public-placeholder-keys.json')
emitter=Path('/home/luke/.local/share/kpi-compact-private-policy/whole-emitter-01/emitter')
node=Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
native=node.parent/'kpi-private-exit-native'
sdk=Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
def pin(path):
    raw=path.read_bytes();return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
pins=[pin(p) for p in sorted(source.rglob('*')) if p.is_file()]
pins += [pin(p) for p in (out/'public-placeholder-keys.json',emitter,node,native,
    sdk/'kaspa.js',sdk/'kaspa_bg.wasm',sdk/'package.json',
    root/'docs/adr/0056-compact-native-batch-fee-screen.md',
    root/'research/next-session/private-change/fees/WHOLE-EMITTER-SPEC-01.md',
    root/'research/next-session/private-change/fees/whole-source-controls-01/CONFORMANCE.json')]
cmd=['/usr/bin/time','-v','-o',str(out/'client-output/resources.log'),'/usr/bin/bwrap',
    '--unshare-all','--die-with-parent','--new-session','--clearenv',
    '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib',
    '--symlink','usr/lib64','/lib64','--ro-bind','/etc/alternatives','/etc/alternatives',
    '--ro-bind','/etc/passwd','/etc/passwd','--ro-bind','/etc/group','/etc/group',
    '--ro-bind','/etc/ld.so.cache','/etc/ld.so.cache','--proc','/proc','--dev','/dev','--tmpfs','/tmp',
    '--ro-bind',str(source),'/app/source','--ro-bind',str(emitter),'/app/emitter',
    '--ro-bind',str(node),'/app/node','--ro-bind',str(native),'/app/native',
    '--ro-bind',str(out/'public-placeholder-keys.json'),'/app/keys.json',
    '--ro-bind',str(sdk),str(sdk),'--bind',str(out/'client-output'),'/out',
    '--setenv','PATH','/usr/bin:/bin','--setenv','LANG','C.UTF-8','--setenv','TZ','UTC',
    '--setenv','HOME','/home/luke','--setenv','PYTHONDONTWRITEBYTECODE','1',
    '--chdir','/app/source','/usr/bin/python3','-B','/app/source/harness.py','/out/result',
    '--emitter','/app/emitter','--emitter-sha',pin(emitter)['sha256'],
    '--node','/app/node','--native','/app/native','--public-keys','/app/keys.json']
plan={'schema':'compact-whole-native-public-runtime/v1','command':cmd,'pins':pins,
    'controller_output':str(out),'requested_limits':{'CPUQuota':'400%','MemoryMax':'4G','MemorySwapMax':'0'},
    'native_cases':54,'financial_acceptances_expected':0,'root_authority':'ADR0056',
    'ordinary_readonly_host_release_immutability_premise':True,'native_data':'PUBLIC_SYNTHETIC_ZERO_PROOFS_ONLY'}
with (out/'RUNTIME-FREEZE.json').open('x') as file:json.dump(plan,file,sort_keys=True,indent=2);file.write('\n')
print(hashlib.sha256((out/'RUNTIME-FREEZE.json').read_bytes()).hexdigest())
