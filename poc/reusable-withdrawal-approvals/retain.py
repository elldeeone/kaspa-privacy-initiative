#!/usr/bin/env python3
"""Explicit public-evidence selection; private runtimes are never copied whole."""
import hashlib
import json
from pathlib import Path
import shutil
import sys

ROOT=Path(__file__).resolve().parents[2]
run,analysis,replay=map(Path,sys.argv[1:4])
dest=ROOT/'research/reusable-withdrawal-approvals-2026-11-06/run';dest.mkdir()
def take(src,name):
    assert src.is_file() and not src.is_symlink(),src
    assert not any(p=='private' for p in src.parts),src
    assert src.suffix not in {'.der','.pem','.key','.wallet','.pyc'},src
    p=dest/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,p)
for name in ('RESULT.json','APPROVALS.json','HOST-CONTROLS.json','before-activity.json','continuing-world.json','spent-world.json'):
    take(run/name,Path('campaign')/name)
cases=('initial','unrelated-payment','continuing-intent','spent-note-control','alice-solo-first','alice-solo-last','terminal-intent')
for case in cases:
    for name in ('input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json'):
        take(run/case/name,Path('campaign')/case/name)
    take(run/(case+'.native.json'),Path('campaign')/(case+'.native.json'))
monitor=run.with_name(run.name+'-monitor')
for name in ('FREEZE.json','INVOCATION.json','RESOURCES.json','stderr.log','stdout.log'):
    take(monitor/name,Path('monitor')/name)
take(monitor/'guest.program.bin',Path('program.bin'))
for p in sorted((monitor/'source').rglob('*')):
    if p.is_file():
        name=Path('monitor')/p.relative_to(monitor)
        if name.suffix=='.md':name=name.with_suffix('.md.txt')
        take(p,name)
for base,name in ((analysis,'analysis'),(replay,'replay')):
    for p in sorted(base.rglob('*')):
        if p.is_file():take(p,Path(name)/p.relative_to(base))
files={str(p.relative_to(dest)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(dest.rglob('*')) if p.is_file()}
(dest/'MANIFEST.json').write_text(json.dumps({'schema':'reusable-withdrawal-approval-public-v1','files':files,'excluded':'all wallet/native secrets, private proving parameters, runtime scratch and raw resource samples retained locally','scope':'supplied funding UTXO and separate counterfactual histories; no live-chain or anonymous-independent-user claim'},sort_keys=True,indent=2)+'\n')
print(json.dumps({'files':len(files),'bytes':sum(v['bytes'] for v in files.values()),'manifestSha256':hashlib.sha256((dest/'MANIFEST.json').read_bytes()).hexdigest()}))
