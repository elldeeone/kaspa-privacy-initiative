#!/usr/bin/env python3
"""Finite public-evidence allowlist. Never recursively copy a runtime."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT=Path(__file__).resolve().parents[2]
DEST=ROOT/'research/withdrawal-request-and-busy-pool-2026-11-06/run'
busy,network,unequal,analysis,quiet=map(Path,sys.argv[1:6])
DEST.mkdir()
def take(src,dest):
    assert src.is_file(),src
    assert not any(part=='private' for part in src.parts)
    assert src.suffix not in ('.der','.key','.pem','.wallet')
    target=DEST/dest;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(src,target)
def item(root,name,prefix):take(root/name,Path(prefix)/name)
proof_files=('input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json')
item(busy,'RESULT.json','busy');item(busy,'stale-prepared.json','busy')
for case in ('dynamic-control','pinned-initial','unrelated-payment','fresh-joint','restored-solo','restored-solo-last'):
    for name in proof_files:item(busy,f'{case}/{name}','busy')
item(quiet,'RESULT.json','quiet')
for name in proof_files:item(quiet,f'quiet-terminal/{name}','quiet')
for root,prefix in ((busy,'busy-monitor'),(quiet,'quiet-monitor')):
    monitor=root.with_name(root.name+'-monitor')
    for name in ('FREEZE.json','INVOCATION.json','RESOURCES.json','stderr.log','stdout.log'):
        item(monitor,name,prefix)
    # Preserve the actual code epoch used for each measured binary.
    for p in sorted((monitor/'source').rglob('*')):
        if p.is_file():
            dest=Path(prefix)/p.relative_to(monitor)
            if dest.suffix=='.md':dest=dest.with_suffix('.md.txt')
            take(p,dest)
take(busy.with_name(busy.name+'-monitor')/'guest.program.bin','pinned.program.bin')
take(ROOT/'research/batched-payment-costs-2026-11-06/run/program.bin','dynamic.program.bin')
for name in ('SELECTION.json','ONION.json','COMPLETE.json','service-tor.log','client-tor.log'):
    item(network,name,'network')
take(network/'fixture/config.json','network/config.json')
for mode in ('direct','onion'):
    for name in ('operator.jsonl','CONTROLS.json','VERIFIED.json'):
        item(network,f'{mode}/{name}','network')
for name in ('public.json','VERIFIED.json'):item(unequal,name,'unequal')
for p in sorted(analysis.iterdir()):
    if p.is_file():take(p,Path('analysis')/p.name)
# Optional additional public verification controls from the final validation pass.
for name in ('PINNED-NEGATIVES.json','PUBLIC-REPLAY.json','SPENT-ELIGIBILITY.json'):
    p=ROOT/'.local/withdrawal-followup'/name
    if p.exists():take(p,name)
failed=ROOT/'.local/withdrawal-followup/network-089c2aa1-96f6-496d-9205-c6d4098befc0'
for name in ('SELECTION.json','FAILURE.json'):
    item(failed,name,'failed-network-attempt')
files={str(p.relative_to(DEST)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(DEST.rglob('*')) if p.is_file()}
(DEST/'MANIFEST.json').write_text(json.dumps({'schema':'public-withdrawal-followup-v1','files':files,'excluded':'all wallet/native secrets, issuer secret, client blinding state, private truth, proving parameters, Tor data directories and runtime scratch; raw resource samples retained locally','scope':'separate counterfactual views share research fixtures; combining published direct keys removes candidate anonymity'},sort_keys=True,indent=2)+'\n')
print(json.dumps({'files':len(files),'bytes':sum(v['bytes'] for v in files.values()),'manifestSha256':hashlib.sha256((DEST/'MANIFEST.json').read_bytes()).hexdigest()}))
