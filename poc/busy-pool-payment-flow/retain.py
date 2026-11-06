#!/usr/bin/env python3
"""Finite public evidence selection. Runtime backups and parameters stay local."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
from analyse import SHARED, PRIORITY, REFERENCE

def sha(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()

def main():
    run, monitor, target = map(lambda s:Path(s).resolve(),sys.argv[1:4])
    assert not target.exists()
    for n in ['MAIN.json','REFERENCE.json']:
        assert json.loads((run/n).read_text())['nativeFull'] is True
    frozen=json.loads((monitor/'FREEZE.json').read_text())
    timing=run/'ARTIFACT-TIMES.json'
    if not timing.exists():
        timing.write_text(json.dumps({'scope':'original same-host filesystem times, not cryptographic timestamp attestation or chain confirmation',
            'staleWorkItemUnixNs':(run/'stale.input.bin').stat().st_mtime_ns,
            'referenceFirstWorkItemUnixNs':(run/'reference-payment-0.input.bin').stat().st_mtime_ns,
            'proofReportUnixNs':{n:(run/n/'proof-report.json').stat().st_mtime_ns for n in SHARED+PRIORITY+REFERENCE}},indent=2,sort_keys=True)+'\n')
    pairs=[]
    for name in ['MAIN.json','REFERENCE.json','APPROVALS.json','HOST-CONTROLS.json','PENDING-CONTROLS.json','STALE.json','COMMON.json','PRIORITY-WAIT.json','ARRIVALS.json','SERVICE.json','ARTIFACT-TIMES.json']:
        pairs.append((run/name,Path(name)))
    for directory in SHARED+PRIORITY+REFERENCE:
        for name in ['input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json']:
            pairs.append((run/directory/name,Path(directory)/name))
    for name in ['FREEZE.json','RESOURCES.json']:
        pairs.append((monitor/name,Path(name)))
    for name,digest in frozen['sourceSha256'].items():
        p=monitor/'source'/name
        assert sha(p)==digest, name
        pairs.append((p,Path('source')/name))
    # Excluded wallet material is read solely to scan the already finite public
    # selection; no secret value or backup path is printed or copied.
    secrets=[]
    for p in (run/'private').glob('wallet-*/backup.json'):
        b=json.loads(p.read_text())
        for raw in [b['wallet'],b['funding'],*b['payouts'].values()]:
            material=bytes(raw)
            secrets += [material,material.hex().encode(),json.dumps(raw,separators=(',',':')).encode()]
    assert secrets
    for src,dst in pairs:
        raw=src.read_bytes()
        compact=raw.replace(b' ',b'').replace(b'\n',b'')
        assert not any(s in raw or s in compact for s in secrets), str(dst)
    target.mkdir()
    for src,dst in pairs:
        dest=target/dst;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
    manifest={'schema':'busy-pool-public-evidence-v1','programImage':frozen['image'],
              'files':{str(dst):sha(target/dst) for _,dst in pairs},
              'excluded':['wallet backups','native private keys','proving parameters','SDK scratch/cache','compiled host executable'],
              'privateFilesRequiredToReplay':False}
    (target/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'publicFiles':len(pairs),'target':str(target),'secretMaterialScanPassed':True}))

if __name__=='__main__':main()
