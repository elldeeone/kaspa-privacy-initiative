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
    for name in ['MAIN.json','REFERENCE.json','APPROVALS.json','HOST-CONTROLS.json','PENDING-CONTROLS.json','STALE.json','COMMON.json','PRIORITY-WAIT.json','ARRIVALS.json','SERVICE.json','OBSERVER-VIEWS.json','ACCOUNTING.json','MEASUREMENTS.json','ARTIFACT-TIMES.json']:
        pairs.append((run/name,Path(name)))
    for directory in SHARED+PRIORITY+REFERENCE:
        for name in ['input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json']:
            pairs.append((run/directory/name,Path(directory)/name))
    for name in ['FREEZE.json','RESOURCES.json']:
        pairs.append((monitor/name,Path(name)))
    for name,digest in frozen['sourceSha256'].items():
        p=monitor/'source'/name
        assert sha(p)==digest, name
        # Keep frozen document bytes without turning their old relative links
        # into live documentation links inside a relocated source snapshot.
        snapshot_name=name+'.txt' if name.endswith('.md') else name
        pairs.append((p,Path('source')/snapshot_name))
    if len(sys.argv)>4:
        cancelled=Path(sys.argv[4]).resolve()
        assert json.loads((cancelled/'RESULT.json').read_text())['replay']['unchangedNativeAncestorIdsAndPayoutSpends'] is True
        for name in ['RESULT.json','FREEZE.json','SAMPLES.jsonl','old-input.bin','fresh-input.bin']:
            pairs.append((cancelled/name,Path('cancellation')/name))
        for name in ['input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json']:
            pairs.append((cancelled/'refreshed'/name,Path('cancellation/refreshed')/name))
        for name,digest in json.loads((cancelled/'FREEZE.json').read_text())['sourceSha256'].items():
            assert sha(cancelled/'source'/name)==digest
            pairs.append((cancelled/'source'/name,Path('cancellation/source')/name))
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
