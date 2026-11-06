#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys
import privacy

packet=Path(sys.argv[1]);manifest=json.loads((packet/'MANIFEST.json').read_text())
actual={str(p.relative_to(packet)) for p in packet.rglob('*') if p.is_file()}-{'MANIFEST.json'}
assert actual==set(manifest['files'])
for name,v in manifest['files'].items():
    p=packet/name;assert p.stat().st_size==v['bytes']
    assert hashlib.sha256(p.read_bytes()).hexdigest()==v['sha256'],name
freeze=json.loads((packet/'monitor/FREEZE.json').read_text())
assert hashlib.sha256((packet/'program.bin').read_bytes()).hexdigest()==freeze['programSha256']
for name,digest in freeze['sourceSha256'].items():
    p=packet/'monitor/source'/name
    if p.suffix=='.md':p=p.with_suffix('.md.txt')
    assert hashlib.sha256(p.read_bytes()).hexdigest()==digest,name
view=json.loads((packet/'analysis/ownership/main-observation.json').read_text())
assert privacy.predict(view)==json.loads((packet/'analysis/ownership/main-prediction.json').read_text())
seal=json.loads((packet/'analysis/ownership/BASE-SEAL.json').read_text())
assert seal['privateTruthReadBeforeSeal'] is False and seal['observerSha256']==privacy.sha(Path(privacy.__file__))
for name,digest in seal['files'].items():assert privacy.sha(packet/'analysis/ownership'/name)==digest
print(json.dumps({'publicFilesVerified':len(actual),'sourceEpochAndObserverSealVerified':True}))
