#!/usr/bin/env python3
"""Check retained hashes and independently recompute service-only predictions."""
import hashlib
import json
from pathlib import Path
import sys
import analyze

packet=Path(sys.argv[1])
manifest=json.loads((packet/'MANIFEST.json').read_text())
actual={str(p.relative_to(packet)) for p in packet.rglob('*') if p.is_file()}-{'MANIFEST.json'}
assert actual==set(manifest['files'])
for name,v in manifest['files'].items():
    p=packet/name
    assert p.stat().st_size==v['bytes']
    assert hashlib.sha256(p.read_bytes()).hexdigest()==v['sha256'],name
for mode in ('direct','onion'):
    predicted=analyze.predict(analyze.logs(packet/'network'/mode/'operator.jsonl'))
    assert predicted==analyze.read(packet/'analysis'/(mode+'-prediction.json'))
seal=analyze.read(packet/'analysis/BASE-SEAL.json')
assert seal['privateTruthReadBeforeSeal'] is False
assert seal['observerSha256']==analyze.digest(Path(analyze.__file__))
for name,digest in seal['files'].items():assert analyze.digest(packet/'analysis'/name)==digest
print(json.dumps({'publicFilesVerified':len(actual),'serviceOnlyPredictionsRecomputed':2,'basePredictionSealVerified':True}))
