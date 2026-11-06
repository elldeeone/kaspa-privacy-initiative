#!/usr/bin/env python3
"""Authenticate the finite retained packet and the executed source epoch."""
import hashlib
import json
from pathlib import Path
import sys

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

root=Path(__file__).resolve().parents[2]
run=Path(sys.argv[1]).resolve()
manifest=json.loads((run/'MANIFEST.json').read_text())
for name,digest in manifest['files'].items():
    p=Path(name)
    assert not p.is_absolute() and '..' not in p.parts
    assert sha(run/p)==digest, name
frozen=json.loads((run/'FREEZE.json').read_text())
assert sha(root/'research/reusable-withdrawal-approvals-2026-11-06/run/program.bin')==frozen['programSha256']
for name,digest in frozen['sourceSha256'].items():
    assert sha(run/'source'/name)==digest
    # Research conclusions may be appended after the executed source freeze;
    # executable source, parameter pins and dependency locks must remain exact.
    if Path(name).suffix in {'.rs','.toml','.lock','.py','.bin'}:
        assert sha(root/name)==digest, 'executed source differs: '+name
print(json.dumps({'publicPacketHashes':True,'executedSourceEpoch':True,'privateMaterialRead':False}))
