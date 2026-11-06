#!/usr/bin/env python3
"""Exact legacy reuse plus explicit fixed-intent authorization hooks."""
import hashlib
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
source=ROOT/'poc/withdrawal-followup/common/src/lib.rs'
text=source.read_text()
changes=[
('use serde::{Deserialize, Serialize};','use serde::{Deserialize, Serialize};\nmod intent;\npub use intent::WithdrawalIntent;'),
('    pub operations: Vec<Operation>,\n}', '    pub operations: Vec<Operation>,\n    pub intent: Option<WithdrawalIntent>,\n}'),
('    let context = e.context(before.root());','''    let context = e.context(before.root());
    let approval_context = if let Some(intent) = &packet.intent {
        ensure(packet.mode == JOINT, "intent requires joint mode")?;
        intent.validate(before, &packet.operations)?;
        ensure(fee <= intent.fee_cap, "intent fee cap")?;
        intent.commitment()
    } else { context };'''),
('s.exit_destination == context,','s.exit_destination == approval_context,'),
('    for (i, op) in packet.operations.iter().enumerate().filter(|_| withdrawing) {','''    if let Some(intent) = &packet.intent {
        intent.check_actual_payouts(&e.outputs[offset..offset + payouts])?;
    }
    for (i, op) in packet.operations.iter().enumerate().filter(|_| withdrawing) {'''),
]
for old,new in changes:
    assert text.count(old)==1,old
    text=text.replace(old,new)
legacy=ROOT/'poc/batched-payment-costs/host/src/bench.rs'
bench=legacy.read_text();assert bench.count('app::Packet {')==2
bench=bench.replace('app::Packet {','app::Packet {\n        intent: None,')
files={'common/src/lib.rs':text,'host/src/legacy_bench.rs':bench}
manifest={'kernelSource':str(source.relative_to(ROOT)),'kernelSourceSha256':hashlib.sha256(source.read_bytes()).hexdigest(),'legacyBenchmarkSource':str(legacy.relative_to(ROOT)),'legacyBenchmarkSha256':hashlib.sha256(legacy.read_bytes()).hexdigest(),'kernelChanges':[old for old,_ in changes],'generatedSha256':{p:hashlib.sha256(v.encode()).hexdigest() for p,v in files.items()}}
files['SOURCE-REUSE.json']=json.dumps(manifest,sort_keys=True,indent=2)+'\n'
for p,v in files.items():
    target=HERE/p
    if '--check' in sys.argv:assert target.read_text()==v,p
    else:target.write_text(v)
if '--check' in sys.argv:print('Legacy kernel and benchmark reuse checked; only declared intent hooks differ.')
