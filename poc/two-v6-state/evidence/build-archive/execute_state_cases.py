#!/usr/bin/env python3
"""Declared CPU guest controls; launch requires independently selected host."""
from pathlib import Path
import datetime
import hashlib
import json
import subprocess
import sys
import time

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/proof')
TARGET = ROOT.parent / 'proof-target'
PACKAGE = ROOT / 'poc/two-v6-state'
HOST = TARGET / 'release/kpi-two-v6-state-proof-host'
PROGRAMS = TARGET / 'two-v6-state-programs'
OUT = TARGET / 'two-v6-state-execution'
IMAGE = 'e9d7bd51e12b253c5cb7839d6854cf30d387dea95aff4e853feb47eb6d0edcf9'
PROGRAM_SHA = 'd1336290bd4b8555edea9c5d7dd56aa4883f1d185b0a4aca9b08105b0537097a'
CASES = [('current-anchor','valid'),('historical-anchor','valid')]
CASES += [('current-anchor',name) for name in (
    'trailing','truncated','wrong-domain','changed-count-both','state-version',
    'even-cm-count','uninitialized','reserve-zero','reserve-equals-fee',
    'historical-path','nf-index','nf-predecessor-path','nf-empty-path',
    'cm-empty-path','history-empty-path','nf-authenticated-replay',
    'outpoint-order','reserve-plus-one')]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

assert len(sys.argv)==2, 'selected host hash required'
assert sha(HOST)==sys.argv[1], 'selected host hash mismatch'
assert sha(PROGRAMS/'guest.program.bin')==PROGRAM_SHA
selection=json.loads((PACKAGE/'host/pins/guest-selection.json').read_text())
assert selection['image']==IMAGE and selection['program_sha256']==PROGRAM_SHA
OUT.mkdir()
plan={'schema':'kpi-two-v6-state-execution-plan-v1','scope':'NONFUNDABLE_SYNTHETIC_GUEST_EXECUTION_ONLY',
    'image':IMAGE,'program_sha256':PROGRAM_SHA,'host_sha256':sys.argv[1],
    'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'cases':CASES,
    'native_predecessor_authenticated':False,'native_settlement':False,'proof_generation':False}
(OUT/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
results=[]
started=time.monotonic()
for context,case in CASES:
    label=context+'-'+case
    output=OUT/label
    command=['/usr/bin/time','-v','-o',str(OUT/(label+'.resources.txt')),
        str(HOST),'execute',context,str(PROGRAMS),str(PACKAGE/'public-fixtures'/context/'input.bin'),str(output),case]
    with (OUT/(label+'.stdout.log')).open('w') as stdout, (OUT/(label+'.stderr.log')).open('w') as stderr:
        result=subprocess.run(command,stdout=stdout,stderr=stderr)
    row={'context':context,'case':case,'exit_code':result.returncode}
    if (output/'report.json').exists():
        row['report']=json.loads((output/'report.json').read_text())
    results.append(row)
    (OUT/'partial-results.json').write_text(json.dumps(results,indent=2)+'\n')
    if result.returncode or not row.get('report',{}).get('passed'):
        raise SystemExit('Guest case failed: '+label)
    print(json.dumps(row),flush=True)
summary={'schema':'kpi-two-v6-state-execution-qualification-v1','image':IMAGE,
    'program_sha256':PROGRAM_SHA,'host_sha256':sys.argv[1],
    'seconds':time.monotonic()-started,'cases':len(results),'all_passed':True,
    'valid_contexts':2,'semantic_rejections':16,'changed_journal_controls':2,
    'scope':'NONFUNDABLE_SYNTHETIC_GUEST_EXECUTION_NO_RECEIPT',
    'native_predecessor_authenticated':False,'native_settlement':False,'results':results}
(OUT/'qualification.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='results'}),flush=True)
