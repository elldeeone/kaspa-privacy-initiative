#!/usr/bin/env python3
"""Compare new solver/search code on EXACT retained public development bytes.

No regeneration, keys, seed, economic request redraw or hidden study input.
The original incomplete prediction files remain unchanged.
"""
import hashlib
import json
from pathlib import Path
import sys
import time
import subprocess
from run import ROOT,HERE,PYTHON,OBSERVER,SCORER,sandbox
from schema import canonical,parse

if __name__=='__main__':
    old=Path(sys.argv[1]).resolve();out=Path(sys.argv[2]).resolve()
    assert not out.is_relative_to(ROOT);out.mkdir(parents=True,exist_ok=False,mode=0o700)
    software=out/'software';software.mkdir(mode=0o700);pins=[]
    for source in sorted(HERE.glob('*.py')):
        data=source.read_bytes();dest=software/source.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes(data);dest.chmod(0o400);pins.append({'path':str(source.relative_to(ROOT)),
          'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    (out/'SOURCE.json').write_bytes(canonical({'files':pins,'same_retained_public_fixture':True}))
    rows=[]
    jobs=[(arm,view) for arm in ('wide32','compact2') for view in (
        ('drain-C.json',) if len(sys.argv)<4 else ('payment-C.json','drain-Cplus8.json','payment-Cplus8.json'))]
    for arm,view in jobs:
        public=old/'generation/cases'/arm/view;truth=old/'generation/cases'/arm/'truth.json'
        artifact=arm+'-'+view.removesuffix('.json')
        start=time.monotonic();cp=subprocess.run(sandbox(software,OBSERVER)+['--chdir','/work',str(PYTHON),'-B','/work/observe.py'],
                                input=public.read_bytes(),capture_output=True)
        pred=out/(artifact+'-prediction.json');pred.write_bytes(cp.stdout);(out/(artifact+'-observer.stderr')).write_bytes(cp.stderr)
        assert cp.returncode==0,'observer failure retained'
        result=parse(cp.stdout);seconds=time.monotonic()-start
        command=sandbox(software,SCORER)+['--ro-bind',str(public),'/public.json','--ro-bind',str(pred),'/prediction.json',
           '--ro-bind',str(truth),'/truth.json','--chdir','/work',str(PYTHON),'-B','/work/score_cli.py',
           '/public.json','/prediction.json','/truth.json']
        scored=subprocess.run(command,capture_output=True);(out/(artifact+'-score.stdout')).write_bytes(scored.stdout)
        (out/(artifact+'-score.stderr')).write_bytes(scored.stderr);assert scored.returncode==0,'independent scorer failure retained'
        score=parse(scored.stdout);rows.append({'arm':arm,'view':view,'status':result['status'],'queries':result.get('queries',0),
            'observer_seconds':seconds,'public_sha256':hashlib.sha256(public.read_bytes()).hexdigest(),
            'true_history_validated':score['true_history_independently_validated'],
            'not_heldout_privacy_qualification':True})
        (out/'PARTIAL-RESULTS.json').write_bytes(canonical({'cases':rows}));print(json.dumps(rows[-1]),flush=True)
    (out/'RESULTS.json').write_bytes(canonical({'schema':'kpx3-linkage-same-public-input-reobserve/v1','cases':rows,
       'regenerated_data':False,'read_seed_or_keys':False,'privacy_qualification':False}))
