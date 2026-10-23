#!/usr/bin/env python3
"""Root-released public development probe, sibling isolated namespaces only."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from run import sandbox,PYTHON,CRYPTO,CRYPTO_SHA,ROOT,HERE,OBSERVER,SCORER
from schema import parse,canonical,digest

if __name__=='__main__':
    output=Path(sys.argv[1]).resolve();assert not output.is_relative_to(ROOT)
    output.mkdir(parents=True,exist_ok=False,mode=0o700)
    software=output/'software';software.mkdir(mode=0o700)
    files=sorted(HERE.glob('*.py'))+[ROOT/'poc/future-recipient/v2/recipient.py',
             ROOT/'research/next-session/private-change/fees/WHOLE-EMITTED-COSTS-01.json']
    pins=[]
    for source in files:
        rel=source.relative_to(ROOT);target=software/rel;target.parent.mkdir(parents=True,exist_ok=True)
        data=source.read_bytes();target.write_bytes(data);target.chmod(0o400)
        pins.append({'path':str(rel),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    (output/'SOURCE.json').write_bytes(canonical({'files':pins,'known_seed_development_only':True}))
    assert hashlib.sha256(CRYPTO.read_bytes()).hexdigest()==CRYPTO_SHA
    genout=output/'generation';genout.mkdir(mode=0o700)
    command=sandbox(software,('schema.py','generate.py','probe_generate_cli.py'),'/work/poc/payment-linkage')
    for rel in ('poc/future-recipient/v2/recipient.py','research/next-session/private-change/fees/WHOLE-EMITTED-COSTS-01.json'):
        command+=['--ro-bind',str(software/rel),'/work/'+rel]
    command+=['--ro-bind',str(CRYPTO),'/crypto','--bind',str(genout),'/out','--chdir','/work/poc/payment-linkage',
              str(PYTHON),'-B','/work/poc/payment-linkage/probe_generate_cli.py','/out/cases','/crypto']
    started=time.monotonic();cp=subprocess.run(command,capture_output=True)
    (output/'generator.stdout').write_bytes(cp.stdout);(output/'generator.stderr').write_bytes(cp.stderr)
    assert cp.returncode==0,'public generator failure retained'
    generation_seconds=time.monotonic()-started;rows=[]
    for arm in ('wide32','compact2'):
        public=genout/'cases'/arm/'drain-C.json';truth=genout/'cases'/arm/'truth.json'
        cmd=sandbox(software,OBSERVER)+['--chdir','/work',str(PYTHON),'-B','/work/observe.py']
        before=time.monotonic();cp=subprocess.run(cmd,input=public.read_bytes(),capture_output=True)
        prediction=output/(arm+'-prediction.json');prediction.write_bytes(cp.stdout)
        (output/(arm+'-observer.stderr')).write_bytes(cp.stderr);assert cp.returncode==0,'public observer failed'
        report=parse(cp.stdout);observer_seconds=time.monotonic()-before
        cmd=sandbox(software,SCORER)+['--ro-bind',str(public),'/public.json','--ro-bind',str(prediction),'/prediction.json',
          '--ro-bind',str(truth),'/truth.json','--chdir','/work',str(PYTHON),'-B','/work/score_cli.py',
          '/public.json','/prediction.json','/truth.json']
        scored=subprocess.run(cmd,capture_output=True);(output/(arm+'-score.stdout')).write_bytes(scored.stdout)
        (output/(arm+'-score.stderr')).write_bytes(scored.stderr);assert scored.returncode==0,'public scorer failed'
        score=parse(scored.stdout)
        rows.append({'arm':arm,'observer_status':report['status'],'queries':report.get('queries',0),
                     'observer_seconds':observer_seconds,'independent_true_history_validated':score['true_history_independently_validated'],
                     'metrics_are_public_development_not_heldout':True})
        # Seal each development result even if a later case fails.
        (output/'PARTIAL-RESULTS.json').write_bytes(canonical({'cases':rows}))
        print(json.dumps(rows[-1]),flush=True)
    result={'schema':'kpx3-linkage-known-public-development-probe/v1','generation_seconds':generation_seconds,
       'cases':rows,'total_seconds':time.monotonic()-started,'privacy_qualification':False,
       'heldout_generation_or_scoring_performed':False,'source_pins':pins}
    (output/'RESULTS.json').write_bytes(canonical(result));print(json.dumps({'public_probe_complete':True}))
