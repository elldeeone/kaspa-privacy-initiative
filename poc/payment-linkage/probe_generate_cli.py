"""Fixed public development fixture; known seeds, never heldout evidence."""
import json
from pathlib import Path
import sys
from generate import build_case,workload
from schema import canonical

if __name__=='__main__':
    out=Path(sys.argv[1]);crypto=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=False)
    work=workload(bytes(32));index=[]
    for arm in ('wide32','compact2'):
        views,truth=build_case(work,bytes([17])*32,0,'overlap',arm,crypto)
        p=out/arm;p.mkdir(mode=0o700)
        for key,view in views.items():
            horizon,profile=key.split('/');(p/(horizon+'-'+profile.replace('+','plus')+'.json')).write_bytes(canonical(view))
        (p/'truth.json').write_bytes(canonical(truth));index.append(arm)
    print(json.dumps({'classification':'PUBLIC_KNOWN_SEED_DEVELOPMENT_ONLY_DO_NOT_FUND',
                      'cases':index,'heldout_generation_or_privacy_qualification':False}))
