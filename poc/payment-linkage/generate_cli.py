#!/usr/bin/env python3
"""Isolated disposable generator. Only explicit fresh study material enters."""
import json
from pathlib import Path
import sys
from generate import build_case,workload
from schema import canonical

if __name__=='__main__':
    seed_file,crypto,output=map(Path,sys.argv[1:4]);seeds=json.loads(seed_file.read_bytes())
    assert set(seeds)=={'schema','workload_hex32','material_hex32'} and seeds['schema']=='kpx3-linkage-study-material/v1'
    assert len(seeds['workload_hex32'])==len(seeds['material_hex32'])==4
    output.mkdir(exist_ok=False,parents=True);cases=[]
    for cluster in range(4):
        seed=bytes.fromhex(seeds['workload_hex32'][cluster]);material=bytes.fromhex(seeds['material_hex32'][cluster])
        assert len(seed)==len(material)==32
        work=workload(seed)
        for timing in ('overlap','staggered'):
            for arm in ('wide32','compact2'):
                pub,truth=build_case(work,material,cluster,timing,arm,crypto)
                case='case-'+str(len(cases)).zfill(3);directory=output/case;directory.mkdir(mode=0o700)
                files=[]
                for key,view in pub.items():
                    horizon,profile=key.split('/');name=horizon+'-'+profile.replace('+','plus')+'.json'
                    path=directory/name;path.write_bytes(canonical(view));path.chmod(0o600)
                    files.append({'horizon':horizon,'profile':profile,'public_file':str(Path(case)/name)})
                (directory/'truth.json').write_bytes(canonical(truth));(directory/'truth.json').chmod(0o600)
                cases.append({'case':case,'cluster':cluster,'timing':timing,'arm':arm,'views':files})
    (output/'PRIVATE-CASES.json').write_bytes(canonical({'schema':'kpx3-linkage-private-case-index/v1','cases':cases}))
    print(json.dumps({'complete_model_ledgers':len(cases),'public_attacker_inputs':sum(len(c['views']) for c in cases),
                      'heldout_labels_not_mounted_to_observers':True,'native_transactions_or_proofs_generated':False}))
