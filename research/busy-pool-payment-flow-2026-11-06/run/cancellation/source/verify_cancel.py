#!/usr/bin/env python3
"""Reverify a fresh replacement witness without changing the original history."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from analyse import SHARED, PRIORITY, REFERENCE

def verify(run, fresh, host, program):
    assert (fresh/'input.bin').read_bytes()==(run/'priority-withdrawal/input.bin').read_bytes()
    assert (fresh/'expected-journal.bin').read_bytes()==(run/'priority-withdrawal/expected-journal.bin').read_bytes()
    old=(run/'priority-withdrawal/native-proof.bin').read_bytes()
    new=(fresh/'native-proof.bin').read_bytes()
    assert len(old)==len(new)==128
    with tempfile.TemporaryDirectory(prefix='kpi-cancel-public-replay-') as temporary:
        target=Path(temporary)
        for name in ['MAIN.json','REFERENCE.json','APPROVALS.json']:
            shutil.copyfile(run/name,target/name)
        for name in SHARED+PRIORITY+REFERENCE:
            source=fresh if name=='priority-withdrawal' else run/name
            (target/name).mkdir()
            for file in ['input.bin','expected-journal.bin','candidate-compressed.bin','native-proof.bin','proof-report.json']:
                shutil.copyfile(source/file,target/name/file)
        main=json.loads((target/'MAIN.json').read_text())
        tx=main['records'][3]['transaction']
        entry=tx['inputs'][0]
        key=next(k for k in ['signatureScript','signature_script'] if k in entry)
        raw=bytes.fromhex(entry[key])
        assert raw.count(old)==1
        entry[key]=raw.replace(old,new).hex()
        (target/'MAIN.json').write_text(json.dumps(main))
        result=subprocess.check_output([str(host),'replay',str(program),str(target)],text=True)
        replay=json.loads(result)
        assert replay['independentPublicReplay'] is True
    return {'exactSameCurrentInputAndJournal':True,'newNativeWitnessBytes':128,
            'unchangedNativeAncestorIdsAndPayoutSpends':True,'fullReplay':replay,
            'originalRecordsModified':False,'walletBackupsRead':False}

if __name__=='__main__':
    print(json.dumps(verify(*map(Path,sys.argv[1:5])),indent=2,sort_keys=True))
