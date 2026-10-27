"""Existing public-seed history controls only; no original/private data."""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

READ = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
BASE = Path('/var/tmp/kpi-local-private-payment-01')
HERE = BASE / 'publication-release/final-data-interface-01'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def main():
    source = ROOT / 'poc/local-private-payment/recovery/test_publication_derived.py'
    scope = {'__name__': 'selected_existing_public_stage', '__file__': str(source)}
    exec(compile(READ(str(source)), str(source), 'exec'), scope)
    scope['HISTORY'] = BASE / 'results/public/wallet-matched21-fixture-01/HISTORY.json'
    scope['CONTEXT'] = BASE / 'results/public/wallet-matched21-fixture-01/CONTEXT.json'
    output = HERE / 'public-controls-02'
    files = scope['prepare'](output)
    raw = READ(str(HERE / 'optional_volume.py'))
    helper = output / 'software/recovery/optional_volume.py'
    scope['save'](helper, raw)
    files['/public/recovery/optional_volume.py'] = helper
    out = output / 'pure-out'
    out.mkdir(mode=0o700)
    code = r'''
import copy,hashlib,json,sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
sys.path[:0]=['/public/wallet','/public/recovery']
import support,history,optional_volume
assets_raw=Path('/public/ASSETS.json').read_bytes()
assets=support.Assets(assets_raw,hashlib.sha256(assets_raw).hexdigest())
context=support.parse(Path('/public/CONTEXT.json').read_bytes())
raw=Path('/public/HISTORY.json').read_bytes()
value=support.parse(raw)
accepted=history.load(raw,context['checkpoint'],context['genesis_sha256'],assets)
cases=[]
receivers=[assets.receiver(hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED '+bytes([i])).digest()) for i in range(3)]
kinds=['received','change','received']
for i in range(3):
 result=optional_volume.attest_loaded(value,accepted,receivers[i],assets,kinds[i])
 assert result=={'schema':'kpxa-own-matched21-boolean-attestation/v1','status':'PASS','approved_own_workload_matched':True}
 cases.append({'name':'known-public-owner-'+str(i),'passed':True})
def refused(name,call):
 try:call()
 except ValueError:cases.append({'name':name,'passed':True});return
 raise AssertionError('control-accepted')
refused('wrong-public-seed',lambda:optional_volume.attest_loaded(value,accepted,assets.receiver(hashlib.sha256(b'KPXA OPTIONAL VOLUME WRONG PUBLIC SEED').digest()),assets,'received'))
refused('wrong-second-input-kind',lambda:optional_volume.attest_loaded(value,accepted,receivers[0],assets,'change'))
owned=history.claims(accepted,receivers[0],assets)
by_nf={c.nf:c for c in owned}
event=next(e for e in accepted.payments if e['nf'] in by_nf)
change=next(c for c in owned if c.position in event['positions'])
changed=copy.deepcopy(owned)
changed_claim=next(c for c in changed if c.position==change.position)
changed_claim.receipt=replace(changed_claim.receipt,value_sompi=changed_claim.receipt.value_sompi+1)
refused('altered-change-pure-formula',lambda:optional_volume._check_loaded(value,accepted,changed,assets,'received'))
other=next(p for p in event['positions'] if p!=change.position)
ambiguous=copy.deepcopy(owned)
fake=copy.deepcopy(change);fake.position=other;fake.nf=hashlib.sha256(b'PUBLIC CONTROL FAKE EXTRA CLAIM').digest()
ambiguous.append(fake)
refused('self-payment-ambiguous-own-output-map',lambda:optional_volume._check_loaded(value,accepted,ambiguous,assets,'received'))
changed_value=copy.deepcopy(value)
t=next(t for t in changed_value['transitions'] if t['kind']=='payment')
p=bytearray.fromhex(t['projection_hex']);at=193+388;p[at:at+8]=(int.from_bytes(p[at:at+8],'little')+1).to_bytes(8,'little');t['projection_hex']=p.hex()
refused('altered-fee-authenticated-replay',lambda:history.load(support.encoded(changed_value),context['checkpoint'],context['genesis_sha256'],assets))
report={'schema':'kpxa-optional-volume-public-controls/v1','classification':'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY','status':'PASS','controls':cases,'protected_originals_read_or_mounted':False,'private_plan_or_invoice_read':False,'new_proof_generation':False,'actual_chain_or_private_volume_claim':False,'amounts_or_owner_classifications_exported':False}
Path('/out/RESULTS.json').write_text(json.dumps(report,sort_keys=True))
'''
    result = subprocess.run(scope['base_command'](files, out) + ['/usr/bin/python3', '-B', '-c', code],
                            stdin=subprocess.DEVNULL, capture_output=True, env=CLEAN)
    assert result.returncode == 0, 'known-public-volume-control-refused'
    report = json.loads(READ(str(out / 'RESULTS.json')))
    assert len(report['controls']) == 8 and all(row['passed'] for row in report['controls'])
    report['helper_sha256'] = hashlib.sha256(raw).hexdigest()
    report['test_source_sha256'] = hashlib.sha256(READ(str(HERE / 'test_optional_volume.py'))).hexdigest()
    target = HERE / 'OPTIONAL-VOLUME-PUBLIC-CONTROLS-02.json'
    scope['save'](target, json.dumps(report, sort_keys=True, indent=2).encode() + b'\n')
    print(json.dumps({'status': 'PASS', 'controls': len(report['controls']),
                      'actual_originals_read_or_mounted': False, 'helper_sha256': report['helper_sha256']}, sort_keys=True))


if __name__ == '__main__':
    main()
