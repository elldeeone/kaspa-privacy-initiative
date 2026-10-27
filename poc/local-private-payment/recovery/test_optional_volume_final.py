#!/usr/bin/env python3
"""Known PUBLIC positive exit-key-coverage controls; no original leaf or metadata.

The replay is an existing genuine-component supplied-context fixture. Mutated
loaded objects are pure negative controls, never accepted-history evidence.
"""
import hashlib
import json
from pathlib import Path
import runpy
import subprocess

HERE = Path('/var/tmp/kpi-local-private-payment-01/publication-release/final-data-interface-01')
READ = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def main(output):
    public_helpers = HERE / 'test_final_publication_scope.py'
    scope = {'__name__': 'known_public_closure_helpers', '__file__': str(public_helpers)}
    raw = READ(str(public_helpers), '69841f50f5c0e44e8d81312900e8b4b1a9117821a6c695cb520a81e0a2c11a26')
    exec(compile(raw, str(public_helpers), 'exec'), scope)
    assert not output.exists()
    output.mkdir(mode=0o700)
    files = scope['known_public_closure'](output)
    source = HERE / 'optional_volume_final.py'
    raw = READ(str(source), 'b8127aabd90ba738fa521cfc023e40e0dd50c7d8cd8b7cc385b664b4212e0e9c')
    target = output / 'software/recovery/optional_volume_final.py'
    scope['save'](target, raw)
    files['/public/recovery/optional_volume_final.py'] = target
    out = output / 'pure-out'
    out.mkdir(mode=0o700)
    code = r'''
import copy,hashlib,json,sys
from pathlib import Path
sys.path[:0]=['/public/wallet','/public/recovery']
import support,history,optional_volume_final
assets_raw=Path('/public/ASSETS.json').read_bytes()
assets=support.Assets(assets_raw,hashlib.sha256(assets_raw).hexdigest())
context=support.parse(Path('/public/CONTEXT.json').read_bytes())
raw=Path('/public/HISTORY.json').read_bytes()
value=support.parse(raw)
accepted=history.load(raw,context['checkpoint'],context['genesis_sha256'],assets)
receivers=[assets.receiver(hashlib.sha256(b'KPXA MATCHED21 KNOWN PUBLIC SEED '+bytes([i])).digest()) for i in range(3)]
kinds=['received','change','received']
cases=[]
for i in range(3):
 result=optional_volume_final.attest_loaded(value,accepted,receivers[i],assets,kinds[i])
 assert result=={'schema':'kpxa-own-final-workload-and-exit-key-attestation/v1','status':'PASS','approved_own_workload_matched':True,'approved_historical_exit_key_coverage':True}
 cases.append({'name':'known-public-fixed-workload-and-exit-key-owner-'+str(i),'passed':True})
def refused(name,call):
 try:call()
 except ValueError:cases.append({'name':name,'passed':True});return
 raise AssertionError('unexpected-control-acceptance')
receiver=receivers[0]
owned=history.claims(accepted,receiver,assets)
own_nfs={c.nf for c in owned}
own_events=[i for i,e in enumerate(accepted.exits) if e['nf'] in own_nfs]
assert len(own_events)==3
def changed():
 result=copy.copy(accepted)
 result.exits=[dict(e) for e in accepted.exits]
 return result
original_reconcile=optional_volume_final.audit.payment.reconcile_payouts
def must_not_reconcile(*args):
 raise AssertionError('private-cardinality-check-was-bypassed')
optional_volume_final.audit.payment.reconcile_payouts=must_not_reconcile
zero=changed();zero.exits=[e for e in zero.exits if e['nf'] not in own_nfs]
refused('zero-owned-exit-coverage-refused-before-reconciliation',lambda:optional_volume_final.attest_loaded(value,zero,receiver,assets,'received'))
two=changed();two.exits.pop(own_events[-1])
refused('two-owned-exit-coverage-refused-before-reconciliation',lambda:optional_volume_final.attest_loaded(value,two,receiver,assets,'received'))
four=changed()
historical_exit_nfs={e['nf'] for e in accepted.exits}
spare=next(c.nf for c in owned if c.nf not in historical_exit_nfs)
foreign=next(i for i,e in enumerate(four.exits) if e['nf'] not in own_nfs)
four.exits[foreign]['nf']=spare
refused('four-distinct-owned-exits-refused-before-reconciliation',lambda:optional_volume_final.attest_loaded(value,four,receiver,assets,'received'))
duplicate=changed();duplicate.exits[own_events[1]]=dict(duplicate.exits[own_events[0]])
refused('three-rows-with-duplicate-owned-exit-NF-refused-before-reconciliation',lambda:optional_volume_final.attest_loaded(value,duplicate,receiver,assets,'received'))
optional_volume_final.audit.payment.reconcile_payouts=original_reconcile
wrong_script=changed();wrong_script.exits[own_events[0]]['payout_spk']=bytes(36)
refused('wrong-historical-payout-script-rejected-by-existing-reconciliation',lambda:optional_volume_final.attest_loaded(value,wrong_script,receiver,assets,'received'))
refused('wrong-second-input-kind-still-refused',lambda:optional_volume_final.attest_loaded(value,accepted,receiver,assets,'change'))
refused('wrong-known-public-seed-still-refused',lambda:optional_volume_final.attest_loaded(value,accepted,assets.receiver(hashlib.sha256(b'KPXA FINAL OPTIONAL WRONG PUBLIC SEED').digest()),assets,'received'))
nonterminal=changed();nonterminal.reserve=60_000_000;nonterminal.point=b'\x01'*36
refused('nonterminal-positive-coverage-refused',lambda:optional_volume_final.attest_loaded(value,nonterminal,receiver,assets,'received'))
assert not any(Path(p).exists() for p in ('/home','/var','/root','/owner','/private','/BACKUP.json','/SIBLING.json'))
report={'schema':'kpxa-optional-final-volume-public-controls/v1','status':'PASS','classification':'KNOWN_PUBLIC_SEEDS_SUPPLIED_CONTEXT_ONLY','controls':cases,'loaded-object-count-mutations-are-accepted-history':False,'protected_originals_read_or_mounted':False,'original_metadata_selected_or_read':False,'private_plan_or_invoice_read':False,'new_proof_generation':False,'network_or_publication_performed':False,'actual_chain_or_private_volume_claim':False,'amounts_NFs_indices_maps_keycounts_or_owner_classifications_exported':False,'namespace_absence_checks':7}
Path('/out/RESULTS.json').write_text(json.dumps(report,sort_keys=True))
'''
    result = subprocess.run(scope['base_command'](files, out) + ['/usr/bin/python3', '-B', '-c', code],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN)
    assert result.returncode == 0, 'known-public-final-volume-controls-refused'
    report = json.loads(READ(str(out / 'RESULTS.json')))
    assert len(report['controls']) == 11 and all(row['passed'] for row in report['controls'])
    report['helper_sha256'] = hashlib.sha256(raw).hexdigest()
    report['test_source_sha256'] = hashlib.sha256(READ(str(Path(__file__).absolute()))).hexdigest()
    scope['save'](output / 'RESULTS.json', scope['encoded'](report))
    print(json.dumps({'status':'PASS','controls':len(report['controls']),
        'helper_sha256':report['helper_sha256'],'protected_originals_read_or_mounted':False},sort_keys=True))


if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    main(p.parse_args().output)
