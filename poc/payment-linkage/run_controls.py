#!/usr/bin/env python3
"""Fixed public controls only. No heldout generation/scoring permission implied."""
import copy
import json
import sys
from pathlib import Path
import z3
from schema import decode,Invalid,parse
from certificate import check,BadCertificate
from observe import analyze
from public_controls import two_outputs,two_sources,one_payer_wide,base,event


def normalized(report):
    return {'status':report['status'],
      'notes':[(r['position'],r['amount_alternative']['status'],r['forced_cashout_event'],
                r['no_direct_cashout']['status'],[(x['event'],x['status']) for x in r['cashout_candidates']])
               for r in report.get('note_results',[])],
      'cashouts':[(r['event'],r['forced_input_position'],[(x['position'],x['status']) for x in r['candidates']],
                  [(x['source_id'],x['status']) for x in r['source_candidates']])
                  for r in report.get('cashout_results',[])]}

def main(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    checks=[]
    def passed(name):
        checks.append({'name':name,'passed':True});print('PASS '+name,flush=True)
    p=two_outputs();a=analyze(p);b=analyze(p,group=False)
    assert a['status']=='COMPLETE' and normalized(a)==normalized(b)
    cash=a['cashout_results'];assert len(cash)==2 and all(r['forced_input_position'] is None for r in cash)
    assert all([x['status'] for x in r['source_candidates']]==['SAT'] for r in cash)
    passed('same-birth-slot-symmetry-and-single-payer-lineage')
    # Notes at continuing full cashout are public-policy zero and cannot cash out.
    for row in a['note_results']:
        if row['birth']==2:assert row['no_direct_cashout']['status']=='SAT' and row['forced_cashout_event'] is None
    passed('zero-dummy-NONE-is-not-positive-forced-link')
    p['profile']='C+1';p['participant_roles']=[2]
    p['participant_records']=[{'participant_role':2,'position':2,'cm':p['events'][1]['notes'][0]['cm'],
      'value_sompi':419_000_000,'original_nf':p['events'][2]['nfs'][0],'invoice_counterparty_role':0}]
    c=analyze(p);d=analyze(p,group=False);assert normalized(c)==normalized(d)
    assert c['cashout_results'][0]['forced_input_position']==2
    passed('participant-class-breaker-and-NF-known-spend')
    # Counterparty metadata cannot enter the source-lineage equations.
    q=two_sources();q['profile']='C+1';q['participant_roles']=[2]
    q['participant_records']=[{'participant_role':2,'position':0,'cm':q['events'][0]['notes'][0]['cm'],
        'value_sompi':600_000_000,'original_nf':q['events'][2]['nfs'][0],'invoice_counterparty_role':1}]
    q0=copy.deepcopy(q);q0['participant_records'][0]['invoice_counterparty_role']=None
    assert normalized(analyze(q))==normalized(analyze(q0))
    passed('known-counterparty-is-not-original-source-equality')
    # Complete value/position inference uses both sources and drains exact reserve.
    e=analyze(two_sources());assert e['status']=='COMPLETE'
    assert [r['forced_input_position'] for r in e['cashout_results']]==[0,1]
    passed('two-source-full-drainage-exact-global-forcing')
    # Binding repeated CM values makes a contradictory declared opening reject.
    dup=two_sources();dup['events'][1]['notes'][0]['cm']=dup['events'][0]['notes'][0]['cm']
    assert analyze(dup)['status']=='REJECTED_INPUT' # public Note opening mismatch
    passed('repeated-public-CM-opening-contradiction')
    repeated=base();repeated['funding_directory'].append({'source_id':1,'payer_role':1})
    event(repeated,'ingress',amount=600_000_000,source=0)
    event(repeated,'ingress',amount=600_000_000,source=1)
    event(repeated,'private',payout=581_000_000)
    event(repeated,'private',payout=581_000_000,mode=0)
    ra=analyze(repeated);rb=analyze(repeated,group=False)
    assert ra['status']=='COMPLETE' and normalized(ra)==normalized(rb) and not ra['symmetry_grouping_enabled']
    assert all(r['forced_input_position'] is None for r in ra['cashout_results'])
    passed('repeated-CM-distinct-positions-disable-grouping-preserve-equal-values')
    unknown=analyze(two_outputs(),backend=lambda _:z3.unknown)
    assert unknown['status']=='INCOMPLETE' and not unknown.get('note_results')
    passed('UNKNOWN-baseline-never-ambiguity')
    valid=two_outputs();ledger=decode(valid);cert=a['certificates'][a['baseline']['certificate_id']]
    for mutation in ('replay','future','value','gap'):
        bad=copy.deepcopy(cert)
        if mutation=='replay':bad['selected_positions'][-1]['position']=bad['selected_positions'][-2]['position']
        if mutation=='future':bad['selected_positions'][0]['position']=4
        if mutation=='value':bad['values'][0]['value_sompi']+=1
        if mutation=='gap':bad['selected_positions'][0]['position']=1 # skipped aligned position
        try:check(ledger,bad)
        except BadCertificate:pass
        else:raise AssertionError(mutation)
    passed('independent-certificate-replay-future-value-gap-rejections')
    negatives=[]
    for name,mutator in [
      ('hidden-root',lambda x:x.update(owner_map={})),
      ('hidden-event',lambda x:x['events'][1].update(selected_position=0)),
      ('float-amount',lambda x:x['events'][0].update(ingress_value_sompi=1020000000.0)),
      ('bool-terminal-start',lambda x:x['events'][-1].update(append_start=False)),
      ('float-participant-role',lambda x:x.update(profile='C+1',participant_roles=[2.0])),
      ('NF-replay',lambda x:x['events'][-1]['nfs'].__setitem__(0,x['events'][1]['nfs'][0])),
      ('reserve',lambda x:x['events'][1].update(reserve_sompi=9)),
      ('alignment',lambda x:x['events'][1].update(append_start=1)),
      ('extra-private-field',lambda x:x['events'][1]['notes'][0].update(owner=2)),
      ('payout-floor',lambda x:x['events'][-1].update(payout_sompi=1)),
      ('oversized-value',lambda x:x['events'][0].update(ingress_value_sompi=2**64)),
      ('bad-cipher-width',lambda x:x['events'][1]['notes'][0].update(ciphertext_hex264='00'))]:
        bad=copy.deepcopy(valid);mutator(bad);r=analyze(bad)
        assert r['status']=='REJECTED_INPUT',(name,r['status']);negatives.append(name)
    passed('strict-private-field-type-frame-count-amount-negatives')
    try:parse(b'{"a":1,"a":2}')
    except Invalid:pass
    else:raise AssertionError('duplicate-json')
    passed('duplicate-json-fields-reject')
    large=one_payer_wide();print('START wide32',flush=True);wide=analyze(large)
    assert wide['status']=='COMPLETE' and len(wide['cashout_results'])==32
    assert all(r['forced_input_position'] is None for r in wide['cashout_results'])
    assert all([s['status'] for s in r['source_candidates']]==['SAT'] for r in wide['cashout_results'])
    passed('wide32-full-independent-drainage-source-lineage-negative-control')
    (output/'RESULTS.json').write_text(json.dumps({'schema':'kpx3-payment-linkage-public-controls/v1',
        'classification':'FIXED_PUBLIC_CONTROLS_NO_HELDOUT_DATA','checks':checks,
        'passed':len(checks),'malformed_inputs_rejected':len(negatives),
        'wide32_queries':wide['queries'],'wide32_classes':len(wide['symmetry_classes']),
        'privacy_or_native_financial_qualification':False},sort_keys=True,indent=2)+'\n')
    print(json.dumps({'passed':len(checks),'malformed_inputs_rejected':len(negatives),'wide32_queries':wide['queries']}))

if __name__=='__main__':main(sys.argv[1])
