"""Additional public proof-boundary controls. Never heldout generation/scoring."""
import json
from pathlib import Path
import sys
from public_controls import two_outputs,two_sources,base,event
from observe import analyze
from run_controls import normalized


def main(output):
    out=Path(output);out.mkdir(parents=True,exist_ok=False);checks=[]
    prefix=two_outputs();prefix['events']=prefix['events'][:2]
    r=analyze(prefix);assert r['status']=='COMPLETE' and not r['entailed_public_lemmas']
    assert all(n['no_direct_cashout']['status']=='SAT' for n in r['note_results'])
    checks.append('open-positive-prefix-has-NONE-and-no-terminal-lemmas')
    p=two_sources();r=analyze(p)
    roots=next(x for x in r['entailed_public_lemmas'] if x['kind']=='ingress-incompatible-with-native-must-P0')
    assert roots['positions']==[] and [e['forced_input_position'] for e in r['cashout_results']]==[0,1]
    checks.append('matching-ingress-native-values-not-forced-into-P0')
    p=base();p['funding_directory'].append({'source_id':1,'payer_role':1})
    event(p,'ingress',amount=600_000_000,source=0);event(p,'ingress',amount=400_000_000,source=1)
    event(p,'private',fee=20_000_000);event(p,'private',payout=961_000_000,mode=0)
    assert analyze(p)['status']=='INCONSISTENT'
    checks.append('too-many-unmatched-positive-ingresses-for-P0-reject')
    p=base();event(p,'ingress',amount=1_020_000_000,source=0)
    event(p,'private',fee=20_000_000);event(p,'private',fee=20_000_000)
    event(p,'private',payout=961_000_000,mode=0)
    r=analyze(p);u=analyze(p,group=False);assert r['status']=='COMPLETE' and normalized(r)==normalized(u)
    finite=next(x for x in r['entailed_public_lemmas'] if x['kind']=='terminal-native-finite-values')['positions']
    assert not {2,3}&set(finite) and {4,5}<=set(finite)
    checks.append('note-before-later-P0-not-falsely-native-finite-bounded')
    p=base();v=9_007_199_254_740_993;event(p,'ingress',amount=v,source=0)
    event(p,'private',payout=v-19_000_000,mode=0)
    r=analyze(p);assert r['status']=='COMPLETE' and r['cashout_results'][0]['input_value_alternative']['baseline_value_sompi']==v
    checks.append('above-2pow53-integer-exactness')
    import z3
    calls=[0]
    def backend(solver):
        calls[0]+=1
        return solver.check() if calls[0]==1 else z3.unknown
    r=analyze(two_outputs(),backend=backend)
    assert r['status']=='INCOMPLETE' and calls[0]==2
    assert all(row['forced_cashout_event'] is None for row in r['note_results'])
    assert all(row['amount_alternative']['status']=='UNKNOWN' for row in r['note_results'])
    checks.append('first-UNKNOWN-stops-all-later-queries-without-forcedness')
    result={'schema':'kpx3-linkage-lemma-boundary-controls/v1','passed':len(checks),'checks':checks,
            'heldout_generation_scoring':False,'privacy_qualified':False}
    (out/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main(sys.argv[1])
