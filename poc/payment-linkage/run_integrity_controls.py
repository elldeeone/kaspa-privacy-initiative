"""Public integrity tests for the incomplete witness search and keyless scorer."""
import copy
import json
from pathlib import Path
import sys
from schema import decode
from construct import Search
from model import Model
from observe import analyze
from prediction import validate_prediction
from public_controls import two_outputs,base,event as add_event


def main(output):
    out=Path(output);out.mkdir(exist_ok=False,parents=True);public=two_outputs();ledger=decode(public)
    report=analyze(public);assert report['status']=='COMPLETE';validate_prediction(ledger,report)
    checks=['complete-public-report-independent-validation']
    for name,mutate in [
      ('missing-note',lambda x:x['note_results'].pop()),
      ('duplicate-note',lambda x:x['note_results'].append(copy.deepcopy(x['note_results'][0]))),
      ('missing-native',lambda x:x['cashout_results'].pop()),
      ('unknown-in-COMPLETE',lambda x:x['cashout_results'][0]['candidates'][0].update(status='UNKNOWN')),
      ('missing-candidate',lambda x:x['cashout_results'][0]['candidates'].pop()),
      ('duplicate-candidate',lambda x:x['cashout_results'][0]['candidates'].append(copy.deepcopy(x['cashout_results'][0]['candidates'][0]))),
      ('missing-source',lambda x:x['cashout_results'][0]['source_candidates'].pop()),
      ('missing-NONE',lambda x:x['note_results'][0].pop('no_direct_cashout')),
      ('wrong-forced-input',lambda x:x['cashout_results'][0].update(forced_input_position=0)),
      ('wrong-forced-note',lambda x:x['note_results'][0].update(forced_cashout_event=2)),
      ('missing-guess-target',lambda x:x['fixed_guesses'].pop()),
      ('bad-public-CM',lambda x:x['note_results'][0].update(cm='00'*32)),
      ('boolean-position',lambda x:x['note_results'][0].update(position=False)),
      ('wrong-baseline-status',lambda x:x['baseline'].update(status='UNKNOWN'))]:
        bad=copy.deepcopy(report);mutate(bad)
        try:validate_prediction(ledger,bad)
        except (ValueError,KeyError,TypeError,AssertionError,StopIteration):pass
        else:raise AssertionError(name)
        checks.append(name)
    search=Search(ledger);cert=search.build();assert cert is not None
    checked=__import__('certificate').check(ledger,cert);event=2;chosen=checked['choices'][event]
    wrong=next(p for p in ledger.notes if p!=chosen)
    model=Model(ledger)
    try:model.sat(cert,{'kind':'select','event':event,'position':wrong})
    except AssertionError:pass
    else:raise AssertionError('wrong-query accepted')
    checks.append('public-SAT-certificate-must-match-exact-query')
    credit=19_000_000
    subset=search._subset([(1,credit+50_000_000),(2,credit+2_000_000_000_000_000_050)],1,credit+50_000_000)
    assert subset==[1]
    checks.append('huge-irrelevant-subset-weight-skips-unbounded-bitshift')
    assert search._subset([(1,100),(2,200)],1,150) is None
    checks.append('subset-search-failure-is-not-UNSAT')
    serial=base();add_event(serial,'ingress',amount=1_260_000_000,source=0)
    for _ in range(3):add_event(serial,'private',fee=20_000_000)
    for i,v in enumerate((300_000_000,400_000_000,500_000_000)):
        add_event(serial,'private',payout=v-19_000_000,mode=0 if i==2 else 2)
    sl=decode(serial);ss=Search(sl);sc=ss.build();si=__import__('certificate').check(sl,sc)
    native_used={si['choices'][e.ordinal] for e in sl.events if e.payout}
    change=next(p for p in sl.events[1].notes if p not in native_used)
    altered=ss.with_changed_value(change,si['values'][change]);assert altered is not None
    Model(sl).sat(altered,{'kind':'note_value','position':change,'baseline_value':si['values'][change]})
    checks.append('serial-unanchored-leaf-permutation-rechecks-change-and-exact-predicate')
    import z3
    def no_memory(solver):raise z3.Z3Exception('out of memory')
    memory=analyze(public,backend=no_memory);assert memory['status']=='INCOMPLETE' and memory['baseline']['status']=='UNKNOWN'
    checks.append('solver-memory-exception-is-INCOMPLETE-never-UNSAT')
    result={'schema':'kpx3-linkage-independent-integrity-controls/v1','passed':len(checks),'checks':checks,
             'heldout_generation_or_scoring':False,'privacy_qualification':False}
    (out/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({'passed':len(checks)}))

if __name__=='__main__':main(sys.argv[1])
