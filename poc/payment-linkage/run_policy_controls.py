"""Fixed public current-uniform versus prospective-varied wallet-scope controls."""
import copy
import json
from pathlib import Path
import sys
from public_controls import base,event
from observe import analyze
from schema import decode
from prediction import validate_prediction


def main(output):
    out=Path(output);out.mkdir(parents=True,exist_ok=False);gross=1_018_867_700
    p=base();p['exit_credit_sompi']=18_867_700
    p['known_wallet_policy']='one_real_full_cashout_wide_positive_equal_current_demo'
    event(p,'ingress',amount=32*gross+19_701_700,source=0,fee=258_500)
    event(p,'private',mode=32,fee=19_701_700)
    r=analyze(p);assert r['status']=='COMPLETE';validate_prediction(decode(p),r)
    wide=[x for x in r['note_results'] if x['birth']==1]
    assert len(wide)==32 and all(x['amount_alternative']['status']=='UNSAT' and
             x['amount_alternative']['baseline_value_sompi']==gross for x in wide)
    varied=copy.deepcopy(p);varied['known_wallet_policy']='one_real_full_cashout_wide_positive_varied_future_wallet'
    v=analyze(varied);assert v['status']=='COMPLETE';validate_prediction(decode(varied),v)
    assert all(x['amount_alternative']['status']=='SAT' for x in v['note_results'] if x['birth']==1)
    result={'schema':'kpx3-linkage-public-policy-controls/v1','passed':2,
      'actual_current_uniform32_policy':'All32 equal claim values forced by one known input, fee and equal-output wallet prior, even before drainage',
      'prospective_varied_positive_policy':'All32 positive, individual values have checked arithmetic alternatives, no cryptographic privacy claim',
      'current_uniform_demo_financial_privacy_qualification':False,'primary16_is_future_varied_wallet_model':True,
      'no_heldout_generation_scoring':True}
    (out/'RESULTS.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main(sys.argv[1])
