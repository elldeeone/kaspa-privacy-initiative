"""Predeclared outgoing-recipient ownership regression: red then green.

Fixed public control, no heldout draw, no native/crypto-owner claim. This exact
file is unchanged between red and green; only the separately pinned core fixes.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
from fixtures import Builder,S
from ledger import decode,check,verify_analysis,canonical
from observer import analyze


def main(args):
    source=Path(__file__).resolve().parent;repo=source.parents[1]
    raw=Path(args.freeze).read_bytes();assert hashlib.sha256(raw).hexdigest()==args.freeze_sha256
    for row in json.loads(raw)['files']:
        data=(repo/row['path']).read_bytes();assert len(data)==row['bytes'] and hashlib.sha256(data).hexdigest()==row['sha256']
    out=Path(args.output).resolve();assert not out.is_relative_to(repo);out.mkdir(parents=True,exist_ok=False,mode=0o700)
    cases=[]
    for maximum in (1,2):
        b=Builder('outgoing-recipient-calibration/'+str(maximum),maximum=maximum)
        boot=b.deposit(0,100*S)
        known_outgoing,sender_change=b.payment([boot],1,30*S,actor=0,invoice='A-to-B')
        b.payment([known_outgoing],3,20*S,actor=1,invoice='B-to-C')
        fixture=b.fixture(0);ledger,actual=fixture.verify();target=2
        assert len(fixture.public['outgoing_invoices'])==1 and len(fixture.public['participant_records'])==2
        assert fixture.public['outgoing_invoices'][0]['recipient_role']==1
        report=analyze(copy.deepcopy(fixture.public));assert report['status']=='COMPLETE';verify_analysis(ledger,report)
        row=next(x for x in report['event_results'] if x['event']==target)
        assert row['mandatory_input_positions']==[known_outgoing]
        assert actual['ancestors'][known_outgoing]=={0} and fixture.actors[target]==1
        cases.append({'max_real_inputs':maximum,'target_event':target,'mandatory_outgoing_note':known_outgoing,
            'expected_current_payer_role':1,'observed_current_payer_role':row['conditional_wallet_payer_role'],
            'original_funding_source':0,'actual_integer_history_compatible':True,
            'target_is_third_party_invoice_not_participant_own_payment':True})
        (out/(str(maximum)+'-public.json')).write_bytes(canonical(fixture.public))
        (out/(str(maximum)+'-analysis.json')).write_bytes(canonical(report))
        (out/(str(maximum)+'-PRIVATE-FIXTURE.json')).write_bytes(canonical({'notes':fixture.notes,'actors':fixture.actors,'certificate':fixture.certificate}))
    passed=all(c['observed_current_payer_role']==c['expected_current_payer_role'] for c in cases)
    result={'schema':'independent-payment-outgoing-recipient-regression/v1','result':'GREEN' if passed else 'RED',
        'cases':cases,'expected_rule':'known outgoing invoice recipient owns that note under the declared wallet facts',
        'privacy_target':'FAIL_when_role_is_recovered','privacy_qualification':False,'native_acceptance':False,
        'heldout_draws':0,'source_freeze_sha256':args.freeze_sha256}
    (out/'RESULTS.json').write_bytes(canonical(result));print(json.dumps({'result':result['result'],'calibrated_cases':2,'privacy_qualification':False}),flush=True)
    if not passed:raise SystemExit(1)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--freeze',required=True);p.add_argument('--freeze-sha256',required=True);p.add_argument('--output',required=True);main(p.parse_args())
