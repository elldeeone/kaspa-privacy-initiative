#!/usr/bin/env python3
"""Seal no-truth predictions, then participant controls and validation separately."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import observe

def write(p,v):
    with p.open('x') as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    run=Path(sys.argv[1]);views=Path(sys.argv[2]);out=Path(sys.argv[3]);out.mkdir()
    reg=observe.read(run/'30-kas/batched/registration.json')
    observations={}
    for name,source in [('named-separate','30-kas-named'),('named-batched','30-kas-named-batched'),('candidate','30-kas-batched')]:
        observations[name]={'schema':'batched-payment-ownership-v1','registration':reg,'publicView':observe.read(views/(source+'.json')),'sideInformation':[]}
    observations['candidate-75']={'schema':'batched-payment-ownership-v1','registration':observe.read(run/'75-kas/batched/registration.json'),'publicView':observe.read(views/'75-kas-batched.json'),'sideInformation':[]}
    predictions={}
    def seal(name,view):
        write(out/(name+'-observation.json'),view)
        result=observe.predict(view);write(out/(name+'-prediction.json'),result);predictions[name]=result
    for name,view in observations.items():seal(name,view)
    files={p.name:sha(p) for p in out.iterdir() if p.is_file()}
    write(out/'BASE-PREDICTION-SEAL.json',{'files':files,'observerSha256':sha(Path(observe.__file__)),'privateTruthReadBeforeSeal':False,'scope':'three separate counterfactual worlds, no published-baseline disclosure to candidate'})
    # Participant/external disclosures now construct additional observer views.
    truth_record=observe.read(run/'30-kas/private/registration-truth.json')
    owners=truth_record['ownerPayouts'];facts=[{'owner':x['owner'],'recipientKey':x['recipientKey']} for x in owners]
    for name,n in [('one-participant',1),('all-but-one',2),('all-known',3),('old-published-destinations',3)]:
        view=copy.deepcopy(observations['candidate']);view['sideInformation']=facts[:n];seal(name,view)
    view=copy.deepcopy(observations['candidate'])
    for e in view['registration']['events']:
        if e['kind']=='redeem':e['owner']=next(x['owner'] for x in facts if x['recipientKey']==e['recipientKey'])
    seal('leaked-origin',view)
    view=copy.deepcopy(observations['candidate'])
    for e in view['registration']['events']:
        if e['kind']=='issue':e['leakedRandomizer']=next(x['randomizer'] for x in owners if x['owner']==e['owner'])
    seal('leaked-randomizer',view)
    write(out/'CONTROL-PREDICTION-SEAL.json',{'files':{p.name:sha(p) for p in out.iterdir() if p.is_file()},'observerSha256':sha(Path(observe.__file__)),'participantFactsAreExplicitSideInformation':True})
    truth={x['owner']:x['recipientKey'] for x in owners}
    truth75={x['owner']:x['recipientKey'] for x in observe.read(run/'75-kas/private/registration-truth.json')['ownerPayouts']}
    for name,prediction in predictions.items():assert (truth75 if name=='candidate-75' else truth) in prediction['completeOwnershipAssignments'],name
    counts={name:p['assignmentCount'] for name,p in predictions.items()}
    assert counts=={'named-separate':1,'named-batched':1,'candidate':6,'candidate-75':6,'one-participant':2,'all-but-one':1,'all-known':1,'old-published-destinations':1,'leaked-origin':1,'leaked-randomizer':1},counts
    assert predictions['named-batched']['identifiedWithdrawnSompiByOwner']==predictions['candidate']['identifiedWithdrawnSompiByOwner']
    assert len(predictions['candidate']['identifiedWithdrawnSompiByOwner'])==3
    # Relabeling humans and changing display order cannot create evidence.
    base=observations['candidate'];v=copy.deepcopy(base)
    v['registration']['owners'].reverse()
    v['registration']['events']=list(reversed(v['registration']['events'][:3]))+list(reversed(v['registration']['events'][3:]))
    assert observe.predict(v)['assignmentCount']==6
    v=copy.deepcopy(base);rename={o:'renamed-'+str(i) for i,o in enumerate(v['registration']['owners'])}
    v['registration']['owners']=[rename[o] for o in v['registration']['owners']]
    for e in v['registration']['events']:
        if 'owner'in e:e['owner']=rename[e['owner']]
    assert observe.predict(v)['assignmentCount']==6
    v=copy.deepcopy(base);v['unreviewed']=1
    try:observe.predict(v)
    except ValueError:pass
    else:raise AssertionError('unknown observation field accepted')
    write(out/'VALIDATION.json',{'counts':counts,'baseSealSha256':sha(out/'BASE-PREDICTION-SEAL.json'),'controlsSealSha256':sha(out/'CONTROL-PREDICTION-SEAL.json'),'truthExcludedFromBasePrediction':True,'truthCompatibleWithEveryPrediction':True,'ownerLabelAndDisplayOrderInvariant':True,'unknownFieldsRefuse':True,'identifiedWithdrawalAmountsStillExact':True,'notAPaymentHistoryAmbiguityScore':True,'scope':'bounded public application/native/prover data; RSA blindness and proof ZK assumed; no network or independent-cohort evidence'})
    print(json.dumps(counts,indent=2))
if __name__=='__main__':main()
