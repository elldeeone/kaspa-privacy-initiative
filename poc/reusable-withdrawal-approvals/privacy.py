#!/usr/bin/env python3
"""Payout-ownership regression under explicit public-chain/prover observation."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
def read(p):return json.loads(p.read_text())
def write(p,v):
    with p.open('x') as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def hexhash(v):return bytes(v).hex()
def predict(view,owner_links=()):
    if view['schema']!='reusable-intent-full-public-view-v1':raise ValueError('schema')
    intent=view['approvals']['intent'];ops=view['approvals']['operations']
    claim_set=set(map(hexhash,intent['claims']))
    owners=sorted({f['owner'] for f in view['knownClaimOwners'] if f['nullifier'] in claim_set})
    assert len(owners)==len(ops)==len(intent['claims'])==2
    assert len({hexhash(o['statement']['exit_destination']) for o in ops})==1
    assert all(o['statement']['exit_value']==intent['denomination'] for o in ops)
    keys=sorted(bytes(s)[3:35].hex() for s in intent['payouts'])
    final=view['records'][-1]
    paid=sorted(o['scriptPublicKey'][6:70] for o in final['transaction']['outputs'][:2])
    assert paid==keys
    assert final['publicPacket']['intent']==intent
    facts={f['recipientKey']:f['owner'] for f in owner_links}
    candidates=[dict(zip(keys,p)) for p in itertools.permutations(owners)]
    candidates=[c for c in candidates if all(c.get(k)==v for k,v in facts.items())]
    assert candidates
    return {'payoutOwnerAssignments':candidates,'count':len(candidates),'amountPerOwnerSompi':intent['denomination'],'assumptions':'two honest distinct note owners, full common-set authorization and cryptographic privacy; no hidden operation-position labels or anonymity against published solo controls'}

def main():
    run,view_path,out=map(Path,sys.argv[1:4]);out.mkdir()
    view=read(view_path)
    old=read(ROOT/'research/batched-payment-costs-2026-11-06/run/core/30-kas/batched/registration.json')
    view['knownClaimOwners']=[{'nullifier':e['claim'],'owner':e['owner']} for e in old['events'] if e['kind']=='issue']
    prediction=predict(view)
    write(out/'main-observation.json',view);write(out/'main-prediction.json',prediction)
    altered=copy.deepcopy(view);altered['knownClaimOwners'].reverse()
    assert predict(altered)==prediction
    renamed=copy.deepcopy(view);names={f['owner']:'person-'+str(i) for i,f in enumerate(view['knownClaimOwners'])}
    for fact in renamed['knownClaimOwners']:fact['owner']=names[fact['owner']]
    assert predict(renamed)['count']==prediction['count']
    write(out/'BASE-SEAL.json',{'privateTruthReadBeforeSeal':False,'observerSha256':sha(Path(__file__)),'files':{p.name:sha(p) for p in out.iterdir() if p.is_file()},'scope':'main local history and complete public prover/native data; counterfactual solo disclosures supplied separately'})
    # The public alternative Bob-solo world provides an explicit owner mapping.
    # It is NOT part of the main chain. Combining published synthetic fixtures
    # defeats their anonymity and is kept as a failure control.
    solo=read(run/'spent-world.json')['records'][-1]
    tx=solo['transaction'];value=read(run/'APPROVALS.json')['intent']['denomination']
    payout=next(o for o in tx['outputs'] if o['value']==value and len(o['scriptPublicKey'])==72)
    bob=next(f['owner'] for f in view['knownClaimOwners'] if f['owner']=='owner-2')
    fact={'owner':bob,'recipientKey':payout['scriptPublicKey'][6:70]}
    combined=predict(view,[fact]);assert combined['count']==1
    write(out/'published-solo-counterfactual.json',{'explicitExtraFact':fact,'prediction':combined,'scope':'combining the public counterfactual with shared payout keys identifies the cohort; no claim these published research keys remain anonymous'})
    write(out/'RESULT.json',{'mainPayoutOwnerAssignments':prediction['count'],'knownParticipantOrPublishedSoloAssignments':combined['count'],'sameWholeSetConsent':True,'newIndividualClaimToPayoutField':False,'amountsHidden':False,'generalFinancialPrivacyQualified':False,'independentClientsQualified':False,'sourceViewSha256':sha(view_path),'permutationInvariance':True})

if __name__=='__main__':main()
