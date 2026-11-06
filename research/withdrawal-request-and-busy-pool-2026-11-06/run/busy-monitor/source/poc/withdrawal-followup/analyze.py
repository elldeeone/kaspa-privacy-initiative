#!/usr/bin/env python3
"""Seal operator-view predictions before accessing controlled owner disclosures."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import sys

OWNERS=['owner-1','owner-2','owner-3']
SOURCES={f'127.0.0.{i+2}':owner for i,owner in enumerate(OWNERS)}
def read(p):return json.loads(p.read_text())
def write(p,v):
    with p.open('x') as f:json.dump(v,f,sort_keys=True,indent=2);f.write('\n')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def logs(p):return [json.loads(line) for line in p.read_text().splitlines()]
def predict(events,windows=(),disclosures=()):
    successes=[e for e in events if 'error' not in e['response']]
    payouts=[e for e in successes if e['request']['kind']=='redeem']
    if len(payouts)!=3:raise ValueError('incomplete three-output cohort')
    keys=sorted(e['response']['recipientKey'] for e in payouts)
    facts={}
    for event in payouts:
        ip=event['peer'].rsplit(':',1)[0]
        owner=SOURCES.get(ip)
        possible=[w['owner'] for w in windows if w['startedUnix']<=event['timestampUnix']<=w['finishedUnix'] and w['kind']=='redeem']
        if len(set(possible))==1:owner=possible[0]
        if owner:facts[event['response']['recipientKey']]=owner
    for fact in disclosures:facts[fact['recipientKey']]=fact['owner']
    candidates=[dict(zip(keys,p)) for p in itertools.permutations(OWNERS)]
    candidates=[c for c in candidates if all(c.get(k)==o for k,o in facts.items())]
    if not candidates:raise ValueError('observer eliminated execution possibilities')
    return {'payoutOwnerAssignments':candidates,'count':len(candidates),'uniquelyIdentifiedPayouts':sum(len({c[k] for c in candidates})==1 for k in keys),'scope':'conditional on three honest distinct owners; one owner may control multiple eligible notes in reality'}

def main():
    network=Path(sys.argv[1]);unequal=Path(sys.argv[2]);out=Path(sys.argv[3]);out.mkdir()
    complete=read(network/'COMPLETE.json');assert complete['completed']
    predictions={}
    for mode in ('direct','onion'):
        events=logs(network/mode/'operator.jsonl')
        write(out/(mode+'-operator.json'),events)
        predictions[mode]=predict(events)
        write(out/(mode+'-prediction.json'),predictions[mode])
        # Baseline must retain every valid candidate under field/order changes.
        shuffled=copy.deepcopy(events);shuffled.reverse()
        for e in shuffled:e['peer']=e['peer'].rsplit(':',1)[0]+':1'
        assert predict(shuffled)==predictions[mode]
    public=read(unequal/'public.json')
    assert public['scope'].startswith('genuine wallet proofs')
    records=public['records']
    small_values=[o['value'] for o in records[0]['transaction']['outputs'][1:]]
    assert small_values==[500_000_000]*3
    changes=[]
    for record in records[1:]:
        # Identify the principal by its EXIT statement, excluding bank/refund.
        # The public raw transaction has an exact principal output; retained
        # input decoding and genuine proof verification happen in Rust replay.
        outputs=record['transaction']['outputs']
        payout=outputs[1] if record!=records[-1] else outputs[0]
        changes.append(payout['value'])
    histories=[]
    funding=public['initialPublicFundingSompi'];common=small_values[0]
    for a,b,c in itertools.permutations(changes):
        x=2*common+b+c;y=common+c
        if funding-x==common+a and x-y==common+b:
            histories.append({'aliceToBobSompi':x,'bobToCarolSompi':y,'finalBalancesSompi':[common+a,common+b,common+c]})
    write(out/'unequal-unmapped-prediction.json',{'possibleHistories':histories,'count':len(histories),'assumptions':'known Alice-funded 60 KAS; known A->B->C roles, no other payments; unknown ownership of later payouts; all three honestly exit 5 KAS first'})
    write(out/'BASE-SEAL.json',{'privateTruthReadBeforeSeal':False,'observerSha256':digest(Path(__file__)),'files':{p.name:digest(p) for p in out.iterdir() if p.is_file()}})
    # Both counterfactuals deliberately share a research fixture. Publishing
    # the identified control makes these particular destinations identifiable.
    published=[{'recipientKey':key,'owner':owner} for key,owner in predictions['direct']['payoutOwnerAssignments'][0].items()]
    combined=predict(logs(network/'onion/operator.jsonl'),disclosures=published)
    assert combined['count']==1
    write(out/'onion-plus-published-direct-control.json',{'prediction':combined,'explicitAdditionalFacts':published,'scope':'combining published counterfactual fixtures reveals their shared keys; this is not an anonymous live-user trial'})
    # Explicitly disclosed auxiliary facts, after base predictions are sealed.
    truth=read(network/'fixture/private/truth.json')
    actual={t['recipientKey']:t['owner'] for t in truth}
    for mode,p in predictions.items():assert actual in p['payoutOwnerAssignments'],mode
    onion=logs(network/'onion/operator.jsonl')
    windows=[read(p) for p in sorted((network/'fixture/private').glob('client-event-*.json'))]
    windows=[w for w in windows if w['mode']=='onion']
    if not windows:raise ValueError('actual client timing windows were not retained')
    timed=predict(onion,windows=windows);assert actual in timed['payoutOwnerAssignments']
    write(out/'onion-plus-client-timing.json',{'prediction':timed,'explicitAdditionalObservation':windows,'scope':'observer has measured client-side request intervals and owner identity as well as service logs; not a timing-only attack by the service'})
    known=predict(onion,disclosures=truth);assert known['count']==1
    write(out/'onion-plus-owner-disclosure.json',known)
    issue_by_nf={bytes(e['request']['operation']['statement']['nullifier']).hex():e['request']['operation']['statement']['exit_value'] for e in onion if e['request']['kind']=='issue' and 'error' not in e['response']}
    identified_amounts={t['owner']:issue_by_nf[t['nullifier']] for t in truth}
    write(out/'onion-plus-known-nullifiers.json',{'explicitAdditionalFacts':[{'owner':t['owner'],'nullifier':t['nullifier']} for t in truth],'identifiedWithdrawalSompi':identified_amounts,'payoutOwnerAssignmentsStill':predict(onion)['count'],'scope':'known nullifier ownership exposes each identified exit amount despite blind output registration'})
    ut=read(unequal/'private/truth.json');x,y=ut['paymentsSompi']
    assert any(h['aliceToBobSompi']==x and h['bobToCarolSompi']==y for h in histories)
    owners=ut['owners'];balances=[t['commonSompi']+t['changeSompi'] for t in owners]
    inferred=[funding-balances[0],balances[2]]
    assert inferred==[x,y]
    write(out/'unequal-later-owner-disclosure.json',{'explicitAdditionalFacts':owners,'identifiedFinalBalancesSompi':balances,'inferredPaymentsSompi':inferred,'actualPaymentsSompi':[x,y],'possibleHistories':1,'scope':'known later owner-to-payout maps expose arithmetic; not a claim that the chain alone supplies those identities'})
    assert len({o['changeSompi'] for o in owners})==3
    write(out/'unequal-known-entitlement.json',{'explicitAdditionalFacts':[{'owner':o['owner'],'expectedChangeSompi':o['changeSompi']} for o in owners],'publicChangeSompi':changes,'possibleChangeOwnerAssignments':1,'scope':'distinct public amounts map to owners when an observer already knows their individual expected withdrawal amounts; fresh keys and Tor cannot hide the public values'})
    write(out/'RESULT.json',{'directServicePayoutOwnerAssignments':predictions['direct']['count'],'onionServicePayoutOwnerAssignments':predictions['onion']['count'],'onionWithClientTimingAssignments':timed['count'],'onionWithOwnerDisclosureAssignments':known['count'],'unequalUnmappedHistories':len(histories),'unequalLaterKnownOwnerHistories':1,'knownPaymentsRecoveredSompi':inferred,'permutationAndPeerPortInvariance':True,'privateTruthReadAfterBaseSeal':True,'limits':'one host, three honest local wallets, finite role model; Tor hides service-side origin, not both-ended traffic correlations, known NF maps, distinctive known entitlements or later disclosure'})

if __name__=='__main__':main()
