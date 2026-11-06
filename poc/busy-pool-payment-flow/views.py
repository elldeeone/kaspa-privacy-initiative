#!/usr/bin/env python3
"""Separate identified payout registration from private client instructions."""
import json
from pathlib import Path
import sys

run=Path(sys.argv[1])
calls=json.loads((run/'SERVICE.json').read_text())['calls']
intent=json.loads((run/'APPROVALS.json').read_text())['intent']
links=[]
for call in calls:
    if call['request']['method']!='entitlement':continue
    result=call['response']['result']
    assert result['nullifier'] in intent['claims'] and result['payout'] in intent['payouts']
    approvals=[c for c in calls if c['actor']==call['actor'] and c['request']['method']=='approve']
    assert len(approvals)==1
    assert approvals[0]['response']['result']['operations'][0]['statement']['nullifier']==result['nullifier']
    links.append({'identifiedSession':call['actor'],'claimNullifier':bytes(result['nullifier']).hex(),
                  'payoutSpk':bytes(result['payout']).hex(),'publicValueSompi':intent['denomination']})
assert len(links)==len(intent['claims'])==3
assert len({x['payoutSpk'] for x in links})==3
later=[]
for call in calls:
    if call['request']['method']=='named':
        later.extend({'identifiedSession':call['actor'],'payoutSpk':bytes(p['spk']).hex(),'valueSompi':p['value']}
                     for p in call['response']['result']['payouts'])
assert len(later)==5
view={'identifiedWithdrawalRegistration':{'facts':links,'ownerPayoutAssignments':1,
       'basis':'actual entitlement responses publish claim nullifier and own payout together in an identified local session'},
      'laterIdentifiedPayouts':later,
      'controllerTrace':{'artifact':'SERVICE.json','includesPrivateClientInstructions':True,
        'scope':'the research controller drives all wallets; credit/transfer instructions are not automatically withdrawal-service knowledge'},
      'knownContactGraphControl':{'basis':'separately supplied contact graph and frozen ordinary-change four-wallet workload',
        'doNotUsePrivateClientInstructionAmountsAsObserverEvidence':True},
      'protectedRegistrationRetested':False,'independentPeople':False,'chainAccepted':False}
with Path(sys.argv[2]).open('x') as f:json.dump(view,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({'identifiedPayoutLinks':len(links),'laterPayoutLinks':len(later),'privateKeysRead':False}))
