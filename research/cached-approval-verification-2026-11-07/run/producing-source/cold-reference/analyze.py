#!/usr/bin/env python3
"""Actual fee/work summaries and explicit conditional observer views."""
import argparse,hashlib,itertools,json,math,pathlib
def read(p):return json.loads(p.read_text())
def privacy(run):
 reg=run/'registration';rows=[json.loads(l) for l in (reg/'operator.jsonl').read_text().splitlines()];issues=[r for r in rows if r['request']['kind']=='issue' and 'error' not in r['response']];redeems=[r for r in rows if r['request']['kind']=='redeem' and 'error' not in r['response']];assert len(issues)==len(redeems)==3
 claims=sorted(bytes(r['request']['operation']['statement']['nullifier']).hex() for r in issues);keys=sorted(r['response']['recipientKey'] for r in redeems);assert len(set(claims))==len(set(keys))==3
 approvals=read(run/'APPROVALS.json');assert sorted(bytes(o['statement']['nullifier']).hex() for o in approvals['operations'])==claims
 assert sorted(bytes(p[3:-1]).hex() for p in approvals['intent']['payouts'])==keys
 candidates=[dict(zip(claims,p)) for p in itertools.permutations(keys)]
 # Auxiliary truth is read only for validation and the explicitly broader views.
 # No wallet backup, native secret or proving parameter is read.
 truth={};by_actor={}
 for who in range(3):
  client=read(run/f'private/wallet-{who}/registration.json');nf=bytes(client['issue']['operation']['statement']['nullifier']).hex();key=bytes.fromhex(client['message'])[-32:].hex();truth[nf]=key;by_actor[who]=(nf,key)
 assert truth in candidates
 calls=[json.loads(l) for l in (run/'actor-calls.jsonl').read_text().splitlines()];labelled=[c['actor'] for c in calls if c['request']['method']=='registration-redeem'];assert len(labelled)==3
 order_facts={by_actor[who][0]:row['response']['recipientKey'] for who,row in zip(labelled,redeems)};assert order_facts==truth
 known={by_actor[0][0]:by_actor[0][1]};colluding={nf:key for who,(nf,key) in by_actor.items() if who!=0}
 count=lambda facts:sum(all(c[k]==v for k,v in facts.items()) for c in candidates)
 return {'scope':'three fixed eligible-claimant roles, actual service transcript and whole-output-set authorization; not real-world population anonymity','serviceOnlyCompatibleAssignments':len(candidates),'oneParticipantOwnKeyKnown':count(known),'allButOneParticipantsColluding':count(colluding),'labelledControllerRedemptionOrder':count(order_facts),'laterAllOwnersDisclosed':count(truth),'truthCompatible':True,'nativeOrWalletSecretsRead':False,'controllerPrivateCommandsAutomaticallyServiceFacts':False,'networkTrafficTimingIndependentlyQualified':False,'withdrawalAmountsHidden':False,'independentPeople':False,'completeFinancialPrivacyQualified':False,'publicCombinedAuxiliaryPublicationRevealsOwners':True}
def costs(run):
 assert read(run/'COMPLETE.json')['complete'];caches={}
 for p in (run/'cache').glob('*/REPORT.json'):
  r=read(p);caches[r['journalHex'][-64:]]=r
 settlements={}
 for p in run.glob('*/TRANSACTION.json'):
  r=read(p);settlements[r['transaction']['id']]=(p.parent.name,read(p.parent/'REPORT.json'))
 result={}
 for name in ('MAIN','REFERENCE'):
  data=read(run/(name+'.json'));records=data['records'];native=sum(r['report']['feeSompi'] for r in records);proof=0.;cache_seconds=0.;fresh_seconds=0.;used=set();steps=[]
  for r in records[1:]:
   tx=r['transaction'];h=hashlib.sha256(bytes.fromhex(tx['payload'])).hexdigest();cache=caches[h];label,fresh=settlements[tx['id']];new=h not in used;used.add(h)
   if new:cache_seconds+=cache['seconds']
   fresh_seconds+=fresh['seconds'];steps.append({'name':label,'staticPacketSha256':h,'cacheCreationSeconds':cache['seconds'] if new else 0.,'freshSettlementSeconds':fresh['seconds'],'nativeFeeSompi':r['report']['feeSompi']})
  cancellation=read(run/'CANCELLATION.json')['seconds'];proof=cache_seconds+fresh_seconds+cancellation
  # Frozen illustrative valuation from prior work, explicitly NOT a current offer.
  tariff=.13;kas_usd=.02987;proof_reference_kas=proof/3600*tariff/kas_usd
  result[name]={'nativeFeeSompi':native,'nativeFeeKAS':native/1e8,'completeReceipts':len(records)-1,'principalSompi':4_000_000_000,'usefulPaymentSompi':4_700_000_000,'nativeFeePercentOfUsefulPayments':native/4_700_000_000*100,'staticCacheCreationSeconds':cache_seconds,'freshSettlementSeconds':fresh_seconds,'discardedCancellationWallSeconds':cancellation,'proofWorkSecondsIncludingColdCachesAndCancellation':proof,'frozenReferenceNativeAndProofOnlyKAS':native/1e8+proof_reference_kas,'frozenReferenceNativeAndProofOnlyPercent':(native/1e8+proof_reference_kas)/47*100,'frozenReferenceUSDPerHour':tariff,'frozenReferenceKASUSD':kas_usd,'actualCommercialPriceOrInvoice':False,'sharedCacheCreationChargedToEachCompleteHistory':True,'steps':steps,'withdrawalWaitSeconds':data['withdrawalWaitSeconds'],'paymentReadiness':data['paymentReadiness']}
 result['nativeFeeSavingSompi']=result['REFERENCE']['nativeFeeSompi']-result['MAIN']['nativeFeeSompi'];result['nativeFeeSavingPercent']=result['nativeFeeSavingSompi']/result['REFERENCE']['nativeFeeSompi']*100
 calls=[json.loads(l) for l in (run/'actor-calls.jsonl').read_text().splitlines()];wallet=[c for c in calls if c['request']['method'] in ('credit','transfer','registration-issue','approve','named')];proofs=sum(c['response']['result'].get('proofs',0) for c in wallet)
 result['walletCalls']={'genuineWalletProofs':proofs,'inclusiveCallSeconds':sum(c['response']['seconds'] for c in wallet),'proofCountsByMethod':{m:sum(c['response']['result'].get('proofs',0) for c in wallet if c['request']['method']==m) for m in sorted({c['request']['method'] for c in wallet})},'includesColdParameterLoadingAndOnionCalls':True,'someCallsOverlapOuterProvingSoDoNotAddWallTimes':True}
 result['notPriced']=['wallet CPU/cold parameter loading','onion/issuer operation','whole-host electricity and hardware','idle capacity, availability, storage and commercial margin'];result['completeCostQualified']=False;result['unboundedLoadQualified']=False;result['chainAccepted']=False
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument('run',type=pathlib.Path);p.add_argument('new_output',type=pathlib.Path);a=p.parse_args();a.new_output.mkdir();out={'privacy':privacy(a.run),'costs':costs(a.run)}
 (a.new_output/'ANALYSIS.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
if __name__=='__main__':main()
