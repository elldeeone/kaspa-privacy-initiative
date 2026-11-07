#!/usr/bin/env python3
"""Replay public exact-bundle, reader, observer, and payout-spend claims."""
import argparse,hashlib,importlib.util,json,pathlib
def read(p):return json.loads(p.read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('public_run',type=pathlib.Path);a=p.parse_args();root=a.public_run;manifest=read(root/'MANIFEST.json')
 for f in manifest['files']:
  b=(root/f['path']).read_bytes();assert len(b)==f['bytes'] and hashlib.sha256(b).hexdigest()==f['sha256']
 bundle=(root/'bundle.json').read_bytes();accepted=read(root/'accepted/bundle.json');envelope=read(root/'bundle-envelope.json');intent=read(root/'bundle-submission-intent.json')
 assert accepted['confirmed']>=10 and accepted['transactionId']==envelope['record']['transactionId']==intent['transactionId'];assert accepted['transaction']['payload']==envelope['record']['transaction']['payload']==bundle.hex()
 readers=read(root/'READERS.json');assert readers['separateWalletReaderProcesses']==3 and readers['independentPublicRpcOperators']==2 and readers['sameHostOnly'] and not readers['selfValidatedChainHeaders']
 controls=read(root/'READER-CONTROLS.json');assert all(controls[k] for k in ('realAcceptedPass','withholdingRefused','reorgRefused','alteredPayloadRefused','alteredOutputRefused','issuerProvidedRouteRefused')) and not controls['forcedLiveReorgTested']
 assert sorted(r['route'] for r in readers['receipts'])==['blue','blue','green']
 assert all(r['transactionId']==accepted['transactionId'] and r['confirmations']>=10 and r['bundleSha256']==hashlib.sha256(bundle).hexdigest() for r in readers['receipts'])
 complete=read(root/'COMPLETE.json');assert complete['freshTN10RehearsalComplete'] and complete['acceptedAtomicBundle'] and complete['confirmedRestoredPayoutSpends']==5 and complete['terminalBankValueSompi']==0 and complete['totalPaidFeeSompi']==sum(complete['paidFeesSompi'].values())
 stage=['ordinary-funding','fund','initial','bundle','external','withdrawal','terminal']+[f'recovery-{i}' for i in range(5)]
 tx={name:read(root/f'accepted/{name}.json') for name in stage};assert all(v['confirmed']>=10 and v['transactionId']==v['transaction']['verboseData']['transactionId'] for v in tx.values())
 previous={v['transactionId']:v['transaction']['outputs'] for v in tx.values()}
 for name in stage[1:]:
  inputs=tx[name]['transaction']['inputs'];assert len(inputs)==1
  point=inputs[0]['previousOutpoint']
  if name=='bundle':
   source=envelope['entries'][0];assert point==source['outpoint']
   input_value=source['utxoEntry']['amount']  # Supplied source snapshot, not independently fetched here.
  else:input_value=previous[point['transactionId']][point['index']]['value']
  paid=input_value-sum(o['value'] for o in tx[name]['transaction']['outputs'])
  assert paid==complete['paidFeesSompi'][name] and paid>0
 assert complete['paidFeesSompi']['ordinary-funding']>0  # Its source UTXO belongs to a prior trial.
 payouts={(tx['withdrawal']['transactionId'],i) for i in (1,2,3)} | {(tx['terminal']['transactionId'],i) for i in (0,1)}
 assert [tx['withdrawal']['transaction']['outputs'][i]['value'] for i in (1,2,3)]==[30_000_000]*3
 assert [tx['terminal']['transaction']['outputs'][i]['value'] for i in (0,1)]==[6_000_000,24_000_000]
 spent=[]
 for i in range(5):
  input=tx[f'recovery-{i}']['transaction']['inputs'][0]['previousOutpoint'];point=(input['transactionId'],input['index']);assert point in payouts and point not in spent;spent.append(point)
 assert set(spent)==payouts
 module=pathlib.Path(__file__).with_name('observe.py');spec=importlib.util.spec_from_file_location('observe',module);observer=importlib.util.module_from_spec(spec);spec.loader.exec_module(observer)
 assert observer.observe(root)==read(root/'SERVICE-PREDICTION.json');score=read(root/'SERVICE-SCORE.json');assert score['exactCorrectOwnerKeyLinks']==0 and score['compatibleMappings']==6 and score['predictionSha256']==hashlib.sha256((root/'SERVICE-PREDICTION.json').read_bytes()).hexdigest()
 assert read(root/'SERVICE-PREDICTION-SEAL.json')['predictionSha256']==score['predictionSha256']
 print('public manifest, exact accepted bundle, three readers, service view, five payout spends and linked fees checked')
if __name__=='__main__':main()
