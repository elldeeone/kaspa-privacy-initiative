#!/usr/bin/env python3
"""Finite public TN10 evidence export. Wallet, issuer and Tor files stay private."""
import argparse,hashlib,json,pathlib,shutil

def read(p):return json.loads(p.read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('private_trial',type=pathlib.Path);p.add_argument('new_public_output',type=pathlib.Path);a=p.parse_args();src=a.private_trial.resolve();dst=a.new_public_output.resolve();dst.mkdir()
 def copy(source,name):
  source=src/source;assert source.is_file() and not source.is_symlink(),source;target=dst/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
 for source,name in [('registration/config.json','config.json'),('registration/bundle.json','bundle.json'),('registration/operator.jsonl','operator.jsonl'),('bundle-envelope.json','bundle-envelope.json'),('bundle-submission-intent.json','bundle-submission-intent.json'),('APPROVALS.json','APPROVALS.json'),('COMPLETE.json','COMPLETE.json'),('SERVICE-PREDICTION.json','SERVICE-PREDICTION.json'),('SERVICE-PREDICTION-SEAL.json','SERVICE-PREDICTION-SEAL.json'),('SERVICE-SCORE.json','SERVICE-SCORE.json'),('READER-CONTROLS.json','READER-CONTROLS.json'),('final-independent-corroboration-snapshot.json','final-snapshot.json')]:copy(source,name)
 stages=['ordinary-funding','fund','initial','bundle','external','withdrawal','terminal']+[f'recovery-{i}' for i in range(5)]
 for stage in stages:copy(f'{stage}-accepted.json',f'accepted/{stage}.json')
 bundle=(dst/'bundle.json').read_bytes();accepted=read(dst/'accepted/bundle.json');envelope=read(dst/'bundle-envelope.json');assert accepted['confirmed']>=10 and accepted['transactionId']==envelope['record']['transactionId'] and accepted['transaction']['payload']==bundle.hex()
 receipts=[]
 for who in range(3):
  path=src/f'private/wallet-{who}';r=read(path/'accepted-bundle-receipt.json');assert r['transactionId']==accepted['transactionId'] and r['confirmations']>=10 and (path/'accepted-bundle.json').read_bytes()==bundle
  receipts.append({'route':r['route'],'transactionId':r['transactionId'],'confirmations':r['confirmations'],'bundleSha256':hashlib.sha256(bundle).hexdigest()})
 assert sorted(r['route'] for r in receipts)==['blue','blue','green']
 (dst/'READERS.json').write_text(json.dumps({'separateWalletReaderProcesses':3,'independentPublicRpcOperators':2,'receipts':receipts,'sameHostOnly':True,'selfValidatedChainHeaders':False},indent=2)+'\n')
 for path in dst.rglob('*'):
  if path.is_file():
   raw=path.read_bytes();assert all(marker not in raw for marker in (b'blindSecret',b'issuer.der',b'sourceKeyPath',b'backup.json')),path
 files=[{'path':str(path.relative_to(dst)),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in sorted(dst.rglob('*')) if path.is_file()]
 (dst/'MANIFEST.json').write_text(json.dumps({'files':files,'privateMaterialIncluded':False,'scope':'one-host TN10 research; accepted transactions and two public RPC operators, no global privacy or production qualification'},indent=2)+'\n')
 print(len(files),'public evidence files exported')
if __name__=='__main__':main()
