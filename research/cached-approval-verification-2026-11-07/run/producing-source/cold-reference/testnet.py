#!/usr/bin/env python3
"""One fresh small TN10 rehearsal, after complete offline functional checks.

All submissions use the retained dual-route, exact-integer, one-shot transport.
An error preserves evidence and stops. A retry needs a new trial identity.
"""
import argparse,hashlib,importlib.util,json,os,pathlib,subprocess,time
ROOT=pathlib.Path(__file__).resolve().parents[2]
CHAIN=ROOT/'poc/recovery-tn10/live-chain.mjs'
s=importlib.util.spec_from_file_location('network',ROOT/'poc/withdrawal-followup/network.py');network=importlib.util.module_from_spec(s);s.loader.exec_module(network)
def read(p):return json.loads(p.read_text())
def write(p,v):
 with p.open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def main():
 a=argparse.ArgumentParser();a.add_argument('configuration',type=pathlib.Path);c=read(a.parse_args().configuration);trial=pathlib.Path(c['trial']);combined=pathlib.Path(c['qualifiedCombinedRun']);diagnostic=read(ROOT/'.local/cached-approval-verification/CURRENT.json');dr=pathlib.Path(diagnostic['run']);processes=[];files=[]
 env=dict(os.environ,RISC0_PROVER='ipc',RISC0_SERVER_PATH='/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools/r0vm-cuda',RISC0_HOME='/home/luke/projects/kpi-intensive-2026-10-22/observer/artifacts/groth16-compression-preparation/risc0-home',CUDA_VISIBLE_DEVICES='0',RAYON_NUM_THREADS='4',OMP_NUM_THREADS='4',MALLOC_ARENA_MAX='2',XDG_CACHE_HOME=str(trial/'xdg-cache'));env.pop('RISC0_DEV_MODE',None);env.pop('KPI_BATCH_REUSE_FROM',None)
 def call(label,args):
  with (trial/(label+'.log')).open('x') as log:
   print('START',label,flush=True);subprocess.run(list(map(str,args)),env=env,stdout=log,stderr=subprocess.STDOUT,check=True);print('DONE',label,flush=True)
 def query(label,addresses):
  call(label,['node',CHAIN,'query',trial,label,json.dumps(list(dict.fromkeys(addresses)))]);return trial/(label+'-snapshot.json')
 def submit(label,envelope):
  call(label,['node',CHAIN,'submit',trial,label,envelope]);accepted=trial/(label+'-accepted.json');assert read(accepted)['confirmed']>=10;return accepted
 def host(label,*args):call(label,[c['host'],*args])
 try:
  while not ((combined/'flow/COMPLETE.json').is_file() and (combined/'cold-reference/COMPLETE.json').is_file()):
   if 'Traceback' in (combined/'runner.log').read_text():raise RuntimeError('combined flow failed; trial remains unfunded')
   time.sleep(1)
  main=read(combined/'flow/MAIN.json');ref=read(combined/'flow/REFERENCE.json');assert main['reserve']==main['liability']==ref['reserve']==ref['liability']==0
  assert main['nativeFull'] and ref['nativeFull'] and len(main['restoredPayoutSpends'])==8
  for program in ('authorization.bin','settlement.bin'):assert (trial/'programs'/program).read_bytes()==(combined/'programs'/program).read_bytes()
  # Claim-only assumptions must fail strict SDK AND actual native verification.
  work=trial/'conditional-negative-work';work.mkdir();env['RISC0_WORK_DIR']=str(work)
  conditional=trial/'conditional-negative'
  call('unresolved-assumption-control',[diagnostic['controlsHost'],'unresolved-control',dr/'programs/authorization.bin',dr/'programs/settlement.bin',dr/'cases/0/input.bin',conditional])
  call('unresolved-native-control',[diagnostic['controlsHost'],'conditional-native',dr/'programs/settlement.bin',dr/'cases/0',conditional])
  assert read(conditional/'NATIVE-REFUSAL.json')['actualNativeFull']
  write(trial/'FUNCTIONAL-PREFLIGHT.json',{'completeOfflineComparisonPassed':True,'completeOfflinePayoutSpends':8,'realConditionalReceiptRefusedByNative':True,'sourceProgramSha256':{p:hashlib.sha256((trial/'programs'/p).read_bytes()).hexdigest() for p in ('authorization.bin','settlement.bin')},'scope':'functional preflight; actual terminal rehearsal still required'})
  print('Offline functional checks passed; starting fresh TN10 rehearsal.',flush=True)
  # Ordinary free test coins only; never spend an old bank reserve.
  source=read(trial/'SOURCE-FUNDING.json');assert source['ordinaryTestKASOnly'] and not source['oldBankReservesUsed']
  submit('ordinary-funding',trial/'ordinary-funding-envelope.json')
  public=read(trial/'PUBLIC.json');snapshot=query('fund-context',[public['fundingAddress']]);host('fund-build','live-build',trial,'fund',snapshot);accepted=submit('fund',trial/'fund-envelope.json');host('fund-commit','live-accept',trial,'fund',accepted)
  bank_addresses=[]
  def stage(phase,previous):
   previous=read(trial/(previous+'-envelope.json'));bank=previous['outputAddresses'][0];bank_addresses.append(bank)
   snapshot=query(phase+'-context',[bank]);host(phase+'-build','live-build',trial,phase,snapshot);accepted=submit(phase,trial/(phase+'-envelope.json'));host(phase+'-commit','live-accept',trial,phase,accepted)
  stage('initial','fund')
  service,socks=network.port(),network.port()
  for role in ('service','client'):
   data=trial/(role+'-tor');data.mkdir(mode=0o700);rc=data/'torrc';options=f'DataDirectory {data}\nLog notice stdout\nClientOnly 1\n'
   options+=(f'SocksPort 0\nHiddenServiceDir {data}/onion\nHiddenServicePort 80 127.0.0.1:{service}\n' if role=='service' else f'SocksPort 127.0.0.1:{socks} IsolateSOCKSAuth\nSafeSocks 1\n');rc.write_text(options)
   log=(trial/(role+'-tor.log')).open('x');files.append(log);processes.append(subprocess.Popen([str(network.TOR),'-f',str(rc)],stdout=log,stderr=subprocess.STDOUT))
  while not all('Bootstrapped 100%' in (trial/(role+'-tor.log')).read_text() for role in ('service','client')):
   if any(p.poll() is not None for p in processes):raise RuntimeError('Tor stopped; preserve trial and do not fall back to identified requests')
   time.sleep(1)
  transport=trial/'transport.json';write(transport,{'onion':(trial/'service-tor/onion/hostname').read_text().strip(),'socks':socks,'servicePort':service})
  host('prepare-owner-approvals','live-approvals',trial,transport);approval_hash=hashlib.sha256((trial/'APPROVALS.json').read_bytes()).hexdigest()
  # Issuer is already stopped by the host. Stop transport too before real updates.
  for p in processes:p.terminate()
  for p in processes:p.wait(timeout=20)
  stage('external','initial');stage('withdrawal','external');assert hashlib.sha256((trial/'APPROVALS.json').read_bytes()).hexdigest()==approval_hash
  stage('terminal','withdrawal')
  payout_addresses=[]
  for phase in ('withdrawal','terminal'):
   envelope=read(trial/(phase+'-envelope.json'));payout_addresses+=envelope['outputAddresses']
  snapshot=query('actual-terminal-payouts',payout_addresses);host('restore-and-sign-payouts','live-recovery',trial,snapshot)
  recovery=[]
  for i in range(5):
   accepted=submit(f'recovery-{i}',trial/f'recovery-{i}-envelope.json');recovery.append(read(accepted))
  # Independent synchronized routes compare every surviving payout and bank UTXO.
  snapshot=read(query('final-independent-corroboration',bank_addresses+payout_addresses))
  entries=snapshot['utxos']['entries'];points={(e['outpoint']['transactionId'],e['outpoint']['index']):e for e in entries}
  assert not any(e['address'] in set(bank_addresses) for e in entries),'continuing bank output remains'
  recovered=0
  for i in range(5):
   envelope=read(trial/f'recovery-{i}-envelope.json');txid=envelope['record']['transactionId'];original=envelope['record']['transaction']['inputs'][0]['previousOutpoint']
   assert (original['transactionId'],original['index']) not in points
   e=points[(txid,0)];assert e['utxoEntry']['amount']==envelope['record']['transaction']['outputs'][0]['value'];recovered+=e['utxoEntry']['amount']
  world=read(trial/'WORLD-terminal.json');assert world['value']==0
  paid={phase:read(trial/(phase+'-envelope.json'))['qualification']['feeSompi'] for phase in ['ordinary-funding','fund','initial','external','withdrawal','terminal'] if (trial/(phase+'-envelope.json')).exists()}
  # Ordinary source transfer uses a distinct filename.
  paid['ordinary-funding']=read(trial/'ordinary-funding-envelope.json')['qualification']['feeSompi']
  for i in range(5):paid[f'recovery-{i}']=read(trial/f'recovery-{i}-envelope.json')['qualification']['feeSompi']
  write(trial/'COMPLETE.json',{'freshTN10RehearsalComplete':True,'network':'testnet-10','principalSompi':400_000_000,'terminalBankValueSompi':0,'confirmedRestoredPayoutSpends':5,'recoveredPayoutValueAfterSpendFeesSompi':recovered,'originalOwnerApprovals':3,'repeatedOwnerApprovals':0,'approvalBytesUnchangedAfterRealAcceptedUpdate':True,'issuerAndTorStoppedBeforeExternalUpdateAndFinalWithdrawal':True,'paidFeesSompi':paid,'totalPaidFeeSompi':sum(paid.values()),'bothSynchronizedIndependentRoutesAgree':True,'consensusChanges':False,'sameHostOnly':True,'independentUsersQualified':False,'productionOrCompleteFinancialPrivacyQualified':False})
  print('Complete terminal TN10 rehearsal and five restored payout spends confirmed.',flush=True)
 except Exception as e:
  write(trial/'FAILURE.json',{'error':str(e),'doNotResubmit':True,'retryRequiresNewIdentity':True});raise
 finally:
  for p in processes:
   if p.poll() is None:p.terminate()
  for p in processes:
   try:p.wait(timeout=20)
   except subprocess.TimeoutExpired:p.kill();p.wait()
  for f in files:f.close()
if __name__=='__main__':main()
