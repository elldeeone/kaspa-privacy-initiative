#!/usr/bin/env python3
"""Finite public evidence export. Never copy runtime folders wholesale."""
import argparse,hashlib,json,pathlib,shutil
ROOT=pathlib.Path(__file__).resolve().parents[2]
PROOF_FILES=('input.bin','journal.bin','expected-journal.bin','receipt.bin','candidate-compressed.bin','native-proof.bin','REPORT.json','TRANSACTION.json','NATIVE.json')
def read(p):return json.loads(p.read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('new_public_output',type=pathlib.Path);a=p.parse_args();out=a.new_public_output.resolve()
 d=read(ROOT/'.local/cached-approval-verification/CURRENT.json');diag=pathlib.Path(d['run']);c=read(ROOT/'.local/cached-approval-verification/COMBINED.json');combined=pathlib.Path(c['run']);t=read(ROOT/'.local/cached-approval-verification/TESTNET.json');trial=pathlib.Path(t['trial'])
 assert read(diag/'DIAGNOSTIC.json')['sameEconomicJournal'];assert read(combined/'flow/COMPLETE.json')['complete'];assert read(combined/'cold-reference/COMPLETE.json')['complete'];assert read(trial/'COMPLETE.json')['freshTN10RehearsalComplete'];out.mkdir()
 selected=[]
 def copy(src,target):
  src=pathlib.Path(src);target=out/target;assert src.is_file() and not src.is_symlink();assert not any(x in ('private','__pycache__','target','reference-recovery-private') for x in target.relative_to(out).parts)
  target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target);selected.append({'path':str(target.relative_to(out)),'bytes':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
 def files(src,target,names,required=False):
  for name in names:
   f=src/name
   if f.is_file():copy(f,pathlib.Path(target)/name)
   elif required:raise FileNotFoundError(f)
 def proofs(src,target):files(src,target,PROOF_FILES)
 def source(src,target):
  for f in src.rglob('*'):
   if not f.is_file() or f.is_symlink():continue
   rel=f.relative_to(src)
   if any(x in ('private','target','__pycache__') for x in rel.parts):continue
   allowed=f.suffix in ('.rs','.toml','.lock','.md','.py') or str(rel)=='SOURCE-REUSE.json' or (f.suffix=='.bin' and rel.parts[0] in ('pins','testnet-pins'))
   if allowed:copy(f,pathlib.Path(target)/rel)
 for src,label in [(diag/'source','diagnostic'),(combined/'source','combined'),(combined/'cold-reference-producing-source','cold-reference'),(trial/'producing-source','rehearsal')]:source(src,pathlib.Path('producing-source')/label)
 files(diag,'diagnostic',('source-freeze.json','DIAGNOSTIC.json','HOST-CONTROLS.json','ADVERSARIAL-ECONOMIC-CONTROLS.json','RECEIPT-CONTROLS.json','NATIVE-CONTROLS.json','PUBLIC-REPLAY.json','authorize.log','diagnostic.log'))
 for name in ('authorization.bin','settlement.bin'):copy(diag/'programs'/name,pathlib.Path('diagnostic/programs')/name)
 for i in range(3):files(diag/'cases'/str(i),f'diagnostic/cases/{i}',('input.bin','CASE.json'),True)
 proofs(diag/'authorization-cache','diagnostic/authorization-cache')
 for name in ('composed-0','composed-1','composed-2','direct-2'):proofs(diag/name,pathlib.Path('diagnostic')/name)
 for name in ('authorization.bin','settlement.bin'):copy(combined/'programs'/name,pathlib.Path('programs')/name)
 for src,label in [(combined/'flow','combined'),(combined/'cold-reference','cold-reference')]:
  files(src,label,('MAIN.json','REFERENCE.json','REFERENCE-RECOVERY.json','APPROVALS.json','ARRIVALS.json','HOST-CONTROLS.json','CANCELLATION.json','COMPLETE.json','SELECTION.json'))
  for cache in (src/'cache').iterdir():
   if cache.is_dir() and (cache/'REPORT.json').is_file():proofs(cache,pathlib.Path(label)/'cache'/cache.name)
  for phase in src.iterdir():
   if phase.is_dir() and (phase/'TRANSACTION.json').is_file():proofs(phase,pathlib.Path(label)/phase.name)
 files(combined,'campaign',('SOURCE-FREEZE.json','COLD-REFERENCE-HOST.json','PARAMETER-SETUP-REPORT.json','CONTROLLER-START-OBSERVATION.json','controller.log','runner.log','cold-reference.log','registration-controls.log','RESOURCE-SUMMARY.json','COLD-PUBLIC-REPLAY.json'))
 files(combined/'analysis','analysis',('ANALYSIS.json',),True)
 files(combined/'flow/registration','registration',('config.json','operator.jsonl','PUBLIC-REPLAY.json','PRIVACY-VIEWS.json','ADDITIVE-CONTROL-SELECTION.json','ADDITIVE-CONTROLS.json'))
 files(trial,'rehearsal',('COMPLETE.json','RECOVERY-PREPARED.json','FUNCTIONAL-PREFLIGHT.json','PARAMETER-SETUP-REPORT.json','SOURCE-FREEZE.json','DRIVER-REVISION.json','testnet-driver-cold-reference-gate.py','testnet-driver-source.py','PUBLIC-REPLAY.json'))
 for name in ('fund','initial','external','withdrawal','terminal'):
  files(trial,'rehearsal',(f'{name}-envelope.json',f'{name}-ACCEPTED.json',f'WORLD-{name}.json'))
  if name!='fund':proofs(trial/name,pathlib.Path('rehearsal')/name)
 files(trial,'rehearsal',('ordinary-funding-envelope.json','ordinary-funding-accepted.json','APPROVALS.json','APPROVAL-CACHE.json'))
 for i in range(5):files(trial,'rehearsal',(f'recovery-{i}-envelope.json',f'recovery-{i}-accepted.json'),True)
 for cache in (trial/'cache').iterdir():
  if cache.is_dir() and (cache/'REPORT.json').is_file():proofs(cache,pathlib.Path('rehearsal/cache')/cache.name)
 files(trial/'conditional-negative','conditional-negative',('REPORT.json',),True)
 files(trial/'conditional-negative','conditional-negative',('conditional-succinct.bin','conditional-compressed.bin','native-proof.bin','NATIVE-REFUSAL.json'))
 if t.get('supersedesUnfundedHarnessFailure'):
  previous=pathlib.Path(t['supersedesUnfundedHarnessFailure']);failure=read(previous/'FAILURE.json');assert 'unresolved-control' in failure['error'];assert not (previous/'ordinary-funding-submission-intent.json').exists()
  summary={'trialDirectory':previous.name,'stage':'Claim-only negative-control harness','testCoinSubmissions':0,'failure':'SDK refused Claim-only assumption earlier than the harness expected','oldFailureSha256':hashlib.sha256((previous/'FAILURE.json').read_bytes()).hexdigest(),'correction':'retain exact SDK refusal layer; production proof checks unchanged; use fresh identity'}
  target=out/'failures/unfunded-expectation-correction.json';target.parent.mkdir(parents=True,exist_ok=True);target.write_text(json.dumps(summary,indent=2)+'\n');selected.append({'path':str(target.relative_to(out)),'bytes':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
 files(trial/'registration','rehearsal/registration' ,('config.json','operator.jsonl'))
 # Exact final selected typed observations; raw RPC traces remain private.
 files(trial,'rehearsal',('final-independent-corroboration-snapshot.json',))
 manifest={'schema':'KPI-cached-verification-public-evidence-v1','files':sorted(selected,key=lambda x:x['path']),'privateWalletNativeKeysBlindingStateOrParametersIncluded':False,'rawPrivateRpcTracesIncluded':False,'observerWarning':'owner-labelled recovery controls and other auxiliary disclosures are broader than the conditional registration-service view'}
 (out/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n');print(len(selected),'explicitly selected public files exported')
if __name__=='__main__':main()
