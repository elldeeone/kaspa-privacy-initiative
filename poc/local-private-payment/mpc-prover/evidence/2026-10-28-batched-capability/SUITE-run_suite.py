#!/usr/bin/env python3
"""Sequential fixed-build public MPC controls; stop on the first surprise."""
import argparse, ast, hashlib, json, os, secrets, subprocess, sys, time
from pathlib import Path
BASE=Path(__file__).resolve().parents[2]
SUITE=Path(__file__).resolve().parent
BUILD=BASE/'.local/mpc-batched-capability-build-03'
SOURCE=BASE/'poc/local-private-payment/mpc-prover'
RUNNER=SOURCE/'tests/run_batched_capability.py'
VERIFIER=BASE/'.local/mpc-prover-public-model-target-02/release/kpi-mascot-public-model'
MODEL=BASE/'.local/mpc-prover-vendor/public-model-01/public_model.txt'
RUNS=BASE/'.local/mpc-batched-capability-runs'
VENDOR=BASE/'.local/mpc-prover-softspoken-vendor'
MODEL_SHA='ef8e22906f0c4dc232cbd49e0905db10000ed3ba4d87020516d449066ffc30d9'
VERIFIER_SHA='24ab066b767d1cbe5e268b39dbb2dce53a1d26607be82a2a670e15b3bd666d4c'
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,data):
 t=p.with_suffix(p.suffix+'.new');t.write_text(json.dumps(data,indent=2)+'\n');t.replace(p)
def cases():
 for node in ast.parse(RUNNER.read_text()).body:
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CASES' for t in node.targets):return list(ast.literal_eval(node.value))
 raise RuntimeError('case list missing')
def checked_inputs(plan):
 b=json.loads((BUILD/'BUILD-RESULT.json').read_text())
 if digest(BUILD/'BUILD-RESULT.json')!=plan['build_result_sha256'] or digest(Path(__file__))!=plan['orchestrator_sha256']:raise RuntimeError('selected suite/build manifest changed')
 if b['success'] is not True or digest(BUILD/'mpc-batched-capability')!=b['link']['sha256']:raise RuntimeError('selected binary changed')
 for n,h in b['source_sha256'].items():
  if digest(SOURCE/n)!=h:raise RuntimeError('selected source changed: '+n)
 for item in b['vendor_artifacts']+b['reused_objects']:
  if digest(Path(item['path']))!=item['sha256']:raise RuntimeError('selected public artifact changed')
 if digest(VERIFIER)!=VERIFIER_SHA or digest(MODEL)!=MODEL_SHA:raise RuntimeError('selected public verifier/model changed')
 return True

def execute(case,plan):
 checked_inputs(plan)
 rid=secrets.token_hex(32)
 if (RUNS/rid).exists():raise RuntimeError('fresh identity collision')
 argv=[sys.executable,str(RUNNER),'--binary',str(BUILD/'mpc-batched-capability'),'--verifier',str(VERIFIER),'--model',str(MODEL),'--vendor-root',str(VENDOR),'--output-parent',str(RUNS),'--expected-model-sha256',MODEL_SHA,'--expected-verifier-sha256',VERIFIER_SHA,'--case',case,'--run-id',rid]
 entry={'case':case,'run_id':rid,'status':'STARTING','argv':argv,'source_freeze_checked_before':True}
 save(SUITE/(case+'.json'),entry)
 started=time.monotonic();observed_peak=0;peak_stream=None;complete_peak=False
 with (SUITE/(case+'.controller.stdout')).open('xb') as out,(SUITE/(case+'.controller.stderr')).open('xb') as err:
  process=subprocess.Popen(argv,cwd=BASE,stdout=out,stderr=err)
  last_lookup=0.0
  while process.poll() is None:
   now=time.monotonic()
   if peak_stream is None and now-last_lookup>=0.5:
    last_lookup=now
    result=subprocess.run(['systemctl','--user','show','kpi-batched-capability-'+rid+'.scope','--property=ControlGroup','--value'],capture_output=True,text=True)
    cg=result.stdout.strip()
    if result.returncode==0 and cg.startswith('/'):
     try:peak_stream=(Path('/sys/fs/cgroup')/cg.lstrip('/')/'memory.peak').open()
     except FileNotFoundError:pass
   if peak_stream:
    try:
     peak_stream.seek(0);observed_peak=max(observed_peak,int(peak_stream.read().strip()))
    except OSError:pass
   time.sleep(0.1)
  if peak_stream:
   try:
    peak_stream.seek(0);observed_peak=max(observed_peak,int(peak_stream.read().strip()));complete_peak=True
   except OSError:pass
   peak_stream.close()
 entry.update(returncode=process.returncode,wall_seconds=time.monotonic()-started,observed_cgroup_memory_peak_bytes=observed_peak,final_peak_read_succeeded=complete_peak)
 public=RUNS/rid/'public'
 if process.returncode==0 and (public/'RESULT.json').is_file():
  result=json.loads((public/'RESULT.json').read_text())
  if result.get('status')=='PASS' and result.get('case')==case and result.get('run_id')==rid and len(result.get('parties',[]))==3:
   checked_inputs(plan);entry.update(status='PASS',public_result=str(public/'RESULT.json'),source_freeze_checked_after=True)
  else:entry['status']='UNEXPECTED_RESULT'
 else:
  entry['status']='UNEXPECTED_RESULT'
  failure=public/'FAILED.json'
  if failure.is_file():entry['typed_failure']=json.loads(failure.read_text())
 save(SUITE/(case+'.json'),entry)
 print(json.dumps({k:entry[k] for k in ['case','run_id','status','returncode','wall_seconds','observed_cgroup_memory_peak_bytes','final_peak_read_succeeded']}),flush=True)
 return entry

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--first',action='store_true');parser.add_argument('--continue-suite',action='store_true');args=parser.parse_args()
 if args.first==args.continue_suite:raise SystemExit('select first or continue-suite')
 plan_path=SUITE/'PLAN.json';state_path=SUITE/'RESULT.json'
 if args.first:
  if plan_path.exists() or state_path.exists():raise SystemExit('first case already initiated; no repeat')
  plan={'schema':'kpi-batched-capability-suite-plan/v1','cases':cases(),'build_result_sha256':digest(BUILD/'BUILD-RESULT.json'),'orchestrator_sha256':digest(Path(__file__)),'stop_on_first_unexpected_result':True,'fresh_identity_each_case':True,'raw_worker_diagnostics_or_TLS_private_keys_read_or_hashed':False}
  save(plan_path,plan);state={'schema':'kpi-batched-capability-suite/v1','status':'RUNNING','cases':[]};save(state_path,state)
  selected=plan['cases'][:1]
 else:
  plan=json.loads(plan_path.read_text());state=json.loads(state_path.read_text())
  if state['status']!='PARTIAL_PASS' or any(e['status']!='PASS' for e in state['cases']):raise SystemExit('cannot continue a failed or complete suite')
  if [e['case'] for e in state['cases']]!=plan['cases'][:len(state['cases'])]:raise SystemExit('nonsequential recorded case set')
  selected=plan['cases'][len(state['cases']):]
 for case in selected:
  entry=execute(case,plan);state['cases'].append(entry)
  state['status']='STOPPED_ON_UNEXPECTED_RESULT' if entry['status']!='PASS' else ('PASS' if len(state['cases'])==len(plan['cases']) else 'PARTIAL_PASS')
  state['raw_worker_diagnostics_or_TLS_private_keys_read_or_hashed']=False;save(state_path,state)
  if entry['status']!='PASS':raise SystemExit(1)
 print(json.dumps({'suite_status':state['status'],'cases_passed':len(state['cases']),'suite_result':str(state_path)}),flush=True)
if __name__=='__main__':main()
