#!/usr/bin/env python3
"""PUBLIC-only checks of selected canonical receipt/metadata/routing functions."""
from pathlib import Path
import ast,hashlib,json,os,re,runpy,stat,types
repo=Path.cwd();here=repo/'.local/owner-fr32-integrated-controls-01';read=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
source=repo/'poc/local-private-payment/private_batch_trial/private_lifecycle.py';raw=read(source);tree=ast.parse(raw)
def need(ok,code):
 if not ok:raise ValueError(code)
namespace={'need':need,'wallet_history':types.SimpleNamespace(SCOPE='PUBLIC_CONTROL_SCOPE'),
 're':re,'stat':stat,'checked':lambda p:Path(p)}
for name in ['public_receipt','private_leaf']:
 node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name)
 exec(compile(ast.Module(body=[node],type_ignores=[]),str(source),'exec'),namespace)
controls=0
def rejects(call):
 global controls
 try:call()
 except ValueError:controls+=1;return
 raise RuntimeError('public-negative-accepted')
valid={'schema':'kpb-original-lifecycle-operation/v1','operation':'pay','scope':'PUBLIC_CONTROL_SCOPE',
 'private_original_or_witness_exported':False,'accepted_backing_or_native_settlement':False,
 'actual_output_proofs':2,'actual_restricted_intent_signature':True,'actual_signature_normalization':True,
 'owner_private_auxiliary_values':2635409,'owner_input_encoding':'KPB_OWNER_FR32V2',
 'owner_private_file_bytes':84333120,'original_seed_recovered_input':True,'input_kind_exported':False,
 'creator_output_correspondence_exported':False}
need(namespace['public_receipt'](valid,'pay')==valid,'positive-v2-public-status');controls+=1
old={k:v for k,v in valid.items() if k not in ['owner_input_encoding','owner_private_file_bytes']}
rejects(lambda:namespace['public_receipt'](old,'pay'))
for key,value in [('owner_input_encoding','KPB_OWNER_INPUT_V1'),('owner_private_file_bytes',84333119),('private_original_or_witness_exported',True)]:
 bad={**valid,key:value};rejects(lambda:namespace['public_receipt'](bad,'pay'))
bad={**valid,'private_nf_hex':'00'*32};rejects(lambda:namespace['public_receipt'](bad,'pay'))
fixture=here/'PUBLIC-FIXTURES'
for owner in range(3):
 p=fixture/f'PUBLIC-LARGE-{owner}.bin';namespace['private_leaf'](p,84333120);controls+=1
rejects(lambda:namespace['private_leaf'](fixture/'PUBLIC-A.txt',84333120))
# Select actual canonical producer constant without importing the full controller.
constants={}
for n in tree.body:
 if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ['OWNER_AUX','OWNER_AUX_SHA']:
  constants[n.targets[0].id]=eval(compile(ast.Expression(n.value),str(source),'eval'),{'ROOT':repo})
body=read(constants['OWNER_AUX'],constants['OWNER_AUX_SHA']);s=constants['OWNER_AUX'].lstat()
need(s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o500,'selected-public-producer');controls+=1
sources=[]
for name in ['private_batch_trial/private_lifecycle.py','private_batch_trial/lifecycle_worker.py','private_batch_trial/prepare_unfunded_batch.py','mpc-prover/financial/run_financial.py']:
 p=repo/'poc/local-private-payment'/name;body=read(p);text=body.decode()
 need('OWNER-PRIVATE-INPUT.txt' not in text and 'OWNER-PRIVATE-INPUT-V2.bin' in text,'new-file-only-caller');controls+=1
 if name.endswith(('lifecycle_worker.py','prepare_unfunded_batch.py')):
  need('kpi-owner-local-aux-public-receipt/v2' in text and 'kpi-owner-local-aux-public-receipt/v1' not in text,'new-receipt-only');controls+=1
 sources.append({'path':str(p),'sha256':hashlib.sha256(body).hexdigest()})
result={'schema':'kpi-owner-fr32-canonical-routing-controls/v1','status':'PASS','controls':controls,
 'canonical_sources':sources,'public_producer_sha256':constants['OWNER_AUX_SHA'],
 'exact_large_file_bytes_each':84333120,'metadata_only_owner_file_checks':True,
 'same_unchanged_private_leaf_path_checker_stub':'public harness passes preselected PUBLIC fixture Paths; unchanged checked() not re-tested',
 'owner_private_files_read_or_hashed':False,'financial_or_privacy_qualification':False}
(here/'ROUTING-RESULT.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'status':'PASS','controls':controls,'producer_sha256':constants['OWNER_AUX_SHA']}))
