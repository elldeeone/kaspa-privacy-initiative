from pathlib import Path
import json,os,subprocess,hashlib,time
role='wide32';rawmanifest=Path('/manifest.json').read_bytes();manifest=json.loads(rawmanifest);r,w=os.pipe();began=time.monotonic()
child=subprocess.Popen(['/prover','prove',role,'/parameters.pk',str(r),'/out/proof'],pass_fds=(r,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
ready=json.loads(child.stdout.readline());assert ready=={'event':'parameters-ready','role':role,'output_arity':manifest['output_arity'],'parameter_manifest_sha256':hashlib.sha256(rawmanifest).hexdigest(),'domain_hex32':manifest['domain_hex32'],'vk_sha256':manifest['vk_sha256'],'compiled_build_identity_sha256':manifest['compiled_build_identity_sha256']}
# The pipe was EMPTY until actual whole-key authenticated READY.
request=Path('/public-canary.json').read_bytes();view=memoryview(request)
while view:n=os.write(w,view);view=view[n:]
os.close(w);os.close(r);stdout,stderr=child.communicate(timeout=3600);assert child.returncode==0 and not stderr
complete=json.loads(stdout);assert complete['event']=='proof-complete' and complete['genuine_Groth16_verified'] and complete['role']==role
report=json.loads(Path('/out/proof/report.json').read_bytes());assert report['role']==role and report['compiled_build_identity_sha256']==manifest['compiled_build_identity_sha256'] and report['genuine_Groth16_verified']
summary={'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_NOTE_NF_DISJOINT_FROM_MAIN','role':role,'parameters_authenticated_before_canary_read_and_write':True,'genuine_Groth16_verified':True,'wall_seconds':time.monotonic()-began,'proof_sha256':report['proof_sha256'],'authorization_sha256':report['authorization_sha256'],'vk_sha256':report['vk_sha256'],'parameter_manifest_sha256':ready['parameter_manifest_sha256'],'no_actual_owner_backup_or_private_witness_hash':True}
Path('/out/SUMMARY.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n');print(json.dumps(summary),flush=True)
