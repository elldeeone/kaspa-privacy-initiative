from pathlib import Path
import json,os,subprocess,hashlib,time
BIN=Path('/prover');OUT=Path('/out');CANARY=b'KPX4/PUBLIC/BEFORE-WITNESS/v1\n'+bytes(range(128));BUILD='8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a';D='35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6'
records=[]
def one(role,pk,label,good=False,code=None):
 readfd,writefd=os.pipe();dest=OUT/(label+'-must-not-produce-proof');began=time.monotonic()
 if not good:os.write(writefd,CANARY);os.close(writefd);writefd=None
 try:
  child=subprocess.Popen([str(BIN),'prove',role,pk,str(readfd),str(dest)],pass_fds=(readfd,),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
  if good:
   line=child.stdout.readline();ready=json.loads(line);m=json.loads(Path('/manifest-'+role+'.json').read_bytes());raw=Path('/manifest-'+role+'.json').read_bytes();expected={'event':'parameters-ready','role':role,'output_arity':{'compact2':2,'wide32':32}[role],'parameter_manifest_sha256':hashlib.sha256(raw).hexdigest(),'domain_hex32':D,'vk_sha256':m['vk_sha256'],'compiled_build_identity_sha256':BUILD};assert ready==expected,'READY identity mismatch'
   os.close(writefd);writefd=None;rest,err=child.communicate(timeout=1800);result=json.loads(rest);assert result=={'event':'error','code':'private_request_invalid'} and child.returncode!=0 and not dest.exists();retained=None
  else:
   result,err=child.communicate(timeout=1800);assert json.loads(result)=={'event':'error','code':code} and child.returncode!=0 and not dest.exists();retained=os.read(readfd,len(CANARY)+1);assert retained==CANARY and 'parameters-ready'not in result
  assert not err and not dest.exists()
  row={'label':label,'role':role,'expected_early_error_code':code,'full_parameter_readiness_before_any_witness_bytes':good,'early_rejection_canary_bytes_retained':len(retained)if retained is not None else None,'all_checks_passed':True,'wall_seconds':time.monotonic()-began,'private_owner_input_read':False,'proof_output_created':False}
  records.append(row);print(json.dumps(row),flush=True)
 finally:
  os.close(readfd)
  if writefd is not None:os.close(writefd)
for role in ['compact2','wide32']:one(role,'/pk-'+role+'.bin','ready-'+role,good=True)
for role in ['compact2','wide32']:one(role,'/missing.bin','missing-'+role,code='parameter_pk_io')
one('compact2','/pk-wide32.bin','wrong-role-compact',code='parameter_pk_length')
one('wide32','/pk-compact2.bin','wrong-role-wide',code='parameter_pk_length')
one('compact2','/bad-corrupt.bin','same-length-corrupt',code='parameter_pk_digest')
one('compact2','/bad-short.bin','short',code='parameter_pk_length')
one('compact2','/bad-trailing.bin','trailing',code='parameter_pk_length')
report={'schema':'kpx4-actual-parameter-readiness-controls/v1','all_checks_passed':True,'cases':records,'actual_two_full_authenticated_PK_loads':True,'wrong_domain_VK_dimensions_and_authenticated_trailing_decoder_controls':'Separate eight tiny-parameter unit tests; do not claim those used full real keys','private_inputs_input_hashes_seed_paths_or_canary_values_published':False,'actual_owner_proof_or_network_execution':False};(OUT/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
