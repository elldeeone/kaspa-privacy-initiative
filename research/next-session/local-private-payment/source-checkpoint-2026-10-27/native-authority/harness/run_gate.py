"""SOURCE ONLY: future one-identity synthetic matrix run, not executed in preparation.
Root must separately select source freeze, built artifacts, resource scope and GO.
All local bodies enter through unchanged helper09. No private paths or RPC.
"""
import argparse,copy,hashlib,json,os,runpy,stat,struct,subprocess,time
from pathlib import Path

BASE=Path('/var/tmp/kpi-nativeauthspend-preparation-vyqdmzti')
BUILD=Path('/var/tmp/kpi-nativeauthspend-work-01/build-01')
RUN=Path('/var/tmp/kpi-nativeauthspend-work-01/run-01')
HELPER='/var/tmp/kpi-root-guard-helper-09.py'
H=runpy.run_path(HELPER)
P=21888242871839275222246405745257275088548364400416034343698204186575808495617
Q=2736030358979909402780800718157159386076813972158567259200215660948447373041

def need(v,c):
    if not v:raise ValueError(c)
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,pin=None):return H['read'](str(p),pin)
def admit(p,pin):
    d=read(p,pin['sha256']);need(len(d)==pin['bytes'],'ARTIFACT_LENGTH');return d
def encoded(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def save(name,body):
    p=RUN/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with p.open('xb')as f:f.write(body)
    d=read(p);return {'path':str(p),'bytes':len(d),'sha256':sha(d)}
def payload(v):return encoded(v)

class Runner:
    def __init__(self,commands):self.c=commands;self.events=[];self.serial=0
    def call(self,kind,v,label,expect_error=None):
        self.serial+=1;tag=f'{self.serial:03d}-{label}';argv=list(self.c['run'][kind]);start=time.time()
        if kind=='witness':
            ip=f'{tag}.input.json';op=f'{tag}.wtns';save(ip,encoded(v))
            argv=[x.replace('/work/INPUT.json','/work/'+ip).replace('/work/OUTPUT.wtns','/work/'+op)for x in argv];inp=None
        else:inp=payload(v)
        result=subprocess.run(argv,input=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
        out=save(tag+'.stdout',result.stdout);err=save(tag+'.stderr',result.stderr)
        event={'label':label,'argv':argv,'returncode':result.returncode,'elapsedSeconds':time.time()-start,'stdout':out,'stderr':err};self.events.append(event)
        if expect_error:
            need(result.returncode==2,'EXPECTED_PARSER_EXIT2');e=json.loads(read(err['path'],err['sha256']));need(e.get('code')==expect_error,'EXPECTED_EXACT_PARSER_CODE');return e
        need(result.returncode==0,'FIRST_PROCESS_FAILURE:'+label)
        if kind=='witness':return read(RUN/op)
        return json.loads(read(out['path'],out['sha256']))

def mutate_wtns(raw,wire,value):
    # Deliberate direct inconsistent assignment; no recomputation/host SAT claim.
    need(raw[:4]==b'wtns'and struct.unpack_from('<I',raw,4)[0]==2,'WTNS_VERSION');nsec=struct.unpack_from('<I',raw,8)[0];need(nsec==2,'WTNS_SECTIONS');at=12;sections={}
    for _ in range(nsec):
        typ,length=struct.unpack_from('<IQ',raw,at);at+=12;need(typ not in sections and at+length<=len(raw),'WTNS_SECTION_BOUNDS');sections[typ]=(at,length);at+=length
    need(at==len(raw)and set(sections)=={1,2},'WTNS_EXACT_EOF');hd,hl=sections[1];need(hl==40 and struct.unpack_from('<I',raw,hd)[0]==32 and int.from_bytes(raw[hd+4:hd+36],'little')==P,'WTNS_FIELD');n=struct.unpack_from('<I',raw,hd+36)[0];v,l=sections[2];need(l==32*n and 0<=wire<n and 0<=value<1<<256,'WTNS_VECTOR');out=bytearray(raw);out[v+wire*32:v+(wire+1)*32]=value.to_bytes(32,'little');return bytes(out)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--freeze',required=True);ap.add_argument('--freeze-sha256',required=True);ap.add_argument('--selection',required=True);ap.add_argument('--selection-sha256',required=True);a=ap.parse_args()
    freeze=json.loads(read(a.freeze,a.freeze_sha256));need(freeze['status']=='SOURCE_ONLY_UNCOMPILED_UNEXECUTED','SOURCE_FREEZE_STATUS')
    for x in freeze['files']:
        rel=Path(x['path']);need(not rel.is_absolute()and '..'not in rel.parts,'SOURCE_PATH');admit(BASE/rel,x)
    selected=json.loads(read(a.selection,a.selection_sha256));need(selected['schema']=='kpi-nativeauth-postbuild-selection/v1'and selected['sourceFreezeSha256']==a.freeze_sha256,'POSTBUILD_SELECTION')
    required={'nativeBinary':'target/release/kpi-nativeauthspend-seam','cppBinary':'cpp0/private_authorization_cpp/private_authorization','cppDat':'cpp0/private_authorization_cpp/private_authorization.dat','ordinaryR1cs':'ordinary/private_authorization.r1cs','cpp0R1cs':'cpp0/private_authorization.r1cs','sym':'ordinary/private_authorization.sym'}
    need(set(selected['artifacts'])==set(required),'POSTBUILD_EXACT_SELECTION');art={}
    for name,rel in required.items():
        pin=selected['artifacts'][name];need(pin['path']==str(BUILD/rel),'POSTBUILD_PATH');art[name]=admit(BUILD/rel,pin)
    need(art['ordinaryR1cs']==art['cpp0R1cs'],'ORDINARY_CPP0_BYTE_IDENTITY')
    commands=json.loads(read(BASE/'COMMANDS-01.json'));control=json.loads(read(BASE/'CONTROLS-01.json'));need(commands['run_root']==str(RUN)and commands['build_root']==str(BUILD),'COMMAND_ROOTS')
    need(not RUN.exists(),'FRESH_RUN_ID_REQUIRED');RUN.mkdir(mode=0o700);st=RUN.stat();need(st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o700,'RUN_OWNER_MODE')
    r=Runner(commands);results=[]
    try:
        matrix_request={'mode':'matrix','ordinaryR1csHex':art['ordinaryR1cs'].hex(),'cpp0R1csHex':art['cpp0R1cs'].hex(),'symHex':art['sym'].hex()}
        prepared=r.call('node',matrix_request,'matrix-preparation');matrix=bytes.fromhex(prepared['matrix']['hex']);mapping=bytes.fromhex(prepared['mapping']['hex']);md=json.loads(matrix);mp=json.loads(mapping)
        need(sha(matrix)==prepared['matrix']['sha256']and sha(mapping)==prepared['mapping']['sha256'],'NORMALIZED_PINS');need(md['nInstances']==67 and md['nPublicInputs']==66 and md['nOutputs']==0,'PREFIX')
        matrix_pin=save('normalized-signature-matrix.json',matrix);map_pin=save('signature-public-map.json',mapping)
        frozen={'mappingSha256':map_pin['sha256'],'normalizedMatrixSha256':matrix_pin['sha256']}
        # This immutable selection is saved BEFORE public keys, signatures or controls.
        save('PRE-CONTROL-MATRIX-SELECTION.json',encoded({'schema':'kpi-nativeauth-pre-control-selection/v1','sourceFreezeSha256':a.freeze_sha256,'postbuildSelectionSha256':a.selection_sha256,'matrix':matrix_pin,'mapping':map_pin,'dimensions':{k:md[k]for k in ['nVars','nInstances','nWitnesses','nOutputs','nPublicInputs','nConstraints']},'frozen':frozen}))
        names={x['name']:x['raw']for x in mp['publicMap']};need(len(names)==66 and set(names.values())==set(range(1,67)),'PUBLIC_BIJECTION')
        keys=r.call('node',{'mode':'keys'},'public-known-keys')['ownerKeys'];derived=r.call('native',{'mode':'derive','ownerKeys':keys},'derive-native-fixture')
        base=r.call('python',{'mode':'build','derived':derived,'variant':'base'},'build-base');changed=r.call('python',{'mode':'build','derived':derived,'variant':'coordinator'},'build-substitution')
        def revalidate(bundle,label):r.call('python',{'mode':'revalidate','bundle':bundle},label+'-public-checks')
        def sign(bundle,role,label):
            revalidate(bundle,label);return r.call('node',{'mode':'sign','role':role,'packetHex':bundle['packetHex']},label+'-owner-authorization')
        auth=sign(base,0,'base');changed_auth=sign(changed,0,'changed-consent');wrong_key_auth=sign(base,1,'wrong-key')
        def prepare(bundle,authorization,label,explicit=None):
            v={'mode':'prepare','packetHex':bundle['packetHex'],'authorization':authorization}
            if explicit is not None:v['explicitPreimages']=explicit
            return r.call('node',v,label+'-verifier-aux')
        sig_input=prepare(base,auth,'base')
        raw_baseline=None
        def run_case(cid,bundle,authorization=None,signature_input=None,native_input=None,outer=False,direct=None):
            nonlocal raw_baseline
            revalidate(bundle,cid)
            si=copy.deepcopy(signature_input)if signature_input is not None else prepare(bundle,authorization,cid)
            raw=r.call('witness',si,cid+'-cpp0')if direct is None else mutate_wtns(raw_baseline,direct[0],direct[1])
            if cid=='P01_BASE':raw_baseline=raw
            request=dict(matrix_request,mode='witness',wtnsHex=raw.hex(),frozen=frozen);normal=r.call('node',request,cid+'-normalize')
            need(normal['matrix']['sha256']==matrix_pin['sha256']and normal['mapping']['sha256']==map_pin['sha256'],'CHANGED_MATRIX_OR_MAPPING')
            wbytes=bytes.fromhex(normal['witness']['hex']);save(cid+'.normalized-witness.json',wbytes)
            out=r.call('native',{'mode':'check','case':cid,'packetHex':bundle['packetHex'],'nativeInput':native_input or bundle['nativeInput'],'signatureMatrixHex':matrix.hex(),'signatureWitnessHex':wbytes.hex(),'pins':{'matrixSha256':matrix_pin['sha256'],'witnessSha256':sha(wbytes),'mappingSha256':map_pin['sha256']},'referenceOutputs':bundle['referenceOutputs'],'outerLowPlusOne':outer},cid+'-actual-matrices')
            want=next(x['expected']for x in control['cases']if x['id']==cid);got=[out['nativeFailures'],out['signatureFailures'],out['linkFailures']]
            need(all((g>0 if w=='positive'else g==w)for g,w in zip(got,want)),'UNEXPECTED_RESIDUAL_REGION:'+cid);need(out['referenceOutputFailures']==[0,0]and out['jointInstances']==3,'REFERENCE_OR_PREFIX')
            need(out['checked']==out['jointRows']==out['nativeRows']+out['signatureRows']+68,'ALL_ROWS_CHECKED');need(out['componentNativeFailures']==out['nativeFailures']and out['componentSignatureFailures']==out['signatureFailures'],'COMPONENT_REGION_PARITY')
            results.append(out)
        run_case('P01_BASE',base,signature_input=sig_input)
        run_case('N01_COORDINATOR_SUBSTITUTION',changed,authorization=auth)
        run_case('P02_RECONSENTED_SUBSTITUTION',changed,authorization=changed_auth)
        run_case('N02_KEY_COPY_LINK',base,authorization=wrong_key_auth)
        run_case('N03_OUTER_LIMB_LINK',base,signature_input=sig_input,outer=True)
        for cid,value in [('N04_SCALAR_PLUS_Q',int(auth['S'])+Q),('N05_SCALAR_EQ_Q',Q)]:
            s=copy.deepcopy(sig_input);s['sigS']=str(value);run_case(cid,base,signature_input=s)
        run_case('N06_BYTE_256_DIRECT',base,signature_input=sig_input,direct=(names['main.ownerKeyBytes[0]'],256))
        run_case('N07_DIGEST_2P128_DIRECT',base,signature_input=sig_input,direct=(names['main.digestLimbs[0]'],1<<128))
        ni=copy.deepcopy(base['nativeInput']);n=bytearray.fromhex(ni['noteHex']);n[0]^=1;ni['noteHex']=n.hex();run_case('N08_NATIVE_OWNER_DIRECT',base,signature_input=sig_input,native_input=ni)
        ni=copy.deepcopy(base['nativeInput']);ni['position']=3+65536;run_case('N09_NATIVE_HIGH_POSITION',base,signature_input=sig_input,native_input=ni)
        s=copy.deepcopy(sig_input);s['preimageA'][0]=str((int(s['preimageA'][0])+1)%P);run_case('N10_PREIMAGE_DIRECT',base,signature_input=s)
        s=copy.deepcopy(sig_input);s['sigR8']=['0','1'];s['preimageR8']=['0','1'];run_case('N11_R8_IDENTITY',base,signature_input=s)
        action=copy.deepcopy(base);pb=bytearray.fromhex(action['packetHex']);pb[193+48]^=1;action['packetHex']=pb.hex();run_case('N12_ACTION_REPLAY',action,authorization=auth)
        for cid,y in [('N13_KEY_IDENTITY',1),('N14_KEY_TORSION',P-1)]:
            badkeys=list(keys);badkeys[0]=(bytes(32)+y.to_bytes(32,'little')).hex();d=r.call('native',{'mode':'derive','ownerKeys':badkeys},cid+'-derive');bundle=r.call('python',{'mode':'build','derived':d,'variant':'base'},cid+'-bundle');bad=copy.deepcopy(auth);bad['ownerKeyHex']=badkeys[0];s=prepare(bundle,bad,cid,{'A':['0',str(y)],'R8':sig_input['preimageR8']});run_case(cid,bundle,signature_input=s)
        tiny=r.call('native',{'mode':'boundary'},'tiny-boundaries');need([x['case']for x in tiny['cases']]==['ONE_ZERO','ONE_TWO','SHORT','LONG']and all(x['verdict']=='ASSIGNMENT_REFUSAL'and x['checked']==0 for x in tiny['cases']),'TINY_BOUNDARIES')
        alias=mutate_wtns(raw_baseline,names['main.ownerKeyBytes[0]'],P);req=dict(matrix_request,mode='witness',wtnsHex=alias.hex(),frozen=frozen);refusal=r.call('node',req,'raw-field-P',expect_error='NONCANONICAL_FIELD')
        need(len(results)==16,'MATRIX_CASE_COUNT');save('RESULT-01.json',encoded({'schema':'kpi-nativeauth-executed-gate/v1','status':'ACTUAL_BOUNDED_MATRIX_CONTROLS_PASS','sourceFreezeSha256':a.freeze_sha256,'postbuildSelectionSha256':a.selection_sha256,'results':results,'tinyBoundaries':tiny,'rawFieldAlias':refusal,'events':r.events,'scope':'ONE_NEW_AUTHORITY_SEAM_NO_SETUP_PROOF_MPC_ACCEPTED_NATIVE_PROFILE_EXIT_PRIVACY_FEE_OR_DELIVERY'}))
    except BaseException as e:
        save('FIRST-FAILURE-01.json',encoded({'status':'STOP_FIRST_UNEXPECTED_FAILURE','type':type(e).__name__,'message':str(e),'events':r.events,'completedCases':results}));raise

if __name__=='__main__':main()
