#!/usr/bin/env python3
"""Genuine new Output/AuthExit component run over public unfunded seed vectors.

This is not the financial trial or privacy workload. It uses the actual mature
signature witness generator/normalizer and complete actual Rust constraints.
All produced PKs, witnesses and runtime records stay outside Git.
"""
import argparse
import copy
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import time

import exit_wire
import wallet_profile as wallet

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
AUTH=BASE/'native-authority'
JS_ROOT=Path('/var/tmp/kpi-signature-predicate-tools-20261026-01')
NODE=Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
CRYPTO=Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto')
BUILD=Path('/var/tmp/kpi-nativeauthspend-work-01/build-03')
LEAF_MAP=Path('/run/user/1000/kpi-nativeauthspend-resume-20261028-03/JS-INSTALLED-LEAF-MAP.json')
LEAF_MAP_SHA='00b536cab3799984c2a2f9895329bc410daa0f11f5093f10aa48d92f3abdca50'
MATRIX_SHA='b573a68be539426b1165e4f1b1d01f054a3ca275c7d7a1811ece99280bf17d11'
MAP_SHA='dfff3a6a7063aef13b053ad3e5ba96fc46c2b306c4d984747b0ddbb135290712'
PINS={
    'cpp0/private_authorization_cpp/private_authorization':'ae4afbca91cc9dc21e987ec680f5a494f8a7c104b2cb83d510869cc50e718a08',
    'cpp0/private_authorization_cpp/private_authorization.dat':'61735c1ae6ac1e04c9c82307f217f8853d6d47ba00849027598edfd9b787c4f9',
    'ordinary/private_authorization.r1cs':'808fa904af765ed3e39186269ca347b273fafd861a7579a321fa444b75d08a35',
    'cpp0/private_authorization.r1cs':'808fa904af765ed3e39186269ca347b273fafd861a7579a321fa444b75d08a35',
    'ordinary/private_authorization.sym':'288da5195c07905f560ea06730d645c1c40db0dfacd5dd9f608b5688792f32a4',
}
CONTROL_CASES=(
    ('P01_GENUINE_EXIT',(0,0,0)),
    ('N01_REDIRECT_WITH_STALE_SIGNATURE',(0,'positive',0)),
    ('P02_RECONSENTED_FEE_CHANGE',(0,0,0)),
    ('N02_ONE_SOMPI_PRIVATE_INFLATION',('positive',0,0)),
    ('N03_SIGNATURE_KEY_COPY_LINK',(0,0,'positive')),
    ('N04_HIGH_MEMBERSHIP_POSITION',('positive',0,0)),
    ('N05_WRONG_ORIGINAL_NF',('positive',0,0)),
    ('N06_SIGNATURE_SCALAR_PLUS_Q',(0,'positive',0)),
)


def need(value,code):
    if not value:raise ValueError(code)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def sha(value):return hashlib.sha256(value).hexdigest()


class Run:
    def __init__(self,args):
        self.output=Path(args.output).absolute()
        need(not self.output.exists(),'fresh-component-run-identity')
        self.output.mkdir(parents=True,mode=0o700)
        self.read=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
        self.binary=Path(args.binary).absolute();self.read(self.binary,args.binary_sha256)
        self.profile_raw=self.read(Path(args.profile).absolute(),args.profile_sha256)
        selected=json.loads(self.profile_raw)
        need(selected['status']=='UNFUNDED_COMPONENT_IDENTITY_NO_FINANCIAL_READINESS','unfunded-profile-selection')
        descriptor=selected['profile_descriptor']
        need(sha(json.dumps(descriptor,sort_keys=True,separators=(',',':')).encode())==selected['profile_id_hex32'],'profile-descriptor-identity')
        self.profile=wallet.Profile(bytes.fromhex(descriptor['domain_hex32']),bytes.fromhex(selected['profile_id_hex32']))
        self.descriptor=descriptor;self.serial=0;self.events=[]
        source_members=[]
        for name in ('component_run.py','wallet_profile.py','owner_authority.mjs','exit_wire.py'):
            body=self.read(HERE/name);source_members.append({'path':str(HERE/name),'sha256':sha(body)})
        frozen_source=BASE.parents[1]/'research/next-session/local-private-payment/source-checkpoint-2026-10-27/native-authority/SOURCE-FREEZE-02.json'
        frozen=json.loads(self.read(frozen_source,'9bded95d08ec2a372bd89b89d83b630155b1e095da7909b2696e423962320b71'))
        frozen={row['path']:row['sha256'] for row in frozen['files']}
        for name in ('harness/worker.mjs','source-bridge/signature-component-adapter-selected.mjs'):
            self.read(AUTH/name,frozen[name]);source_members.append({'path':str(AUTH/name),'sha256':frozen[name]})
        # This finite recipe precedes creating any component fixture/opening.
        self.save('SELECTION.json',encoded({'schema':'kpb-unfunded-wallet-component-selection/v1',
            'profile_sha256':args.profile_sha256,'binary_sha256':args.binary_sha256,
            'domain_hex32':descriptor['domain_hex32'],'profile_id_hex32':selected['profile_id_hex32'],
            'source_members':source_members,
            'operation':args.operation,'control_cases':CONTROL_CASES,'public_seed_vectors':['00..1f','20..3f'],
            'actual_private_original_or_financial_inputs':False,'financial_trial_or_privacy_qualification':False}))
        self.modules=wallet.authenticate_js(LEAF_MAP,LEAF_MAP_SHA,JS_ROOT)
        self.crypto=wallet.Crypto(CRYPTO)
        self.signature_artifacts={name:self.read(BUILD/name,pin) for name,pin in PINS.items()}
        self.matrix_request={'mode':'matrix','ordinaryR1csHex':self.signature_artifacts['ordinary/private_authorization.r1cs'].hex(),
            'cpp0R1csHex':self.signature_artifacts['cpp0/private_authorization.r1cs'].hex(),
            'symHex':self.signature_artifacts['ordinary/private_authorization.sym'].hex()}
        self.artifacts={}
        self.authority=wallet.Authority(NODE,self.modules)
        self.receiver=wallet.Receiver(bytes(range(32)),self.profile,self.crypto,self.authority)
        self.other=wallet.Receiver(bytes(range(32,64)),self.profile,self.crypto,self.authority)

    def save(self,name,body):
        path=self.output/name
        with path.open('xb') as stream:stream.write(body)
        return {'path':str(path),'sha256':sha(body),'bytes':len(body)}

    def call(self,label,argv,value=None):
        self.serial+=1;tag=f'{self.serial:03d}-{label}';started=time.monotonic()
        result=subprocess.run(list(map(str,argv)),input=None if value is None else encoded(value),capture_output=True,
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','TZ':'UTC','RAYON_NUM_THREADS':'4'})
        stdout=self.save(tag+'.stdout',result.stdout);stderr=self.save(tag+'.stderr',result.stderr)
        self.events.append({'label':label,'returncode':result.returncode,'seconds':time.monotonic()-started,'stdout':stdout,'stderr':stderr})
        need(result.returncode==0,'component-process-failure:'+label)
        return result.stdout

    def isolation(self):
        return ['/usr/bin/bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
            '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
            '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin',
            '--setenv','LANG','C.UTF-8','--setenv','TZ','UTC','--setenv','RAYON_NUM_THREADS','4']

    def native(self,label,request):
        argv=self.isolation()+['--ro-bind',str(self.binary),'/public/relation',
            '--bind',str(self.output),str(self.output),'/public/relation']
        return json.loads(self.call(label,argv,request))

    def normalize(self,label,signature_input):
        input_name=f'{label}.signature-input.json';wtns_name=f'{label}.wtns'
        self.save(input_name,encoded(signature_input))
        cpp=BUILD/'cpp0/private_authorization_cpp'
        argv=self.isolation()+['--ro-bind',str(cpp/'private_authorization'),'/generator/private_authorization',
            '--ro-bind',str(cpp/'private_authorization.dat'),'/generator/private_authorization.dat',
            '--bind',str(self.output),'/work','--chdir','/work','/generator/private_authorization','/work/'+input_name,'/work/'+wtns_name]
        self.call(label+'-actual-cpp0',argv)
        wtns=self.read(self.output/wtns_name)
        request={**self.matrix_request,'mode':'witness','wtnsHex':wtns.hex(),
            'frozen':{'mappingSha256':MAP_SHA,'normalizedMatrixSha256':MATRIX_SHA}}
        argv=self.isolation()+['--ro-bind',str(NODE),'/runtime/node','--ro-bind',str(self.modules),'/src/node_modules',
            '--ro-bind',str(AUTH/'harness/worker.mjs'),'/src/harness/worker.mjs',
            '--ro-bind',str(AUTH/'source-bridge/signature-component-adapter-selected.mjs'),'/src/source-bridge/signature-component-adapter-selected.mjs',
            '/runtime/node','/src/harness/worker.mjs']
        value=json.loads(self.call(label+'-mature-normalization',argv,request))
        need(value['matrix']['sha256']==MATRIX_SHA and value['mapping']['sha256']==MAP_SHA,'exact-mature-signature-matrix-and-map')
        matrix=bytes.fromhex(value['matrix']['hex']);mapping=bytes.fromhex(value['mapping']['hex']);witness=bytes.fromhex(value['witness']['hex'])
        need(sha(matrix)==MATRIX_SHA and sha(mapping)==MAP_SHA and sha(witness)==value['witness']['sha256'],'normalizer-actual-bytes')
        if not self.artifacts:
            self.artifacts['matrix']=self.save('SIGNATURE-MATRIX.json',matrix)
            self.artifacts['mapping']=self.save('SIGNATURE-MAP.json',mapping)
        witness=self.save(label+'.NORMALIZED-WITNESS.json',witness)
        return {'matrix':self.artifacts['matrix']['path'],'matrix_sha256':MATRIX_SHA,'mapping_sha256':MAP_SHA,
            'witness':witness['path'],'witness_sha256':witness['sha256']}

    def fixture(self):
        spec=importlib.util.spec_from_file_location('_kpb_component_trees',BASE/'integration/trees.py')
        trees=importlib.util.module_from_spec(spec);sys.modules[spec.name]=trees;spec.loader.exec_module(trees)
        delivery=wallet.deliver(self.crypto,self.receiver.invoice(7),200_000_000,bytes([11])*32,0)
        state=trees.PublicState([delivery.cm])
        context=exit_wire.HeadContext(bytes.fromhex(self.descriptor['chain_genesis_hex32']),hashlib.sha256(b'UNFUNDED COMPONENT POOL').digest(),
            self.profile.profile_id,self.profile.domain,bytes.fromhex(self.descriptor['service_policy_hex32']),
            bytes([4])*32+bytes(4),state.cm.root(),state.nf.root(),1,1,200_000_000)
        receipt=self.receiver.open(delivery.ciphertext)
        nf=self.receiver.nullifier(receipt,0)
        claim=wallet.RecoveredOpening(0,receipt,nf,tuple(state.cm.path(0)[at:at+32] for at in range(0,512,32)),False)
        witness=state.insert(nf)
        raw=exit_wire.body(context,bytes([5])*32,state.nf.root(),len(state.entries),0,1_000_000,199_000_000,
            b'\0\0\x20'+receipt.native_pk+b'\xac',nf,witness)
        tail=b'UNFUNDED COMPONENT POLICY; NO NATIVE ACCEPTANCE CLAIM'
        projection=exit_wire.projection(raw,tail)
        approved=wallet.authorize_exit(self.receiver,claim,projection,context,tail,approved_fee_sompi=1_000_000)
        self.save('PUBLIC-SYNTHETIC-PROJECTION.bin',projection)
        return delivery,context,claim,raw,projection,tail,approved

    def setup_prove_verify(self,role,request,label):
        parameters=self.output/(label+'-parameters')
        setup=self.native(label+'-fresh-setup',{**request,'operation':'setup','output_directory':str(parameters)})
        metadata=parameters/'MANIFEST.json';raw=self.read(metadata);manifest=json.loads(raw)
        need(manifest['pk_bytes']==(parameters/'parameters.pk').stat().st_size,'complete-parameter-size')
        pins={'manifest':str(metadata),'manifest_sha256':sha(raw),'pk':str(parameters/'parameters.pk'),'pk_sha256':manifest['pk_sha256']}
        result=self.native(label+'-genuine-proof',{**request,'operation':'prove','parameters':pins})
        verify={'operation':'verify','role':role,'profile':request['profile'],'statement_hex':request['statement_hex'],
            'proof_hex128':result['proof_hex128'],'parameters':{'manifest':str(metadata),'manifest_sha256':sha(raw)}}
        good=self.native(label+'-independent-public-verification',verify);need(good['accepted'] is True,'actual-new-profile-proof-verification')
        changed=bytearray.fromhex(request['statement_hex']);changed[-1]^=1
        bad=self.native(label+'-wrong-public-statement',{**verify,'statement_hex':changed.hex()})
        need(bad['accepted'] is False,'proof-must-bind-exact-public-statement')
        self.save(label+'-PROOF.json',encoded(result));return {'setup':setup,'manifest':{'path':str(metadata),'sha256':sha(raw)},'verified':True,'wrong_statement_rejected':True}

    def execute(self,operation):
        delivery,context,claim,raw,projection,tail,approved=self.fixture()
        profile={'domain_hex32':self.profile.domain.hex(),'profile_id_hex32':self.profile.profile_id.hex()}
        output_request={'operation':'derive-output','role':'new-output','profile':profile,'statement_hex':'',
            'note_hex168':claim.receipt.note_bytes().hex(),'blinding_hex32':bytes(32).hex(),'cf_hash_hex32':hashlib.sha256(delivery.ciphertext).hexdigest()}
        statement=self.native('derive-actual-output-statement',output_request)['statement_hex168']
        output_request={key:value for key,value in output_request.items() if key!='cf_hash_hex32'}
        output_request.update(operation='check-native',statement_hex=statement)
        output_check=self.native('actual-output-matrix',output_request)
        need(output_check['counts']['output_residual_failures']==0,'actual-output-R1CS-satisfied')
        result={'schema':'kpb-unfunded-wallet-component-result/v1','profile':profile,'selected_operation':operation,'output_matrix':output_check,
            'exit_controls_executed':[], 'all_frozen_exit_controls_completed':False,
            'actual_private_originals_or_funding_used':False,'native_financial_readiness_or_privacy_qualification':False}
        if operation in ('output-proof','all-proofs'):
            result['output_proof']=self.setup_prove_verify('new-output',output_request,'OUTPUT')
        if operation in ('exit-check','exit-controls','exit-proof','all-proofs'):
            signature_input=self.authority.signature_inputs(approved.statement,approved.authorization)
            signature=self.normalize('P01_GENUINE_EXIT',signature_input)
            request={**approved.private_request,'operation':'check-joined','signature':signature}
            baseline=self.native('actual-complete-auth-exit-matrix',request)
            need(tuple(baseline['counts'][key] for key in ('native_residual_failures','signature_residual_failures','link_residual_failures'))==(0,0,0),'actual-AuthExit-R1CS-satisfied')
            result['exit_matrix']=baseline
            result['exit_controls_executed'].append({'id':'P01_GENUINE_EXIT','expected':[0,0,0],'counts':baseline['counts']})
            if operation in ('exit-controls','exit-proof','all-proofs'):
                def signed_inputs(statement,receiver=self.receiver):
                    authorization=self.authority.sign(receiver.keys(7).signing_seed,statement)
                    return self.authority.signature_inputs(statement,authorization)

                def check_case(label,statement,inputs,changes=None):
                    selected={**approved.private_request,'operation':'check-joined','statement_hex':statement.hex(),
                        'signature':self.normalize(label,inputs),**(changes or {})}
                    value=self.native(label+'-complete-actual-matrices',selected)
                    counts=[value['counts'][key] for key in ('native_residual_failures','signature_residual_failures','link_residual_failures')]
                    expected=dict(CONTROL_CASES)[label]
                    need(all(got>0 if want=='positive' else got==want for got,want in zip(counts,expected)),
                        'unexpected-actual-residual-region:'+label)
                    result['exit_controls_executed'].append({'id':label,'expected':expected,'counts':value['counts']})

                diverted=bytearray(raw);diverted[376:412]=b'\0\0\x20'+self.other.invoice(7).native_pk+b'\xac'
                statement=exit_wire.statement(exit_wire.projection(bytes(diverted),tail))
                stale=copy.deepcopy(signature_input);digest=hashlib.sha256(statement).digest()
                stale['digestLimbs']=[str(int.from_bytes(digest[at:at+16],'little')) for at in (0,16)]
                check_case('N01_REDIRECT_WITH_STALE_SIGNATURE',statement,stale)

                repriced=bytearray(raw);repriced[360:368]=(1_000_001).to_bytes(8,'little');repriced[368:376]=(198_999_999).to_bytes(8,'little')
                statement=exit_wire.statement(exit_wire.projection(bytes(repriced),tail))
                check_case('P02_RECONSENTED_FEE_CHANGE',statement,signed_inputs(statement))

                inflated=bytearray(raw);inflated[276:284]=(200_000_001).to_bytes(8,'little');inflated[368:376]=(199_000_001).to_bytes(8,'little')
                statement=exit_wire.statement(exit_wire.projection(bytes(inflated),tail))
                check_case('N02_ONE_SOMPI_PRIVATE_INFLATION',statement,signed_inputs(statement))
                check_case('N03_SIGNATURE_KEY_COPY_LINK',approved.statement,signed_inputs(approved.statement,self.other))

                tree_spec=importlib.util.spec_from_file_location('_kpb_control_nf_tree',BASE/'integration/trees.py')
                tree_module=importlib.util.module_from_spec(tree_spec);sys.modules[tree_spec.name]=tree_module;tree_spec.loader.exec_module(tree_module)
                def with_nf(nf):
                    state=tree_module.PublicState([delivery.cm]);witness=state.insert(nf)
                    return exit_wire.statement(exit_wire.projection(exit_wire.body(context,bytes([5])*32,state.nf.root(),2,0,
                        1_000_000,199_000_000,b'\0\0\x20'+claim.receipt.native_pk+b'\xac',nf,witness),tail))

                high_nf=hmac.digest(self.receiver.keys(7).nf_secret,wallet.legacy.NF_TAG+self.profile.domain+
                    claim.receipt.commitment()+(1<<16).to_bytes(4,'little'),'sha256')
                statement=with_nf(high_nf)
                check_case('N04_HIGH_MEMBERSHIP_POSITION',statement,signed_inputs(statement),{'position':1<<16})
                wrong_nf=bytearray(claim.nf);wrong_nf[0]^=1
                statement=with_nf(bytes(wrong_nf))
                check_case('N05_WRONG_ORIGINAL_NF',statement,signed_inputs(statement))
                scalar_alias=copy.deepcopy(signature_input)
                scalar_alias['sigS']=str(int(scalar_alias['sigS'])+2736030358979909402780800718157159386076813972158567259200215660948447373041)
                check_case('N06_SIGNATURE_SCALAR_PLUS_Q',approved.statement,scalar_alias)
                need(len(result['exit_controls_executed'])==len(CONTROL_CASES),'complete-frozen-exit-controls')
                result['all_frozen_exit_controls_completed']=True
            if operation in ('exit-proof','all-proofs'):
                result['exit_proof']=self.setup_prove_verify('new-auth-exit',request,'AUTH-EXIT')
        self.save('EVENTS.json',encoded(self.events))
        self.save('RESULT.json',encoded(result));return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--operation',choices=('output-check','output-proof','exit-check','exit-controls','exit-proof','all-proofs'),required=True)
    for name in ('output','binary','binary-sha256','profile','profile-sha256'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();run=None
    try:
        run=Run(args);result=run.execute(args.operation)
        print(json.dumps({'status':'COMPONENT_RUN_COMPLETED','output':str(run.output),
            'output_constraints':result['output_matrix']['constraints'],'exit_constraints':result.get('exit_matrix',{}).get('constraints'),
            'output_proof_completed':'output_proof'in result,'exit_proof_completed':'exit_proof'in result,
            'native_financial_or_privacy_readiness':False}))
    except BaseException as error:
        if run is not None:
            run.save('FIRST-FAILURE.json',encoded({'schema':'kpb-component-first-failure/v1','type':type(error).__name__,'message':str(error),'events':run.events}))
        raise
    finally:
        if run is not None:run.authority.close()


if __name__=='__main__':main()
