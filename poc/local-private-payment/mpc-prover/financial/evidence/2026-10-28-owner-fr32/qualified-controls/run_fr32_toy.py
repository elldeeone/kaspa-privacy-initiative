#!/usr/bin/env python3
"""One PUBLIC 3/5 toy proof through ADR81 files and unchanged V2/TLS/DDNNT.
No recorder, diagnostic reader, wallet file, or original owner file is used.
"""
import argparse
import hashlib
import types
import json
import os
from pathlib import Path
import runpy
import secrets
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GUARD = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
read = GUARD['read']

def digest(path):
    return hashlib.sha256(read(Path(path))).hexdigest()


def load_base(selection):
    path = REPO / '.local/financial-runtime-source-05/run_toy.py'
    admitted = read(path, selection['base_launcher_sha256'])
    module = types.ModuleType('immutable_source05_toy')
    module.__file__ = str(path)
    exec(compile(admitted, str(path), 'exec'), module.__dict__)
    module.digest = digest
    return module


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary','owner-client','verifier','model','vendor-root','output-parent']:
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--expected-model-sha256',required=True)
    parser.add_argument('--expected-verifier-sha256',required=True)
    parser.add_argument('--selection-sha256',required=True)
    parser.add_argument('--run-id',required=True)
    args = parser.parse_args()
    if len(args.run_id)!=64 or any(c not in '0123456789abcdef' for c in args.run_id):
        raise SystemExit('fresh canonical identity required')
    for name in ['binary','owner_client','verifier','model','vendor_root','output_parent']:
        setattr(args,name,getattr(args,name).absolute())
    args.control='positive'
    selection=json.loads(read(HERE/'TINY-CONTROL-SELECTION.json',args.selection_sha256))
    read(Path(__file__),selection['launcher_sha256'])
    base=load_base(selection)

    class Attempt(base.Attempt):
        def freeze(self):
            for attr,key in [('binary','binary_sha256'),('owner_client','owner_client_sha256'),
                             ('verifier','verifier_sha256'),('model','model_sha256')]:
                if digest(getattr(self.args,attr))!=selection[key]:
                    raise RuntimeError('unselected public runtime dependency')
            if self.args.expected_model_sha256!=selection['model_sha256'] or \
               self.args.expected_verifier_sha256!=selection['verifier_sha256']:
                raise RuntimeError('public expected identity mismatch')
            records=[]
            for item in selection['public_sources']:
                path=Path(item['path']); body=read(path,item['sha256'])
                records.append({'path':str(path),'sha256':item['sha256'],'bytes':len(body)})
            for item in selection['vendor_artifacts']:
                read(Path(item['path']),item['sha256'])
            # Metadata only: the controller never opens or hashes either owner file.
            shape=[]
            for owner in range(2):
                path=HERE/'PUBLIC-FIXTURES'/f'PUBLIC-TOY-{owner}.bin'
                GUARD['refresh'](); _,s=GUARD['m'].GUARD.metadata(path)
                if s.st_size!=64 or s.st_nlink!=1 or s.st_mode&0o777!=0o600 or s.st_uid!=os.getuid():
                    raise RuntimeError('public fixture file metadata mismatch')
                shape.append({'owner':owner,'file_bytes':s.st_size,'count':1})
            frozen={'schema':'kpi-owner-fr32-tiny-proof-freeze/v1','run_id':args.run_id,
                'control':'positive','model_sha256':selection['model_sha256'],
                'verifier_sha256':selection['verifier_sha256'],
                'binary_sha256':selection['binary_sha256'],
                'owner_client_sha256':selection['owner_client_sha256'],
                'public_sources':records,'vendor_artifacts':selection['vendor_artifacts'],
                'resources':base.selected_resources(args.run_id),'fixtures':{'x':3,'y':5,'public_t':128},
                'file_shape':shape,'file_encoding':'KPB_OWNER_FR32V2',
                'v2_trace_identity':selection['model_sha256'],
                'v2_layout_identity':selection['toy_layout_sha256'],
                'qualified_old_gate_dependency':selection['qualified_gate_dependency'],
                'new_client_origin':'Source05 plus isolated codec and fixed count1 public-only main',
                'expected':'all3 same verified proof; independent128accept/129reject',
                'private_keys_or_raw_diagnostics_read_or_hashed':False,
                'scope':'public-fixture file-reader/V2/TLS/DDNNT functional proof; no financial/privacy qualification'}
            base.write_json(self.public/'SOURCE-AND-CONTROL-FREEZE.json',frozen)
            return frozen

        def contracts(self,pins,freeze):
            fields=base.public_fields(self.args.model)
            cohort=hashlib.sha256(json.dumps({'run':args.run_id,'certificates':pins,
                'model':args.expected_model_sha256,'source_freeze':freeze},sort_keys=True).encode()).hexdigest()
            contracts=[]
            for owner in range(2):
                body=('KPI_OWNER_CONTRACT_V2\nrun_nonce '+args.run_id+'\nmodel '+args.expected_model_sha256+
                    '\nsource '+fields['source']+'\npk '+fields['pk_sha256']+'\nvk '+fields['vk_sha256']+
                    '\ntrace '+selection['model_sha256']+'\nlayout '+selection['toy_layout_sha256']+
                    '\ncohort '+cohort+'\nowner_id '+str(owner)+'\ninput_count 1\n')
                for party in range(3):
                    body+='server_certificate_'+str(party)+' '+pins['P'+str(party)]+'\n'
                body+='owner_certificate '+pins['C'+str(owner)]+'\nEND\n'
                path=self.public/f'owner-{owner}.contract';path.write_text(body);contracts.append(path)
            return contracts

        def role_command(self,role,keys,certs,command):
            argv,work=super().role_command(role,keys,certs,command)
            if role.startswith('C'):
                owner=int(role[1:])
                # Locate the executable command, after all bwrap mount operands.
                index=len(argv)-len(command)
                argv[index:index]=['--dir','/owner','--ro-bind',
                    str(HERE/'PUBLIC-FIXTURES'/f'PUBLIC-TOY-{owner}.bin'),
                    '/owner/OWNER-PRIVATE-INPUT-V2.bin']
                argv.append('/owner/OWNER-PRIVATE-INPUT-V2.bin')
            return argv,work

        def launch(self,role,argv,work,private_input=None):
            # No stdin value route: each new client parses only its own binary leaf.
            return super().launch(role,argv,work,private_input=None)

    os.umask(0o077)
    attempt=Attempt(args)
    try:
        result=attempt.execute()
        result['file_encoding']='KPB_OWNER_FR32V2'
        result['owner_file_controller_body_reads_or_hashes']=False
        result['unchanged_V2_TLS_DDNNT']=True
        result['financial_or_payment_privacy_qualified']=False
        base.write_json(attempt.public/'RESULT.json',result)
        print(json.dumps({'run_id':args.run_id,'status':result['status'],
            'public_result':str(attempt.public/'RESULT.json')}),flush=True)
    except BaseException as error:
        base.write_json(attempt.public/'CONTROLLER-STOP.json',{'status':'STOPPED','reason':str(error),
            'run_id':args.run_id,'role_exit_statuses_before_cleanup':{
                role:process.poll() for role,process in attempt.processes.items()},
            'private_keys_or_raw_diagnostics_read_or_hashed':False})
        raise
    finally:
        attempt.stop_owned()
        base.write_json(attempt.public/'COMMANDS.json',attempt.commands)

if __name__=='__main__':
    main()
