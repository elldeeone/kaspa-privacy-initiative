#!/usr/bin/env python3
"""Genuine public-canary capacity proofs/native checks; never accepted history."""
import argparse
import copy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess

import capacity as c
from native_selected import CapacityRuntime
from actions import Candidate
from primitives import NFEntry, SparseTree, ZERO, h, need, u32, u64
from native_runtime import save

HERE=Path(__file__).resolve().parent


@dataclass(frozen=True)
class InvalidDuplicateState:
    """Adversarial duplicate update, never a valid Snapshot or accepted replay."""
    cm_cursor:int
    nullifiers:tuple
    cm_root:bytes
    def state(self,domain):
        return b'KPX2ST01'+domain+self.cm_root+u32(self.cm_cursor)+nf_tree(self.nullifiers).root+u32(len(self.nullifiers))


def nf_tree(rows):
    return SparseTree(17,{i:r.leaf() for i,r in enumerate(rows)},b'KPX1NFN\0',h(b'KPX1NFE\0'))


def invalid_or_valid_insert(rows,value,occupied):
    rows=list(rows);count=len(rows);tree=nf_tree(rows)
    if occupied:
        choices=[(i,r) for i,r in enumerate(rows) if r.value==value]
    else:
        number=int.from_bytes(value,'little')
        choices=[(i,r) for i,r in enumerate(rows) if int.from_bytes(r.value,'little')<number
            and (r.next_value==ZERO or number<int.from_bytes(r.next_value,'little'))]
    need(len(choices)==1,'one-actual-current-NF-predecessor')
    index,pred=choices[0]
    middle=tree.with_leaf(index,NFEntry(pred.value,value,count).leaf())
    witness=u32(index)+pred.value+pred.next_value+u32(pred.next_index)+b''.join(tree.path(index))+b''.join(middle.path(count))
    rows[index]=NFEntry(pred.value,value,count)
    rows.append(NFEntry(value,pred.next_value,pred.next_index))
    need(len(witness)==1160,'exact-public-NF-witness')
    return tuple(rows),witness


def occupied_candidate(domain,previous,current,first):
    original_nf=first.auth[204:236]
    need(sum(r.value==original_nf for r in current.nullifiers)==1,'real-NF-actually-spent-in-current-state')
    dk,ds=c.sample(domain,'fresh-occupied-control-dummy-key'),c.sample(domain,'fresh-occupied-control-dummy-seed')
    dummy=c.dummy_nf(domain,dk,ds,1)
    need(dummy!=original_nf and all(r.value!=dummy for r in current.nullifiers),'fresh-control-dummy-unspent')
    rows,w0=invalid_or_valid_insert(current.nullifiers,original_nf,True)
    rows,w1=invalid_or_valid_insert(rows,dummy,False)
    cm,_=current.roots();invalid=InvalidDuplicateState(current.cm_cursor,rows,cm.root)
    auth=(b'KPX4AU01'+domain+bytes.fromhex(previous['transactionId'])+u32(previous['index'])
        +current.state(domain)+u64(c.VALUE)+u64(c.FEE)+original_nf+dummy+ZERO+bytes(32)+h(bytes(528))
        +invalid.state(domain)+u64(0)+u64(c.VALUE-c.FEE)+first.auth[492:528])
    inputs=copy.deepcopy(first.inputs)
    inputs[1]['dummy_key_hex32'],inputs[1]['dummy_seed_hex32']=dk.hex(),ds.hex()
    return Candidate('compact2',0,auth,inputs,(bytes(168),bytes(168)),bytes(528),b'',w0+w1,b'',invalid,c.FEE,c.VALUE-c.FEE,0)


def public_keys():
    keys={}
    for role in ('compact2','wide32'):
        pins=HERE/'prover/pins'/role
        selection=json.loads((pins/'parameter-selection.json').read_bytes())
        raw=(pins/'public-parameters.json').read_bytes();manifest=json.loads(raw)
        vk=(pins/'verification-key.bin').read_bytes()
        need(selection['selected'] is True and selection['role']==role and manifest['role']==role
             and selection['manifest_sha256']==hashlib.sha256(raw).hexdigest()
             and selection['vk_sha256']==hashlib.sha256(vk).hexdigest()
             and manifest['vk_sha256']==hashlib.sha256(vk).hexdigest()
             and manifest['domain_hex32']==json.loads(c.PUBLIC.read_bytes())['domain_hex32'],
             'installed-fresh-role-parameters')
        keys[role]=vk
    return keys


def prove(binary,parameters,candidate,output):
    fixture=output.parent/(output.name+'.public-fixture.json');save(fixture,candidate.private_witness())
    descriptor=os.open(fixture,os.O_RDONLY)
    try:
        command=['/usr/bin/time','-v','-o',str(output.parent/(output.name+'.resources.log')),
            str(binary),'prove',candidate.role,str(parameters/candidate.role/'parameters.pk'),str(descriptor),str(output)]
        result=subprocess.run(command,pass_fds=(descriptor,),capture_output=True,text=True)
    finally:
        os.close(descriptor)
    (output.parent/(output.name+'.stdout.log')).write_text(result.stdout)
    (output.parent/(output.name+'.stderr.log')).write_text(result.stderr)
    if result.returncode!=0:raise RuntimeError('owner-proof-failed:'+output.name)
    proof=(output/'proof128.bin').read_bytes()
    need(len(proof)==128 and (output/'authorization528.bin').read_bytes()==candidate.auth,'proof-for-exact-candidate')
    events=[json.loads(line) for line in result.stdout.splitlines()]
    need(events[0]['event']=='parameters-ready' and events[-1]['event']=='proof-complete','authenticated-parameter-event-before-proof')
    report=json.loads((output/'report.json').read_bytes())
    need(report['genuine_Groth16_verified'] is True,'owner-proof-verified')
    return proof,report


def positive(runtime,domain,before,candidate,previous,reserve,keys,proof,output):
    body,entries,metrics,report=c.validate_raw(runtime,candidate,previous,reserve,keys['compact2'],keys['wide32'],output,proof)
    need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
         and all(e['accepted'] is True for e in report['per_input_ScriptEngine']),'actual-Native-Full-positive')
    need(metrics['actual_fee_sompi']==candidate.fee and candidate.fee>=100*metrics['mining_mass'],'actual-rate100-fee')
    value={**c.summary(domain,before,candidate),'genuine_proof_and_native_Full_accepted':True,
        'actual_native_validation_calls':1,'proof_sha256':h(proof).hex(),'authorization_sha256':h(candidate.auth).hex(),
        'transaction_id':body['id'],'engine_units':report['per_input_ScriptEngine'][0]['units'],'metrics':metrics}
    value.pop('native_or_proof_or_accepted_history_claimed')
    value['proof_and_native_validity_claimed']=True
    value['accepted_history_or_chain_currentness_claimed']=False
    return body,entries,value


def run(args):
    output=c.fresh(args.output);runtime=CapacityRuntime();domain=runtime.domain;keys=public_keys()
    binary=args.binary.absolute();parameters=args.parameters.absolute();initial=c.construct(domain,2)
    point={'transactionId':c.sample(domain,'FAKE-CAPACITY-PREVIOUS').hex(),'index':0}
    first=c.cashout(domain,initial,c.CM_MAX-2,2*c.VALUE,point)
    proof,first_report=prove(binary,parameters,first,output/'proof-first')
    first_body,first_entries,first_result=positive(runtime,domain,initial,first,point,2*c.VALUE,keys,proof,output/'native-first')
    current_point={'transactionId':first_body['id'],'index':0}
    second=c.cashout(domain,first.after,c.CM_MAX-1,c.VALUE,current_point)
    proof2,second_report=prove(binary,parameters,second,output/'proof-terminal')
    second_body,second_entries,second_result=positive(runtime,domain,first.after,second,current_point,c.VALUE,keys,proof2,output/'native-terminal')
    need(second_body['inputs'][0]['previousOutpoint']=={'transactionId':first_body['id'],'index':0}
         and first_body['outputs'][0]['value']==c.VALUE and len(second_body['outputs'])==1,'exact-native-reserve-chain')
    need(first.after.state(domain)==second.auth[76:188] and second.after.cm_cursor==65535
         and len(second.after.nullifiers)==131071 and second.reserve_after==0,'exact-final-capacity-drain')
    duplicate=occupied_candidate(domain,current_point,first.after,first)
    duplicate_proof,duplicate_report=prove(binary,parameters,duplicate,output/'proof-current-occupied-NF')
    _,_,dmetrics,dreport=c.validate_raw(runtime,duplicate,current_point,c.VALUE,keys['compact2'],keys['wide32'],output/'native-current-occupied-NF',duplicate_proof)
    engine=dreport['per_input_ScriptEngine'][0]
    need(dreport['Full']['accepted'] is False and engine['accepted'] is False
         and engine['units']<14_750_000 and not engine['typed_error'].startswith('ZkIntegrity'),'current-occupied-NF-before-G16')
    rows=[{'case':'first-nonterminal-full-cashout',**first_result,'owner_report':first_report},
          {'case':'second-terminal-full-cashout',**second_result,'owner_report':second_report}]
    negative={'case':'fresh-current-state-private-valid-occupied-NF','genuine_private_proof_verified':True,
        'current_outpoint_and_state_refreshed':True,'reserve_not_insufficient':True,
        'private_input_sompi':c.VALUE,'current_reserve_sompi':c.VALUE,'current_NF_count':len(first.after.nullifiers),
        'next_NF_count':len(duplicate.after.nullifiers),'real_NF_equals_predecessor_value':True,
        'rejected_before_G16':True,'engine_units':engine['units'],'typed_error':dreport['Full']['typed_error'],
        'proof_sha256':h(duplicate_proof).hex(),'authorization_sha256':h(duplicate.auth).hex(),
        'owner_report':duplicate_report,'actual_native_validation_calls':1,'metrics':dmetrics}
    result={'schema':'kpx-capacity-genuine-proof-native-rehearsal/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_CONSTRUCTED_PRESTATE','domain_hex32':domain.hex(),
        'cases':rows,'occupied_NF_negative':negative,'actual_genuine_proofs':3,'actual_native_validation_calls':3,
        'zero_terminal_reserve':True,'final_CM_cursor':65535,'final_NF_count':131071,
        'native_reserve_before_sompi':2*c.VALUE,'native_payouts_sompi':2*(c.VALUE-c.FEE),
        'all_actual_cashout_fees_sompi':2*c.FEE,'reserve_equation_holds':2*c.VALUE==2*(c.VALUE-c.FEE)+2*c.FEE,
        'original_backups_or_accepted_chain_or_privacy_or_full_history_claimed':False}
    from runtime_resources import capture
    result['owned_cgroup_resources_before_controller_exit']=capture()
    result['all_prover_and_native_subprocesses_waited']=True
    save(output/'RESULTS.json',result)
    print(json.dumps({'actual_genuine_proofs':3,'native_positives':2,'fresh_current_occupied_NF_rejected':True,
        'final_CM_cursor':65535,'final_NF_count':131071,'zero_terminal_reserve':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binary','parameters','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();run(args)
