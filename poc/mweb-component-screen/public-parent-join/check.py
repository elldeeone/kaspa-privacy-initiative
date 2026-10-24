#!/usr/bin/env python3
"""Read-only joins of retained public MWEB parents/spends; no crypto reruns."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[3]
BASE=ROOT/'research/next-session/independent-payments/privacy-components'
MANIFEST_SHA='80d08a185e6590e761f814d4bfcc271bf731f8b3ab0041a48b35fce7c49e4d9f'
LIST_SHA='a12e3ded7e70afdac97638778b71fe135eeb4bc3eb177323daba62f40ddd9b39'
INSPECTOR_SHA='39c15d3ff27486d49f8847111493be345e13ee91e8a9b955b553dc9b10e03069'
RUN_ID='MWEB-READ-ONLY-PUBLIC-PARENT-JOIN-01'


def digest(data):return hashlib.sha256(data).hexdigest()
def need(value,code):
    if not value:raise ValueError(code)
def save(path,value):
    with path.open('x') as f:json.dump(value,f,sort_keys=True,indent=2);f.write('\n')
def hex_value(value,width,code):
    need(type(value) is str and len(value)==2*width
         and all(c in '0123456789abcdef' for c in value),code)
    return value


def join(parent,spend,receipt):
    need(len(spend['inputs'])==1,'one-spend-input-required')
    index={}
    for row in parent['outputs']:
        ident=hex_value(row['output_id'],32,'parent-ID-encoding')
        need(ident not in index,'ambiguous-parent-output-ID')
        hex_value(row['commitment'],33,'parent-commitment-encoding')
        hex_value(row['receiver_pubkey'],33,'parent-key-encoding')
        index[ident]=row
    incoming=spend['inputs'][0]
    ident=hex_value(incoming['spent_output_id'],32,'spend-ID-encoding')
    need(ident in index,'missing-parent-output-ID')
    actual=index[ident]
    need(incoming['commitment']==actual['commitment'],'parent-commitment-mismatch')
    need(incoming['output_pubkey']==actual['receiver_pubkey'],'parent-authorization-key-mismatch')
    need(ident==receipt['received_output_id'],'recipient-observation-parent-ID-mismatch')
    fees=[r['fee'] for r in spend['kernels']]
    need(fees and all(type(value) is int and value>=0 for value in fees),'public-fee-encoding')
    need(sum(fees)==receipt['spend_fee'],'public-fee-observation-mismatch')
    amount,after,fee=receipt['recovered_amount'],receipt['spend_output_amount'],receipt['spend_fee']
    need(all(type(value) is int and value>=0 for value in (amount,after,fee))
         and amount==after+fee,'retained-amount-observation-equation')
    return {'received_output_id':ident,'parent_output_id':actual['output_id'],
        'input_commitment_equals_parent':True,'input_authorization_key_equals_parent_Ko':True,
        'input_commitment':incoming['commitment'],'parent_commitment':actual['commitment'],
        'input_output_pubkey':incoming['output_pubkey'],'parent_receiver_pubkey':actual['receiver_pubkey'],
        'public_fee_sum':sum(fees),'public_fee_matches_retained_observation':True,
        'retained_amount_equation':{'received':amount,'next_output':after,'fee':fee},
        'hidden_plaintext_amounts_independently_verified_from_wire':False}


def run(inspector,output):
    output=output.absolute();inspector=inspector.absolute()
    need(not output.exists() and not output.is_relative_to(ROOT),'fresh-output-outside-Git-required')
    need(not any(p.is_symlink() for p in (output,*output.parents)),'output-symlink')
    output.mkdir(parents=True,mode=0o700)
    manifest_raw=(BASE/'MANIFEST.json').read_bytes();need(digest(manifest_raw)==MANIFEST_SHA,'original-manifest-identity')
    need(digest((BASE/'PUBLIC-FILES.txt').read_bytes())==LIST_SHA,'original-finite-list-identity')
    manifest=json.loads(manifest_raw); selected={r['path']:r for r in manifest['files']}
    # Read and preserve only already-public inputs; inspect fresh owned copies.
    inputs=output/'inputs';inputs.mkdir(mode=0o700)
    identities=[]
    def pinned(relative):
        path=BASE/relative;name=str(path.relative_to(ROOT));need(name in selected,'input-not-in-original-packet')
        need(not path.is_symlink(),'public-input-symlink');raw=path.read_bytes();row=selected[name]
        need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'original-public-input-byte-identity')
        identities.append(row);return raw
    binary=inspector.read_bytes();need(digest(binary)==INSPECTOR_SHA,'already-selected-inspector-identity')
    owned=output/'inspect-public';owned.write_bytes(binary);owned.chmod(0o500)
    reports={};receipts={}
    names={'aggregate':'aggregate.tx','R1-spend':'R1.spend.tx','R2-spend':'R2.spend.tx'}
    for label,name in names.items():
        raw=pinned('recipient-extension/run-01/'+name);path=inputs/name;path.write_bytes(raw);path.chmod(0o400)
        r=subprocess.run([str(owned),str(path)],capture_output=True,text=True)
        need(r.returncode==0,'public-inspector-failed');report=json.loads(r.stdout)
        need(report['inspection_only'] is True,'inspection-only-mode')
        reports[label]=report;save(output/(label+'.fields.json'),report)
    for actor in ('R1','R2'):
        receipts[actor]=json.loads(pinned('recipient-extension/run-01/'+actor+'.receipt.json'))
    prior_result=json.loads(pinned('recipient-extension/run-01/RESULTS.json'))
    positives=[]
    for actor in ('R1','R2'):
        value=join(reports['aggregate'],reports[actor+'-spend'],receipts[actor]);positives.append({'actor':actor,**value})
    need(positives[0]['parent_output_id']!=positives[1]['parent_output_id'],'recipients-must-consume-distinct-parents')
    # Calibrate only inspected public-field copies. These are not transactions
    # and no crypto validation is claimed for mutated copies.
    calibrations=[]
    for actor,other_actor in [('R1','R2'),('R2','R1')]:
        other_id=receipts[other_actor]['received_output_id']
        other=next(r for r in reports['aggregate']['outputs'] if r['output_id']==other_id)
        def add(label,mutate,expected):
            copied=copy.deepcopy(reports[actor+'-spend']);mutate(copied['inputs'][0])
            try:join(reports['aggregate'],copied,receipts[actor])
            except ValueError as error:observed=str(error)
            else:raise RuntimeError('calibration-unexpectedly-accepted:'+label)
            need(observed==expected,'calibration-wrong-rejection-boundary:'+label)
            calibrations.append({'actor':actor,'case':label,'keeps_original_input_ID':copied['inputs'][0]['spent_output_id']==receipts[actor]['received_output_id'],
                'expected_rejection':expected,'observed_rejection':observed,'rejected':True,
                'mutated_public_field_copy_not_signed_transaction':True,'cryptographic_validation_run':False})
        add('same-ID-other-parent-commitment',lambda r:r.update(commitment=other['commitment']),'parent-commitment-mismatch')
        add('same-ID-other-parent-authorization-key',lambda r:r.update(output_pubkey=other['receiver_pubkey']),'parent-authorization-key-mismatch')
        add('cross-parent-ID-only',lambda r:r.update(spent_output_id=other_id),'parent-commitment-mismatch')
        add('other-complete-parent-fields-original-recipient',lambda r:r.update(spent_output_id=other_id,commitment=other['commitment'],output_pubkey=other['receiver_pubkey']),'recipient-observation-parent-ID-mismatch')
        missing='00'*32
        need(all(r['output_id']!=missing for r in reports['aggregate']['outputs']),'missing-ID-control-collision')
        add('absent-parent-ID',lambda r:r.update(spent_output_id=missing),'missing-parent-output-ID')
    save(output/'INPUTS.json',{'run_id':RUN_ID,'original_manifest_sha256':MANIFEST_SHA,'original_public_list_sha256':LIST_SHA,
         'inspector_sha256':INSPECTOR_SHA,'files':identities,'new_private_input_or_key_material_read':False})
    result={'schema':'kpi-MWEB-explicit-public-parent-field-join/v1','run_id':RUN_ID,
        'classification':'READ_ONLY_EXISTING_PUBLIC_OBJECTS_NO_CHAIN_OR_PRIVACY_QUALIFICATION',
        'actual_parent_joins':positives,'parent_ID_commitment_and_Ko_all_match':True,
        'two_distinct_received_parent_outputs':True,'calibrated_public_field_copy_negatives':calibrations,
        'actual_public_inspections':3,'actual_signature_or_rangeproof_validation_calls':0,
        'new_signatures_proofs_keys_random_draws_or_upstream_changes':0,
        'original_standalone_crypto_validation_is_separate_retained_evidence':True,
        'retained_recipient_result_sha256':digest((BASE/'recipient-extension/run-01/RESULTS.json').read_bytes()),
        'retained_recipient_crypto_result_matches_input_manifest':prior_result['schema']=='kpi-MWEB-independent-recipient-component/v1',
        'accepted_chain_UTXO_global_unspentness_reorg_or_currentness_claimed':False,
        'source_sha256':digest(Path(__file__).read_bytes())}
    save(output/'RESULTS.json',result)
    print(json.dumps({'read_only_parent_joins':2,'ID_commitment_and_Ko_match':True,
        'calibrated_public_copy_rejections':len(calibrations),'new_crypto_validations_or_random_draws':0}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inspector',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.inspector,a.output)
