#!/usr/bin/env python3
"""Live-only entry sizing and ordinary GN preparation. No proof or broadcast.

Sizing uses independent public synthetic material, never a real owner NF. The
actual initial P0 is later built by Alice's one-backup cold wallet after a fresh
accepted-GN capture. No operator P0 witness or precomputed owner exit is made.
"""
import argparse
import json
from pathlib import Path
import secrets
from types import SimpleNamespace

import phase
import wallet_core
import materialize as local

LIVE_SHA='a9321198d989289fa44f79a968cee5bab6da604fc941c4291e598a84fd363398'
LABELS=('founding','initial-payment','partial-cashout','change-payment','full-cashout','terminal-cashout')


def selected():
    identity=phase.selected();path=phase.PHASE/'LIVE-WORKLOAD-SELECTION-01.json';raw=path.read_bytes()
    phase.require(phase.digest(raw)==LIVE_SHA,'selected-live-workload')
    selection=phase.parse(raw)
    phase.require(selection['schema']=='kpx3-private-change-live-workload/v1'
        and selection['authority_adr55_sha256']==phase.ADR_SHA
        and selection['common_contract_sha256']==phase.CONTRACT_SHA
        and selection['domain_hex32']==identity['domain_hex32']
        and selection['trial_id']==identity['trial_id']
        and selection['initial_private_recipient_sompi']==200_000_000
        and selection['requested_partial_native_payout_sompi']==10_000_000
        and selection['requested_subsequent_private_payment_sompi']==60_000_000
        and selection['private_note_floor_sompi']==60_000_000
        and selection['native_payout_floor_sompi']==10_000_000
        and selection['fee_rate_sompi_per_mass']==100
        and selection['six_native_stage_sequence']==list(LABELS)
        and selection['adopted_10KAS_fee_privacy_targets_unchanged'] is True,
        'live-functional-workload-keeps-floors-and-original-targets')
    return identity,selection


def save(t,path,value):t.private_write(path,t.encoded(value))


def public_parameters():
    raw=(phase.PHASE/'prover/parameters-01/public-parameters.json').read_bytes()
    vk=(phase.PHASE/'prover/session-01/setup-01/verification-key.bin').read_bytes()
    parameters=phase.parse(raw)
    phase.require(phase.digest(raw)==local.PARAMETERS_SHA and phase.digest(vk)==local.VK_SHA
        and parameters['vk_hex328']==vk.hex(),'same-selected-parameters-live-entry')
    return raw,vk


def size(output):
    identity,selection=selected();core=wallet_core.load();t,_,p=phase.helpers()
    output=t.outside_git(output);phase.require(not output.exists(),'fresh-private-live-sizing-output');t.private_dir(output)
    manifest,vk=public_parameters();principal=selection['initial_private_recipient_sompi']
    with core.owner_runtime.SelectedExecutable(t.DEFAULT_BRIDGE,t.BRIDGE_SHA) as bridge, \
         core.owner_runtime.SelectedExecutable(p.NATIVE,p.NATIVE_SHA) as native:
        module=core.receiver_tools.recipient();crypto=core.receiver_tools.Crypto(bridge)
        ctx=SimpleNamespace(module=module,crypto=crypto,domain=bytes.fromhex(identity['domain_hex32']),p=p)
        owner_seed=bytes.fromhex(phase.digest(b'KPX3/LIVE-ENTRY/PUBLIC-SIZING-OWNER/DO-NOT-FUND'))
        other_seed=bytes.fromhex(phase.digest(b'KPX3/LIVE-ENTRY/PUBLIC-SIZING-RECIPIENT/DO-NOT-FUND'))
        receiver=module.Receiver(owner_seed,ctx.domain,crypto)
        recipient=module.Receiver(other_seed,ctx.domain,crypto).invoice(0)
        fee=1;attempt=0
        while True:
            case=output/f'attempt-{attempt:04d}';t.private_dir(case)
            reserve=principal+fee
            note=module.Receipt.for_invoice(receiver.invoice(0),reserve,secrets.token_bytes(32))
            record=module.Delivery(0,note.commitment(),crypto.seal(receiver.invoice(0).delivery_pk,note.encode()))
            snapshot=module.Snapshot([record],[module.NFEntry(bytes(32),bytes(32),0)])
            genesis=p.genesis(local.LegacyRuntime(native),ctx,vk,note.note_bytes(),record)
            fake={'transactionId':phase.digest(b'KPX3/LIVE-ENTRY/SIZING-FAKE-POINT\0'+ctx.domain),'index':0}
            descriptor=local.public_descriptor(ctx,genesis,vk,manifest,fake)
            current=local.head(ctx,core,snapshot,bytes.fromhex(genesis['redeem_hex']),fake,reserve)
            recovered=module.recover(receiver,snapshot.pin(ctx.domain),snapshot)
            action=local.recognized_template(ctx,core,descriptor,current,snapshot,owner_seed,receiver,recovered,
                core.change_action.Intent('prepare-private-payment',principal,recipient))
            candidate=action.sizing(fee)
            phase.require(not hasattr(candidate,'private_witness'),'sizing-has-no-private-witness')
            request=dict(candidate.public_request,mode='quote',fee_rate_sompi_per_mass='100')
            result=core.change_wallet.native_call(native,request)
            core.change_wallet.check_body(result,descriptor,current,candidate,candidate.auth,bytes(128),fee)
            phase.require(result['verified'] is False and result['public_checks_reached_G16'] is True
                and int(result['fee_sompi'])==fee
                and int(result['required_fee_sompi'])==100*int(result['mining_mass']),
                'current-native-synthetic-sizing-quote')
            save(t,case/'PRIVATE-DIAGNOSTIC-REQUEST.json',request)
            save(t,case/'PRIVATE-DIAGNOSTIC-RESULT.json',result)
            required=int(result['required_fee_sompi'])
            if fee==required:break
            phase.require(required>fee,'monotone-exact-live-P0-fee-fixedpoint')
            fee=required;attempt+=1
        report={'schema':'kpx3-private-change-live-entry-sizing/v1','live_workload_selection_sha256':LIVE_SHA,
            'classification':'SYNTHETIC_PUBLIC_SIZING_ONLY_DO_NOT_SUBMIT',
            'domain_hex32':identity['domain_hex32'],'parameters_sha256':local.PARAMETERS_SHA,
            'vk_sha256':local.VK_SHA,'fee_rate_sompi_per_mass':100,
            'initial_private_recipient_sompi':principal,'P0_fee_sompi':fee,
            'Alice_whole_note_sompi':principal+fee,'mining_mass':int(result['mining_mass']),
            'diagnostic_native_quotes':attempt+1,'real_owner_NF_or_witness_used':False,
            'private_witness_or_proof_or_setup_RPC_funding_broadcast':False,
            'actual_Alice_material_quote_proof_and_Full_still_required':True,
            'original_10KAS_local_and_fee_privacy_targets_unchanged':True}
        save(t,output/'SIZING-RESULT.json',report)
        return report


def found(trial,source_path,sizing_path,output,birth_start_hash):
    identity,selection=selected();core=wallet_core.load();t,_,p=phase.helpers()
    manifest,vk=public_parameters();sizing=phase.parse(sizing_path.read_bytes())
    phase.require(sizing['schema']=='kpx3-private-change-live-entry-sizing/v1'
        and sizing['live_workload_selection_sha256']==LIVE_SHA
        and sizing['domain_hex32']==identity['domain_hex32']
        and sizing['parameters_sha256']==local.PARAMETERS_SHA and sizing['vk_sha256']==local.VK_SHA
        and sizing['initial_private_recipient_sompi']==selection['initial_private_recipient_sompi']
        and type(sizing['P0_fee_sompi']) is int and sizing['P0_fee_sompi']>0
        and sizing['P0_fee_sompi']==100*sizing['mining_mass']
        and sizing['Alice_whole_note_sompi']==selection['initial_private_recipient_sompi']+sizing['P0_fee_sompi'],
        'selected-exact-P0-sizing')
    phase.require(type(birth_start_hash) is str and len(bytes.fromhex(birth_start_hash))==32
        and bytes.fromhex(birth_start_hash).hex()==birth_start_hash and birth_start_hash!='00'*32,
        'actual-pre-founding-birth-checkpoint-required')
    with core.owner_runtime.SelectedExecutable(t.DEFAULT_BRIDGE,t.BRIDGE_SHA) as bridge, \
         core.owner_runtime.SelectedExecutable(p.NATIVE,p.NATIVE_SHA) as native, \
         core.owner_runtime.SelectedExecutable(p.GENERIC,p.GENERIC_SHA) as generic:
        ctx=phase.LocalContext(trial,core.receiver_tools.recipient(),core.receiver_tools.Crypto(bridge))
        output=p.fresh(output,ctx.directory)
        source=p.read(source_path)
        phase.require(source['oracle_stage']=='LOCAL_PLANNED_TN10_FUNDING_BODY',
                      'root-provided-real-planned-source-only')
        previous,context=local.source_context(ctx,source)
        # Recalculate the sizing body's official mass without another VM run.
        diagnostic=read_final_sizing(sizing_path.parent)
        quoted=diagnostic['transaction'];quoted_context=diagnostic['supplied_context']
        auth=bytes.fromhex(quoted['payload'])[:528]
        target=selection['initial_private_recipient_sompi'];selected_fee=sizing['P0_fee_sompi']
        phase.require(len(auth)==528 and auth[:8]==b'KPX3AU01'
            and auth[8:40].hex()==identity['domain_hex32']
            and int.from_bytes(auth[188:196],'little')==sizing['Alice_whole_note_sompi']
            and int.from_bytes(auth[196:204],'little')==selected_fee
            and int.from_bytes(auth[476:484],'little')==target
            and int.from_bytes(auth[484:492],'little')==0 and auth[492:528]==bytes(36)
            and len(quoted['inputs'])==len(quoted['outputs'])==len(quoted_context)==1
            and quoted['inputs'][0]['computeBudget']==1600
            and quoted['outputs'][0]['value']==target and quoted['outputs'][0]['covenant'] is None
            and int(quoted_context[0]['amount_sompi'])==sizing['Alice_whole_note_sompi']
            and diagnostic['mode']=='quote' and diagnostic['fee_rate_sompi_per_mass']=='100'
            and int(diagnostic['fee_sompi'])==int(diagnostic['required_fee_sompi'])==selected_fee
            and int(diagnostic['mining_mass'])==sizing['mining_mass'],
            'retained-diagnostic-exact-live-P0-amount-rate-fee-shape')
        normalized,metrics=p.normalize(local.LegacyRuntime(generic),diagnostic['transaction'],
            diagnostic['supplied_context'],output/'sizing-source-recheck')
        phase.require(normalized==diagnostic['transaction']
            and 100*metrics['mining_mass']==sizing['P0_fee_sompi'],'official-sizing-mass-rechecked')
        reserve=sizing['Alice_whole_note_sompi'];_,alice=ctx.owner('alice')
        note=ctx.module.Receipt.for_invoice(alice.invoice(0),reserve,secrets.token_bytes(32))
        record=ctx.module.Delivery(0,note.commitment(),ctx.crypto.seal(alice.invoice(0).delivery_pk,note.encode()))
        genesis=p.genesis(local.LegacyRuntime(native),ctx,vk,note.note_bytes(),record)
        body,fee,change=local.founding(ctx,source,previous,[context],genesis,reserve,generic,output)
        phase.require(source['amount_sompi']==reserve+fee+change,'actual-live-source-entry-and-all-change')
        descriptor=local.public_descriptor(ctx,genesis,vk,manifest,local.point(body))
        descriptor['birth_start_hash']=birth_start_hash
        save(t,output/'genesis.json',genesis);save(t,output/'public-descriptor.json',descriptor)
        save(t,output/'source-context.json',source)
        report={'schema':'kpx3-private-change-live-GN-prepared/v1','live_workload_selection_sha256':LIVE_SHA,
            'trial_id':identity['trial_id'],'domain_hex32':identity['domain_hex32'],
            'transaction_id':body['id'],'ordinary_source_sompi':source['amount_sompi'],
            'Alice_whole_note_sompi':reserve,'intended_Bob_payment_sompi':selection['initial_private_recipient_sompi'],
            'expected_P0_fee_sompi':sizing['P0_fee_sompi'],'founding_fee_sompi':fee,
            'ordinary_change_sompi':change,'root_actual_context_Full_before_submit_required':True,
            'Alice_fresh_capture_one_backup_C0_payment_quote_proof_Full_still_required':True,
            'operator_P0_or_owner_exit_witness_proof_created':False,'funding_or_broadcast':False}
        save(t,output/'GN-PREPARED.json',report)
        return report


def read_final_sizing(directory):
    candidates=sorted(directory.glob('attempt-*/PRIVATE-DIAGNOSTIC-RESULT.json'))
    phase.require(bool(candidates),'retained-private-sizing-record-required')
    result=phase.parse(candidates[-1].read_bytes())
    phase.require(result['verified'] is False and result['public_checks_reached_G16'] is True,
                  'selected-failed-G16-sizing-record')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='operation',required=True)
    sizing=sub.add_parser('size');sizing.add_argument('--output',type=Path,required=True)
    founding=sub.add_parser('found');founding.add_argument('trial',type=Path)
    for name in ('source','sizing','output'):founding.add_argument('--'+name,type=Path,required=True)
    founding.add_argument('--birth-start-hash',required=True)
    args=parser.parse_args()
    result=size(args.output) if args.operation=='size' else found(args.trial,args.source,args.sizing,args.output,args.birth_start_hash)
    print(json.dumps(result,sort_keys=True))
