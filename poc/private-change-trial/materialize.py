#!/usr/bin/env python3
"""Local six-body change rehearsal plus one separate C0 payment fork.

No proving/setup/RPC/submission API. Public zero-proof sizing/native quotes run
only under the root-selected local preparation runtime. Witnesses stay private.
"""
import argparse
import copy
import json
from pathlib import Path
import secrets

import economics as e
import phase
import wallet_core

RATE=100
PARAMETERS_SHA='b440d08fddcdbbfb7d6b8355ab097a7bedd3fb85b8aa228f07070d4fcb3a91d0'
VK_SHA='dade8f90f1bec1c9b150f5eb126d73a1c8a1959ef1fb9da1178820debf693bae'


class LegacyRuntime:
    def __init__(self,selected):self.selected=selected
    def run(self,arguments,*,input_text=None):return self.selected.run(arguments,input=input_text)


def point(body):return {'transactionId':body['id'],'index':0}


def source_context(ctx,source):
    phase.require(set(source)=={'source_key','oracle_stage','transaction_id','index','amount_sompi',
        'spk_version','spk_hex','block_daa_score','is_coinbase','covenant_id'},'exact-local-source-fields')
    phase.require(source['source_key']=='TRIAL_FUNDING_KEY' and source['oracle_stage'] in
        ('LOCAL_SYNTHETIC_TN10_FUNDING_BODY','LOCAL_PLANNED_TN10_FUNDING_BODY')
        and type(source['amount_sompi']) is int and 0<source['amount_sompi']<=e.MAX_SOMPI
        and type(source['spk_version']) is int and source['spk_version']==0
        and source['is_coinbase'] is False and source['covenant_id'] is None
        and '0000'+source['spk_hex']==ctx.profile['funding_destination']['canonical_spk_hex'],
        'selected-ordinary-source-context')
    previous={'transactionId':source['transaction_id'],'index':source['index']}
    phase.require(len(bytes.fromhex(previous['transactionId']))==32
        and bytes.fromhex(previous['transactionId']).hex()==previous['transactionId']
        and type(previous['index']) is int and 0<=previous['index']<=0xffffffff,'source-outpoint')
    return previous,ctx.p.context_entry(source['amount_sompi'],'0000'+source['spk_hex'],source['block_daa_score'])


def synthetic_source(ctx):
    return {'source_key':'TRIAL_FUNDING_KEY','oracle_stage':'LOCAL_SYNTHETIC_TN10_FUNDING_BODY',
        'transaction_id':phase.digest(b'KPX3/CHANGE/SYNTHETIC/DO-NOT-SUBMIT\0'+ctx.domain),
        'index':0,'amount_sompi':1_100_000_000,'spk_version':0,
        'spk_hex':ctx.profile['funding_destination']['spk_hex'],'block_daa_score':'0',
        'is_coinbase':False,'covenant_id':None}


def save(ctx,path,value):ctx.t.private_write(path,ctx.t.encoded(value))


def directory(ctx,path):
    ctx.t.private_dir(path)
    return path


def public_descriptor(ctx,genesis,vk,manifest,founding):
    redeem=bytes.fromhex(genesis['redeem_hex'])
    return {'schema':'kpx3-private-network-descriptor/v1','network_id':'testnet-10',
        'genesis_hash_hex':phase.GENESIS,'domain_hex32':ctx.domain.hex(),
        'founding_outpoint':founding,'birth_start_hash':'00'*32,
        'initial_redeem_hex':redeem.hex(),'vk_hex328':vk.hex(),
        'immutable_policy_sha256':phase.digest(redeem[114:]),
        'public_params_manifest_sha256':phase.digest(manifest)}


def head(ctx,core,snapshot,redeem,previous,reserve):
    state=core.change_action.state(snapshot,ctx.domain)
    phase.require(redeem[2:114]==state,'local-current-redeem-state')
    utxo={'outpoint':previous,**ctx.p.context_entry(reserve,core.change_action.p2sh(redeem))}
    return {'state_hex112':state.hex(),'reserve_sompi':reserve,'current_redeem_hex':redeem.hex(),
            'outpoint':previous,'current_utxo':utxo}


def template(ctx,core,descriptor,current,snapshot,owner,intent):
    seed,receiver,recovered=ctx.recognize(owner,snapshot)
    return recognized_template(ctx,core,descriptor,current,snapshot,seed,receiver,recovered,intent)


def recognized_template(ctx,core,descriptor,current,snapshot,seed,receiver,recovered,intent):
    claim=core.change_action.select_claim(recovered)
    destination=bytes(36)
    if intent.operation!='prepare-private-payment':
        _,public,_=core.change_action.payout_key(seed,descriptor,claim,ctx.crypto)
        destination=b'\0\0\x20'+public+b'\xac'
    return core.change_action.material(descriptor,current,receiver,claim,recovered.owned,
        snapshot,snapshot.pin(ctx.domain),destination,intent)


def sizing_fee(ctx,core,template,native,out):
    """Diagnostic only: never constructs or serializes a private witness."""
    fee=1;attempt=0
    while True:
        candidate=template.sizing(fee)
        phase.require(not hasattr(candidate,'private_witness'),'sizing-has-no-witness-api')
        result=core.change_wallet.native_call(native,dict(candidate.public_request,mode='quote',
            fee_rate_sompi_per_mass=str(RATE)),out/f'sizing-{attempt:04d}.json')
        core.change_wallet.check_body(result,template.descriptor,template.head,candidate,
                                     candidate.auth,bytes(128),fee)
        phase.require(result['verified'] is False and result['public_checks_reached_G16'] is True
            and int(result['required_fee_sompi'])==RATE*int(result['mining_mass']),
            'public-sizing-native-failed-G16-seam')
        required=int(result['required_fee_sompi'])
        if fee>=required:return fee
        fee=required;attempt+=1


def after_candidate(ctx,core,template,candidate):
    after=ctx.module.Snapshot(list(template.after_nf.deliveries),list(template.after_nf.nullifiers))
    if candidate.remaining:
        for slot in range(2):
            cm=candidate.auth[268+slot*32:300+slot*32]
            cipher=candidate.ciphertexts[slot*264:(slot+1)*264]
            after.deliveries.append(ctx.module.Delivery(len(after.deliveries),cm,cipher))
    phase.require(core.change_action.state(after,ctx.domain)==candidate.after,'selected-candidate-public-state')
    return after


def actual_stage(ctx,core,template,native,out,label):
    case=directory(ctx,out/label)
    candidate,quote,mass=core.change_wallet.quote_action(template,native,RATE,case)
    phase.require(type(candidate) is core.change_action.ActualCandidate,'selected-actual-candidate-type')
    body=quote['transaction'];contexts=quote['supplied_context']
    phase.require(body['payload']==(candidate.auth+candidate.ciphertexts+candidate.public_witness).hex(),
                  'exact-final-actual-payload')
    # Serialize only this already-legal, exactly quoted actual witness. Never
    # serialize any diagnostic sizing candidate or prior fee guess.
    save(ctx,case/'witness.json',candidate.private_witness())
    save(ctx,case/'transaction.json',body);save(ctx,case/'supplied-context.json',contexts)
    save(ctx,case/'selected-actual-quote.json',quote)
    save(ctx,case/'selected-public-request.json',candidate.public_request)
    entries=[{'amount':int(row['amount_sompi']),'scriptPublicKey':row['script_public_key'],
        'blockDaaScore':int(row['block_daa_score']),'isCoinbase':False,'covenantId':None} for row in contexts]
    save(ctx,case/'validation-case.json',{'transaction':body,'entries':entries})
    after=after_candidate(ctx,core,template,candidate)
    return after,candidate,body,{'stage':label,'fee_sompi':candidate.fee,'payout_sompi':candidate.payout,
        'reserve_after_sompi':candidate.remaining,'mining_mass':mass,'transaction_id':body['id'],
        'body_directory':str(case),'quote_id':quote['quote_id']}


def founding(ctx,source,previous,contexts,genesis,reserve,generic,out):
    fee=1;attempt=0
    while True:
        change=source['amount_sompi']-reserve-fee
        phase.require(change>=0,'ordinary-source-affordability')
        outputs=[(reserve,genesis['script_public_key_hex'])]
        if change:outputs.append((change,contexts[0]['script_public_key']))
        unsigned=ctx.p.transaction(previous,outputs,bytes.fromhex(genesis['payload_hex536']),bytes(66),10)
        body,metrics=ctx.p.normalize(LegacyRuntime(generic),unsigned,contexts,out/f'founding-quote-{attempt:04d}')
        required=RATE*metrics['mining_mass']
        if fee>=required:break
        fee=required;attempt+=1
    signed=ctx.p.sdk_call(body,contexts,ctx.profile['secrets']['funding_secret_hex32'])
    wanted=copy.deepcopy(body);wanted['inputs'][0]['signatureScript']=signed['inputs'][0]['signatureScript']
    phase.require(signed==wanted,'ordinary-SDK-signature-only')
    body,metrics=ctx.p.normalize(LegacyRuntime(generic),signed,contexts,out/'founding-final')
    phase.require(ctx.p.sdk_call(body,contexts)==body and metrics['actual_fee_sompi']==fee,
                  'ordinary-signed-fee-SDK-roundtrip')
    return body,fee,change


def prepare(directory_path,vk_path,parameters_path,output,source_path=None):
    phase.selected();core=wallet_core.load();t,a,p=phase.helpers()
    manifest=parameters_path.read_bytes();parameters=phase.parse(manifest);vk=vk_path.read_bytes()
    phase.require(phase.digest(manifest)==PARAMETERS_SHA and phase.digest(vk)==VK_SHA and len(vk)==328
        and parameters['domain_hex32']==phase.selected()['domain_hex32']
        and parameters['vk_hex328']==vk.hex(),'fresh-selected-parameters-and-VK')
    with core.owner_runtime.SelectedExecutable(t.DEFAULT_BRIDGE,t.BRIDGE_SHA) as bridge, \
         core.owner_runtime.SelectedExecutable(p.NATIVE,p.NATIVE_SHA) as native, \
         core.owner_runtime.SelectedExecutable(p.GENERIC,p.GENERIC_SHA) as generic:
        ctx=phase.LocalContext(directory_path,core.receiver_tools.recipient(),core.receiver_tools.Crypto(bridge))
        output=p.fresh(output,ctx.directory)
        source=p.read(source_path) if source_path else synthetic_source(ctx)
        source_point,context=source_context(ctx,source);save(ctx,output/'source-context.json',source)
        source_is_synthetic=source['oracle_stage']=='LOCAL_SYNTHETIC_TN10_FUNDING_BODY'
        bob=core.change_action.parse_invoice(bytes.fromhex(ctx.profile['private_invoices_hex208']['bob']),ctx.domain)
        charlie=core.change_action.parse_invoice(bytes.fromhex(ctx.profile['private_invoices_hex208']['charlie']),ctx.domain)
        fee=1;bootstrap_attempt=0
        while True:
            candidate_dir=directory(ctx,output/f'initial-sizing-{bootstrap_attempt:04d}')
            _,alice=ctx.owner('alice');reserve=e.PRINCIPAL+fee
            note=ctx.module.Receipt.for_invoice(alice.invoice(0),reserve,secrets.token_bytes(32))
            cipher=ctx.crypto.seal(alice.invoice(0).delivery_pk,note.encode())
            record=ctx.module.Delivery(0,note.commitment(),cipher)
            before=ctx.module.Snapshot([record],[ctx.module.NFEntry(bytes(32),bytes(32),0)])
            genesis=ctx.p.genesis(LegacyRuntime(native),ctx,vk,note.note_bytes(),record)
            descriptor=public_descriptor(ctx,genesis,vk,manifest,{'transactionId':'00'*32,'index':0})
            current=head(ctx,core,before,bytes.fromhex(genesis['redeem_hex']),descriptor['founding_outpoint'],reserve)
            intent=core.change_action.Intent('prepare-private-payment',e.PRINCIPAL,bob)
            initial=template(ctx,core,descriptor,current,before,'alice',intent)
            actual_fee=sizing_fee(ctx,core,initial,native,candidate_dir)
            if actual_fee==fee:break
            fee=actual_fee;bootstrap_attempt+=1
        founded,entry_fee,ordinary_change=founding(ctx,source,source_point,[context],genesis,reserve,generic,output)
        descriptor=public_descriptor(ctx,genesis,vk,manifest,point(founded))
        redeem=bytes.fromhex(genesis['redeem_hex'])
        current=head(ctx,core,before,redeem,point(founded),reserve)
        initial=template(ctx,core,descriptor,current,before,'alice',intent)
        after,selected,previous,row=actual_stage(ctx,core,initial,native,output,'initial-payment')
        phase.require(selected.fee==fee and selected.remaining==e.PRINCIPAL
            and sum(int.from_bytes(note[64:72],'little') for note in selected.notes)==e.PRINCIPAL,
            'initial-exact-payment-no-Alice-tail')
        rows=[row]
        main_nfs={selected.auth[204:236],selected.auth[236:268]}
        original_bob=core.change_action.select_claim(ctx.recognize('bob',after)[2])
        for owner,label,operation,amount,invoice in (
            ('bob','partial-cashout','prepare-partial-cashout',e.PARTIAL_PAYOUT,None),
            ('bob','change-payment','prepare-private-payment',e.FOLLOW_ON_PAYMENT,charlie),
            ('bob','full-cashout','prepare-full-cashout',0,None),
            ('charlie','terminal-cashout','prepare-full-cashout',0,None)):
            redeem=redeem[:2]+selected.after+redeem[114:]
            current=head(ctx,core,after,redeem,point(previous),selected.remaining)
            old=after
            action=template(ctx,core,descriptor,current,old,owner,core.change_action.Intent(operation,amount,invoice))
            if label=='change-payment':first_bob_change=action.claim
            after,selected,previous,row=actual_stage(ctx,core,action,native,output,label)
            rows.append(row);main_nfs.update((selected.auth[204:236],selected.auth[236:268]))
            if label in ('partial-cashout','change-payment'):
                historical=ctx.recognize('bob',after)[2]
                consumed=original_bob if label=='partial-cashout' else first_bob_change
                matching=[claim for claim in historical.owned if claim.position==consumed.position]
                phase.require(len(matching)==1 and not matching[0].owner_action_available,
                              'consumed-original-or-change-unavailable')
        phase.require(selected.remaining==0 and len(after.deliveries)==9 and len(after.nullifiers)==11,
                      'main-terminal-zero-CM9-NF11')
        phase.require(all(ctx.recognize(owner,after)[2].all_owned_unspent_sompi==0
            for owner in ('alice','bob','charlie')),'all-original-backups-zero-private-tails')
        private_fees=dict(zip(e.FEE_NAMES,[row['fee_sompi'] for row in rows]))
        modeled=e.derive(private_fees)
        phase.require(modeled['native_payouts_sompi']==sum(row['payout_sompi'] for row in rows)
            and source['amount_sompi']==ordinary_change+entry_fee+modeled['private_fees_sompi']
                +modeled['native_payouts_sompi'],'actual-main-whole-source-reconciliation')
        # Independent PUBLIC SYNTHETIC control, never a real main-route claim.
        # Reusing a main claim here would intersect two NF pairs and reveal its
        # shuffled real-NF slot if both unbroadcast statements were published.
        fork_dir=directory(ctx,output/'zero-change-sizing')
        canary_seed=bytes.fromhex(phase.digest(b'KPX3/CHANGE/C0/PUBLIC-OWNER/DO-NOT-FUND'))
        recipient_seed=bytes.fromhex(phase.digest(b'KPX3/CHANGE/C0/PUBLIC-RECIPIENT/DO-NOT-FUND'))
        canary=ctx.module.Receiver(canary_seed,ctx.domain,ctx.crypto)
        canary_recipient=ctx.module.Receiver(recipient_seed,ctx.domain,ctx.crypto).invoice(0)
        canary_note=ctx.module.Receipt.for_invoice(canary.invoice(0),e.PRINCIPAL,
            bytes.fromhex(phase.digest(b'KPX3/CHANGE/C0/PUBLIC-RHO/DO-NOT-FUND')))
        canary_delivery=ctx.module.Delivery(0,canary_note.commitment(),
            ctx.crypto.seal(canary.invoice(0).delivery_pk,canary_note.encode()))
        fork_snapshot=ctx.module.Snapshot([canary_delivery],[ctx.module.NFEntry(bytes(32),bytes(32),0)])
        fork_genesis=ctx.p.genesis(LegacyRuntime(native),ctx,vk,canary_note.note_bytes(),canary_delivery)
        fake_point={'transactionId':phase.digest(b'KPX3/CHANGE/C0/FAKE-OUTPOINT/DO-NOT-FUND\0'+ctx.domain),'index':0}
        fork_descriptor=public_descriptor(ctx,fork_genesis,vk,manifest,fake_point)
        fork_head=head(ctx,core,fork_snapshot,bytes.fromhex(fork_genesis['redeem_hex']),fake_point,e.PRINCIPAL)
        recovered=ctx.module.recover(canary,fork_snapshot.pin(ctx.domain),fork_snapshot)
        claim=core.change_action.select_claim(recovered)
        provisional=recognized_template(ctx,core,fork_descriptor,fork_head,fork_snapshot,
            canary_seed,canary,recovered,
            core.change_action.Intent('prepare-private-payment',claim.receipt.value_sompi,canary_recipient))
        fork_fee=sizing_fee(ctx,core,provisional,native,fork_dir)
        target=claim.receipt.value_sompi-fork_fee
        phase.require(target>=e.NOTE_FLOOR,'zero-change-recipient-floor')
        fork_template=recognized_template(ctx,core,fork_descriptor,fork_head,fork_snapshot,
            canary_seed,canary,recovered,
            core.change_action.Intent('prepare-private-payment',target,canary_recipient))
        fork_after,fork_actual,fork_body,fork_row=actual_stage(ctx,core,fork_template,native,output,'zero-change-control')
        phase.require(fork_actual.fee==fork_fee and fork_actual.payout==0
            and len(fork_after.deliveries)==3 and len(fork_after.nullifiers)==3
            and fork_actual.remaining==target
            and ctx.module.recover(canary,fork_after.pin(ctx.domain),fork_after).all_owned_unspent_sompi==0
            and ctx.module.recover(ctx.module.Receiver(recipient_seed,ctx.domain,ctx.crypto),
                fork_after.pin(ctx.domain),fork_after).all_owned_unspent_sompi==target
            and sum(int.from_bytes(note[64:72],'little')>0 for note in fork_actual.notes)==1,
            'separate-exact-zero-change-branch')
        phase.require({fork_actual.auth[204:236],fork_actual.auth[236:268]}.isdisjoint(main_nfs)
            and {row.cm for row in fork_after.deliveries}.isdisjoint({row.cm for row in after.deliveries}),
            'public-synthetic-C0-no-main-claim-or-NF-overlap')
        save(ctx,output/'zero-change-control/PUBLIC-SYNTHETIC.json',{
            'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND','not_a_canonical_main_trial_branch':True,
            'public_canary_owner_seed_hex32':canary_seed.hex(),
            'public_canary_recipient_seed_hex32':recipient_seed.hex(),
            'fake_outpoint':fake_point,'CM_count_after':3,'NF_count_after':3,
            'zero_self_change':True,'no_main_claim_or_NF_overlap':True,'broadcast':False})
        phase.require(len({row['transaction_id'] for row in rows+[fork_row]})==6,
                      'six-distinct-private-statements')
        save(ctx,output/'genesis.json',genesis);save(ctx,output/'local-descriptor.json',descriptor)
        result={'schema':'kpx3-private-change-local-preparation/v1','trial_id':ctx.profile['trial_id'],
            'domain_hex32':ctx.domain.hex(),'source_context_kind':source['oracle_stage'],
            'synthetic_funding_context':source_is_synthetic,'accepted_chain_backing':False,
            'actual_source_trial_readiness':False,'source_sompi':source['amount_sompi'],
            'earlier_ordinary_funding_costs_included_here':False,
            'founding_fee_sompi':entry_fee,'ordinary_change_sompi':ordinary_change,
            'founding_body_directory':str(output/'founding-final'),'stages':rows,'alternate_C0_stage':fork_row,
            'private_fee_total_sompi':modeled['private_fees_sompi'],
            'native_payouts_sompi':modeled['native_payouts_sompi'],'terminal_reserve_sompi':0,
            'final_CM_count':9,'final_NF_count':11,'all_recognized_private_tails_sompi':0,
            'parameters_sha256':PARAMETERS_SHA,'vk_sha256':VK_SHA,
            'private_proofs_or_setup_or_RPC_or_broadcast_performed':False,
            'negative_public_sizing_and_actual_quote_native_VM_performed':True,
            'main_unbroadcast_Auth_NF_bodies_and_proof_requests_must_remain_private':True,
            'independent_cold_recovery_or_privacy_or_fee_qualified':False}
        save(ctx,output/'MATERIALIZED.json',result)
        return {'phase':'synthetic-local-prepared' if source_is_synthetic else 'provided-context-local-prepared',
            'private_actions':5,'separate_C0_actions':1,'private_proofs':0,'funding_or_broadcast':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trial',type=Path)
    for name in ('vk','parameters','output'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--source',type=Path)
    args=parser.parse_args()
    print(json.dumps(prepare(args.trial,args.vk,args.parameters,args.output,args.source),sort_keys=True))
