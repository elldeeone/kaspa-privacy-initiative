#!/usr/bin/env python3
"""Prepare exact four-body fee fixed points; no VM/proof/setup/network calls."""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import secrets

import action as a
import prepare as p
import trial as t

RATE = 100


def point(body, index=0):
    return {'transactionId': body['id'], 'index': index}


def rawpoint(value):
    raw = bytes.fromhex(value['transactionId'])
    t.require(len(raw) == 32 and raw.hex() == value['transactionId'], 'outpoint-txid')
    return raw + a.u32(value['index'])


def strict_source(ctx, source):
    t.require(set(source) == {'source_key','oracle_stage','transaction_id','index','amount_sompi',
        'spk_version','spk_hex','block_daa_score','is_coinbase','covenant_id'}, 'planned-source-fields')
    t.require(source['source_key'] == 'TRIAL_FUNDING_KEY'
        and source['oracle_stage'] == 'LOCAL_PLANNED_TN10_FUNDING_BODY'
        and type(source['amount_sompi']) is int and 0 < source['amount_sompi'] <= a.MAX
        and type(source['spk_version']) is int and source['spk_version'] == 0
        and '0000'+source['spk_hex'] == ctx.profile['funding_destination']['canonical_spk_hex']
        and source['is_coinbase'] is False and source['covenant_id'] is None
        and source['block_daa_score'] == '0', 'prospective-source-identity')
    previous = {'transactionId':source['transaction_id'],'index':source['index']}
    rawpoint(previous)
    return previous, p.context_entry(source['amount_sompi'],'0000'+source['spk_hex'])


def quote(runtime, stage, builder, output):
    fee,attempt = 1,0
    rows=[]
    while True:
        prepared = builder(fee)
        directory=output/f'{stage}-{attempt:03d}'
        body,metrics=p.normalize(runtime,prepared['body'],prepared['contexts'],directory)
        actual=sum(int(row['amount_sompi']) for row in prepared['contexts'])-sum(row['value'] for row in body['outputs'])
        t.require(actual==fee==metrics['actual_fee_sompi'],'fee-body-authorization')
        required=RATE*metrics['mining_mass']
        rows.append({'fee_sompi':fee,'required_sompi':required,'mining_mass':metrics['mining_mass']})
        if fee>=required:
            p.save(output/(stage+'-fixedpoint.json'),{'schema':'kpx3-source-fee-fixedpoint/v1',
                'rate_sompi_per_mass':RATE,'fee_sompi':fee,'attempts':rows,'native_VM_performed':False})
            return fee,prepared,body,directory
        fee=max(fee,required);attempt+=1


def private_case(ctx, public, redeem, previous, amount, spk):
    contexts=[p.context_entry(amount,spk)]
    return {'body':p.private_transaction(public,redeem,previous,spk),'contexts':contexts}


def snapshot(value):
    return {'deliveries':[row.public() for row in value.deliveries],
        'nullifiers':[{'value':row.value.hex(),'next_value':row.next_value.hex(),
                      'next_index':row.next_index} for row in value.nullifiers]}


def materialize(directory, source_path, vk_path, output):
    ctx=p.Context(directory)
    executable_type=type(ctx.crypto.runtime_handle)
    try:
        output=p.fresh(output,ctx.directory)
        source=p.read(source_path);source_point,source_context=strict_source(ctx,source)
        vk=vk_path.read_bytes();t.require(len(vk)==328 and vk!=bytes(328),'fresh-VK328')
        # Only the root-selected caller supplies the new setup's public VK.
        # The final runtime freeze must bind its setup/core/build provenance.
        recipe_path=ctx.directory/'actual-action-recipe.json'
        if recipe_path.exists():
            recipe=p.read(recipe_path)
            t.require(recipe['planned_source']==source and recipe['selected_vk_sha256']==t.digest(vk),
                      'saved-actual-recipe-source-key-selection')
        else:
            recipe=p.read(ctx.directory/'local-shape/recipe.json')
            # Select once per identity, before any actual-body quote. Keep the
            # setup-only recipe unchanged and retain a failed attempt's choice.
            recipe['recipient_order']=['bob','charlie']
            secrets.SystemRandom().shuffle(recipe['recipient_order'])
            recipe['planned_source']=source
            recipe['selected_vk_sha256']=t.digest(vk)
            p.save(recipe_path,recipe)
        p.save(output/'planned-source.json',source)
        p.save(output/'recipe.json',recipe)
        with executable_type(p.NATIVE,p.NATIVE_SHA) as native, executable_type(p.GENERIC,p.GENERIC_SHA) as generic:
            cache={}
            def payment_shape(fee):
                raw,record,before,after,fixture,public=ctx.payment(fee,recipe,bytes(36))
                genesis=p.genesis(native,ctx,vk,raw,record)
                redeem=bytes.fromhex(genesis['redeem_hex'])
                prepared=private_case(ctx,public,redeem,
                    {'transactionId':bytes(32).hex(),'index':0},2*a.FLOOR+fee,genesis['script_public_key_hex'])
                cache[fee]=(raw,record,before,after,fixture,public,genesis)
                return prepared
            spend_fee,_,_,_=quote(generic,'payment-shape',payment_shape,output)
            raw,record,before,_,_,_,genesis=cache[spend_fee]
            reserve=2*a.FLOOR+spend_fee

            def founding(fee):
                change=source['amount_sompi']-reserve-fee
                t.require(change>=0,'ordinary-source-affordability')
                outputs=[(reserve,genesis['script_public_key_hex'])]
                if change:outputs.append((change,source_context['script_public_key']))
                return {'body':p.transaction(source_point,outputs,bytes.fromhex(genesis['payload_hex536']),
                    bytes(66),10),'contexts':[source_context]}
            founding_fee,founded,unsigned,founding_quote=quote(generic,'founding',founding,output)
            signed=p.sdk_call(unsigned,founded['contexts'],ctx.profile['secrets']['funding_secret_hex32'])
            expected=copy.deepcopy(unsigned);expected['inputs'][0]['signatureScript']=signed['inputs'][0]['signatureScript']
            t.require(signed==expected,'SDK-signature-only-substitution')
            founding_body,_=p.normalize(generic,signed,founded['contexts'],output/'founding-final')
            t.require(p.sdk_call(founding_body,founded['contexts'])==founding_body,'founding-SDK-roundtrip')
            initial_redeem=bytes.fromhex(genesis['redeem_hex'])
            # Keep the exact already-quoted ciphertexts/notes; only bind prior outpoint.
            after,fixture,public=a.action(ctx.module,ctx.domain,before,
                [(0,ctx.wallets['alice']),None],[(bytes.fromhex(row['note_hex168']),delivery)
                    for row,delivery in zip(cache[spend_fee][4]['outputs'],cache[spend_fee][3].deliveries[1:])],
                rawpoint(point(founding_body)),reserve,spend_fee,0,bytes(36),
                [tuple(bytes.fromhex(v) for v in row) for row in recipe['dummy_inputs'][:2]])
            current=private_case(ctx,public,initial_redeem,point(founding_body),reserve,genesis['script_public_key_hex'])
            spend_body,spend_metrics=p.normalize(generic,current['body'],current['contexts'],output/'spend-final')
            t.require(spend_fee>=RATE*spend_metrics['mining_mass'],'actual-payment-fee-fixedpoint')
            p.sdk_call(spend_body,current['contexts'])
            stages=[{'stage':'spend','body_directory':str(output/'spend-final'),'fee_sompi':spend_fee,
                     'public':public,'contexts':current['contexts']}]
            p.save(output/'spend-witness.json',fixture)
            records={'founding':snapshot(before),'after-spend':snapshot(after)}
            previous=spend_body;redeem=initial_redeem[:2]+a.state(ctx.domain,after)+initial_redeem[114:]
            remaining=2*a.FLOOR
            founding_point=rawpoint(point(founding_body))
            for owner,label,dummy_start in [('bob','bob-full',2),('charlie','charlie-terminal',4)]:
                claim=ctx.own_claim(owner,after)
                position,note=claim.position,claim.receipt
                _,destination=a.payout_secret(ctx.seeds[owner],ctx.domain,founding_point,
                    after.deliveries[position].cm,position,ctx.crypto,[note.native_pk])
                old=after;old_redeem=redeem;old_previous=previous;old_remaining=remaining
                action_cache={}
                def exit_case(fee):
                    terminal=owner=='charlie';outputs=[]
                    if not terminal:
                        outputs=[a.dummy_output(ctx.module,ctx.domain,len(old.deliveries)+slot,
                            bytes.fromhex(recipe['rho'][3+slot]),bytes.fromhex(recipe['dummy_ciphers'][slot]))
                            for slot in range(2)]
                    next_state,witness,vector=a.action(ctx.module,ctx.domain,old,
                        [(position,ctx.wallets[owner]),None],outputs,rawpoint(point(old_previous)),
                        old_remaining,fee,a.FLOOR-fee,destination,
                        [tuple(bytes.fromhex(v) for v in row) for row in recipe['dummy_inputs'][dummy_start:dummy_start+2]])
                    result=private_case(ctx,vector,old_redeem,point(old_previous),old_remaining,
                        old_previous['outputs'][0]['scriptPublicKey'])
                    action_cache[fee]=(next_state,witness,vector)
                    return result
                fee,case,body,_=quote(generic,label,exit_case,output)
                after,witness,public=action_cache[fee]
                body,_=p.normalize(generic,body,case['contexts'],output/(label+'-final'))
                p.sdk_call(body,case['contexts'])
                p.save(output/(label+'-witness.json'),witness)
                stages.append({'stage':label,'body_directory':str(output/(label+'-final')),
                    'fee_sompi':fee,'public':public,'contexts':case['contexts']})
                records['after-'+label]=snapshot(after)
                remaining=int.from_bytes(bytes.fromhex(public['auth_hex528'])[476:484],'little')
                previous=body;redeem=old_redeem[:2]+a.state(ctx.domain,after)+old_redeem[114:]
            t.require(remaining==0 and len(after.deliveries)==5 and len(after.nullifiers)==7,
                      'prospective-terminal-zero-counts')
            t.require(all(ctx.module.recover(wallet,after.pin(ctx.domain),after).all_owned_unspent_sompi==0
                          for wallet in ctx.wallets.values()),'prospective-zero-owner-tails')
            fees=founding_fee+sum(row['fee_sompi'] for row in stages)
            payouts=sum(int.from_bytes(bytes.fromhex(row['public']['auth_hex528'])[484:492],'little')
                        for row in stages)
            change=founding_body['outputs'][1]['value'] if len(founding_body['outputs'])==2 else 0
            t.require(change+payouts+fees==source['amount_sompi'],'whole-source-change-fees-payouts')
            predecessor=founding_body
            for row in stages:
                body=p.read(Path(row['body_directory'])/'transaction.json')
                t.require(body['inputs'][0]['previousOutpoint']==point(predecessor)
                    and int(row['contexts'][0]['amount_sompi'])==predecessor['outputs'][0]['value']
                    and row['contexts'][0]['script_public_key']==predecessor['outputs'][0]['scriptPublicKey'],
                    'actual-previous-output-link')
                predecessor=body
            p.save(output/'private-records.json',records)
            p.save(output/'genesis.json',genesis)
            manifest={'schema':'kpx3-private-four-body-preparation/v1','classification':t.CLASS,
                'trial_id':ctx.profile['trial_id'],'domain_hex32':ctx.domain.hex(),
                'planned_source':source,'founding_body_directory':str(output/'founding-final'),
                'founding_fee_sompi':founding_fee,'source_sompi':source['amount_sompi'],
                'vk_hex328':vk.hex(),'initial_redeem_hex':initial_redeem.hex(),
                'stages':stages,'terminal_reserve_sompi':remaining,'final_CM_count':5,'final_NF_count':7,
                'total_fees_sompi':fees,'native_payouts_sompi':payouts,'ordinary_change_sompi':change,
                'native_VM_or_private_proof_or_setup_performed_here':False,'network_or_broadcast':False}
            p.save(output/'MATERIALIZED.json',manifest)
            return {'phase':'four-body-prepared-noVM','trial_id':ctx.profile['trial_id'],
                    'native_VM_or_proof_or_setup_performed':False}
    finally:ctx.close()


def main():
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trial',type=Path)
    for field in ('source','vk','output'):parser.add_argument('--'+field,type=Path,required=True)
    args=parser.parse_args()
    try:print(json.dumps(materialize(args.trial,args.source,args.vk,args.output),sort_keys=True))
    except (ValueError,KeyError,TypeError,OSError):
        raise SystemExit('private four-body preparation refused; no broadcast interface') from None


if __name__=='__main__':main()
