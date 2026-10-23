#!/usr/bin/env python3
"""Source arithmetic only. No transaction, witness, proof, signature, RPC or native VM."""
import argparse, hashlib, json, pathlib, subprocess
K=10**12
U64=(1<<64)-1
RATES=(100,200,500)
LIABILITY=60_000_000
MIN_PAYOUT=10_000_000
FEE_CAP=LIABILITY-MIN_PAYOUT
NATIVE_REV='01b532e8b553523216471682649693af92f0fd16'
VPROGS_REV='f9b84a863a7c7c20586a9cf947550475e894f72e'

def storage(inputs,outputs):
    """Exact pinned KIP9 integer formula; cells are (plurality,amount)."""
    assert inputs and outputs and all(p>=1 and a>0 for p,a in inputs+outputs)
    harmonic_out=0
    for p,a in outputs:
        product=K*p*p
        if product>U64:raise OverflowError('native output storage numerator')
        harmonic_out+=product//a
        if harmonic_out>U64:raise OverflowError('native output storage sum')
    po=sum(p for p,_ in outputs)
    pi=sum(p for p,_ in inputs)
    if po==1 or (len(inputs)<=2 and (pi==1 or (po==2 and pi==2))):
        credit=min(U64,sum(K*p*p//a for p,a in inputs))
    else:
        mean=max(1,sum(a for _,a in inputs)//pi)
        credit=min(U64,pi*(K//mean))
    return max(0,harmonic_out-credit)

def mass(estimated_bytes,output_raw_script_lengths,budgets,inputs,outputs):
    compute=estimated_bytes+10*sum(2+x for x in output_raw_script_lengths)+100*sum(budgets)
    stored=storage(inputs,outputs)
    return {'estimated_bytes':estimated_bytes,'compute_mass':compute,'transient_mass':4*estimated_bytes,'storage_mass':stored,'normalized_mining_mass':max(compute,2*estimated_bytes,stored),'default_relay_mass':max(compute,2*estimated_bytes),'native_dimension_limits_pass':compute<=500_000 and stored<=500_000 and 4*estimated_bytes<=1_000_000}

def least_fee(rate,make_mass,fee_cap=FEE_CAP):
    """Least nonnegative fixed-point fee. Monotone cases only; no arbitrary retry cap."""
    fee=0;iterations=0
    while True:
        m=make_mass(fee)
        required=rate*m['normalized_mining_mass'];iterations+=1
        evaluated={'fee_sompi':fee,'metrics_evaluated_at_fee_sompi':fee,'required_fee_sompi':required,'iterations':iterations,'metrics':m}
        if not m['native_dimension_limits_pass']:
            return {'passes':False,'reason':'native dimension limit',**evaluated}
        if required<=fee:
            return {'passes':True,**evaluated}
        if required>fee_cap:
            return {'passes':False,'reason':'minimum next fee exceeds50M attributable cost allowance','next_required_fee_sompi':required,'fee_cap_sompi':fee_cap,**evaluated}
        fee=required

def permission_shape(depth,continuing=False,delegate_change=False):
    assert 1<=depth<=32
    L=445+22*depth
    # amount=deduct=60M needs a five-byte minimal script-number push.
    S=L+68*depth+52
    # Three inputs: permission public witness,53-byte delegate redeem+push,
    # and66-byte P2PK signature. One52-byte P2PK output; no payload.
    E=94+3*54+S+54+66+52
    out_scripts=[34]
    if continuing:E+=87;out_scripts.append(35) #53-byte output+34-byte covenant binding
    if delegate_change:E+=53;out_scripts.append(35)
    bound=L*L+4*L+139+65*(2*depth+3)
    b=bound//10_000
    assert b*10_000+9999>=bound
    return {'depth':depth,'redeem_bytes':L,'permission_signature_script_bytes':S,'estimated_bytes':E,'output_raw_script_lengths':out_scripts,'source_upper_bound_permission_units':bound,'conservative_permission_budget':b,'budgets':[b,0,10],'delegate_units_upper_bound':1835,'fee_input_units':100001}

def outputs_for_standard_claim(fee,remainder):
    out=[(1,LIABILITY-fee)]
    if remainder:out.append((1,remainder))
    return out

def standard_claim(signature_bytes,budget,payload,remainder=0):
    E=200+signature_bytes+payload+(53 if remainder else 0)
    return lambda fee:mass(E,[34]+([35]if remainder else[]),[budget],[(1,LIABILITY+remainder)],outputs_for_standard_claim(fee,remainder))

def official_permission_quote(depth,rate,delegate_amount=LIABILITY,continuing=False,fee_coin_value=None):
    shape=permission_shape(depth,continuing,delegate_amount>LIABILITY)
    if fee_coin_value is not None:
        assert fee_coin_value>FEE_CAP
        shape['estimated_bytes']+=52
        shape['output_raw_script_lengths'].append(34)
    def describe(fee):
        # Fees require a separate nondelegate input; fee0 is limit arithmetic,
        # use amount1 in that placeholder to keep the storage formula defined.
        cells=[(2,50_000_000),(1,delegate_amount),(1,fee_coin_value if fee_coin_value is not None else max(1,fee))]
        outs=[(1,LIABILITY+(0 if continuing else 50_000_000))]
        if continuing:outs.append((2,50_000_000))
        if delegate_amount>LIABILITY:outs.append((1,delegate_amount-LIABILITY))
        if fee_coin_value is not None:outs.append((1,fee_coin_value-fee))
        return mass(shape['estimated_bytes'],shape['output_raw_script_lengths'],shape['budgets'],cells,outs)
    row=least_fee(rate,describe)
    return {'shape':shape,'rate':rate,'fixed_fee_coin_value_sompi':fee_coin_value,'fee_change_output':fee_coin_value is not None,'fee_source':'additional nondelegate payer input; not liability or permission rent','claim_funded_under_unchanged_script':False,'quote':row}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--native',type=pathlib.Path,required=True);parser.add_argument('--vprogs',type=pathlib.Path,required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
    if args.output.exists():raise SystemExit('refusing preexisting output')
    root=pathlib.Path(__file__).resolve().parents[3]
    pins=[]
    for kind,checkout,revision in [('native',args.native,NATIVE_REV),('vprogs',args.vprogs,VPROGS_REV)]:
        actual=subprocess.check_output(['git','-C',str(checkout),'rev-parse','HEAD'],text=True).strip()
        if actual!=revision:raise SystemExit(f'{kind}: wrong checkout revision')
    native_files=['consensus/core/src/mass/mod.rs','consensus/core/src/mass/units.rs','consensus/core/src/constants.rs','consensus/core/src/config/params.rs','crypto/txscript/src/lib.rs','crypto/txscript/src/runtime_resource_meter.rs','crypto/txscript/src/opcodes/mod.rs','crypto/txscript/src/zk_precompiles/groth16/mod.rs','crypto/txscript/src/zk_precompiles/tags.rs','mining/src/mempool/check_transaction_standard.rs','mining/src/mempool/check_transaction_limits.rs']
    vprogs_files=['zk/backend/risc0/api/src/permission_script.rs','zk/backend/risc0/api/src/permission_tree.rs','zk/backend/risc0/api/src/permission_tags.rs','zk/abi/src/delegate_script.rs','zk/backend/risc0/test-suite/tests/permission_spend.rs','zk/backend/risc0/covenant/src/script.rs','Cargo.lock']
    for kind,base,paths in [('native',args.native,native_files),('vprogs',args.vprogs,vprogs_files),('repository',root,['poc/shared-pool/src/s7_lifecycle/native.rs','docs/rfc/0012-useful-privacy-requirements.md','research/next-session/ordinary-budget/actual-01/results/report.json'])]:
        for rel in paths:
            p=base/rel;b=p.read_bytes()
            if kind in ('native','vprogs'):
                committed=subprocess.check_output(['git','-C',str(base),'ls-tree','HEAD','--',rel],text=True).split()[2]
                working=subprocess.check_output(['git','-C',str(base),'hash-object','--',rel],text=True).strip()
                if committed!=working:raise SystemExit(f'{kind}: modified pinned source {rel}')
            pins.append({'kind':kind,'relative_path':rel,'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    # Independent integer-size checks against three already measured shapes.
    assert 94+54+24709+53+1204==26114
    assert 26114+370+170000==196484
    assert 94+54+24709+53+5231+370+160000==190511
    assert 94+2*54+24709+66+53+5231+370+160000+1000==191631
    standard=[]
    for sig,budget,payload,label in [(1024,11,0,'conditional compact ticket'),(4096,50,0,'conditional wider ticket'),(24709,100,5231,'conditional retained-size proof-free shape')]:
        standard.append({'label':label,'not_an_emitted_or_qualified_script':True,'signature_script_bytes':sig,'budget':budget,'allowance':budget*10000+9999,'payload_bytes':payload,'rates':[{'rate':r,**least_fee(r,standard_claim(sig,budget,payload))}for r in RATES]})
    split=[]
    for remainder in [10_000_000,20_000_000,25_000_000,60_000_000,1_000_000_000]:
        split.append({'reserve_remainder_sompi':remainder,'optimistic_shape':'1024-byte signature_script, budget11, no covenant IDs','rates':[{'rate':r,**least_fee(r,standard_claim(1024,11,0,remainder))}for r in RATES]})
    fanout=[]
    for cov in [False,True]:
        p=2 if cov else 1
        for n in [1,7,8,16,30,31]:
            #Zero-fee/nochange lower bound; valid positive fees only reduce input credit.
            stored=storage([(1,n*LIABILITY)],[(p,LIABILITY)]*n)
            fanout.append({'tickets':n,'covenant_ID':cov,'ticket_plurality':p,'zero_fee_storage_lower_bound':stored,'storage_limit_pass':stored<=500000,'rate_quotes_storage_only':[{'rate':r,'total_sompi':r*stored,'ceil_per_ticket_sompi':(r*stored+n-1)//n}for r in RATES]})
    upstream=[]
    for d in [1,16,32]:
        upstream.extend(official_permission_quote(d,r)for r in RATES)
    practical_external_fee=[official_permission_quote(d,r,fee_coin_value=100_000_000) for d in [1,16,32] for r in RATES]
    continuation=[]
    for delegate in [60_000_000,60_000_001,70_000_000,80_000_000,120_000_000,1_000_000_000,1_000_000_000_000]:
        continuation.append({'delegate_input_sompi':delegate,'rows':[official_permission_quote(16,r,delegate,True)for r in RATES]})
    lifecycle=[]
    for r in RATES:
        lifecycle.append({'rate':r,'single_two_verifier_lower_bound':2*147500*r,'three_verifier_lower_bound':3*147500*r,'one_admit_plus_one_two_digest_ticket_authorization_lower_bound':2*147500*r,'one_admit_plus_one_five_input_outer_authorization_lower_bound':(147500+155000)*r,'target_10KAS_lifecycle_at_reference':20_000_000,'reference_only_target':r==100})
    #Optimistic same-shape batching with BextraP2SHtickets, zero newmetadata.
    #Not a claim that existing P/J authorizes tickets or1700 covers an altered branch.
    batching=[]
    for B in [2,4,8,12]:
        E=25118+551*B;C=195488+921*B
        allocation=(C*100+B-1)//B
        batching.append({'payments_and_tickets':B,'conditional_estimated_bytes':E,'conditional_compute_mass':C,'optimistic_reference_native_share_sompi':allocation,'unamortized_admit_G16_floor_plus_share_sompi':14_750_000+allocation,'remaining_20M_for_claim_funding_service_retries':20_000_000-14_750_000-allocation,'newticketmetadata_bytes_assumed':0,'existing_proofs_authorize_these_outputs':False,'budget1700_for_newcode_qualified':False})
    frontiers=[]
    terminal_lower_mass=1015+360+1000 #selectedd1threeinputprofile; permissionbudget optimistically0
    terminal_upper_mass=4575 #conservatively covering sourcebound; not actualmeter
    for Ba in [1,2,4,8,12]:
        for Bp in [2,4,8,12]:
            payment_curve=195488+498*Bp
            row={'admit_attributed_real_users_Ba':Ba,'private_payments_Bp':Bp,'same_principal_sompi':1_000_000_000,'reference_lifecycle_cap_sompi':20_000_000,'current_genuine_B2_anchor_used':Bp==2,'other_Bp_shapes_conditional':Bp!=2,'actual_native_admit_support_for_Ba_above1':False}
            for label,A in [('ideal_admit_G16_floor',147500),('optimistic_division_of_measured_admit_atom',191631)]:
                admit_share=(100*A+Ba-1)//Ba
                payment_share=(100*payment_curve+Bp-1)//Bp
                floor=admit_share+payment_share+100*terminal_lower_mass
                upper=admit_share+payment_share+100*terminal_upper_mass
                row[label]={'admit_fee_share_sompi':admit_share,'private_fee_share_sompi':payment_share,'necessary_total_with_terminal_lower_sompi':floor,'necessary_budget_test_pass':floor<=20_000_000,'shape_source_upper_total_sompi':upper,'unallocated_budget_after_shape_upper_sompi':20_000_000-upper,'excludes_funding_creation_service_proving_retries':True}
            frontiers.append(row)
    necessary_arity=[]
    for terminal in [0,terminal_lower_mass,terminal_upper_mass]:
        for A,label in [(147500,'ideal_admit_verifier_floor'),(191631,'measured_admit_atom')]:
            residual=200000-A-498-terminal
            minimum=None if residual<=0 else (195488+residual-1)//residual
            necessary_arity.append({'Ba':1,'admit_mass_atom':A,'admit_interpretation':label,'terminal_mass':terminal,'terminal_interpretation':'source_upper_not_a_necessary_lower_bound'if terminal==terminal_upper_mass else'optimistic_lower_bound','minimum_Bp_for_fixed_padded_shape_arithmetic':minimum,'qualified_native_arity_range':'onlyB2isgenuine;4/8/12sourceconditional;largerunselected','extra_ticket_outputs_and_metadata_included':False})
    result={'format':'native-exit-cost-envelope-source-only-v1','calculator_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'both_checkout_revisions_and_native_vprogs_source_blobs_verified':True,'native_revision':NATIVE_REV,'vprogs_revision':VPROGS_REV,'liability_sompi':LIABILITY,'minimum_retained_payout_sompi':MIN_PAYOUT,'maximum_attributable_fee_sompi':FEE_CAP,'max_affordable_mining_mass':[{'rate':r,'mass':FEE_CAP//r}for r in RATES],'native_baseline_size_checks_pass':True,'native_execution_performed':False,'sources':pins,'standard_ticket_conditional':standard,'shared_reserve_conditional':split,'ticket_fanout_storage_lower_bounds':fanout,'official_permission_terminal_external_fee':upstream,'official_permission_terminal_1KAS_fee_input_and_change':practical_external_fee,'official_permission_continuing_external_fee':continuation,'known_cost_atoms':{'ADMIT_factory1700_measured_mass':201631,'ADMIT_prospective1600_measured_mass':191631,'ADMIT_actual_authorized_fee_sompi':40000000,'paired1700_measured_mass':196484,'paired_actual_authorized_total_fee_sompi':80000000,'paired_useful_payment_count':2,'paired_actual_authorized_per_payment_fee_sompi':40000000,'fixed_fees_repriced':False},'10KAS_lifecycle_lower_bounds':lifecycle,'Ba_Bp_integer_route_frontiers':frontiers,'unamortized_admit_minimum_Bp_shape_frontiers':necessary_arity,'optimistic_batch_ticket_shape':batching,'scope':'source-derived arithmetic only; full claim candidate, accepted authorization, funding availability, privacy and full per-user lifecycle remain unqualified'}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'output':str(args.output),'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),'source_count':len(pins),'new_native_or_proving_jobs':False}))
if __name__=='__main__':main()
