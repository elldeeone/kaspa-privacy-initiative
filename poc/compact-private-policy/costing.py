"""Integer lifecycle cost screen from actual emitted bytes/native mass receipts.

Future matching circuits and useful simultaneous demand are assumptions. No
transaction in this cost projection was signed, proved, funded or broadcast.
"""
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys
import all_branch_meter

RESULT_SHA='9e6675f6f0482b86e62fc2d5968933a4ab7798a481f2c5ec0df1c6699e921d68'
MAX=2_870_000_000_000_000_000
RATE=100
ENTRY_UPPER=2585 # Preserve the previous conservative direct-entry charge.

def sha(raw):return hashlib.sha256(raw).hexdigest()
def storage(inputs,outputs):
    if not all(type(v) is int and 0<v<=MAX for v in inputs+outputs):raise ValueError('integer-positive-amount-range')
    if not (len(inputs)==1 or len(outputs)==1 or len(inputs)==len(outputs)==2):
        raise ValueError('only-source-relaxed-KIP9-plurality1-shapes')
    return max(0,sum(10**12//v for v in outputs)-sum(10**12//v for v in inputs))
def charge(label,inputs,outputs,fee,mass):
    if sum(inputs)>MAX or sum(inputs)!=sum(outputs)+fee:raise ValueError('checked-backing-equation')
    actual_storage=storage(inputs,outputs)
    if actual_storage>mass or fee<RATE*mass:raise ValueError('underfunded-normalized-fee')
    return {'label':label,'inputs_sompi':inputs,'outputs_sompi':outputs,'fee_sompi':fee,
        'normalized_mass_ceiling':mass,'KIP9_storage_mass':actual_storage}

def batch(n,base,payer_budget):
    payer=base['wide_P0']+100*(payer_budget-1600);continuing=base['continuing'];terminal=base['terminal']
    exit_fee=RATE*continuing;pay_fee=RATE*payer;entry_fee=RATE*ENTRY_UPPER
    gross=1_000_000_000+exit_fee;reserve=n*gross;note=reserve+pay_fee;change=10_000_000_000
    source=note+change+entry_fee
    ledger=[charge('direct-entry',[source],[note,change],entry_fee,ENTRY_UPPER),
            charge('wide-P0',[note],[reserve],pay_fee,payer)]
    n_count=64;m_count=3
    for ordinal in range(n):
        remaining=reserve-gross;outputs=([remaining] if remaining else [])+[1_000_000_000]
        ledger.append(charge('independent-owner-exit-'+str(ordinal+1),[reserve],outputs,exit_fee,
            continuing if remaining else terminal))
        reserve=remaining;m_count+=2
        if remaining:n_count+=2
    fees=sum(row['fee_sompi'] for row in ledger);percent=Fraction(100*fees,n*1_000_000_000)
    if source!=change+n*1_000_000_000+fees+reserve:raise ValueError('complete-batch-reconciliation')
    return {'simultaneously_demanded_independent_recipients_required':n,'payer_budget':payer_budget,'exit_budget':1600,
        'native_useful_payment_each_sompi':1_000_000_000,'receiver_gross_note_each_sompi':gross,
        'ordinary_change_sompi':change,'source_sompi':source,'complete_fee_sompi':fees,
        'complete_fee_percent':float(percent),'complete_fee_percent_exact':[percent.numerator,percent.denominator],
        'passes_unchanged_2_percent_byte_and_mass_screen':fees<=20_000_000*n,
        'terminal_overpayment_sompi':exit_fee-RATE*terminal,
        'terminal_reserve_sompi':reserve,'final_physical_CM_count':n_count,'final_NF_count':m_count,
        'initial_alignment_skipped_empty_slots':31,'extra_CM_slots_from_continuing_exits':62,
        'lifecycle_proved_funded_or_privacy_qualified':False,'ledger':ledger}

def repeated(base):
    # Two separate-time compact private payments; the remaining payer change is
    # a third owner cashout, never counted as a useful payment.
    pay_fee=RATE*base['compact_P0'];exit_fee=RATE*base['continuing'];entry_fee=RATE*ENTRY_UPPER
    receiver=1_000_000_000+exit_fee;payer_final=10_000_000_000+exit_fee
    note=2*receiver+payer_final+2*pay_fee;ordinary_change=10_000_000_000;source=note+ordinary_change+entry_fee
    reserve=note;ledger=[charge('direct-entry',[source],[note,ordinary_change],entry_fee,ENTRY_UPPER)]
    for ordinal in (1,2):
        reserve_after=reserve-pay_fee
        ledger.append(charge('compact-P0-payment-'+str(ordinal),[reserve],[reserve_after],pay_fee,base['compact_P0']))
        reserve=reserve_after
    for ordinal,payout in enumerate((1_000_000_000,1_000_000_000,10_000_000_000),1):
        reserve_after=reserve-payout-exit_fee;outputs=([reserve_after] if reserve_after else [])+[payout]
        ledger.append(charge('independent-owner-cashout-'+str(ordinal),[reserve],outputs,exit_fee,
            base['continuing'] if reserve_after else base['terminal']));reserve=reserve_after
    fees=sum(row['fee_sompi'] for row in ledger);percent=Fraction(fees*100,2_000_000_000)
    if source!=ordinary_change+2_000_000_000+10_000_000_000+fees+reserve:raise ValueError('repeated-lifecycle-reconciliation')
    return {'useful_private_payments':2,'net_useful_each_sompi':1_000_000_000,'payer_private_change_cashout_sompi':10_000_000_000,
        'payer_change_counted_as_useful_payment':False,'proof_verifications_required':5,
        'complete_fee_sompi':fees,'complete_fee_percent':float(percent),
        'passes_2_percent':False,'all_amounts_integer_sompi':True,'terminal_reserve_sompi':reserve,'ledger':ledger}

def run(result_file):
    raw=result_file.read_bytes()
    if sha(raw)!=RESULT_SHA:raise ValueError('selected-single-native-batch')
    report=json.loads(raw)
    if (report['case_count']!=55 or report['final_G16_seams']!=8
            or not report['all_expected_typed_verdicts_match'] or report['financial_acceptances']!=0):
        raise ValueError('actual-native-screen-verdicts')
    shapes={}
    desired={(32,'none'):'wide_P0',(2,'none'):'continuing',(0,'none'):'terminal',(2,'compact-P0'):'compact_P0'}
    redeem=None;measured=[]
    for index,row in enumerate(report['results']):
        if (row['mode'],row['fault']) not in desired:continue
        case=json.loads((result_file.parent/f'case-{index:03d}/case.json').read_bytes())
        current=bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])[199:]
        if redeem is not None and current!=redeem:raise ValueError('same-whole-program')
        redeem=current;metrics=row['metrics'];payload=len(case['transaction']['payload'])//2
        out_spk=sum(len(out['scriptPublicKey'])//2 for out in case['transaction']['outputs'])
        # Same source formula used by the official estimator, independently
        # checked against all four actual native receipt shapes.
        estimate=94+54+199+len(redeem)+sum(18+(len(out['scriptPublicKey'])//2-2) for out in case['transaction']['outputs'])+payload
        compute=estimate+10*out_spk+160000
        normalized=max(compute,2*estimate,storage([100_000_000_000],[out['value'] for out in case['transaction']['outputs']]))
        if (metrics['estimated_bytes']!=estimate or metrics['compute_mass']!=compute
                or metrics['transient_mass']!=4*estimate or metrics['mining_mass']!=normalized):
            raise ValueError('native-source-mass-formula-conformance')
        name=desired[(row['mode'],row['fault'])];shapes[name]=normalized
        measured.append({'shape':name,'compute_mass':compute,'normalized_mass':normalized,
            'estimated_bytes':estimate,'payload_bytes':payload,'observed_zeroProof_units':row['native_units']})
    if len(shapes)!=4:raise ValueError('all-native-wire-shapes-required')
    retained=all_branch_meter.retained_branch_upper_bounds(redeem)
    if max(retained.values())>2_009_999:raise ValueError('retained-budget200-upper')
    # Additional routes are priced explicitly but not substituted for the
    # private batch. REVEAL loses private input/owner secrecy by definition.
    length=len(redeem);additional=[]
    for name,inputs,output_script_bytes,payload,budget in (
            ('REVEAL-continuing',1,[35,34],2029,200),('REVEAL-terminal',1,[34],2029,200),
            ('ADMIT-with-change',2,[35,34],1344,210),('ADMIT-no-change',2,[35],1344,210)):
        witness_bytes=199+length+(66 if inputs==2 else 0)
        estimate=94+54*inputs+witness_bytes+sum(18+x for x in output_script_bytes)+payload
        compute=estimate+10*sum(x+2 for x in output_script_bytes)+100*budget
        additional.append({'route':name,'estimated_bytes':estimate,'compute_mass':compute,
            'normalized_byte_compute_mass':max(compute,2*estimate),'fee_at100_before_any_larger_storage':100*max(compute,2*estimate),
            'KIP9_storage_must_be_recomputed_for_actual_amounts':True,'new_native_branch_signature_test':False})
    return {'classification':'ACTUAL_EMITTED_BYTES_AND_NATIVE_MASS_WITH_FUTURE_CIRCUIT_LIFECYCLE_PROJECTION',
        'selected_native_result_sha256':RESULT_SHA,'common_redeem_bytes':len(redeem),'native_wire_shapes':measured,
        'retained_ADMIT_REVEAL_source_upper_units':retained,'retained_selected_budget':200,
        'ordinary_funding_signature_budget':10,'ordinary_Schnorr_source_unit_upper':100099,
        'source_meter_Schnorr_tariff':100000,'direct_entry_mass_ceiling':ENTRY_UPPER,
        'entry_ceiling_conservative_not_new_native_founding_measurement':True,
        'batch32':[batch(32,shapes,budget) for budget in (1600,2200)],
        'separate_time_private_change_payments':repeated(shapes),'retained_additional_routes':additional,
        'new_crypto_setup_PK_seed_prover_funding_or_RPC':0,'fee_privacy_or_production_qualification':False,
        'still_required':['matched compact and wide relations and adversarial proof controls',
            'receipt/recovery sparse physical-position support','genuine32 already demanded independent recipients',
            'full native entry-payment-independent-exits rehearsal','capacity and financial-privacy qualification']}
if __name__=='__main__':
    result=run(Path(sys.argv[1]));result['calculator_sha256']=sha(Path(__file__).read_bytes())
    result['all_branch_meter_sha256']=sha(Path(all_branch_meter.__file__).read_bytes())
    with Path(sys.argv[2]).open('x') as file:json.dump(result,file,sort_keys=True,indent=2);file.write('\n')
    print(json.dumps({'batch32_fee_percent':[x['complete_fee_percent'] for x in result['batch32']],
        'separate_time_repeated_payment_percent':result['separate_time_private_change_payments']['complete_fee_percent']},sort_keys=True))
