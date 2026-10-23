#!/usr/bin/env python3
"""Source-only whole-policy embedding screen. Never a runnable financial policy.

Exact old spans are checked against the sealed common-program template. New
guards/append pieces are emitted, with every other old byte/cost retained as an
overcount. A real new policy/circuit, explicit ADR and native lifecycle remain
required. No proposed lower compute budget is selected by this calculator.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path

import kernel as k
import source_meter as meter

ROOT=Path(__file__).resolve().parents[2]
TEMPLATE_SHA='731eb10da7a96a3f1f67b3c3fb0da6d45294820c8c610dc9d7d0d0fd1dd10556'
ZERO_CIPHER_HASH=bytes.fromhex('8889eb3cdd3d0ac94711b47ce78b430d8e23a7b31ecc994c56d0c3310c87674a')
ENTRY_MASS=2585


def sha(raw):return hashlib.sha256(raw).hexdigest()


def old_cm_span():
    s=k.Script()
    def path(start,slot):
        for j in range(16):
            s.num(0);s.num(273);s.num(277);s.raw.append(0xbc)
            s.data(b'\0');s.op('CAT');s.op('BIN2NUM')
            if slot:s.num(slot);s.op('ADD')
            s.num(1<<j);s.op('DIV');s.num(2);s.op('MOD');s.op('IF')
            s.payload(start+32*j,32);s.op('SWAP');s.op('ELSE')
            s.payload(start+32*j,32);s.op('ENDIF');s.hash_pair()
    for cm,start,slot in [(268,3376,0),(300,3888,1)]:
        s.op('TOALT');s.data(k.EMPTY[0]);path(start,slot);s.op('FROMALT');s.op('EQUALVERIFY')
        s.payload(cm,32);path(start,slot)
    return bytes(s.raw)


def zero_check(start,length):
    s=k.Script();s.payload(start,length);s.data(bytes(length));s.op('EQUALVERIFY');return bytes(s.raw)


def payload_size(n):
    if n==0:return 528+2320
    return 528+2320+296*n+32*(16-(n.bit_length()-1))


def new_cm_span(n):
    """Old root on stack -> new root; native-checked metadata gives aligned start."""
    s=k.Script();level=n.bit_length()-1;path_start=2848+296*n
    def path():
        for j in range(16-level):
            s.unsigned(304);s.num(n);s.op('DIV');s.num(1<<j);s.op('DIV')
            s.num(2);s.op('MOD');s.op('IF')
            s.payload(path_start+32*j,32);s.op('SWAP');s.op('ELSE')
            s.payload(path_start+32*j,32);s.op('ENDIF');s.hash_pair()
    def subtree(first,count):
        if count==1:s.payload(2848+32*first,32)
        else:
            subtree(first,count//2);subtree(first+count//2,count//2);s.hash_pair()
    s.op('TOALT');s.data(k.EMPTY[level]);path();s.op('FROMALT');s.op('EQUALVERIFY')
    subtree(0,n);path();return bytes(s.raw)


def mode_guards(n):
    """Complete new frame/mode/reserved/alignment/count/array+box bindings."""
    s=k.Script();s.op('PAYLOADLEN');s.num(payload_size(n));s.op('NUMEQUALVERIFY')
    s.payload(300,1);s.data(bytes([n]));s.op('EQUALVERIFY')
    for start,length in [(301,3),(308,24)]:s.payload(start,length);s.data(bytes(length));s.op('EQUALVERIFY')
    # ceil(old_n/N)*N == metadata.start; bounded old_n<=65535 is retained.
    s.unsigned(148);s.num(n-1);s.op('ADD');s.num(n);s.op('DIV');s.num(n);s.raw.append(0x95)
    s.unsigned(304);s.op('NUMEQUALVERIFY')
    s.unsigned(304);s.num(n);s.op('ADD');s.unsigned(436);s.op('NUMEQUALVERIFY')
    s.unsigned(436);s.num(65535);s.raw.extend([0xa1,0x69])
    s.payload(2848,32*n);s.op('SHA256');s.payload(268,32);s.op('EQUALVERIFY')
    s.payload(2848+32*n,264*n);s.op('SHA256');s.payload(332,32);s.op('EQUALVERIFY')
    if n>2:s.payload(484,8);s.data(bytes(8));s.op('EQUALVERIFY') # Wide mode is payer P0 only.
    return bytes(s.raw)


def terminal_guards():
    s=k.Script();s.op('PAYLOADLEN');s.num(payload_size(0));s.op('NUMEQUALVERIFY')
    s.payload(332,32);s.data(ZERO_CIPHER_HASH);s.op('EQUALVERIFY')
    # Existing64-zero CM0/1 check becomes exact zero CM-array hash+metadata.
    # Existing R0/P>0, CM-root/n carry, NF2 and private-note zero gates remain.
    return bytes(s.raw)


def piece_units(raw,root=False):
    m=meter.Meter([meter.Item(32)] if root else [],[meter.Item(128)] if root else [])
    m.run(meter.ast(raw))
    if root:
        if len(m.stack)!=1 or len(m.alt)!=1:raise ValueError('CM-piece-stack-contract')
    elif m.stack or m.alt:raise ValueError('guard-stack-contract')
    return m.units


def source_screen():
    tail=(ROOT/'poc/private-exit-recovery/kpx3-policy-template.bin').read_bytes()
    if sha(tail)!=TEMPLATE_SHA:raise ValueError('approved-old-common-program-identity')
    old=b'\x4c\x70'+bytes(112)+tail
    removed=[old_cm_span(),zero_check(528,528),zero_check(3376,1024)]
    if any(tail.count(raw)!=1 for raw in removed):raise ValueError('exact-unique-old-span-conformance')
    old_units=meter.current_private_upper_bound(old)
    terminal=terminal_guards();terminal_units=piece_units(terminal)
    rows=[]
    for n in (4,8,16,32):
        small=new_cm_span(2);wide=new_cm_span(n);guards=[mode_guards(2),mode_guards(n)]
        # Conservative embedding: retain every other old byte, even checks a
        # real emitter must replace. Extra VK328+selector, 64-byte rewrite and
        # 64-byte dispatcher allowances are explicit, uncredited overhead.
        extra_vk_and_selector=345;rewrite_allowance=64;dispatcher_allowance=64
        shared_size=len(old)-sum(map(len,removed))+len(small)+len(wide)+sum(map(len,guards))
        shared_size+=len(terminal)+extra_vk_and_selector+rewrite_allowance+dispatcher_allowance
        if not shared_size+199<32768:raise ValueError('fixed-width-old-script-length-operands')
        added_units=max(piece_units(small,True),piece_units(wide,True))+max(map(piece_units,guards))
        added_units+=terminal_units+400+8*(rewrite_allowance+dispatcher_allowance)
        upper_units=old_units+7*max(shared_size-len(old),0)+added_units
        rows.append({'n':n,'common_redeem_embedding_upper_bytes':shared_size,
            'old_exact_CM2_span_bytes':len(removed[0]),'old_exact_terminal_zero_spans_bytes':sum(map(len,removed[1:])),
            'new_small_CM_span_bytes':len(small),'new_wide_CM_span_bytes':len(wide),
            'new_mode_guard_bytes':list(map(len,guards)),'new_terminal_guard_bytes':len(terminal),
            'extra_VK_and_selector_bytes':extra_vk_and_selector,'rewrite_bytes_allowance':rewrite_allowance,
            'dispatcher_bytes_allowance':dispatcher_allowance,'all_private_modes_script_units_source_upper':upper_units,
            'budget1600_all_valid_path_allowance':16009999,'source_upper_fits1600':upper_units<=16009999,
            'source_upper_fits1550':upper_units<=15509999,'source_upper_fits1500':upper_units<=15009999,
            'wider_P0_payload_bytes':payload_size(n),'compact_continuing_payload_bytes':payload_size(2),
            'terminal_payload_bytes':payload_size(0)})
    return {'old_common_bytes':len(old),'old_private_source_upper_units':old_units,'candidate_components':rows}


def envelope(row,wide_exits=False,payer_budget=1600,exit_budget=1600):
    n=row['n'];length=row['common_redeem_embedding_upper_bytes']
    private_payload=payload_size(n);exit_payload=payload_size(n if wide_exits else 2)
    pay_compute=100*payer_budget+length+private_payload+770
    exit_compute=100*exit_budget+length+exit_payload+1182
    terminal_compute=100*exit_budget+length+payload_size(0)+759
    pay_bytes=400+length+private_payload;exit_bytes=452+length+exit_payload
    term_bytes=399+length+payload_size(0)
    pay_mass=max(pay_compute,2*pay_bytes);exit_mass=max(exit_compute,2*exit_bytes)
    term_mass=max(terminal_compute,2*term_bytes)
    # Every note prefunds the same continuing ceiling. The last receiver pays
    # that ceiling too, explicitly overpaying the cheaper terminal minimum.
    # Thus all N useful native payouts are exactly1B, independent of exit order.
    exit_fee=100*exit_mass;pay_fee=100*pay_mass;entry_fee=100*ENTRY_MASS
    note_value=1_000_000_000+exit_fee;reserve=n*note_value
    founding_value=reserve+pay_fee;source_value=founding_value+10_000_000_000+entry_fee
    storage_entry=max(0,10**12//founding_value+10**12//10_000_000_000-10**12//source_value)
    storage_pay=max(0,10**12//reserve-10**12//founding_value)
    storages=[max(0,10**12//((remaining-1)*note_value)+10**12//1_000_000_000-10**12//(remaining*note_value))
              for remaining in range(2,n+1)]
    storage_terminal=max(0,10**12//1_000_000_000-10**12//note_value)
    if not (storage_entry<=ENTRY_MASS and storage_pay<=pay_mass and max(storages,default=0)<=exit_mass
            and storage_terminal<=term_mass):raise ValueError('contextual-storage-dominates-envelope')
    fees=entry_fee+pay_fee+n*exit_fee
    if source_value!=10_000_000_000+n*1_000_000_000+fees:raise ValueError('whole-integer-backing-reconciliation')
    mean=Fraction(fees,n*100);percent=Fraction(fees*100,n*1_000_000_000)
    return {'n':n,'mode':'fixed-wide-exits' if wide_exits else 'dual-wide-payment-compact-exit',
        'payer_budget':payer_budget,'exit_budget':exit_budget,'common_bytes_upper':length,
        'source_script_unit_upper':row['all_private_modes_script_units_source_upper'],
        'payer_mass':pay_mass,'continuing_mass':exit_mass,'terminal_minimum_mass':term_mass,
        'terminal_fee_overpayment_mass_explicit':exit_mass-term_mass,'source_coin_sompi':source_value,
        'founding_note_sompi':founding_value,'receiver_note_each_sompi':note_value,
        'ordinary_change_sompi':10_000_000_000,'native_payout_each_sompi':1_000_000_000,
        'complete_fee_sompi':fees,'mean_mass_numerator':mean.numerator,'mean_mass_denominator':mean.denominator,
        'complete_fee_percent':float(percent),'fits_2_percent_in_source_envelope':fees<=20_000_000*n,
        'actual_program_circuit_native_lifecycle_or_privacy_qualified':False,
        'source_budget_upper_requires_independent_review_and_complete_new_emitter_conformance':True,
        'storage_bound_sompi_inputs_integer':{'entry':storage_entry,'payer':storage_pay,
            'max_continuing':max(storages,default=0),'terminal':storage_terminal}}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('new_output',type=Path);a=p.parse_args()
    data=source_screen();data['schema']='kpx-compact-whole-policy-source-screen/v1'
    data['envelopes']=[envelope(row,wide,budget) for row in data['candidate_components']
                       for wide in [False,True] for budget in [1600,2200]]
    data['calculator_sha256']=sha(Path(__file__).read_bytes());data['source_meter_sha256']=sha(Path(meter.__file__).read_bytes())
    data['financial_circuit_or_native_program_implemented']=False
    data['actual_Groth16_PK_seed_setup_funding_RPC_runs']=0
    with a.new_output.open('x') as f:json.dump(data,f,indent=2,sort_keys=True);f.write('\n')
    print(json.dumps({'sha256':sha(a.new_output.read_bytes()),'candidate_rows':len(data['candidate_components']),
        'passing_source_envelopes':sum(x['fits_2_percent_in_source_envelope'] for x in data['envelopes'])},sort_keys=True))
