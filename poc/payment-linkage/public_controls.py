"""Small explicit public fixtures; no hidden seed, wallet, proof, PK or network."""
import copy
import hashlib
import json
from schema import canonical

DOMAIN=hashlib.sha256(b'KPI/LINKAGE/PUBLIC-CONTROLS/DO-NOT-FUND').digest()
BOX=(bytes([9])*264).hex()  # Shape only; never described as genuine encryption.
SPK='000020'+'11'*32+'ac'

def h(label):return hashlib.sha256(label.encode()).hexdigest()

def base(profile='C'):
    return {'schema':'kpx3-payment-linkage-public/v1',
      'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_ARITHMETIC_MODEL',
      'known_wallet_policy':'one_real_input_full_native_cashout','profile':profile,
      'rate_sompi_per_mass':100,'exit_credit_sompi':19_000_000,'domain_hex32':DOMAIN.hex(),
      'funding_directory':[{'source_id':0,'payer_role':0}],
      'participant_roles':{'C':[],'C+1':[2],'C+8':list(range(2,10))}[profile],
      'participant_records':[],'events':[]}

def event(pub,kind,*,amount=0,source=None,payout=0,fee=19_000_000,mode=2,cms=None):
    rows=pub['events'];ordinal=len(rows);before=rows[-1]['reserve_sompi'] if rows else 0
    n=rows[-1]['cm_cursor'] if rows else 0;m=rows[-1]['nf_count'] if rows else 1
    row={'ordinal':ordinal,'tx_id':h('tx'+str(ordinal)),'minute':ordinal,'kind':kind,
       'prior_reserve_sompi':before,'reserve_sompi':before,'fee_sompi':fee,
       'payout_sompi':payout,'payout_spk_hex36':SPK if payout else None,
       'prior_cm_cursor':n,'cm_cursor':n,'prior_nf_count':m,'nf_count':m,
       'mode':None if kind=='ingress' else mode,'append_start':n,'notes':[],'nfs':[],
       'ingress_value_sompi':amount if kind=='ingress' else None,
       'ingress_source_id':source if kind=='ingress' else None,
       'public_ingress_note_hex168':None}
    if kind=='ingress':
        opening=bytes(64)+amount.to_bytes(8,'little')+bytes(96)
        row['public_ingress_note_hex168']=opening.hex();row['reserve_sompi']=before+amount
        cms=[hashlib.sha256(b'KPX1NOT\0'+DOMAIN+opening).hexdigest()]
        start=n
    else:
        row['reserve_sompi']=before-payout-fee;row['nfs']=[h(f'nf{ordinal}/{i}') for i in (0,1)];row['nf_count']=m+2
        start=((n+mode-1)//mode)*mode if mode else 0
        cms=cms if cms is not None else [h(f'cm{ordinal}/{i}') for i in range(mode)]
    row['append_start']=start;row['cm_cursor']=start+len(cms) if mode else n
    row['notes']=[{'position':start+i,'cm':cm,'ciphertext_hex264':BOX} for i,cm in enumerate(cms)]
    rows.append(row);return row

def two_outputs():
    p=base();event(p,'ingress',amount=1_020_000_000,source=0)
    event(p,'private',fee=20_000_000)
    event(p,'private',payout=400_000_000)
    event(p,'private',payout=562_000_000,mode=0)
    return p

def two_sources():
    p=base();p['funding_directory'].append({'source_id':1,'payer_role':1})
    event(p,'ingress',amount=600_000_000,source=0)
    event(p,'ingress',amount=400_000_000,source=1)
    event(p,'private',payout=581_000_000)
    event(p,'private',payout=381_000_000,mode=0)
    return p

def one_payer_wide():
    p=base();event(p,'ingress',amount=3_220_000_000,source=0)
    event(p,'private',fee=20_000_000,mode=32)
    for i in range(32):event(p,'private',payout=81_000_000,mode=0 if i==31 else 2)
    return p
