#!/usr/bin/env python3
"""stdin-only public arithmetic observer; no truth/generator/secret file reads."""
import json
import sys
from schema import decode,parse,digest,Invalid,ScopeLimit
from model import Model

ASSUMPTIONS=['complete public chronology and truthful predeclared participant records',
             'known honest one-real-input wallet and full-native-cashout policy',
             'exact integer backing/single-spend and binding equal-CM values',
             'source lineage is original funding ancestry, not economic sender identity']
MISSING=['actual hash/NF preimage existence, authorized owner worlds and equal probabilities',
         'ciphertext decryption/correct delivery, cryptographic/setup soundness',
         'native/chain acceptance, data availability, network and endpoint privacy']

def analyze(public,*,group=True,backend=None):
    report={'schema':'kpx3-payment-linkage-analysis/v1','classification':'CONDITIONAL_SYNTHETIC_INTEGER_RELAXATION',
            'owner_identity':'NOT_MODELLED','privacy_qualification':False,'assumptions':ASSUMPTIONS,
            'missing_constraints':MISSING}
    try:ledger=decode(public)
    except ScopeLimit as error:return dict(report,status='INCOMPLETE_SCOPE',reason=str(error))
    except (Invalid,TypeError,KeyError,OverflowError) as error:return dict(report,status='REJECTED_INPUT',reason=str(error))
    engine=Model(ledger,group=group,backend=backend);result=engine.run()
    flags=[]
    for p,n in ledger.notes.items():
        if ledger.events[n.birth].kind!='private':continue
        raw=bytes.fromhex(n.ciphertext)
        flags.append({'position':p,'all_zero':not any(raw),'historical_highbit_not_honest_seal':bool(raw[31]&128)})
    guesses=[];known={r['position']:r for r in ledger.participants};birth_counterparties={}
    for r in ledger.participants:
        if r['invoice_counterparty_role'] is not None:
            birth_counterparties.setdefault(ledger.notes[r['position']].birth,set()).add(r['invoice_counterparty_role'])
    results={r['position']:r for r in result.get('note_results',[])}
    for p,n in ledger.notes.items():
        if ledger.events[n.birth].kind!='private':continue
        row=results.get(p);feasible=[] if row is None else [r['event'] for r in row['cashout_candidates'] if r['status']=='SAT']
        source=known.get(p);spend=ledger.nf_spends.get(p)
        participant_cashout=spend if spend is not None and ledger.events[spend].payout else None
        prior=4_500_000_000+public['exit_credit_sompi']
        amount_event=min(feasible,key=lambda e:(abs(ledger.events[e].payout+ledger.events[e].fee-prior),e)) if feasible else None
        time_event=min(feasible,key=lambda e:(ledger.events[e].minute-ledger.events[n.birth].minute,e)) if feasible else None
        labels=birth_counterparties.get(n.birth,set())
        guesses.append({'position':p,'price_prior_note_value_sompi':prior,
            'participant_note_value_sompi':source['value_sompi'] if source else None,
            'participant_direct_cashout_event':participant_cashout,'participant_record_known':source is not None,
            'closest_amount_cashout_event':amount_event,'closest_time_cashout_event':time_event,
            'same_birth_counterparty_role_heuristic':next(iter(labels)) if len(labels)==1 else None})
    scripts={}
    for e in ledger.events:
        if e.payout:scripts.setdefault(public['events'][e.ordinal]['payout_spk_hex36'],[]).append(e.ordinal)
    clusters=[{'payout_spk_hex36':spk,'events':events,'human_identity_or_CM_link_inferred':False}
              for spk,events in sorted(scripts.items()) if len(events)>1]
    return dict(report,known_wallet_policy=public['known_wallet_policy'],public_payout_SPK_reuse_clusters=clusters,public_sha256=digest(public),solver_version=__import__('z3').get_full_version(),
                ciphertext_format_flags=flags,fixed_guesses=guesses,**result)

if __name__=='__main__':
    try: print(json.dumps(analyze(parse(sys.stdin.buffer.read())),sort_keys=True,separators=(',',':')))
    except (ValueError,TypeError,KeyError) as error:
        print(json.dumps({'schema':'kpx3-payment-linkage-analysis/v1','status':'REJECTED_INPUT','reason':str(error)}))
        raise SystemExit(2)
