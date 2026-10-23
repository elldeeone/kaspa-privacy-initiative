"""Separate post-barrier scorer: no observer, generator, seed or key import."""
import hashlib
import math
from schema import decode,digest,hx,MAX
from certificate import check
from prediction import validate_prediction

CREDIT=18_867_700
FEES={'entry':258_500,'admit':5_098_200,'wide':19_701_700,'compact':18_826_500,
      'cashout':18_867_700,'terminal':18_718_200}

class BadTruth(ValueError):pass

def need(ok,text):
    if not ok:raise BadTruth(text)

def ratio(a,b):return {'successes':a,'denominator':b,'fraction':a/b if b else None}

def validate(public,truth):
    ledger=decode(public);end=len(ledger.events);rows={n['position']:n for n in truth['notes'] if n['birth']<end}
    need(set(rows)==set(ledger.notes),'truth-note-set')
    for p,n in rows.items():
        opening=hx(n['opening'],168)
        need(type(n['value']) is int and int.from_bytes(opening[64:72],'little')==n['value'],
             'truth-Note168-value64')
        need(hashlib.sha256(b'KPX1NOT\0'+hx(public['domain_hex32'],32)+opening).hexdigest()==n['cm']==ledger.notes[p].cm,
             'truth-note-cm-opening')
        need(n['birth']==ledger.notes[p].birth,'truth-note-birth')
        need(n['cipher']==ledger.notes[p].ciphertext,'truth-public-cipher-placement')
        if n['value']:
            need(type(n['owner']) is int and 0<=n['owner']<34,'truth-modeled-owner')
            hx(n['nf'],32)
            actual=[e.ordinal for e in ledger.events if n['nf'] in e.nfs]
            target=n['consumer'] if n['consumer'] is not None and n['consumer']<end else None
            need(actual==([] if target is None else [target]),'truth-original-NF-occurrence')
        else:
            need(n['owner'] is None and n['nf'] is None,'truth-zero-note')
            need(opening[:72]==bytes(72) and opening[104:]==bytes(64),'truth-canonical-zero-note-except-rho')
    inputs=[r for r in truth['private_inputs'] if r['event']<end]
    cert={'values':[{'position':p,'value_sompi':rows[p]['value']} for p in sorted(rows)],
          'selected_positions':[{'event':r['event'],'position':r['selected_position']} for r in inputs]}
    checked=check(ledger,cert);spent=set()
    for e in ledger.events:
        if e.kind=='private':
            r=next(x for x in inputs if x['event']==e.ordinal);n=rows[r['selected_position']]
            available=[v for v in rows.values() if v['birth']<e.ordinal and v['position'] not in spent
                       and v['value'] and v['owner']==r['owner']]
            expected=min(available,key=lambda v:(-v['value'],v['position']))
            need(expected['position']==n['position'] and n['owner']==r['owner'],'truth-largest-owned-selector')
            spent.add(n['position'])
        for p in e.notes:
            n=rows[p]
            if n['purpose']=='economic':
                obligation=truth['obligations'][n['obligation']]
                need(obligation['obligation']==n['obligation'] and obligation['recipient']==n['owner']
                     and obligation['payer']==n['payer'] and n['value']==obligation['principal_sompi']+CREDIT,
                     'truth-original-demand-and-fee-credit')
                need(e.kind=='private' and not e.payout and r['owner']==n['payer'],'truth-economic-payer')
            if n['purpose']=='change':need(e.kind=='private' and not e.payout and n['owner']==r['owner'],
                                           'truth-self-change')
        audit=truth['fee_audit'][e.ordinal]
        need(audit['event']==e.ordinal and sum(audit['inputs'])==sum(audit['outputs'])+e.fee,
             'truth-whole-native-value-fee-audit')
        mass=max(0,sum(10**12//v for v in audit['outputs'])-sum(10**12//v for v in audit['inputs']))
        need(mass==audit['storage'] and mass<=audit['modeled_mass_ceiling'] and
             e.fee==100*audit['modeled_mass_ceiling'],'truth-integer-KIP9-fee-audit')
        required=FEES['entry' if e.ordinal==0 else 'admit'] if e.kind=='ingress' else (
            FEES['terminal'] if e.mode==0 else FEES['cashout'] if e.payout else FEES['wide'] if e.mode==32 else FEES['compact'])
        need(e.fee==required,'truth-selected-public-fee-profile')
    expected_participants={p for p,n in rows.items() if n['value'] and n['owner'] in public['participant_roles']}
    need({r['position'] for r in ledger.participants}==expected_participants,'truth-participant-exact-allowed-scope')
    for r in ledger.participants:
        n=rows[r['position']]
        need(r['participant_role']==n['owner'] and r['original_nf']==n['nf'] and
             r['value_sompi']==n['value'] and r['invoice_counterparty_role']==n['payer'],
             'truth-only-own-legitimate-records')
    if ledger.events[-1].reserve==0:
        delivered=[n['obligation'] for n in rows.values() if n['purpose']=='economic']
        need(sorted(delivered)==list(range(64)),'truth-exactly64-original-economic-payments')
        need(truth['end_reserve_sompi']==0,'truth-terminal-zero')
        need(sum(r['external_source_sompi'] for r in truth['ordinary_sources'])==
             sum(r['ordinary_change_sompi'] for r in truth['ordinary_sources'])+
             sum(e.payout+e.fee for e in ledger.events),'truth-all-sources-fees-and-native-tails')
    return ledger,rows,checked

def score(public,prediction,truth):
    ledger,rows,actual=validate(public,truth)
    need(prediction['public_sha256']==digest(public),'prediction-public-binding')
    meta={'schema':'kpx3-payment-linkage-postbarrier-score/v1','classification':'CONDITIONAL_SYNTHETIC_MODEL_NO_PRIVACY_QUALIFICATION',
          'cluster':truth['cluster'],'timing':truth['timing'],'arm':truth['arm'],
          'profile':public['profile'],'known_wallet_policy':public['known_wallet_policy'],
          'current_uniform_demo_privacy_qualification':False,'horizon':'drain' if ledger.events[-1].reserve==0 else 'payment',
          'true_history_independently_validated':True,'prediction_status':prediction['status'],
          'public_sha256':digest(public),'prediction_sha256':digest(prediction),'owner_identity':'NOT_MODELLED',
          'private_keys_or_seed_inputs':False,'privacy_qualification':False}
    if prediction['status']!='COMPLETE':return dict(meta,complete=False,metrics=None)
    validate_prediction(ledger,prediction)
    note_results={r['position']:r for r in prediction['note_results']}
    guesses={r['position']:r for r in prediction['fixed_guesses']}
    public_targets=[p for p,n in ledger.notes.items() if ledger.events[n.birth].kind=='private']
    economic=[p for p in public_targets if rows[p]['purpose']=='economic']
    honest=[p for p in economic if rows[p]['owner'] not in public['participant_roles']]
    positive_forced=forced_value=honest_forced=prior_hits=sender_hits=sender_count=0
    participant_known=[p for p in economic if p not in honest]
    for p in public_targets:
        n=rows[p];r=note_results[p];consumer=n['consumer']
        direct=consumer if consumer is not None and consumer<len(ledger.events) and ledger.events[consumer].payout else None
        if r['forced_cashout_event'] is not None:
            need(r['forced_cashout_event']==direct,'forced-link-excludes-true-history')
            positive_forced+=1;honest_forced+=p in honest
        alt=r['amount_alternative']
        if alt['status']=='UNSAT':
            need(alt['baseline_value_sompi']==n['value'],'forced-value-excludes-truth');forced_value+=1
        for candidate in r['cashout_candidates']:
            if candidate['event']==direct:need(candidate['status']!='UNSAT','candidate-excludes-true-history')
        if direct is None:need(r['no_direct_cashout']['status']!='UNSAT','NONE-excludes-true-history')
        if p in honest:
            principal=truth['obligations'][n['obligation']]['principal_sompi']
            prior_hits+=10*abs(4_500_000_000-principal)<=principal
            sender=guesses[p]['same_birth_counterparty_role_heuristic']
            if sender is not None:sender_count+=1;sender_hits+=sender==n['payer']
    source_forced=0
    for row in prediction['cashout_results']:
        real=actual['choices'][row['event']]
        candidate=next(r for r in row['candidates'] if r['position']==real)
        need(candidate['status']!='UNSAT','cashout-input-excludes-true-history')
        actual_source=actual['native_sources'][row['event']]
        need(next(r for r in row['source_candidates'] if r['source_id']==actual_source)['status']!='UNSAT',
             'lineage-excludes-true-history')
        sat=[r for r in row['source_candidates'] if r['status']=='SAT']
        if len(sat)==1:source_forced+=1
    selective=[]
    ranked=sorted(public_targets,key=lambda p:(len([c for c in note_results[p]['cashout_candidates'] if c['status']=='SAT'])
                   or 10**9,ledger.notes[p].birth,p))
    for percent in (5,10,25):
        wanted=math.ceil(len(public_targets)*percent/100);chosen=ranked[:wanted];known=0;correct=0
        for p in chosen:
            guess=guesses[p]['closest_time_cashout_event']
            if guess is None:continue
            known+=1;n=rows[p];actual_direct=n['consumer']
            if actual_direct is not None and actual_direct<len(ledger.events) and ledger.events[actual_direct].payout:
                correct+=guess==actual_direct
        selective.append({'coverage_percent_requested':percent,'public_targets':len(public_targets),
                          'requested_predictions':wanted,'actual_predictions':known,'precision':ratio(correct,known),
                          'no_hidden_economic_mask_used':True})
    metrics={'all_public_positive_forced_links':ratio(positive_forced,len(public_targets)),
             'all_public_exact_note_value_forced':ratio(forced_value,len(public_targets)),
             'native_original_source_forced':ratio(source_forced,len(prediction['cashout_results'])),
             'honest_economic_prior_within10':ratio(prior_hits,len(honest)),
             'honest_economic_positive_forced_links':ratio(honest_forced,len(honest)),
             'application_counterparty_heuristic_precision':ratio(sender_hits,sender_count),
             'application_counterparty_heuristic_coverage':ratio(sender_count,len(honest)),
             'economic_targets':len(economic),'honest_economic_targets':len(honest),
             'legitimately_known_participant_targets':len(participant_known)}
    return dict(meta,complete=True,metrics=metrics,selective_precision=selective,
        counts={'public_private_output_positions':len(public_targets),'economic_obligations_present':len(economic),
                'padded_or_self_change_positions':len(public_targets)-len(economic)},
        fee_scope={'source_arithmetic_not_native_execution':True,'all_fees_sompi':sum(e.fee for e in ledger.events),
                   'economic_principal_sompi':sum(r['principal_sompi'] for r in truth['obligations']),
                   'fee_credit_not_counted_as_useful_payment':True},
        unchanged_common_price_failure={'numerator':21103,'denominator':100025,'exceeds20percent':True})
