"""Independent exhaustive public prediction validation; no truth or Z3."""
from schema import digest
from certificate import check,swap

class BadPrediction(ValueError):pass

def need(condition,text):
    if not condition:raise BadPrediction(text)

def validate_prediction(ledger,prediction):
    need(prediction['status']=='COMPLETE' and prediction['baseline']['status']=='SAT','complete-baseline-required')
    def exact_rows(rows,field,expected,label):
        need(type(rows) is list and len(rows)==len(expected),label+'-count')
        values=[r[field] for r in rows]
        need(all(type(v) is int for v in values),label+'-integer')
        need(len(set(values))==len(values) and set(values)==set(expected),label+'-set')
    def complete_status(row):need(row['status'] in ('SAT','UNSAT'),'COMPLETE-has-unknown-or-unqueried')
    native={e.ordinal:e for e in ledger.events if e.payout}
    exact_rows(prediction['cashout_results'],'event',native,'cashout-query')
    exact_rows(prediction['note_results'],'position',ledger.notes,'note-query')
    private_positions={p for p,n in ledger.notes.items() if ledger.events[n.birth].kind=='private'}
    exact_rows(prediction['fixed_guesses'],'position',private_positions,'guess-target')
    for row in prediction['cashout_results']:
        e=native[row['event']]
        eligible={p for p,n in ledger.notes.items() if n.birth<e.ordinal}
        exact_rows(row['candidates'],'position',eligible,'cashout-input-candidate')
        exact_rows(row['source_candidates'],'source_id',ledger.source_ids,'source-candidate')
        for q in row['candidates']+row['source_candidates']+[row['input_value_alternative']]:complete_status(q)
        sat=[q['position'] for q in row['candidates'] if q['status']=='SAT']
        need(bool(sat),'COMPLETE-cashout-no-SAT-input')
        need(row['forced_input_position'] is None or type(row['forced_input_position']) is int,'forced-input-integer')
        need(row['forced_input_position']==(sat[0] if len(sat)==1 else None),'forced-input-summary')
    for row in prediction['note_results']:
        p=row['position'];eligible={e.ordinal for e in native.values() if ledger.notes[p].birth<e.ordinal}
        exact_rows(row['cashout_candidates'],'event',eligible,'note-outgoing-candidate')
        for q in row['cashout_candidates']+[row['no_direct_cashout'],row['amount_alternative']]:complete_status(q)
        for q in row['cashout_candidates']:
            need(q['position']==p,'outgoing-candidate-position')
            source=next(x for x in prediction['cashout_results'] if x['event']==q['event'])
            duplicate=next(x for x in source['candidates'] if x['position']==p)
            need(all(q[k]==v for k,v in duplicate.items()),'candidate-projection-disagrees')
        sat=[q['event'] for q in row['cashout_candidates'] if q['status']=='SAT']
        forced=sat[0] if len(sat)==1 and row['no_direct_cashout']['status']=='UNSAT' else None
        need(row['forced_cashout_event'] is None or type(row['forced_cashout_event']) is int,'forced-outgoing-integer')
        need(row['forced_cashout_event']==forced,'forced-outgoing-summary')
    for key,cert in prediction['certificates'].items():
        need(digest(cert)==key,'certificate-content-address');check(ledger,cert)
    def resolved(row):
        cert=prediction['certificates'][row['certificate_id']]
        if row.get('swap') is not None:cert=swap(ledger,cert,*row['swap'])
        return check(ledger,cert)
    for row in prediction['cashout_results']:
        ordinal=row['event']
        for c in row['candidates']:
            if c['status']=='SAT':need(resolved(c)['choices'][ordinal]==c['position'],'SAT-input-certificate-target')
        for c in row['source_candidates']:
            if c['status']=='SAT':need(resolved(c)['native_sources'][ordinal]==c['source_id'],'SAT-source-certificate-target')
        c=row['input_value_alternative']
        if c['status']=='SAT':
            info=resolved(c);need(info['values'][info['choices'][ordinal]]!=c['baseline_value_sompi'],
                                  'SAT-input-value-certificate-target')
    for row in prediction['note_results']:
        p=row['position'];c=row['amount_alternative']
        if c['status']=='SAT':need(resolved(c)['values'][p]!=c['baseline_value_sompi'],'SAT-note-value-certificate-target')
        c=row['no_direct_cashout']
        if c['status']=='SAT':
            info=resolved(c);need(all(info['choices'][e.ordinal]!=p for e in ledger.events if e.payout),
                                  'SAT-NONE-certificate-target')
    need(prediction['baseline']['certificate_id'] in prediction['certificates'],'baseline-certificate-missing')
    for row in prediction['note_results']:
        n=ledger.notes[row['position']]
        need(row['cm']==n.cm and row['birth']==n.birth,'note-public-binding')
        need(type(row['private_born']) is bool and row['private_born']==(ledger.events[n.birth].kind=='private'),
             'public-born-classification')
    return True
