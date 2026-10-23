"""Independent integer certificate verification; deliberately no Z3 or generator."""
from schema import MAX,FLOOR,Invalid

class BadCertificate(ValueError): pass

def need(condition,text):
    if not condition:raise BadCertificate(text)

def check(ledger,certificate):
    need(type(certificate) is dict and set(certificate)=={'values','selected_positions'},'certificate-fields')
    vals=certificate['values'];rows=certificate['selected_positions']
    need(type(vals) is list and len(vals)==len(ledger.notes),'certificate-values')
    positions=sorted(ledger.notes);values={};lineage={};unspent={};choices={}
    for pos,row in zip(positions,vals,strict=True):
        need(type(row) is dict and set(row)=={'position','value_sompi'} and type(row['position']) is int and row['position']==pos,
             'certificate-position-fields')
        v=row['value_sompi'];need(type(v) is int and 0<=v<=MAX and (v==0 or v>=FLOOR),'certificate-value-range')
        need(ledger.notes[pos].value is None or ledger.notes[pos].value==v,'certificate-public-value')
        values[pos]=v
    private=[e for e in ledger.events if e.kind=='private']
    need(type(rows) is list and len(rows)==len(private),'certificate-selections')
    for e,row in zip(private,rows,strict=True):
        need(type(row) is dict and set(row)=={'event','position'} and type(row['event']) is int and row['event']==e.ordinal
             and type(row['position']) is int,'certificate-selection-fields')
        choices[e.ordinal]=row['position']
    same_cm={}
    for p,n in ledger.notes.items():
        if n.cm in same_cm:need(values[p]==same_cm[n.cm],'certificate-cm-value-binding')
        same_cm[n.cm]=values[p]
    native_sources={}
    for e in ledger.events:
        if e.kind=='ingress':
            need(len(e.notes)==1 and values[e.notes[0]]==e.ingress,'certificate-ingress')
            source=e.source
        else:
            selected=choices[e.ordinal]
            need(selected in unspent and unspent[selected]>=FLOOR
                 and ledger.notes[selected].birth<e.ordinal,'certificate-replay-future-zero-gap')
            v=unspent.pop(selected);source=lineage[selected]
            need(v==sum(values[p] for p in e.notes)+e.payout+e.fee,'certificate-conservation')
            need(v<=MAX and v<=ledger.public['events'][e.ordinal]['prior_reserve_sompi'],
                 'certificate-backing-range')
            if e.payout:
                need(all(values[p]==0 for p in e.notes),'certificate-full-cashout-policy')
                native_sources[e.ordinal]=source
            else:
                need(any(values[p]>0 for p in e.notes),'certificate-no-value-action')
                policy=ledger.public['known_wallet_policy']
                if e.mode==32 and policy!='one_real_input_full_native_cashout':
                    need(all(values[p]>=FLOOR for p in e.notes),'certificate-known-wide-positive-policy')
                    if policy=='one_real_full_cashout_wide_positive_equal_current_demo':
                        need(len({values[p] for p in e.notes})==1,'certificate-current-uniform-wide-policy')
        for p in e.notes:
            unspent[p]=values[p];lineage[p]=source if values[p] else -1
        need(sum(unspent.values())==e.reserve,'certificate-prefix-reserve')
    for row in ledger.participants:
        p=row['position'];need(values[p]==row['value_sompi'],'certificate-participant-value')
        actual=[e for e,s in choices.items() if s==p]
        expected=ledger.nf_spends[p]
        need(actual==([] if expected is None else [expected]),'certificate-participant-nf-spend')
        # Counterparty metadata intentionally supplies no original-lineage equation.
    return {'values':values,'choices':choices,'lineage':lineage,'native_sources':native_sources}

def swap(ledger,certificate,left,right):
    import copy
    result=copy.deepcopy(certificate)
    by_pos={row['position']:row for row in result['values']}
    by_pos[left]['value_sompi'],by_pos[right]['value_sompi']=by_pos[right]['value_sompi'],by_pos[left]['value_sompi']
    for row in result['selected_positions']:
        if row['position']==left:row['position']=right
        elif row['position']==right:row['position']=left
    check(ledger,result)
    return result
