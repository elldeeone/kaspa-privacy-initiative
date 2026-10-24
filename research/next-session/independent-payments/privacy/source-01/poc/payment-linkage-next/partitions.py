"""Visible-component controls, not cryptographic assignment-hiding proofs."""
from ledger import canonical,digest,need

def recover_public_partitions(envelope):
    need(type(envelope) is dict and set(envelope)=={'classification','components','permuted_display'},'envelope-fields')
    need(envelope['classification']=='PUBLIC_COMPONENT_ENVELOPE_NOT_NATIVE_SETTLEMENT','envelope-kind')
    seen=set();partitions={}
    for c in envelope['components']:
        need(type(c) is dict and set(c)=={'component_id','ordered_outputs','public_output_digest'},'component-fields')
        need(c['component_id'] not in partitions and c['public_output_digest']==digest(c['ordered_outputs']),'component-binding')
        keys=[]
        for out in c['ordered_outputs']:
            need(type(out) is dict and set(out)=={'position','cm','cipher'},'output-fields')
            key=canonical(out);need(key not in seen,'duplicate-component-output');seen.add(key);keys.append(out['position'])
        partitions[c['component_id']]=keys
    need(len(envelope['permuted_display'])==len(seen) and
         {canonical(o) for o in envelope['permuted_display']}==seen,'display-coverage')
    return {'public_partitions':partitions,'partition_hiding_claim':False,
            'reason':'explicit component output arrays remain public; display ordering does not erase them',
            'hidden_assignment_wrappers_without_these_arrays_not_evaluated':True,'native_acceptance':False}

def direct_invoice_guesses(ledger):
    """Use only a participant's own invoice and exact public action partition."""
    known={r['position'] for r in ledger.records};labels={}
    for r in ledger.records:
        birth=ledger.notes[r['position']].birth
        if r['invoice_payer_role'] is not None:labels.setdefault(birth,set()).add(r['invoice_payer_role'])
    for r in ledger.public['outgoing_invoices']:
        birth=ledger.notes[r['position']].birth;labels.setdefault(birth,set()).add(ledger.public['participant_role'])
    guesses=[]
    for p,n in sorted(ledger.notes.items()):
        event=ledger.events[n.birth]
        if event['kind']!='action':continue
        roles=labels.get(n.birth,set())
        guesses.append({'position':p,'invoice_payer_role_guess':next(iter(roles)) if len(roles)==1 else None,
                        'already_known_own_receipt':p in known,'rule':'same public component as a legitimate own invoice'})
    return guesses
