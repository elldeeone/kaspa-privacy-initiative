"""Post-result independent recount; publishes aggregate-only review output.

Requires the retained diagnosis directory, including its allowlisted staged
truth. It never opens the original attempt or seed. This reviewer is not part
of the frozen observer or privacy qualification experiment.
"""
import argparse
import json,hashlib
from pathlib import Path
from collections import Counter
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('attempt', type=Path, help='retained completed diagnosis directory')
parser.add_argument('--receipt', type=Path, help='optional create-only aggregate review receipt')
args=parser.parse_args()
ROOT=args.attempt.resolve()
STAGE=ROOT/'classification-inputs'
def load(path): return json.loads(path.read_text())
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def need(test):
    if not test: raise AssertionError('independent aggregate review disagrees')
freeze,seal,completion=(load(ROOT/n) for n in ('freeze.json','public-seal.json','completion.json'))
manifest=load(STAGE/'manifest.json')
need(completion['complete'] is True and completion['freeze_sha256']==sha(ROOT/'freeze.json') and completion['public_seal_sha256']==sha(ROOT/'public-seal.json'))
need(completion['aggregate_sha256']==sha(ROOT/'runs/classify/result.json'))
need(seal['truth_opened'] is False and seal['seed_opened'] is False and manifest['seed_included'] is False)
need(manifest['public_seal_sha256']==sha(ROOT/'public-seal.json'))
for name,pin in manifest['files'].items(): need(sha(STAGE/name)==pin)
for name,pin in freeze['sources'].items(): need(sha(ROOT/'code'/name)==pin)
for index,record in enumerate(seal['records']):
    for name,pin in record['files'].items(): need(sha(ROOT/'runs'/('trace-'+str(index))/name)==pin)
aggregate=load(ROOT/'runs/classify/result.json')

def make_graph(public,truth):
    notes,parents,private_parents,native,event_inputs={}, {}, {}, {}, {}
    spent=set(); reserve=0
    for e,h in zip(public['events'],truth['events'],strict=True):
        k=e['event']; ins=h['inputs']; need(len(ins)==len(set(ins)))
        need(all(n in notes and n not in spent for n in ins)); spent.update(ins)
        for n in ins: need(notes[n]['recipient']==h['owner'])
        need(sum(notes[n]['value'] for n in ins)+e['deposit']==sum(o['value'] for o in h['outputs'])+e['payout']+e['fee'])
        reserve+=e['deposit']-e['payout']-e['fee']; need(reserve==e['reserve'] and reserve>=0)
        ancestral_inputs=set(ins)
        if e['bridge'] is not None:
            for source in e['bridge']['sources']: ancestral_inputs.update(native[source['ref']])
            if e['bridge']['change_ref']: native[e['bridge']['change_ref']]=set(ancestral_inputs)
        event_inputs[k]=ancestral_inputs
        for o in h['outputs']:
            n=o['position']; need(n not in notes); notes[n]=dict(o,born=k)
            parents[n]=set(ancestral_inputs); private_parents[n]=set(ins)
        if e['payout']: native[e['event_id']]=set(ancestral_inputs)
    need(reserve==0)
    def reaches(root,events,private=False):
        links=private_parents if private else parents
        todo=[n for event in events for n in (truth['events'][event]['inputs'] if private else event_inputs[event])]
        seen=set()
        while todo:
            n=todo.pop()
            if n==root: return True
            if n not in seen: seen.add(n); todo.extend(links[n])
        return False
    def closed(root,leg):
        n=notes[root]; events=leg['events']; extra=leg['coinput']
        if n['value']==0: return not events and extra is None and leg['value']==0
        if leg['value']!=n['value'] or not events or events!=sorted(set(events)) or leg['owner'] not in (None,n['recipient']): return False
        if extra is not None and (extra==root or extra not in notes or notes[extra]['value']<=0): return False
        unspent={root}; total=n['value']; paid=0
        if extra is not None: unspent.add(extra); total+=notes[extra]['value']
        for k in events:
            h,e=truth['events'][k],public['events'][k]
            ins=set(h['inputs'])
            if h['kind'] not in ('partial','exit') or not ins or not e['payout'] or ins-unspent or any(notes[n]['born']>=k for n in ins): return False
            unspent-=ins
            unspent|={o['position'] for o in h['outputs'] if o['value']>0}
            paid+=e['payout']+e['fee']
        return len(unspent)==0 and total==paid
    return reaches,closed

def correct(g,t):
    a,b=g['sender']==t['sender'],g['recipient']==t['recipient']
    return dict(sender=a,recipient=b,relationship=a and b,amount_exact=g['amount']==t['amount'],amount_within_10pct=abs(g['amount']-t['amount'])*10<=t['amount'])

def transition(a,b):
    return dict(targets=len(a),before=sum(a),after=sum(b),both=sum(x and y for x,y in zip(a,b)),gains=sum(not x and y for x,y in zip(a,b)),losses=sum(x and not y for x,y in zip(a,b)),neither=sum(not x and not y for x,y in zip(a,b)))

vectors={}; route_flags=Counter(); categories=Counter(); hit_categories=Counter(); offers=unique=unions=0; targets_total=0
for arm in ('whole','partial'):
    public=load(STAGE/(arm+'-public.json')); truth=load(STAGE/(arm+'-truth.json'))
    trace={r['event']:r for r in load(STAGE/(arm+'-pooled-trace.json'))['rows']}
    targets=sorted([t for t in truth['targets'] if min(t['sender'],t['recipient'])>=8],key=lambda t:t['obligation'])
    need(len(targets)==37)
    reaches,closed=make_graph(public,truth)
    vectors[arm]={t['obligation']:correct(trace[t['event']]['guess'],t) for t in targets}
    if arm=='whole': continue
    prior={t['obligation']:correct(trace[t['event']]['prior'],t) for t in targets}
    targets_total=len(targets)
    for t in targets:
        row=trace[t['event']]; h=truth['events'][t['event']]; receipt,change=(o['position'] for o in h['outputs'])
        routes={json.dumps(r,sort_keys=True,separators=(',',':')):r for r in row['decompositions']}
        offers+=len(row['decompositions']);unique+=len(routes);unions+=len(row['selected_record']['supports'])
        found=[]
        for r in routes.values():
            rv,cv=r['receipt'],r['tail']
            flags=dict(inputs_match=len(r['input_positions'])==len(set(r['input_positions'])) and set(r['input_positions'])==set(h['inputs']),receipt_closed=closed(receipt,rv),change_closed=closed(change,cv),receipt_private_ancestry=reaches(receipt,rv['events'],True),receipt_all_ancestry=reaches(receipt,rv['events']),change_private_ancestry=reaches(change,cv['events'],True),change_all_ancestry=reaches(change,cv['events']),receipt_follows_change=reaches(change,rv['events']),change_follows_receipt=reaches(receipt,cv['events']),receipt_owner_matches=bool(rv['events']) and all(truth['events'][k]['owner']==t['recipient'] for k in rv['events']),change_owner_matches=bool(cv['events']) and all(truth['events'][k]['owner']==t['sender'] for k in cv['events']))
            flags['both_closed']=flags['inputs_match'] and flags['receipt_closed'] and flags['change_closed']; flags['input_change_closed']=flags['inputs_match'] and flags['change_closed']
            flags['receipt_native_only']=flags['receipt_all_ancestry'] and not flags['receipt_private_ancestry'];flags['change_native_only']=flags['change_all_ancestry'] and not flags['change_private_ancestry']
            route_flags.update(k for k,v in flags.items() if v);found.append(flags)
        anyf={k:any(f[k] for f in found) for k in aggregate['groups']['partial']['pooled']['construction_flags']}
        category=('fallback' if row['fallback'] else 'all_both_closed' if found and all(f['both_closed'] for f in found) else 'some_both_closed' if anyf['both_closed'] else 'closed_value_path_only' if anyf['receipt_closed'] or anyf['input_change_closed'] else 'ancestry_without_closed_value_path' if anyf['receipt_all_ancestry'] or anyf['change_all_ancestry'] else 'wrong_branch_only' if anyf['receipt_follows_change'] or anyf['change_follows_receipt'] else 'unrelated_selected_payouts')
        categories[category]+=1
        if vectors[arm][t['obligation']]['amount_within_10pct']: hit_categories[category]+=1

saved=aggregate['groups']['partial']['pooled']
metrics=tuple(saved['correct'])
counts={k:sum(v[k] for v in vectors['partial'].values()) for k in metrics}
need(counts==saved['correct'])
prior_transitions={k:transition([v[k] for v in prior.values()],[v[k] for v in vectors['partial'].values()]) for k in metrics}
need(prior_transitions==saved['prior_to_attack'])
paired={k:transition([v[k] for v in vectors['whole'].values()],[v[k] for v in vectors['partial'].values()]) for k in metrics}
need(paired==aggregate['whole_to_partial']['pooled']['split_tail'])
need({k:categories[k] for k in saved['support_classes']}==saved['support_classes'])
need({k:hit_categories[k] for k in saved['support_classes']}==saved['hits_by_support_class']['amount_within_10pct'])
need({k:route_flags[k] for k in saved['construction_flags']}==saved['construction_flags'])
need((offers,unique,unions)==(saved['offers'],saved['unique_constructions'],saved['old_union_supports']))

def public_tree(value):
    if type(value) in (int,bool): return True
    if type(value) is str: return '/' not in value and not (len(value)==64 and all(c in '0123456789abcdef' for c in value))
    if type(value) is list: return all(type(v) is str and public_tree(v) for v in value)
    if type(value) is dict: return all(type(k) is str and public_tree(v) for k,v in value.items())
    return False
need(public_tree(aggregate))
receipt=dict(schema='kpi-sparse-independent-review-v1',independent_recount_agrees=True,reviewer='separate agent using independent graph traversal and flow simulation',source_freeze_sha256=sha(ROOT/'freeze.json'),public_seal_sha256=sha(ROOT/'public-seal.json'),aggregate_sha256=sha(ROOT/'runs/classify/result.json'),primary_targets=targets_total,selected_constructions=unique,old_union_supports=unions,partial_pooled_counts=counts,prior_to_split_tail=prior_transitions,whole_to_partial_split_tail=paired,support_classes=dict(categories),within_10pct_hits_by_support_class=dict(hit_categories),route_flags={k:route_flags[k] for k in saved['construction_flags']},public_export_aggregate_only=True,seed_opened=False,original_attempt_opened=False,limits=['Common-price numerical hits remain scored as hits.','Zero matching selected value paths does not show no transcript signal or exclude other attacks.','One paired synthetic history; no real-user or native transaction privacy evidence.','Same-host author-controlled verification is not independent attestation.'])
if args.receipt is not None:
    with args.receipt.open('x') as stream:
        json.dump(receipt,stream,indent=2);stream.write('\n')
print(json.dumps(receipt,indent=2))
