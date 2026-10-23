"""Fixed post-barrier aggregate; four independent clusters, no refitting."""
import itertools
import math

ALPHA=0.05
FAMILY=128
PRIMARY=('all_public_positive_forced_links','honest_economic_prior_within10',
         'all_public_exact_note_value_forced','native_original_source_forced')

def bound(values,width=1):
    if len(values)!=4 or any(v is None for v in values):return None
    average=sum(values)/4
    radius=width*math.sqrt(math.log(2*FAMILY/ALPHA)/(2*4))
    return {'independent_clusters':4,'mean_cluster_fraction':average,'range_width':width,
            'one_sided95_upper':min(1,average+radius),'one_sided95_lower':max(-1 if width==2 else 0,average-radius),
            'radius':radius,'comparison_family_size':FAMILY,'directional_family_size':2*FAMILY,
            'simultaneous_both_tail_95_coverage':True,'qualification':False}

def aggregate(scores):
    if len(scores)!=96:raise ValueError('exactly96-scores-required')
    by={}
    for row in scores:
        key=(row['cluster'],row['timing'],row['arm'],row['profile'],row['horizon'])
        if key in by:raise ValueError('duplicate-score-cell')
        by[key]=row
    cells=[];family_count=0
    for timing,arm,profile,horizon in itertools.product(('overlap','staggered'),('wide32','compact2'),
                                                       ('C','C+1','C+8'),('payment','drain')):
        rows=[by[(c,timing,arm,profile,horizon)] for c in range(4)]
        metrics={}
        for name in PRIMARY:
            values=[r['metrics'][name]['fraction'] if r['complete'] else None for r in rows]
            metrics[name]={'cluster_counts':[r['metrics'][name] if r['complete'] else None for r in rows],
                           'bound':bound(values),'complete_clusters':sum(r['complete'] for r in rows)}
            family_count+=1
        cells.append({'timing':timing,'arm':arm,'profile':profile,'horizon':horizon,'metrics':metrics,
                      'application_counterparty_heuristic_descriptive':[
                          r['metrics']['application_counterparty_heuristic_precision'] if r['complete'] else None for r in rows]})
    paired=[]
    for timing,profile,horizon in itertools.product(('overlap','staggered'),('C','C+1','C+8'),('payment','drain')):
        for name in ('honest_economic_prior_within10','honest_economic_positive_forced_links'):
            values=[]
            for c in range(4):
                wide=by[(c,timing,'wide32',profile,horizon)];serial=by[(c,timing,'compact2',profile,horizon)]
                a=wide['metrics'][name]['fraction'] if wide['complete'] else None
                b=serial['metrics'][name]['fraction'] if serial['complete'] else None
                values.append(a-b if a is not None and b is not None else None)
            paired.append({'timing':timing,'profile':profile,'horizon':horizon,'metric':name,
                           'wide_minus_serial_cluster_differences':values,'bound':bound(values,width=2)})
            family_count+=1
    assert family_count==120 and FAMILY==128
    return {'schema':'kpx3-payment-linkage-study-aggregate/v1','classification':'SCOPED_SYNTHETIC_COUNTEREXAMPLE_STUDY',
            'primary_workload':'VARIED_POSITIVE_FUTURE_WALLET',
            'current_uniform_financial_demo_privacy_qualification':False,
            'scores':96,'independent_clusters':4,'paired_complete_ledgers':16,
            'unique_economic_obligations':256,'public_arms_timing_views_not_independent_samples':True,
            'complete_score_cells':sum(r['complete'] for r in scores),'all_complete':all(r['complete'] for r in scores),
            'cells':cells,'paired':paired,'fixed_comparisons':family_count,'bonferroni_family':FAMILY,
            'unchanged_price_prior_failure':{'hits':21103,'total':100025,'probability':21103/100025,
                                             'exceeds_original20percent_cap':True},
            'identity_in_exact_model':'NOT_MODELLED','protocol_two_real_inputs_not_relaxed_here':True,
            'SAT_candidates_are_not_crypto_or_equal_probability_histories':True,
            'privacy_qualification':False,'fee_qualification':False,'native_acceptance_claimed':False}
