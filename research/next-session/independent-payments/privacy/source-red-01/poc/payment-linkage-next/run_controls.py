"""One frozen run of eight fixed PUBLIC falsification groups; no holdout.

Full fixture owner/purpose maps stay in the private runtime. Public outputs
contain only exact observer inputs, arithmetic certificates and sanitized checks.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys
import z3
from ledger import decode,check,verify_analysis,canonical,digest,Invalid,BadCertificate,MAX
from observer import analyze
from partitions import recover_public_partitions,direct_invoice_guesses
from fixtures import Builder,Fixture,S,F,sparse,singleton,forwarded_origin,partial_two_sources,breadth


def save(path,obj):path.write_bytes(canonical(obj))

def run(args):
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700)
    source=Path(__file__).resolve().parent;repo=source.parents[1]
    assert not output.is_relative_to(repo),'runtime outside Git'
    freeze_raw=Path(args.freeze).read_bytes();freeze=json.loads(freeze_raw)
    assert hashlib.sha256(freeze_raw).hexdigest()==args.freeze_sha256
    for row in freeze['files']:
        raw=(repo/row['path']).read_bytes();assert len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256']
    checks=[];privacy_failures=[];counter=0;instances=[]
    def case(fixture,label):
        nonlocal counter
        ledger,actual=fixture.verify();report=analyze(copy.deepcopy(fixture.public));assert report['status']=='COMPLETE'
        verify_analysis(ledger,report)
        for row in report['event_results']:
            i=row['event'];true=set(actual['inputs'][i])
            for candidate in row['inputs']:
                name='selected' if candidate['position'] in true else 'excluded'
                assert candidate[name]['status']!='UNSAT','true-history-exclusion'
            if row['conditional_wallet_payer_role'] is not None:
                assert row['conditional_wallet_payer_role']==fixture.actors[i],'wrong-conditional-payer-role'
        stem=f'{counter:02}-{label}';counter+=1
        save(output/(stem+'-public.json'),fixture.public);save(output/(stem+'-analysis.json'),report)
        # Labeled control truth is never a selected public output.
        save(output/(stem+'-PRIVATE-FIXTURE.json'),{'notes':fixture.notes,'actors':fixture.actors,'actual_integer_certificate':fixture.certificate})
        instances.append({'name':label,'status':report['status'],'queries':report['queries'],'true_history_compatible':True})
        return ledger,actual,report
    def row(report,event):return next(r for r in report['event_results'] if r['event']==event)
    def reject(fn):
        try:fn()
        except (ValueError,KeyError,TypeError,AssertionError,StopIteration):return
        raise AssertionError('expected-rejection')
    # 1. Public component partitions survive a transport/display permutation.
    f,_,_,_=sparse();ledger,actual=f.verify()
    components=[{'component_id':str(e['ordinal']),'ordered_outputs':e['outputs'],'public_output_digest':digest(e['outputs'])} for e in ledger.events if e['kind']=='action']
    display=[copy.deepcopy(o) for c in components for o in c['ordered_outputs']][::-1]
    envelope={'classification':'PUBLIC_COMPONENT_ENVELOPE_NOT_NATIVE_SETTLEMENT','components':components,'permuted_display':display}
    recovered=recover_public_partitions(envelope)
    assert recovered['public_partitions']=={c['component_id']:[o['position'] for o in c['ordered_outputs']] for c in components}
    bad=copy.deepcopy(envelope);bad['permuted_display'].pop();reject(lambda:recover_public_partitions(bad))
    save(output/'visible-envelope-public.json',envelope);checks.append('public-partition-wrapper-falsified');privacy_failures.append('plain-public-aggregation-does-not-hide-previously-disclosed-partitions')
    # 2. Same64 actual invoice obligations, full drainage and all fees/change.
    cohort=[]
    for wide in (True,False):
        fixture=breadth(wide);ll,ii=fixture.verify();guesses=direct_invoice_guesses(ll);by={g['position']:g for g in guesses}
        known={r['position'] for r in ll.records};economic=[p for p,n in fixture.notes.items() if n['purpose']=='economic'];assert len(economic)==64
        honest=[p for p in economic if p not in known];assert len(honest)==62
        covered=[p for p in honest if by[p]['invoice_payer_role_guess'] is not None]
        assert all(by[p]['invoice_payer_role_guess']==fixture.notes[p]['issuer'] for p in covered)
        expected=62 if wide else 0;assert len(covered)==expected and ll.events[-1]['reserve_after']==0
        cohort.append({'layout':'wide32' if wide else 'existing-serial-optional-change','genuine_invoice_obligations':64,'other_economic_targets':62,'direct_same_partition_role_guesses':len(covered),'correct_direct_guesses':len(covered),'all_pool_fees':sum(e['fee'] for e in ll.events if e['kind']=='action'),'terminal_reserve':0,'global_reconstruction_not_scored_in_this_restricted_metadata_control':True})
        label='wide32' if wide else 'serial';save(output/(label+'-breadth-public.json'),fixture.public)
        save(output/(label+'-breadth-metadata-analysis.json'),{'guesses':guesses,'counts':cohort[-1],'privacy_qualification':False})
        save(output/(label+'-breadth-PRIVATE-FIXTURE.json'),{'notes':fixture.notes,'actors':fixture.actors,'actual_integer_certificate':fixture.certificate})
    checks.append('direct-economic-cohort-breadth-measured-without-counting-change');privacy_failures.append('smaller-direct-cohort-is-not-general-anonymity')
    # 3. Known own NF excludes receipt; spent bootstrap leaves only sender change.
    propagation=[]
    for maximum in (1,2):
        fixture,sibling,target,_=sparse(maximum=maximum)
        ll,ii,rr=case(fixture,'sparse-'+str(maximum));answer=row(rr,target)
        assert answer['mandatory_input_positions']==[sibling] and answer['conditional_wallet_payer_role']==0
        propagation.append({'max_real_inputs':maximum,'later_event':target,'mandatory_sender_change_position':sibling,'conditional_payer_role':0,'privacy_target':'FAIL'})
    checks.append('known-invoice-sibling-to-later-input-role-propagation');privacy_failures.append('existing-serial-baseline-leaks-later-payer-role-in-sparse-prefix')
    # 4. A formal prefix support induction independent of output split/order.
    ancestry=[]
    for maximum,split,future in ((1,False,False),(2,False,True),(2,True,True)):
        fixture,target=singleton(maximum,split,future=future);ll,ii,rr=case(fixture,'singleton-'+str(maximum)+'-'+str(split)+'-'+str(future))
        preceding={e['source_id'] for e in ll.events if e['kind']=='ingress' and e['ordinal']<target}
        assert preceding=={0} and ii['native_causal_support'][target]=={0}
        # All positive sources are explicit ingress notes; transitions consume
        # only earlier positives, preserve nonnegative value, and create none.
        ancestry.append({'maximum':maximum,'two_actual_inputs':split,'future_source_arrived_only_after_target':future,'only_possible_prefix_funding_source':0,'privacy_target':'FAIL'})
    checks.append('singleton-funding-causal-conservation-certificate');privacy_failures.append('later-real-funding-cannot-hide-earlier-singleton-exit')
    # 5. Participant is also a payer: include bootstrap, receipt/change and own
    # outgoing invoice facts. No counterparty-to-origin shortcut is permitted.
    fixture,target=forwarded_origin();ll,ii,rr=case(fixture,'forwarded-origin')
    true_input=ii['inputs'][target];assert len(true_input)==1 and ii['ancestors'][true_input[0]]=={1}
    assert row(rr,target)['conditional_wallet_payer_role']==0 and fixture.public['participant_role']==0
    assert fixture.public['outgoing_invoices'] and len(fixture.public['participant_records'])==3
    assert ii['ancestors'][true_input[0]]!={fixture.public['participant_role']}
    checks.append('legitimate-current-payer-is-not-original-funder')
    # 6. Extra genuinely feasible input and generic-output semantics prevent a
    # false sender-change deduction. Zero remainder is not valid for new API.
    guards=[]
    for label,kwargs in (('independent-extra',{'extra':True}),('zero-generic-optional',{'zero':True}),('generic-second-recipient',{'generic':True})):
        fixture,sibling,target,_=sparse(**kwargs);ll,ii,rr=case(fixture,label);answer=row(rr,target)
        assert answer['conditional_wallet_payer_role']!=0
        if not kwargs.get('generic'):assert sibling not in answer['mandatory_input_positions']
        else:assert sibling in answer['mandatory_input_positions'] and fixture.notes[sibling]['owner']==4
        guards.append({'name':label,'false_payer0_propagation':False,'not_an_anonymity_pass':True})
    zero=sparse(zero=True)[0];z=copy.deepcopy(zero.public);z['wallet_policy']='one-invoice-positive-change';reject(lambda:check(decode(z),zero.certificate))
    checks.append('positive-change-extra-eligibility-and-generic-owner-guards')
    # 7. Two-input/partial capability, publicly full no-append mode, actual gaps,
    # numeric/replay/future/currentness rejections.
    fixture=partial_two_sources();ll,ii,rr=case(fixture,'two-input-partial')
    assert len(ii['inputs'][2])==2 and any(v>0 for p,v in ii['values'].items() if ll.notes[p].birth==2)
    one=copy.deepcopy(fixture.public);one['max_real_inputs']=1;reject(lambda:check(decode(one),fixture.certificate))
    fixture,target=singleton(2,split=True,noappend=True);ll,ii,rr=case(fixture,'prospective-noappend-other-reserve')
    assert ll.events[target]['reserve_after']>0 and ll.events[target]['mode']==0 and not ll.events[target]['outputs']
    old=copy.deepcopy(fixture.public);old['profile']='legacy';reject(lambda:decode(old))
    fixture,sibling,target,_=sparse();ll,ii=fixture.verify()
    for kind in ('duplicate-input','replay','future','gap','overflow','boolean'):
        bad=copy.deepcopy(fixture.certificate)
        if kind=='duplicate-input':bad['inputs'][1]['positions']=[sibling,sibling]
        elif kind=='replay':bad['inputs'][1]['positions']=[0]
        elif kind=='future':bad['inputs'][0]['positions']=[fixture.public['events'][target]['outputs'][0]['position']]
        elif kind=='gap':bad['inputs'][0]['positions']=[1]
        elif kind=='overflow':bad['values'][0]['value']=MAX+1
        else:bad['values'][0]['value']=True
        reject(lambda bad=bad:check(ll,bad))
    stale=copy.deepcopy(fixture.public);stale['events'][1]['n_before']+=1;reject(lambda:decode(stale))
    fee=copy.deepcopy(fixture.public);fee['events'][1]['fee']+=1;reject(lambda:decode(fee))
    private=copy.deepcopy(fixture.public);private['hidden_owner_map']={};reject(lambda:decode(private))
    checks.append('two-real-partial-noappend-and-malformed-state-boundaries')
    # 8. First UNKNOWN prevents all derived forcedness; certificate and COMPLETE
    # assertions are independently tied to the exact requested predicate.
    fixture,_,_,_=sparse();ll,ii=fixture.verify();calls=[0]
    def stop(solver):
        calls[0]+=1;return solver.check() if calls[0]==1 else z3.unknown
    unknown=analyze(fixture.public,backend=stop);verify_analysis(ll,unknown)
    assert unknown['status']=='INCOMPLETE' and calls[0]==2 and all(not r['mandatory_input_positions'] and r['conditional_wallet_payer_role'] is None for r in unknown['event_results'])
    save(output/'injected-UNKNOWN-analysis.json',unknown)
    good=analyze(fixture.public);verify_analysis(ll,good)
    missing=copy.deepcopy(good);missing['event_results'][0]['inputs'].pop();reject(lambda:verify_analysis(ll,missing))
    wrong=copy.deepcopy(good);wrong['event_results'][-1]['mandatory_input_positions']=[];reject(lambda:verify_analysis(ll,wrong))
    wrong=copy.deepcopy(good);wrong['event_results'][-1]['conditional_wallet_payer_role']=1;reject(lambda:verify_analysis(ll,wrong))
    # Reuse a valid base certificate for a predicate it does not satisfy.
    wrong=copy.deepcopy(good);baseline=wrong['baseline']['certificate'];r=wrong['event_results'][0]['inputs'][0]
    r['excluded']={'status':'SAT','certificate':baseline};reject(lambda:verify_analysis(ll,wrong))
    checks.append('UNKNOWN-complete-coverage-and-exact-certificate-query-guards')
    assert len(checks)==8
    report={'schema':'independent-payment-public-falsification-controls/v1','classification':'FINITE_PUBLIC_SYMBOLIC_CONTROL_NOT_HELDOUT_CRYPTO_OR_NATIVE','groups_passed':8,'groups':checks,'global_cases':instances,'direct_cohort':cohort,'change_propagation':propagation,'singleton':ancestry,'guard_cases':guards,'expected_privacy_failures':privacy_failures,'all_true_integer_histories_compatible':True,'heldout_draws':0,'old_96_views_rescored':False,'old_package_modified':False,'original_amount_prior_failure':{'hits':21103,'total':100025,'above20percent':True},'human_identity':'NOT_MODELLED','crypto_owner_world_equivalence':'NOT_ESTABLISHED','privacy_qualification':False,'native_acceptance':False,'operational_resource_limits_are_not_privacy_thresholds':True,'source_freeze_sha256':args.freeze_sha256}
    save(output/'RESULTS.json',report)
    print(json.dumps({'groups_passed':8,'global_cases':len(instances),'new_holdout_draws':0,'privacy_qualification':False}),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--freeze',required=True);p.add_argument('--freeze-sha256',required=True);p.add_argument('--output',required=True)
    run(p.parse_args())
