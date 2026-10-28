"""PUBLIC invented fixtures only. No Tor, private capture, Original or proofs."""
import copy
import unittest

import metadata_attack as m


def hx(number, width=32):
    return number.to_bytes(width, 'big').hex()


def fixture():
    bind = {'method_sha256': hx(1), 'selection_sha256': hx(2),
            'trial_id': '11111111-1111-4111-8111-111111111111',
            'phase': m.PHASE, 'attempt_id': '22222222-2222-4222-8222-222222222222'}
    shape = {'cm_count': 3, 'nf_count': 1, 'reserve': 6000000000, 'exit_mode': 'continuing'}
    plan = {'schema': 'kpb-method03-metadata-plan/v1', 'view': m.VIEW,
            'binding': bind, 'owners': [0, 1, 2], 'corrupt_owner': 1,
            'arms': {'A': {'note_index': 11, 'fresh_payout': True, 'origin': 'controller'},
                     'B': {'note_index': 13, 'fresh_payout': True, 'origin': 'owner-pipe'}},
            'common_amounts': {'note': 200000000, 'fee': 1, 'payout': 199999999},
            'head_shape': shape, 'sources': {'invented-public-fixture': hx(3)},
            'required_coverage': list(m.REQUIRED_COVERAGE)}
    obs = {'schema': 'kpb-method03-metadata-observation/v1', 'binding': copy.deepcopy(bind),
           'sources': copy.deepcopy(plan['sources']), 'clocks': [], 'launches': [],
           'statuses': [], 'exits': [], 'arrivals': {'A': [], 'B': []}, 'facts': [],
           'coverage': {k: {'complete': True, 'evidence_refs': ['public-fixture/' + k]}
                        for k in m.REQUIRED_COVERAGE},
           'unmodeled': [{'scope': 'GLOBAL-HOST/UNION', 'category': 'full-global-host-view',
                          'evidence_refs': ['public-fixture/full-host-absent']},
                         {'scope': 'GLOBAL-HOST/UNION', 'category': 'full-corrupt-server-view',
                          'evidence_refs': ['public-fixture/full-server-absent']}]}
    tp = {'transport_source_sha256': hx(4), 'tor_binary_sha256': hx(5),
          'curl_binary_sha256': hx(6), 'onion_endpoint': 'public-fixture.invalid.onion',
          'receiver_source_sha256': hx(7), 'request_policy': {'attempts': 1, 'redirects': False}}
    obs['transport_parameters'] = {'A': copy.deepcopy(tp), 'B': copy.deepcopy(tp)}
    obs['arm_partition'] = {'mechanism': 'source-admitted-public-context',
        'contexts': {'A': [hx(101)], 'B': [hx(102)]}, 'evidence_refs': ['public-fixture/heads']}
    roles = ['controller', 'receiver/0'] + ['transport/' + str(i) for i in range(6)]
    for i, role in enumerate(roles):
        obs['clocks'].append({'schema': 'kpb-method03-clock-snapshot/v1', 'role': role,
            'pid': 100 + i, 'boot_id': '33333333-3333-4333-8333-333333333333',
            'clock_id': 'CLOCK_MONOTONIC',
            'time_namespace': {'link': 'time:[50]', 'inode': 50},
            'time_for_children_namespace': {'link': 'time:[50]', 'inode': 50},
            'timens_offsets': {'monotonic_ns': 0, 'boottime_ns': 0},
            'sample': {'monotonic_before_ns': 10, 'realtime_ns': 20,
                       'boottime_ns': 15, 'monotonic_after_ns': 30}})
    for ai, arm in enumerate(m.ARMS):
        for owner in m.OWNERS:
            slot = ai * 3 + owner
            obs['launches'].append({'arm': arm, 'owner': owner, 'role': m.role(arm, owner),
                'started_ns': 100, 'post_popen_ns': 110, 'pid': 1000 + slot,
                'event_ref': 'public-fixture/launch/' + str(slot),
                'metadata': {'argv': ['public-fixture'], 'mounts': [],
                             'fd_topology': {'observed_launcher_pid_only': 1000 + slot},
                             'schedule': {'actual_launch_index': slot}}})
            obs['exits'].append({'arm': arm, 'owner': owner, 'role': m.role(arm, owner),
                                'returncode': 0, 'event_ref': 'public-fixture/exit/' + str(slot)})
            obs['statuses'].append({'schema': 'kpb-method03-status-observation/v1',
                'arm': arm, 'owner': owner, 'role': m.role(arm, owner),
                'reader_id': 'controller/' + m.role(arm, owner), 'reader_pid': 100,
                'reader_observed_monotonic_ns': 1000,
                'reader_observed_realtime_ns': 2000, 'reader_observed_boottime_ns': 1500,
                'consumed_monotonic_ns': 2000,
                'value': {'schema': 'kpb-exit-transport-status/v1', 'transport_receipt': True,
                          'financial_or_chain_acceptance': False}})
            obs['arrivals'][arm].append({'arrival_id': hx(10 + slot), 'ordinal': slot + 1,
                'accepted_monotonic_ns': 490 + owner, 'post_handler_monotonic_ns': 500 + owner,
                'recorded_monotonic_ns': 3000 + owner, 'http_status': 202, 'frame_bytes': 4096,
                'event_ref': 'public-fixture/arrival/' + str(slot),
                'native': {'nf_hex32': hx(20 + slot), 'destination_spk_hex36': hx(30 + slot, 36),
                           'payout': 199999999, 'fee': 1, 'action_hex32': hx(40 + slot),
                           'context_sha256': hx(101 + ai), 'outpoint_hex36': hx(201 + ai, 36),
                           'head_shape': copy.deepcopy(shape)}})
    for owner in m.OWNERS:
        obs['facts'].append(link('A', owner, hx(10 + owner), 'controller-labelled-release'))
    for ai, arm in enumerate(m.ARMS):
        obs['facts'].append(link(arm, 1, hx(11 + ai * 3), 'corrupt-own-payout'))
    truth = [{'schema': 'kpb-method03-one-owner-truth/v1', 'binding': copy.deepcopy(bind),
              'owner': owner, 'arrivals': {'A': hx(10 + owner), 'B': hx(13 + owner)}}
             for owner in m.OWNERS]
    return plan, obs, truth


def link(arm, owner, aid, category):
    return {'kind': 'owner-arrival', 'arm': arm, 'owner': owner, 'arrival_id': aid,
            'category': category, 'evidence_refs': ['public-fixture/' + category]}


def evaluate(plan, obs, truth):
    pred = m.predict(plan, obs)
    scores = [m.score_owner(plan, obs, pred, t) for t in truth]
    return pred, scores, m.aggregate_owner_scores(plan, obs, pred, scores)


class PublicControls(unittest.TestCase):
    def test_bounded_synthetic_gain_retains_full_truth_and_stays_unqualified(self):
        p, o, t = fixture()
        pred, scores, result = evaluate(p, o, t)
        self.assertEqual(pred['candidate_counts'], {'A': [1, 1, 1], 'B': [2, 1, 2]})
        self.assertEqual(len(pred['joint_models']), 2)
        self.assertTrue(result['all_joint_true_assignment_retained'])
        self.assertTrue(result['bounded_route_candidate_increase'])
        self.assertFalse(result['overall_privacy_qualified'])
        self.assertEqual(result['status'], 'UNQUALIFIED')
        self.assertNotIn('compatible_joint_model_indices', str(result))
        self.assertNotIn('joint_models', str(result))
        self.assertNotIn('arrivals', str(result))
        self.assertNotIn('digest_tie_rank', str(result))
        self.assertIn('digest_tie_rank', scores[0]['metrics']['B'])

    def test_source_known_same_position_bridge_collapses_both_arms(self):
        p, o, t = fixture()
        for i in range(3):
            o['facts'].append({'kind': 'same-owner',
                'left': {'arm': 'A', 'arrival_id': hx(10+i)},
                'right': {'arm': 'B', 'arrival_id': hx(13+i)},
                'category': 'actual-source-order', 'evidence_refs': ['public-fixture/order']})
        pred, _, result = evaluate(p, o, t)
        self.assertEqual(pred['candidate_counts'], {'A': [1,1,1], 'B': [1,1,1]})
        self.assertFalse(result['bounded_route_candidate_increase'])

    def test_per_reader_upper_does_not_use_late_queue_or_recorded_time(self):
        p, o, _ = fixture()
        o['statuses'][3]['reader_observed_monotonic_ns'] = 499
        data = m.extract(p, o)
        self.assertEqual(data['windows']['B', 0]['upper_ns'], 499)
        self.assertEqual(len(m.predict(p, o)['joint_models']), 0)

    def test_ack_survives_later_process_failure_without_widening(self):
        p, o, t = fixture()
        o['statuses'][3]['reader_observed_monotonic_ns'] = 499
        o['exits'][3]['returncode'] = -15
        self.assertEqual(m.extract(p, o)['windows']['B',0]['upper_ns'], 499)
        self.assertEqual(len(m.predict(p, o)['joint_models']), 0)
        self.assertFalse(m.predict(p, o)['all_transports_ack_and_exit0'])

    def test_no_ack_failure_keeps_possibly_arrived_unbounded_tail(self):
        p, o, t = fixture()
        o['statuses'] = [s for s in o['statuses'] if not(s['arm']=='B' and s['owner']==0)]
        o['exits'][3]['returncode'] = 7
        o['arrivals']['B'][0]['post_handler_monotonic_ns'] = 1000000
        o['arrivals']['B'][0]['recorded_monotonic_ns'] = 1000001
        pred, _, result = evaluate(p, o, t)
        self.assertIsNone(m.extract(p, o)['windows']['B',0]['upper_ns'])
        self.assertTrue(result['all_joint_true_assignment_retained'])
        self.assertFalse(result['bounded_route_candidate_increase'])

    def test_pre_popen_bound_not_later_launch_event(self):
        p, o, _ = fixture()
        o['launches'][0]['post_popen_ns'] = 900
        self.assertEqual(len(m.predict(p,o)['joint_models']), 2)
        o['launches'][0].pop('started_ns')
        with self.assertRaises(KeyError): m.predict(p,o)

    def test_actual_clock_offset_shared_by_both_arms(self):
        p,o,t=fixture()
        rc=o['clocks'][1]
        rc['time_namespace']=rc['time_for_children_namespace']={'link':'time:[51]','inode':51}
        rc['timens_offsets']['monotonic_ns']=10000
        for arm in m.ARMS:
            for row in o['arrivals'][arm]:
                for k in ('accepted_monotonic_ns','post_handler_monotonic_ns','recorded_monotonic_ns'):
                    row[k]+=10000
        pred,_,result=evaluate(p,o,t)
        self.assertEqual(pred['shared_observed_clock_delta_ns'],10000)
        self.assertTrue(result['all_joint_true_assignment_retained'])
        # Fitting a different offset to B would save this incompatible vector;
        # one actual observed domain never permits that per-arm fit.
        for row in o['arrivals']['B']:
            for k in ('accepted_monotonic_ns','post_handler_monotonic_ns','recorded_monotonic_ns'):
                row[k]+=10000
        self.assertEqual(m.predict(p,o)['joint_models'],[])

    def test_missing_or_ambiguous_clock_fails_closed(self):
        p,o,_=fixture()
        for mutate in (
            lambda q:q['clocks'].pop(),
            lambda q:q['clocks'][1].update(boot_id='44444444-4444-4444-8444-444444444444'),
            lambda q:q['clocks'][1].update(time_for_children_namespace={'link':'time:[52]','inode':52}),
            lambda q:q['clocks'][1]['timens_offsets'].update(monotonic_ns=99)):
            v=copy.deepcopy(o);mutate(v)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ValueError):m.predict(p,v)

    def test_accept_ordinal_and_post_order_are_not_fifo_joins(self):
        p,o,t=fixture()
        o['arrivals']['B'][0]['ordinal']=6;o['arrivals']['B'][2]['ordinal']=4
        o['arrivals']['B'].reverse()
        self.assertEqual(m.predict(p,o)['candidate_counts']['B'],[2,1,2])
        # A single receiver retains its actual global counter, never arm-local
        # renumbering. Same ordinal in a second arm is an invalid duplicate.
        o['arrivals']['B'][0]['ordinal']=o['arrivals']['A'][0]['ordinal']
        with self.assertRaises(ValueError):m.predict(p,o)

    def test_duplicate_reused_nf_spk_action_outpoint_and_context_refuse(self):
        p,o,_=fixture()
        for key in ('nf_hex32','destination_spk_hex36','action_hex32','outpoint_hex36','context_sha256'):
            v=copy.deepcopy(o)
            v['arrivals']['B'][0]['native'][key]=v['arrivals']['A'][0]['native'][key]
            with self.subTest(key=key):
                with self.assertRaises(ValueError):m.predict(p,v)

    def test_truth_dependent_arm_partition_missing_extra_or_overlap_refuse(self):
        p,o,_=fixture()
        for mutate in (
            lambda q:q['arm_partition'].update(mechanism='private-owner-path'),
            lambda q:q['arm_partition']['contexts']['B'].append(hx(101)),
            lambda q:q['arm_partition']['contexts']['B'].append(hx(103)),
            lambda q:q['arrivals']['B'].pop()):
            v=copy.deepcopy(o);mutate(v)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ValueError):m.predict(p,v)

    def test_incomplete_facts_or_native_coverage_cannot_claim_gain(self):
        p,o,t=fixture()
        for key in m.REQUIRED_COVERAGE:
            v=copy.deepcopy(o);v['coverage'][key]['complete']=False
            with self.subTest(key=key):
                _,_,r=evaluate(p,v,t)
                self.assertFalse(r['bounded_route_candidate_increase'])
                self.assertEqual(r['missing_coverage'],[key])

    def test_no_baseline_or_corrupt_own_fact_never_qualified(self):
        p,o,t=fixture()
        for category in ('controller-labelled-release','corrupt-own-payout'):
            v=copy.deepcopy(o);v['facts']=[f for f in v['facts'] if f['category']!=category]
            pred,_,r=evaluate(p,v,t)
            self.assertFalse(pred['finite_primary_view_complete'])
            self.assertFalse(r['bounded_route_candidate_increase'])

    def test_unmodeled_primary_or_unknown_never_hides_in_overall_unqualified(self):
        p,o,t=fixture()
        for scope, category in ((m.VIEW,'missing-stream-join'), ('UNKNOWN','opaque-contact-fields'),
                                ('GLOBAL-HOST/UNION','actually-unmodeled-primary-contact')):
            v=copy.deepcopy(o)
            v['unmodeled'].append({'scope':scope,'category':category,
                                  'evidence_refs':['public-fixture/omitted-fact']})
            pred,_,r=evaluate(p,v,t)
            self.assertEqual(pred['candidate_counts']['B'],[2,1,2])
            self.assertEqual(r['primary_unmodeled_count'],1)
            self.assertFalse(r['bounded_route_candidate_increase'])

    def test_exact_universe_and_sealed_model_recomputation(self):
        p,o,t=fixture();pred=m.predict(p,o)
        bad=copy.deepcopy(pred);bad['joint_models'][0]['B'][0]=hx(999)
        with self.assertRaises(ValueError):m.score_owner(p,o,bad,t[0])
        bad=copy.deepcopy(pred);bad['candidate_counts']['B'][0]=3
        with self.assertRaises(ValueError):m.score_owner(p,o,bad,t[0])
        bad=copy.deepcopy(o);bad['facts'][0]['arrival_id']=hx(999)
        with self.assertRaises(ValueError):m.predict(p,bad)

    def test_individually_possible_owner_pairs_need_one_whole_joint_truth(self):
        p,o,t=fixture();pred=m.predict(p,o)
        # Every owner tuple below occurs in some genuine joint row. Together
        # they do not form any one row, so per-owner retained Booleans fail.
        for owner,which in ((0,0),(1,0),(2,1)):
            t[owner]['arrivals']={a:pred['joint_models'][which][a][owner] for a in m.ARMS}
        scores=[m.score_owner(p,o,pred,x) for x in t]
        self.assertTrue(all(s['compatible_joint_model_indices'] for s in scores))
        r=m.aggregate_owner_scores(p,o,pred,scores)
        self.assertFalse(r['all_joint_true_assignment_retained'])
        self.assertEqual(r['status'],'INVALID_MODEL')
        self.assertFalse(r['bounded_route_candidate_increase'])

    def test_forged_mask_and_metrics_refuse(self):
        p,o,t=fixture();pred,scores,_=evaluate(p,o,t)
        for mutate in (
            lambda s:s[0]['compatible_joint_model_indices'].append(1),
            lambda s:s[0]['metrics']['B'].update(candidate_count=3),
            lambda s:s[0]['metrics']['B'].update(digest_tie_rank=99),
            lambda s:s[0].update(prediction_sha256=hx(999))):
            bad=copy.deepcopy(scores);mutate(bad)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ValueError):m.aggregate_owner_scores(p,o,pred,bad)

    def test_mismatched_view_binding_economics_and_transport_refuse(self):
        p,o,_=fixture()
        for mutate in (
            lambda q:q['binding'].update(selection_sha256=hx(99)),
            lambda q:q['sources'].update(other=hx(99)),
            lambda q:q['transport_parameters']['B'].update(onion_endpoint='other.onion'),
            lambda q:q['arrivals']['B'][0]['native'].update(fee=2),
            lambda q:q['arrivals']['B'][0]['native']['head_shape'].update(reserve=7)):
            v=copy.deepcopy(o);mutate(v)
            with self.subTest(mutate=mutate):
                with self.assertRaises(ValueError):m.predict(p,v)
        p['view']='TERMINAL+CONTACT'
        with self.assertRaises(ValueError):m.predict(p,o)

    def test_empty_models_have_no_truth_rank(self):
        p,o,t=fixture();o['facts'].append(link('B',0,hx(14),'counterexample'))
        pred,scores,r=evaluate(p,o,t)
        self.assertEqual(pred['joint_models'],[])
        self.assertTrue(all(s['metrics']['B']['rank_interval'] is None for s in scores))
        self.assertEqual(r['status'],'INVALID_MODEL')

    def test_prediction_pure_no_io_and_no_truth_input(self):
        p,o,t=fixture();before=copy.deepcopy((p,o))
        pred=m.predict(p,o)
        self.assertEqual((p,o),before)
        t[0]['arrivals']['B']=hx(999)
        self.assertEqual(m.predict(p,o),pred)
        self.assertNotIn('owner_truth',m.predict.__code__.co_varnames)


if __name__ == '__main__':
    unittest.main()
