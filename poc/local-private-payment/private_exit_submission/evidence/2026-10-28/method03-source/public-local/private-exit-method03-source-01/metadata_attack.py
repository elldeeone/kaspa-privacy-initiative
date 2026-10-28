"""UNSELECTED METHOD03 finite metadata attack. Pure functions; no body/file IO.

Inputs are admitted SOURCE-produced view records, never imported PASS authority.
The selected launcher must consume persistent budgets before intake, salt/seal
predictions before truth, and keep observations, predictions and owner score
masks private. This module cannot establish those temporal facts by itself.
No cryptographic anonymity, accepted chain, full-host/server or live funds claim.
"""
import hashlib
import itertools
import json
import re
import uuid

OWNERS = (0, 1, 2)
ARMS = ('A', 'B')
VIEW = 'CONTROLLER+TERMINAL'
PHASE = 'private-exit-route-03'
REQUIRED_COVERAGE = (
    'controller_metadata', 'source_schedule', 'traffic_metadata',
    'clock_snapshots', 'reader_status', 'receiver_metadata',
    'public_native_facts', 'arm_partition', 'native_verification', 'corrupt_contacts',
    'corrupt_receipts', 'corrupt_own_payout', 'transport_outcomes',
)


def need(condition, category):
    if not condition:
        raise ValueError('method03-' + category)


def integer(value):
    need(type(value) is int, 'integer')
    return value


def hex_bytes(value, width):
    need(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % (2 * width), value),
         'canonical-hex-' + str(width))
    return value


def digest(value):
    """Only inside selected private roles if value contains private facts."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def refs(value):
    need(type(value) is list and value and all(type(v) is str and v for v in value)
         and len(value) == len(set(value)), 'nonempty-evidence-refs')


def binding(value):
    need(type(value) is dict and set(value) == {
        'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'},
         'exact-binding')
    for key in ('method_sha256', 'selection_sha256'):
        hex_bytes(value[key], 32)
    for key in ('trial_id', 'attempt_id'):
        need(str(uuid.UUID(value[key])) == value[key], 'canonical-binding-uuid')
    need(value['phase'] == PHASE, 'phase')
    return value


def role(arm, owner):
    need(arm in ARMS and type(owner) is int and owner in OWNERS, 'arm-owner')
    return 'transport/' + str(owner + (3 if arm == 'B' else 0))


def check_plan(plan):
    need(plan['schema'] == 'kpb-method03-metadata-plan/v1'
         and plan['view'] == VIEW and plan['owners'] == list(OWNERS)
         and plan['corrupt_owner'] == 1, 'finite-primary-plan')
    binding(plan['binding'])
    need(set(plan['arms']) == set(ARMS), 'two-arms')
    for arm in ARMS:
        row = plan['arms'][arm]
        need(row['fresh_payout'] is True
             and row['origin'] == ('controller' if arm == 'A' else 'owner-pipe'),
             'both-fresh-only-origin-differs')
        need(integer(row['note_index']) >= 0, 'note-index')
    need(plan['arms']['A']['note_index'] != plan['arms']['B']['note_index'],
         'independent-note-indexes')
    shape = plan['head_shape']
    need(set(shape) == {'cm_count', 'nf_count', 'reserve', 'exit_mode'}
         and shape['exit_mode'] == 'continuing'
         and all(type(shape[k]) is int and shape[k] >= 0
                 for k in ('cm_count', 'nf_count', 'reserve')), 'common-head-shape')
    amounts = plan['common_amounts']
    need(set(amounts) == {'note', 'fee', 'payout'}
         and all(type(v) is int and 0 <= v < 2**64 for v in amounts.values())
         and amounts['note'] > 0 and amounts['payout'] > 0
         and amounts['fee'] + amounts['payout'] == amounts['note'], 'integer-amounts')
    sources = plan['sources']
    need(type(sources) is dict and sources and all(type(k) is str and k for k in sources),
         'source-pins')
    for value in sources.values():
        hex_bytes(value, 32)
    need(set(plan['required_coverage']) >= set(REQUIRED_COVERAGE), 'required-coverage-plan')
    return plan


def clock_offsets(observation):
    """One observed receiver-minus-controller offset shared by BOTH arms.

    Trusted source captures actual role-local ns/time_for_children identities,
    boot ID and kernel offsets BEFORE intake. Different current/children time
    namespaces are deliberately refused: no guessed /proc offset attribution.
    No caller qualified Boolean, cross-boot wall-clock fit, zero-offset default
    or post-truth calibration. A different calibration needs a new source freeze.
    """
    clocks = observation['clocks']
    expected = {'controller', 'receiver/0'} | {role(a, o) for a in ARMS for o in OWNERS}
    need(type(clocks) is list and len(clocks) == len(expected), 'exact-role-clock-snapshots')
    by_role = {}
    for row in clocks:
        need(row['schema'] == 'kpb-method03-clock-snapshot/v1'
             and row['role'] in expected and row['role'] not in by_role
             and row['clock_id'] == 'CLOCK_MONOTONIC', 'observed-role-clock')
        need(integer(row['pid']) > 0, 'actual-role-local-pid')
        need(str(uuid.UUID(row['boot_id'])) == row['boot_id'], 'observed-boot-id')
        for key in ('time_namespace', 'time_for_children_namespace'):
            ns = row[key]
            need(integer(ns['inode']) > 0 and ns['link'] == 'time:[%d]' % ns['inode'],
                 'observed-time-namespace')
        need(row['time_namespace'] == row['time_for_children_namespace'],
             'ambiguous-current-children-time-namespace')
        need(set(row['timens_offsets']) == {'monotonic_ns', 'boottime_ns'},
             'observed-kernel-offset-fields')
        for value in row['timens_offsets'].values():
            integer(value)
        sample = row['sample']
        need(set(sample) == {'monotonic_before_ns', 'realtime_ns', 'boottime_ns',
                             'monotonic_after_ns'}, 'clock-sample-fields')
        for value in sample.values():
            integer(value)
        need(sample['monotonic_before_ns'] <= sample['monotonic_after_ns'],
             'clock-sample-bracket')
        by_role[row['role']] = row
    need(set(by_role) == expected and len({r['boot_id'] for r in clocks}) == 1,
         'same-observed-kernel-boot')
    # A namespace identity cannot have different offsets in one captured vector.
    offsets_by_ns = {}
    for row in clocks:
        ns = row['time_namespace']['inode']
        need(ns not in offsets_by_ns or offsets_by_ns[ns] == row['timens_offsets'],
             'consistent-offset-per-observed-namespace')
        offsets_by_ns[ns] = row['timens_offsets']
    delta = (by_role['receiver/0']['timens_offsets']['monotonic_ns']
             - by_role['controller']['timens_offsets']['monotonic_ns'])
    return by_role, delta


def extract(plan, observation):
    """Extract real launch/reader/arrival bounds; retain all source metadata.

    Normalization never invents inner transport PIDs, stream identity or FIFO.
    Controller roles label outgoing submissions, not remote arrivals by default.
    All source-derived/body/session/fallback joins must enter the facts grammar;
    fixed-source coverage admission is an external trust boundary, not a Boolean
    that this pure matcher can independently prove complete.
    """
    check_plan(plan)
    need(observation['schema'] == 'kpb-method03-metadata-observation/v1'
         and observation['binding'] == plan['binding']
         and observation['sources'] == plan['sources'], 'observation-binding-source')
    transport = observation['transport_parameters']
    need(set(transport) == set(ARMS) and transport['A'] == transport['B']
         and set(transport['A']) >= {'transport_source_sha256', 'tor_binary_sha256',
                                    'curl_binary_sha256', 'onion_endpoint', 'receiver_source_sha256',
                                    'request_policy'}, 'same-actual-Tor-transport-both-arms')
    for key in ('transport_source_sha256', 'tor_binary_sha256', 'curl_binary_sha256',
                'receiver_source_sha256'):
        hex_bytes(transport['A'][key], 32)
    need(type(transport['A']['onion_endpoint']) is str and transport['A']['onion_endpoint'],
         'actual-public-endpoint')
    partition = observation['arm_partition']
    need(partition['mechanism'] == 'source-admitted-public-context'
         and set(partition['contexts']) == set(ARMS), 'public-arm-partition')
    refs(partition['evidence_refs'])
    for values in partition['contexts'].values():
        need(type(values) is list and values and len(values) == len(set(values)),
             'public-arm-context-sets')
        for value in values:
            hex_bytes(value, 32)
    need(not set(partition['contexts']['A']) & set(partition['contexts']['B']),
         'observer-legitimate-disjoint-arm-partition')
    clocks, delta = clock_offsets(observation)
    expected = {(a, o) for a in ARMS for o in OWNERS}
    launches, exits, statuses = {}, {}, {}
    for row in observation['launches']:
        key = row['arm'], row['owner']
        need(key in expected and key not in launches and row['role'] == role(*key),
             'unique-source-role-launch')
        need(integer(row['pid']) > 0 and type(row['event_ref']) is str and row['event_ref'],
             'actual-launch-metadata')
        need(integer(row['started_ns']) <= integer(row['post_popen_ns']),
             'persisted-pre-Popen-bound')
        need(clocks['controller']['sample']['monotonic_after_ns'] <= row['started_ns'],
             'controller-clock-before-launch')
        need(set(row['metadata']) >= {'argv', 'mounts', 'fd_topology', 'schedule'},
             'complete-retained-controller-metadata')
        launches[key] = row
    for row in observation['exits']:
        key = row['arm'], row['owner']
        need(key in expected and key not in exits and row['role'] == role(*key),
             'unique-final-exit')
        integer(row['returncode']); refs([row['event_ref']])
        exits[key] = row
    for row in observation['statuses']:
        key = row['arm'], row['owner']
        need(key in expected and key not in statuses and row['role'] == role(*key)
             and row['schema'] == 'kpb-method03-status-observation/v1'
             and row['reader_id'] == 'controller/' + row['role'], 'unique-reader-status')
        need(row['reader_pid'] == clocks['controller']['pid'], 'actual-controller-reader-pid')
        for name in ('reader_observed_monotonic_ns', 'reader_observed_realtime_ns',
                     'reader_observed_boottime_ns', 'consumed_monotonic_ns'):
            integer(row[name])
        need(row['reader_observed_monotonic_ns'] <= row['consumed_monotonic_ns'],
             'reader-before-queue-consumption')
        value = row['value']
        need(set(value) == {'schema', 'transport_receipt', 'financial_or_chain_acceptance'}
             and value['schema'] == 'kpb-exit-transport-status/v1'
             and type(value['transport_receipt']) is bool
             and value['financial_or_chain_acceptance'] is False, 'fixed-transport-status')
        statuses[key] = row
    need(set(launches) == set(exits) == expected, 'all-six-attempts-retained')
    windows = {}
    for key in sorted(expected):
        launch, final = launches[key], exits[key]
        status = statuses.get(key)
        ack = status is not None and status['value']['transport_receipt'] is True
        upper = status['reader_observed_monotonic_ns'] if ack else None
        # An observed valid 202 survives a later process failure; never widen the
        # attack by deleting an already observed receipt because final rc != 0.
        need(upper is None or launch['started_ns'] <= upper, 'causal-ACK-bound')
        windows[key] = {'lower_ns': launch['started_ns'], 'upper_ns': upper,
                        'ack_observed': ack, 'final_returncode': final['returncode']}
    arrivals = {}
    nfs, ids, spks, actions, ordinals = set(), set(), set(), set(), set()
    outpoints = {a: set() for a in ARMS}
    for arm in ARMS:
        rows = observation['arrivals'][arm]
        need(type(rows) is list and len(rows) == 3, 'exact-three-arrivals-per-arm')
        arrivals[arm] = {}
        for row in rows:
            ordinal = integer(row['ordinal'])
            need(ordinal > 0 and ordinal not in ordinals, 'actual-global-accept-reservation-ordinals')
            ordinals.add(ordinal)
            aid = hex_bytes(row['arrival_id'], 32)
            need(aid not in ids, 'disjoint-exact-projection-universes'); ids.add(aid)
            accepted, post, recorded = [integer(row[k]) for k in (
                'accepted_monotonic_ns', 'post_handler_monotonic_ns', 'recorded_monotonic_ns')]
            need(clocks['receiver/0']['sample']['monotonic_after_ns'] <= accepted <= post <= recorded,
                 'receiver-source-event-order')
            need(row['http_status'] == 202 and row['frame_bytes'] == 4096, 'actual-received-frame-shape')
            refs([row['event_ref']])
            native = row['native']
            nf = hex_bytes(native['nf_hex32'], 32)
            need(nf not in nfs, 'independent-note-NF-universes'); nfs.add(nf)
            spk = hex_bytes(native['destination_spk_hex36'], 36)
            need(spk not in spks, 'independent-fresh-payout-SPKs'); spks.add(spk)
            for k in ('action_hex32', 'context_sha256'):
                hex_bytes(native[k], 32)
            need(native['action_hex32'] not in actions, 'independent-onchain-actions')
            actions.add(native['action_hex32'])
            outpoints[arm].add(hex_bytes(native['outpoint_hex36'], 36))
            need(native['context_sha256'] in partition['contexts'][arm]
                 and native['head_shape'] == plan['head_shape'], 'public-context-arm-and-shape')
            need(integer(native['payout']) == plan['common_amounts']['payout']
                 and integer(native['fee']) == plan['common_amounts']['fee'], 'same-public-economics')
            arrivals[arm][aid] = row
    need(not outpoints['A'] & outpoints['B'], 'independent-arm-outpoints')
    need(all({r['native']['context_sha256'] for r in arrivals[a].values()}
             == set(partition['contexts'][a]) for a in ARMS), 'exact-used-public-arm-contexts')
    return {'windows': windows, 'arrivals': arrivals, 'clock_delta_ns': delta}


def check_facts(observation, arrivals):
    facts = observation['facts']
    need(type(facts) is list, 'fact-list')
    for fact in facts:
        need(type(fact['category']) is str and fact['category'], 'fact-category')
        refs(fact['evidence_refs'])
        kind = fact['kind']
        if kind in ('owner-arrival', 'allowed-edges'):
            arm, owner = fact['arm'], fact['owner']; role(arm, owner)
            values = [fact['arrival_id']] if kind == 'owner-arrival' else fact['arrival_ids']
            need(type(values) is list and len(values) == len(set(values))
                 and all(v in arrivals[arm] for v in values), 'fact-selected-universe')
        else:
            need(kind in ('same-owner', 'different-owner'), 'finite-fact-kind')
            for endpoint in (fact['left'], fact['right']):
                need(endpoint['arm'] in ARMS
                     and endpoint['arrival_id'] in arrivals[endpoint['arm']], 'cross-fact-selected-universe')
    return facts


def fact_holds(fact, assignments):
    kind = fact['kind']
    if kind in ('owner-arrival', 'allowed-edges'):
        allowed = [fact['arrival_id']] if kind == 'owner-arrival' else fact['arrival_ids']
        return assignments[fact['arm']][fact['owner']] in allowed
    def owner_of(endpoint):
        return assignments[endpoint['arm']].index(endpoint['arrival_id'])
    same = owner_of(fact['left']) == owner_of(fact['right'])
    return same if kind == 'same-owner' else not same


def predict(plan, observation):
    """Truth-free PRIVATE prediction. Exact joint models, never public graphs."""
    data = extract(plan, observation)
    facts = check_facts(observation, data['arrivals'])
    delta = data['clock_delta_ns']
    pairs = []
    for a in itertools.permutations(sorted(data['arrivals']['A'])):
        for b in itertools.permutations(sorted(data['arrivals']['B'])):
            model = {'A': list(a), 'B': list(b)}
            valid = True
            for arm in ARMS:
                for owner in OWNERS:
                    win = data['windows'][arm, owner]
                    t = data['arrivals'][arm][model[arm][owner]]['post_handler_monotonic_ns']
                    valid &= win['lower_ns'] + delta <= t
                    valid &= win['upper_ns'] is None or t <= win['upper_ns'] + delta
            if valid and all(fact_holds(fact, model) for fact in facts):
                pairs.append(model)
    projections = {arm: sorted({tuple(m[arm]) for m in pairs}) for arm in ARMS}
    compatible = {arm: [sorted({m[arm][owner] for m in pairs}) for owner in OWNERS] for arm in ARMS}
    # Retain full correlations; every marginal model must be a projection of a
    # computed JOINT pair, and never rebuild joint pairs from marginal edges.
    for arm in ARMS:
        need({tuple(m[arm]) for m in pairs} == set(projections[arm]), 'exact-joint-projection')
    coverage = observation['coverage']
    for key in plan['required_coverage']:
        need(key in coverage and type(coverage[key]['complete']) is bool, 'coverage-not-omitted')
        refs(coverage[key]['evidence_refs'])
    baseline = all(any(f['kind'] == 'owner-arrival' and f.get('arm') == 'A'
                       and f.get('owner') == owner and f['category'] == 'controller-labelled-release'
                       for f in facts) for owner in OWNERS)
    own_facts = all(any(f['kind'] == 'owner-arrival' and f.get('arm') == arm
                       and f.get('owner') == plan['corrupt_owner']
                       and f['category'] == 'corrupt-own-payout' for f in facts) for arm in ARMS)
    all_success = all(w['ack_observed'] and w['final_returncode'] == 0 for w in data['windows'].values())
    need(type(observation['unmodeled']) is list, 'explicit-unmodeled-facts')
    primary_missing = []
    for item in observation['unmodeled']:
        need(set(item) == {'scope', 'category', 'evidence_refs'}
             and item['scope'] in (VIEW, 'GLOBAL-HOST/UNION', 'UNKNOWN')
             and type(item['category']) is str and item['category'], 'scoped-unmodeled-fact')
        refs(item['evidence_refs'])
        external_only = item['scope'] == 'GLOBAL-HOST/UNION' and item['category'] in (
            'full-global-host-view', 'full-corrupt-server-view')
        if not external_only:
            primary_missing.append(item['category'])
    finite_complete = bool(pairs) and baseline and own_facts and all_success and all(
        coverage[k]['complete'] for k in plan['required_coverage']) and not primary_missing
    return {'schema': 'kpb-method03-private-joint-prediction/v1', 'binding': plan['binding'],
        'view': VIEW, 'plan_sha256': digest(plan), 'observation_sha256': digest(observation),
        'universe': {arm: sorted(data['arrivals'][arm]) for arm in ARMS},
        'joint_models': pairs, 'arm_model_projections': {a: [list(x) for x in projections[a]] for a in ARMS},
        'compatible_arrivals': compatible,
        'candidate_counts': {a: [len(x) for x in compatible[a]] for a in ARMS},
        'shared_observed_clock_delta_ns': delta, 'clock_qualified': True,
        'baseline_labelled_routes_present': baseline, 'corrupt_own_facts_present': own_facts,
        'finite_primary_view_complete': finite_complete,
        'missing_coverage': [k for k in plan['required_coverage'] if not coverage[k]['complete']],
        'unmodeled_count': len(observation['unmodeled']),
        'primary_unmodeled_count': len(primary_missing),
        'all_transports_ack_and_exit0': all_success, 'overall_privacy_qualified': False}


def score_owner(plan, observation, prediction, owner_truth):
    """POSTSEAL one-owner role only. Return PRIVATE mask; never publish it.

    Launcher checks actual all-view seal/one-shot barrier before truth mount.
    Recompute exact selected universe/models before using redundant fields.
    """
    need(prediction == predict(plan, observation), 'exact-sealed-prediction-recomputation')
    need(owner_truth['schema'] == 'kpb-method03-one-owner-truth/v1'
         and owner_truth['binding'] == plan['binding'], 'one-owner-truth-binding')
    owner = owner_truth['owner']; role('A', owner)
    truth = owner_truth['arrivals']
    need(set(truth) == set(ARMS) and all(truth[a] in prediction['universe'][a] for a in ARMS),
         'truth-exact-selected-universe')
    masks = [i for i, model in enumerate(prediction['joint_models'])
             if all(model[a][owner] == truth[a] for a in ARMS)]
    metrics = {}
    for arm in ARMS:
        values = prediction['compatible_arrivals'][arm][owner]
        metrics[arm] = {'candidate_count': len(values),
            'rank_interval': [1, len(values)] if truth[arm] in values else None,
            'digest_tie_rank': values.index(truth[arm]) + 1 if truth[arm] in values else None,
            'correct_unique': len(values) == 1 and values[0] == truth[arm],
            'wrong_unique': len(values) == 1 and values[0] != truth[arm]}
    return {'schema': 'kpb-method03-private-owner-score/v1', 'binding': plan['binding'],
        'owner': owner, 'prediction_sha256': digest(prediction),
        'compatible_joint_model_indices': masks, 'metrics': metrics}


def aggregate_owner_scores(plan, observation, prediction, private_scores):
    """Closed aggregate reads source-bound private score capsules, not Originals.

    Imported masks are not authority: trusted pinned one-owner workers and
    launcher must admit each capsule. Host exports only this aggregate result.
    Intersect masks so individually retained owner edges cannot hide exclusion
    of the COMPLETE true assignment from the joint A/B model.
    """
    need(prediction == predict(plan, observation), 'exact-aggregate-prediction')
    need(type(private_scores) is list and len(private_scores) == 3
         and {s['owner'] for s in private_scores} == set(OWNERS), 'all-three-private-owner-scores')
    indices = set(range(len(prediction['joint_models'])))
    metrics = {}
    for score in private_scores:
        need(score['schema'] == 'kpb-method03-private-owner-score/v1'
             and score['binding'] == plan['binding']
             and score['prediction_sha256'] == digest(prediction), 'same-sealed-score-binding')
        mask = score['compatible_joint_model_indices']
        need(type(mask) is list and all(type(i) is int and i in indices for i in mask)
             and len(mask) == len(set(mask)), 'score-mask-selected-joint-universe')
        if mask:
            owner = score['owner']
            pair = {a: prediction['joint_models'][mask[0]][a][owner] for a in ARMS}
            exact_mask = [i for i, model in enumerate(prediction['joint_models'])
                          if all(model[a][owner] == pair[a] for a in ARMS)]
            need(mask == exact_mask, 'exact-owner-truth-mask')
            for arm in ARMS:
                values = prediction['compatible_arrivals'][arm][owner]
                expected = {'candidate_count': len(values), 'rank_interval': [1, len(values)],
                    'digest_tie_rank': values.index(pair[arm]) + 1,
                    'correct_unique': len(values) == 1 and values[0] == pair[arm],
                    'wrong_unique': len(values) == 1 and values[0] != pair[arm]}
                need(score['metrics'][arm] == expected, 'recomputed-private-owner-metrics')
        metrics[score['owner']] = score['metrics']
    retained = set(indices)
    for score in private_scores:
        retained &= set(score['compatible_joint_model_indices'])
    for owner in OWNERS:
        for arm in ARMS:
            row = metrics[owner][arm]
            count = prediction['candidate_counts'][arm][owner]
            need(row['candidate_count'] == count and type(row['correct_unique']) is bool
                 and type(row['wrong_unique']) is bool
                 and not (row['correct_unique'] and row['wrong_unique']), 'derived-owner-score-fields')
            need(row['rank_interval'] in (None, [1, count])
                 and (row['digest_tie_rank'] is None or type(row['digest_tie_rank']) is int
                      and 1 <= row['digest_tie_rank'] <= count), 'rank-fields')
    honest = [o for o in OWNERS if o != plan['corrupt_owner']]
    counts = prediction['candidate_counts']
    numerical = all(counts['B'][o] >= counts['A'][o] for o in honest) and any(
        counts['B'][o] > counts['A'][o] for o in honest)
    valid = bool(retained) and prediction['finite_primary_view_complete']
    return {'schema': 'kpb-method03-public-aggregate-score/v1', 'binding': plan['binding'],
        'view': VIEW, 'candidate_counts': counts,
        # Exact digest tie positions stay inside PRIVATE score capsules. With
        # two honest candidates an owner-labelled rank1/2 can declassify the
        # matching terminal ID; recording a rank does not authorize publishing it.
        'per_owner_metrics': [{'owner': o, 'arms': {
            a: {k: v for k, v in metrics[o][a].items() if k != 'digest_tie_rank'}
            for a in ARMS}} for o in OWNERS],
        'all_joint_true_assignment_retained': bool(retained),
        'finite_primary_view_complete': prediction['finite_primary_view_complete'],
        'bounded_route_candidate_increase': valid and numerical,
        'clock_qualified': prediction['clock_qualified'],
        'missing_coverage': prediction['missing_coverage'],
        'unmodeled_count': prediction['unmodeled_count'],
        'primary_unmodeled_count': prediction['primary_unmodeled_count'],
        'status': 'INVALID_MODEL' if not retained else 'UNQUALIFIED',
        'overall_privacy_qualified': False,
        'scope': 'UNFUNDED_COMPONENT_FINITE_CONTROLLER_TERMINAL_VIEW_ONLY'}
