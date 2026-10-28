"""Public-fixture causal timing diagnostic, never a privacy qualification.

No network, capture, Original, key, raw packet/proof/log or financial-body IO.
The matcher uses one shared receiver-minus-controller clock offset per complete
bijection. Truth is used only by score_models, after model construction.
"""
import hashlib
import itertools
import json
import os
from pathlib import Path

LAUNCHER_SHA = '0582a871c6f03a1d512618cede051c6b36bae37acae4a26be25b11534fcd9dec'
RECEIVER_SHA = '0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac'
TRANSPORT_SHA = '88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4'
RUN_ID = 'bb4f2d10-57da-4913-b4cd-0b424defd468'
EVENTS_SHA = '2ac89f31386b1bf234b5c91821fc1d213acd4772cfea80e2f2f23eec6e723027'
RECEIVED_SHA = '7656814ff7515cee9770fcc55308dc57a951860c361454e4f37ddac81cfc95c0'
FIXTURE_SHA = 'b6705efda984a68e94bf2078baa8cb071c626589f886011cafe198bfab267ed0'


def need(value, category):
    if not value:
        raise ValueError(category)


def integer(value):
    need(type(value) is int, 'timing-integer-nanoseconds')
    return value


def enumerate_models(windows, arrivals, offset_range=(None, None)):
    """Project all full bijections with ONE shared unknown offset delta.

    delta=receiver_clock-controller_clock. For a matched r in [L+delta,U+delta],
    delta lies in [r-U,r-L]. Missing L/U and range endpoints mean unbounded;
    no guessed Tor delay, FIFO rule or timestamp backdating is introduced.
    """
    need(type(windows) is list and type(arrivals) is list
         and len(windows) == len(arrivals) == 3, 'timing-three-public-fixture-events')
    clients = [row['client'] for row in windows]
    ids = [row['ordinal'] for row in arrivals]
    need(all(type(v) is int for v in clients + ids)
         and len(set(clients)) == len(set(ids)) == 3, 'timing-distinct-client-arrival-labels')
    windows = sorted(windows, key=lambda row: row['client'])
    stamps = {row['ordinal']: integer(row['post_handler_monotonic_ns']) for row in arrivals}
    for row in windows:
        for key in ('lower_ns', 'upper_ns'):
            if row[key] is not None:
                integer(row[key])
        need(row['lower_ns'] is None or row['upper_ns'] is None
             or row['lower_ns'] <= row['upper_ns'], 'timing-causal-host-window')
    need(type(offset_range) in (tuple, list) and len(offset_range) == 2, 'timing-offset-range')
    low0, high0 = offset_range
    for bound in offset_range:
        if bound is not None:
            integer(bound)
    need(low0 is None or high0 is None or low0 <= high0, 'timing-valid-clock-offset-range')
    models, offsets = [], []
    for assignment in itertools.permutations(sorted(ids)):
        low, high = low0, high0
        for row, arrival in zip(windows, assignment):
            timestamp = stamps[arrival]
            if row['upper_ns'] is not None:
                edge_low = timestamp - row['upper_ns']
                low = edge_low if low is None else max(low, edge_low)
            if row['lower_ns'] is not None:
                edge_high = timestamp - row['lower_ns']
                high = edge_high if high is None else min(high, edge_high)
        if low is None or high is None or low <= high:
            models.append(list(assignment)); offsets.append({'lower_ns': low, 'upper_ns': high})
    compatible = [sorted({model[i] for model in models}) for i in range(3)]
    return {'client_order': [row['client'] for row in windows], 'models': models,
            'model_shared_offset_ranges_ns': offsets, 'compatible_arrivals': compatible,
            'candidate_counts': [len(row) for row in compatible],
            'compatible_bijections': len(models)}


def score_models(prediction, actual_client_arrival):
    """Known PUBLIC fixture truth, not a private owner/truth query."""
    order = prediction['client_order']
    need(set(actual_client_arrival) == set(order), 'timing-complete-public-fixture-truth')
    truth = [actual_client_arrival[client] for client in order]
    need(len(set(truth)) == 3, 'timing-bijective-public-truth')
    ids = prediction['compatible_arrivals']
    unique = {client: values[0] for client, values in zip(order, ids) if len(values) == 1}
    return {'public_truth_retained': truth in prediction['models'],
            'correct_unique': sum(unique.get(client) == actual_client_arrival[client] for client in order),
            'wrong_unique': sum(value != actual_client_arrival[client] for client, value in unique.items()),
            'ranks': [{'client': client, 'candidate_count': len(values),
                       'rank_interval': [1, len(values)] if values else None,
                       'ordinal_tie_rank': values.index(actual_client_arrival[client]) + 1
                           if actual_client_arrival[client] in values else None}
                      for client, values in zip(order, ids)]}


def extract_windows(events):
    """Exact Tor13 source semantics; no post-Popen launch event as L."""
    need(type(events) is list, 'timing-structured-event-list')
    windows = []
    for client in range(3):
        role = 'transport-' + str(client)
        launch = [(i, e) for i, e in enumerate(events)
                  if e.get('kind') == 'launch' and e.get('role') == role]
        statuses = [(i, e) for i, e in enumerate(events)
                    if e.get('kind') == 'role-status' and e.get('role') == role
                    and e.get('value', {}).get('schema') == 'kpb-exit-transport-status/v1']
        exits = [(i, e) for i, e in enumerate(events)
                 if e.get('kind') == 'role-exit' and e.get('role') == role]
        need(len(launch) == len(exits) == 1 and len(statuses) <= 1, 'timing-exact-launch-exit-status')
        li, launched = launch[0]
        ei, exited = exits[0]
        integer(exited['returncode']); integer(launched['pid'])
        post_popen = integer(launched['monotonic_ns'])
        lower = launched.get('started_ns')  # persisted immediately BEFORE Popen.
        if lower is not None:
            integer(lower)
            need(lower <= post_popen, 'timing-pre-Popen-not-later-than-post-event')
        upper, status_index = None, None
        succeeded = False
        if statuses:
            status_index, status = statuses[0]
            value = status['value']
            need(set(value) == {'schema', 'transport_receipt', 'financial_or_chain_acceptance'},
                 'timing-finite-transport-status')
            need(type(value['transport_receipt']) is bool
                 and value['financial_or_chain_acceptance'] is False, 'timing-transport-only-status')
            succeeded = value['transport_receipt'] is True and exited['returncode'] == 0
            if succeeded:
                upper = integer(status['monotonic_ns'])  # host reader/queue consumer observation.
        need(li < ei and (status_index is None or li < status_index), 'timing-status-after-transport-launch')
        pipes = {kind: [(i, e) for i, e in enumerate(events)
                        if e.get('kind') == kind and e.get('client') == client]
                 for kind in ('pipe-created', 'pipe-write-start', 'pipe-write-complete')}
        need(all(len(rows) == 1 for rows in pipes.values()), 'timing-complete-public-pipe-events')
        created_i, created = pipes['pipe-created'][0]
        start_i, start = pipes['pipe-write-start'][0]
        complete_i, complete = pipes['pipe-write-complete'][0]
        need(created_i < li < start_i < complete_i and complete['bytes'] == 4096,
             'timing-actual-pipe-before-launch-write-order')
        windows.append({'client': client, 'lower_ns': lower, 'upper_ns': upper,
            'launch_event_index': li, 'status_event_index': status_index, 'exit_event_index': ei,
            'observed_launcher_pid': launched['pid'], 'inner_transport_or_curl_pid_observed': False,
            'post_Popen_launch_event_ns': post_popen,
            'spawn_observation_gap_ns': post_popen - lower if lower is not None else None,
            'typed_202_and_exit0': succeeded, 'returncode': exited['returncode'],
            'pipe_inode': created['pipe_inode'], 'controller_read_fd': created['read_fd'],
            'controller_write_fd': created['write_fd'], 'pipe_created_event_index': created_i,
            'pipe_write_start_ns': integer(start['monotonic_ns']),
            'pipe_write_complete_ns': integer(complete['monotonic_ns']),
            'upper_bound_is_delayed_host_status_observation_not_child_clock': True})
    return windows


def diagnose(events, arrivals, public_truth, *, clock_qualified=False):
    # This Tor13 run has no captured timens IDs/offsets or calibration receipt.
    # Caller booleans cannot promote it into a clock/privacy qualification.
    need(clock_qualified is False, 'timing-no-retroactive-clock-qualification')
    windows = extract_windows(events)
    zero = enumerate_models(windows, arrivals, (0, 0))
    shared_unknown = enumerate_models(windows, arrivals, (None, None))
    launch_order = [row['client'] for row in sorted(windows, key=lambda row: row['lower_ns']
                                                   if row['lower_ns'] is not None else -1)]
    arrival_order = [row['ordinal'] for row in sorted(arrivals,
                    key=lambda row: row['post_handler_monotonic_ns'])]
    fifo = dict(zip(launch_order, arrival_order))
    return {'schema': 'kpb-public-tor13-timing-diagnostic/v1',
        'classification': 'PUBLIC_KNOWN_FIXTURE_FUNCTIONALITY_ONLY',
        'windows': windows,
        'conditional_zero_offset': {**zero, **score_models(zero, public_truth)},
        'conditional_one_shared_unbounded_constant_offset': {
            **shared_unknown, **score_models(shared_unknown, public_truth)},
        'unsafe_FIFO_sensitivity_only': {'predicted_public_client_arrival': fifo,
            'correct': sum(fifo[client] == public_truth[client] for client in fifo),
            'wrong': sum(fifo[client] != public_truth[client] for client in fifo),
            'this_is_not_an_admissible_Tor_ordering_attack': True},
        'clock_qualified': False,
        'clock_limit': 'Actual13 time-namespace identity/offset/calibration evidence was not captured. Both offset models are conditional sensitivity analyses, not retrospectively verified clocks.',
        'post_Popen_launch_event_used_as_lower_bound': False,
        'receiver_recorded_ns_used_as_pre_ACK_timestamp': False,
        'Tor_FIFO_delay_bound_or_timestamp_backdating_assumed': False,
        'private_owner_or_full_privacy_view_measured': False,
        'owner_origin_pipe_mode_qualified': False,
        'full_host_or_corrupt_server_capture_available': False,
        'overall_privacy_qualified': False, 'status': 'UNQUALIFIED'}


def analyze_metadata(events, receiver_clock, public_mapping):
    """Source-bound typed PUBLIC exports; caller admits their exact byte hashes."""
    need(receiver_clock['schema'] == 'kpb-public-receiver-clock-only-export/v1'
         and public_mapping['schema'] == 'kpb-public-fixture-arrival-client-mapping/v1',
         'timing-public-clock-and-fixture-export-schema')
    for value in (receiver_clock, public_mapping):
        need(value['trial_id'] == RUN_ID and value['clock_qualified'] is False
             and value['privacy_or_financial_qualification'] is False
             and value['source_events_sha256'] == EVENTS_SHA
             and value['source_received_sha256'] == RECEIVED_SHA
             and value['source_fixture_selection_sha256'] == FIXTURE_SHA
             and value['source_launcher_sha256'] == LAUNCHER_SHA
             and value['source_receiver_sha256'] == RECEIVER_SHA,
             'timing-same-run-exact-source-event-fixture-bindings')
    rows = receiver_clock['records']
    need(type(rows) is list and len(rows) == 3, 'timing-three-actual-arrival-records')
    arrivals = []
    for row in rows:
        need(not set(row) & {'projection_hex', 'proof_hex128', 'exit_id', 'frame_sha256'},
             'timing-clock-export-without-raw-packet-proof-or-identifier')
        need(row['schema'] == 'kpb-exit-transport-arrival/v1'
             and row['received_body_bytes'] == 4096 and row['http_status'] == 202
             and row['framing'] == 'PASS' and row['broadcast'] is False
             and row['financial_validation'] == 'NOT_RUN', 'timing-actual-untrusted-HTTP-receipts')
        accepted, handler, post, recorded = (integer(row[key]) for key in (
            'accepted_monotonic_ns', 'handler_monotonic_ns',
            'post_handler_monotonic_ns', 'recorded_monotonic_ns'))
        need(accepted <= handler <= post <= recorded, 'timing-receiver-source-event-order')
        arrivals.append({'ordinal': integer(row['arrival_sequence']),
                         'post_handler_monotonic_ns': post})
    mapping = public_mapping['mapping']
    need(type(mapping) is list and len(mapping) == 3, 'timing-complete-known-public-fixture-map')
    truth = {row['public_fixture_client_index']: row['arrival_sequence'] for row in mapping}
    need(set(truth) == {0, 1, 2} and set(truth.values()) == {row['ordinal'] for row in arrivals},
         'timing-public-fixture-map-bijection')
    result = diagnose(events, arrivals, truth)
    result['trial_id'] = RUN_ID
    result['source_bindings'] = {'launcher_sha256': LAUNCHER_SHA, 'receiver_sha256': RECEIVER_SHA,
        'transport_sha256': TRANSPORT_SHA, 'events_sha256': EVENTS_SHA,
        'known_fixture_selection_sha256': FIXTURE_SHA, 'received_export_reference_sha256': RECEIVED_SHA}
    result['clock_facts_as_recorded'] = receiver_clock['source_clock_facts']
    result['receiver_event_choice'] = 'post_handler before body read; recorded postresponse is retained only in source metadata, never an ACK upper bound'
    result['public_fixture_truth_for_scoring_only'] = truth
    result['raw_received_export_or_packet_bodies_read_by_diagnostic'] = False
    return result


def write_new(path, value):
    path = Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)),
         'timing-new-public-output-path')
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {'path': str(path), 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}

