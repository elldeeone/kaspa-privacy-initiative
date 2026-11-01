"""Frozen source-only observer worker entrypoint.

The selected launcher may call only ``run()`` with inherited FD40.  This
version builds the complete ten-leaf internal model and public candidate
filters, then exits CONFIGURED0 because Step-2 coverage is still open.  It
never returns models, predictions or a Python capability and never writes
FD62.  The native supervisor remains the sole future output authority.
"""

import hashlib
import os

import privacy_capture_model as capture
import privacy_codec as codec
import privacy_fd40_archive as archive


CONFIGURED0_EXIT = 78
CONFIGURED0_MESSAGE = b'KPB_OBSERVER_STATIC_STEP2_OPEN\n'


def run():
    """Consume inherited FD40, build all private models, and fail closed."""

    def closure(records, payload_bytes, hello):
        counts = {}
        for row in records:
            counts[row['stream']] = counts.get(row['stream'], 0) + 1
        return {
            'schema': 'kpb-capture-source-closure/v1',
            'attempt_id': hello['attempt_id'],
            'cohort_sha256': hello['cohort_sha256'],
            'producer_record_count': len(records),
            'capture_record_count': len(records),
            'producer_payload_bytes': payload_bytes,
            'capture_payload_bytes': payload_bytes,
            'producer_stream_counts': counts,
            'capture_stream_counts': counts,
            'record_chain_sha256': hashlib.sha256(
                codec.encoded(records)).hexdigest(),
            'unknown_record_count': 0,
            'capture_root_closed': True,
            'producer_fd_closed': True,
        }

    def terminal_model(leaf, public):
        typed = leaf['typed']
        source_events = [row['value'] for row in typed['records']
                         if row['stream'] == 'event']
        selected = (source_events[0], source_events[2], source_events[4])
        events = []
        for sequence, (source, kind) in enumerate(zip(
                selected,
                ('candidate-constructed', 'native-full', 'trial-closed'))):
            events.append({
                'sequence': sequence,
                'kind': kind,
                'monotonic_ns': source['monotonic_ns'],
                'candidate_sha256': source['candidate_sha256'],
                'transaction_id_hex32': None,
                'outcome': 'ok',
            })
        groups = []
        for row in typed['records']:
            if row['stream'] != 'group':
                continue
            source = row['value']
            groups.append({
                'group_id_sha256': source['group_id_sha256'],
                'owner_component': source.get('owner_component'),
                'nfs_hex32': source['nfs_hex32'],
                'tuple_sha256': source['tuple_sha256'],
            })
        records = ([{'stream': 'event', 'value': row} for row in events]
                   + [{'stream': 'group', 'value': row} for row in groups])
        value = {
            'schema': 'kpb-terminal-observer-history/v1',
            'round': public['round'],
            'projection_sha256': public['projection_sha256'],
            'cohort_sha256': typed['meta']['cohort_sha256'],
            'mode': 'UNFUNDED_NETWORK_DISABLED',
            'events': events,
            'groups': groups,
            'amount_observations': [],
            'retry_history': [],
            'rejected_or_orphaned': [],
            'reorg_history': [],
            'cross_round_links': [],
            'closure': closure(
                records,
                sum(len(codec.encoded(row['value'])) for row in records),
                typed['hello']),
        }
        return capture.terminal(codec.encoded(value), public)

    def dispatcher_model(leaf, public):
        typed = leaf['typed']
        events = [row['value'] for row in typed['records']
                  if row['stream'] == 'event']
        retries = [row['value'] for row in typed['records']
                   if row['stream'] == 'retry']
        records = ([{'stream': 'event', 'value': row} for row in events]
                   + [{'stream': 'retry', 'value': row} for row in retries])
        value = {
            **typed['meta'],
            'events': events,
            'retry_history': retries,
            'closure': closure(
                records, sum(row['bytes'] for row in events),
                typed['hello']),
        }
        # No Python policy-source token is admitted. The exact dispatcher
        # mapping row therefore remains open in this source-only worker.
        return capture.dispatcher(codec.encoded(value), public)

    def colluder_model(leaf, public):
        typed = leaf['typed']

        def legacy(row):
            source = row['source']
            return {'source': {
                'observer_stage': source['observer_stage'],
                'stage_sequence': source['stage_sequence'],
                'operation_id_sha256': source['operation_id_sha256'],
                'contact_owner_component':
                    source['contact_owner_component'],
                'contact_binding_qualified': False,
                'source_event_sequence': source['source_event_sequence'],
                'observed_monotonic_ns': source['observed_monotonic_ns'],
            }, 'value': row['value']}

        originals = [legacy(row) for row in typed['records']
                     if row['stream'] == 'original']
        invoices = [legacy(row) for row in typed['records']
                    if row['stream'] == 'invoice']
        receipts = [legacy(row) for row in typed['records']
                    if row['stream'] == 'decrypted-receipt']
        retries = [legacy(row) for row in typed['records']
                   if row['stream'] == 'retry']
        if len(originals) != 1:
            raise ValueError('observer-static-c1-original-count')
        records = ([{'stream': 'original', **originals[0]}]
                   + [{'stream': 'invoice', **row} for row in invoices]
                   + [{'stream': 'decrypted-receipt', **row}
                      for row in receipts]
                   + [{'stream': 'retry', **row} for row in retries])
        meta = typed['meta']
        value = {
            'schema': 'kpb-colluder-wallet-observer-capture/v1',
            'round': public['round'],
            'projection_sha256': public['projection_sha256'],
            'cohort_sha256': meta['cohort_sha256'],
            'owner_component': 1,
            'original': originals[0],
            'invoices': invoices,
            'decrypted_receipts': receipts,
            'retry_history': retries,
            'closure': closure(
                records,
                sum(len(codec.encoded(row['value'])) for row in records),
                typed['hello']),
        }
        # Qualified C1 values stay open until the native postcapture
        # capability is consumed; this downgrade preserves only legitimate
        # wallet self-knowledge.
        return capture.colluder_wallet(codec.encoded(value), public)

    selected = archive.read_selected_fd40_typed_capture()
    parsed = archive._consume_selected(selected)
    archive.inspect_public_state_transitions(parsed)

    artifact_rounds = []
    terminal_artifacts = []
    for round_index, public in enumerate(parsed['public_rounds']):
        leaves = parsed['typed_leaves'][round_index * 5:(round_index + 1) * 5]
        projection = capture.public_projection(
            parsed['projection_bytes'][round_index], public)
        terminal = terminal_model(leaves[1], public)
        dispatcher = dispatcher_model(leaves[2], public)
        corrupt = leaves[3]['typed']['nonauthorizing_model_artifact']
        colluder = colluder_model(leaves[4], public)
        artifacts = [projection, terminal, dispatcher, corrupt, colluder]
        capture.derive_view_artifacts(public, artifacts)
        artifact_rounds.append(artifacts)
        terminal_artifacts.append(terminal)

    derived_rounds = [capture.derive_view_artifacts(public, artifacts)
                      for public, artifacts in zip(
                          parsed['public_rounds'], artifact_rounds)]
    for view in codec.VIEWS:
        models = [codec.assignments(
            public, derived['views'][view]['constraints'])
            for public, derived in zip(parsed['public_rounds'],
                                       derived_rounds)]
        capture.inspect_fd40_public_state_candidate_filter(
            parsed, models, terminal_artifacts)
        capture.inspect_fd40_public_observable_candidate_filters(
            parsed, models, terminal_artifacts)
        if view in ('corrupt-server-plus-wallet', 'union'):
            capture.inspect_fd40_c1_contact_value_candidate_filter(
                parsed, models, terminal_artifacts)

    phase = capture._private_completion_phase_partition(
        parsed['public_rounds'], artifact_rounds)
    step2_open = [row for view in phase['views']
                  for row in view['step2_open_fields']]
    unselected_assumptions = [row for row in step2_open
        if row['proposed_resolution'] ==
            'source_assumption_pending_selection']
    if step2_open or unselected_assumptions:
        os.write(2, CONFIGURED0_MESSAGE)
        return CONFIGURED0_EXIT

    # This source revision can never reach FD62: even a future zero-open model
    # still requires the native phase authority and source-owned binding
    # adapter before the production v2 encoder may be invoked.
    raise ValueError('observer-static-native-fd62-authority-required')


if __name__ == '__main__':
    raise SystemExit(run())
