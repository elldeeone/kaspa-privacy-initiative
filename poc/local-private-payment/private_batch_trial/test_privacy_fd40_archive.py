"""Adversarial controls for the complete selected FD40 v2 parser."""

import copy
import fcntl
import hashlib
import json
import os
import struct
import subprocess
import sys
import unittest

import privacy_codec as codec
import privacy_capture_model as capture
import privacy_fd40_archive as archive
import privacy_fd40_structural as structural
from test_privacy_capture_model import (
    c03_with_projection, colluder_fixture, continuous_projection_pair,
    dispatcher_fixture, qualified_colluder_fixture, raw, terminal_fixture,
)
from test_privacy_capture_producer import p1_channel, selection
from test_privacy_public_state import TREES


def digest(label):
    return hashlib.sha256(label.encode()).digest()


def frame(tag, payload=b''):
    if not isinstance(payload, bytes):
        payload = codec.encoded(payload)
    return archive.EVENT_MAGIC + bytes((tag,)) + struct.pack(
        '>Q', len(payload)) + payload


def event_wire(hello, meta=None, records=(), projection=None):
    value = bytearray(frame(1, hello))
    if projection is not None:
        value.extend(frame(4, projection))
    else:
        value.extend(frame(2, meta))
        for row in records:
            value.extend(frame(3, row))
    value.extend(frame(5))
    return bytes(value)


def event_evidence(raw, round_number, kind):
    at = 0; count = 0; payload_bytes = 0; end = None
    while at < len(raw):
        header = raw[at:at + 17]
        size = int.from_bytes(header[9:17], 'big')
        payload = raw[at + 17:at + 17 + size]
        count += 1; payload_bytes += size
        if header[8] == 5:
            end = hashlib.sha256(header + payload).digest()
        at += 17 + size
    assert at == len(raw) and end is not None
    root = hashlib.sha256(raw).digest()
    eof = hashlib.sha256(
        b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
        + struct.pack('>IBQQQ', round_number, kind, count, payload_bytes,
                      len(raw)) + root + end).digest()
    return root, end, eof, count, payload_bytes, len(raw)


def p1_evidence(raw, round_number):
    at = 0; count = 0; payload_bytes = 0; end = None
    while at < len(raw):
        header = raw[at:at + 112]
        size = int.from_bytes(header[44:48], 'big')
        payload = raw[at + 112:at + 112 + size]
        count += 1; payload_bytes += size
        if header[8] == 5:
            end = hashlib.sha256(header + payload).digest()
        at += 112 + size
    assert at == len(raw) and end is not None
    root = hashlib.sha256(raw).digest()
    eof = hashlib.sha256(
        b'KPB_CAPTURE_PRODUCER_STREAM_EOF_V1\n'
        + struct.pack('>IBQQQ', round_number, 4, count, payload_bytes,
                      len(raw)) + root + end).digest()
    return root, end, eof, count, payload_bytes, len(raw)


def valid_continuous_public_state_pair(*, repeat_ciphertext=False):
    """Build two exact public transitions over one retained tree state."""
    templates, _ = continuous_projection_pair()
    state = TREES.PublicState([
        digest('fd40-valid-old-cm-' + str(index)) for index in range(3)
    ])
    raws = []
    for round_number, template in enumerate(templates, 1):
        prefix = template[:193]
        body = bytearray(template[193:])
        body[204:236] = state.cm.root()
        body[236:268] = state.nf.root()
        body[268:272] = len(state.cms).to_bytes(4, 'little')
        body[272:276] = len(state.entries).to_bytes(4, 'little')

        nfs = sorted(
            (digest('fd40-valid-nf-' + str(round_number) + '-' + str(index))
             for index in range(3)),
            key=lambda value: int.from_bytes(value, 'little'))
        for index, nf in enumerate(nfs):
            body[404 + 96 * index:436 + 96 * index] = nf
            body[3812 + 1160 * index:
                 3812 + 1160 * (index + 1)] = state.insert(nf)
        body[316:348] = state.nf.root()
        body[352:356] = len(state.entries).to_bytes(4, 'little')

        for index in range(6):
            cm = digest('fd40-valid-cm-' + str(round_number) + '-' +
                        str(index))
            body[692 + 520 * index:724 + 520 * index] = cm
            body[7292 + 512 * index:
                 7292 + 512 * (index + 1)] = state.append(cm)
        body[284:316] = state.cm.root()
        body[348:352] = len(state.cms).to_bytes(4, 'little')
        if repeat_ciphertext:
            first = bytes(body[692 + 96:692 + 360])
            second = 692 + 520
            body[second + 96:second + 360] = first
            body[second + 360:second + 392] = hashlib.sha256(
                first).digest()
        raws.append(prefix + bytes(body))
    return raws, [archive._public_from_projection(index + 1, value)
                  for index, value in enumerate(raws)]


class ArchiveFixture:
    def __init__(self, *, valid_public_state=False,
                 repeat_ciphertext=False):
        self.selected = selection()
        self.raw_projections, self.publics = (
            valid_continuous_public_state_pair(
                repeat_ciphertext=repeat_ciphertext)
            if valid_public_state else
            continuous_projection_pair())
        for financial, public in zip(
                self.selected['financial_rounds'], self.publics):
            financial['retained_projection_sha256'] = \
                public['projection_sha256']
        self.roles = self.selected['role_launch_closure']
        # The selected native manifest identifies one pinned P1 component.
        # Make the source-only fixture match that genuine invariant.
        p1_roles = [row for row in self.roles
                    if row['kind'] == 'corrupt-server-capture']
        for row in p1_roles:
            row['source_sha256'] = '21' * 32
            row['build_sha256'] = '22' * 32
            row['launch_sha256'] = '23' * 32
        self.p1_roles = p1_roles
        self.entries = []
        for component in range(1, 11):
            fields = {
                field: digest('manifest-' + str(component) + '-' + field)
                for field in archive.WORKER_FIELDS}
            fields['component'] = component
            self.entries.append(fields)
        self.entries[1].update({
            'source_identity': bytes.fromhex('21' * 32),
            'build_identity': bytes.fromhex('22' * 32),
            'launcher_identity': bytes.fromhex('23' * 32),
        })
        self.binding = self._binding()
        self.source_closure = self.binding['source_closure']
        self.processes = [digest('process-' + str(index))
                          for index in range(10)]
        self.exits = [digest('exit-' + str(index)) for index in range(10)]
        self.wires = self._wires()
        self.section = self._section()
        self.value, self.leaf_offsets = self._archive()

    def replace_leaf_wire(self, slot, wire):
        start = self.leaf_offsets[slot]
        old_size = int.from_bytes(
            self.value[start + 311:start + 319], 'little')
        if len(wire) != old_size:
            raise AssertionError('same-width mutation required')
        round_number, kind = slot // 5 + 1, slot % 5 + 1
        evidence = (p1_evidence(wire, round_number) if kind == 4 else
                    event_evidence(wire, round_number, kind))
        changed = bytearray(self.value)
        changed[start + 199:start + 231] = evidence[0]
        changed[start + 231:start + 263] = evidence[1]
        changed[start + 263:start + 295] = evidence[2]
        changed[start + 295:start + 319] = struct.pack('<QQQ', *evidence[3:])
        changed[start + 319:start + 319 + old_size] = wire
        return bytes(changed)

    def _binding(self):
        result = {'classification': 1}
        for field in archive.RUN_DIGEST_FIELDS:
            result[field] = digest('binding-' + field)
        result['capture'] = hashlib.sha256(
            b'KPB_CAPTURE_IDENTITY_V1\n'
            + self.selected['capture_identity'].encode()).digest()
        result['finite_manifest_identity'] = digest('manifest-id')
        result['finite_manifest_parent_recomputation_identity'] = digest(
            'manifest-parent')
        for field in archive.OUTER_DIGEST_FIELDS:
            result[field] = digest('binding-' + field)
        result['manifest_entries'] = self.entries
        result['observer_worker'] = {
            field: digest('observer-' + field)
            for field in archive.WORKER_FIELDS}
        result['score_worker'] = {
            field: digest('score-' + field) for field in archive.WORKER_FIELDS}
        result['aggregate_worker'] = {
            field: digest('aggregate-' + field)
            for field in archive.WORKER_FIELDS}
        result['financial_runs'] = tuple(bytes.fromhex(row['financial_run_id'])
            for row in self.selected['financial_rounds'])
        result['round_attempts'] = tuple(hashlib.sha256(
            b'KPB_CAPTURE_ATTEMPT_ID_V1\n' + row['attempt_id'].encode()
        ).digest() for row in self.selected['rounds'])
        result['round_cohorts'] = tuple(bytes.fromhex(row['cohort_sha256'])
            for row in self.selected['rounds'])
        result['round_capture_plans'] = (
            digest('capture-plan-1'), digest('capture-plan-2'))
        result['projections'] = tuple(bytes.fromhex(row['projection_sha256'])
                                      for row in self.publics)
        encoded = bytearray((1,))
        encoded.extend(b''.join(result[field]
                                for field in archive.RUN_DIGEST_FIELDS))
        encoded.extend(result['finite_manifest_identity'])
        encoded.extend(result['finite_manifest_parent_recomputation_identity'])
        encoded.extend(b''.join(result[field]
                                for field in archive.OUTER_DIGEST_FIELDS))
        for entry in self.entries:
            encoded.append(entry['component'])
            encoded.extend(b''.join(entry[field]
                            for field in archive.WORKER_FIELDS))
        for worker in ('observer_worker', 'score_worker', 'aggregate_worker'):
            encoded.extend(b''.join(result[worker][field]
                                    for field in archive.WORKER_FIELDS))
        for field in archive.ROUND_ARRAY_FIELDS:
            encoded.extend(b''.join(result[field]))
        assert len(encoded) == structural.RUN_BINDING_BYTES
        result['wire_bytes'] = bytes(encoded)
        return result

    def _hello(self, round_number, kind):
        index = round_number - 1
        return {
            'schema': 'kpb-capture-event-channel/v1',
            'round': round_number, 'kind': kind,
            'attempt_id': self.selected['rounds'][index]['attempt_id'],
            'cohort_sha256': self.selected['rounds'][index][
                'cohort_sha256'],
            'financial_run_id': self.selected['financial_rounds'][index][
                'financial_run_id'],
            'capture_identity': self.selected['capture_identity'],
        }

    def _terminal(self, round_number, public):
        meta = {
            'schema': 'kpb-terminal-observer-history/v2',
            'round': round_number,
            'projection_sha256': public['projection_sha256'],
            'cohort_sha256': self.selected['rounds'][round_number - 1][
                'cohort_sha256'],
            'mode': 'CONFIGURED0_NETWORK_DISABLED',
            'amount_observations': [], 'status': 'UNQUALIFIED_SOURCE_ONLY',
            'scope': 'PAYMENT_TERMINAL_STREAM_CONTROL_ONLY',
            'actual_network_execution': False, 'actual_receipt': False,
            'privacy_measurement_usable': False,
        }
        def event(sequence, kind):
            return {'stream': 'event', 'value': {
                'accepted_head_hex32': None, 'candidate_sha256': '31' * 32,
                'case_sha256': '32' * 32,
                'final_checkpoint_sha256':
                    ('35' * 32 if sequence >= 3 else None),
                'kind': kind, 'monotonic_ns': 100 + sequence,
                'native_full_sha256': ('34' * 32 if sequence >= 2 else None),
                'outcome': 'ok',
                'projection_sha256': public['projection_sha256'],
                'r0_receipt_sha256': ('33' * 32 if sequence >= 1 else None),
                'sequence': sequence, 'settlement_sha256': None,
                'transaction_id_hex32': None,
            }}
        records = [event(index, kind) for index, kind in enumerate((
            'candidate-constructed', 'r0-verified',
            'native-full-verified', 'durable-final'))]
        records.append({'stream': 'group', 'value': {
            'group_id_sha256': digest(
                'terminal-group-' + str(round_number)).hex(),
            'nfs_hex32': public['nfs_hex32'],
            'owner_component_absent': True,
            'privacy_measurement_usable': False,
            'projection_sha256': public['projection_sha256'],
            'source_complete': True,
            'tuple_sha256': public['tuple_sha256'],
        }})
        records.append({'stream': 'mapping-complete', 'value': {
            'cross_round_owner_nf_tuple_export_count': 0,
            'cross_round_owner_nf_tuple_exports_source_complete': True,
            'grouping_source_complete': True,
            'owner_component_present': False,
            'privacy_measurement_usable': False,
            'public_continuity_modeled_separately': True,
        }})
        records.append(event(4, 'pre-network-capture-closed'))
        return event_wire(self._hello(
            round_number, 'terminal-history-v2-control'), meta, records)

    def _wires(self):
        result = []
        for round_number, (projection, public) in enumerate(zip(
                self.raw_projections, self.publics), 1):
            result.append(event_wire(
                self._hello(round_number, 'public-projection'),
                projection=projection))
            result.append(self._terminal(round_number, public))
            dispatcher = dispatcher_fixture(
                public,
                cohort_sha256=self.selected['rounds'][round_number - 1][
                    'cohort_sha256'],
                run_sha256=self.selected['financial_rounds'][
                    round_number - 1]['financial_run_id'],
                construction_attempt_sha256=self.binding['round_attempts'][
                    round_number - 1].hex(),
                capture_plan_sha256=self.binding['round_capture_plans'][
                    round_number - 1].hex())
            meta = {key: value for key, value in dispatcher.items()
                    if key not in ('events', 'retry_history', 'closure')}
            records = ([{'stream': 'event', 'value': value}
                        for value in dispatcher['events']] +
                       [{'stream': 'retry', 'value': value}
                        for value in dispatcher['retry_history']])
            result.append(event_wire(
                self._hello(round_number, 'dispatcher-capture'),
                meta, records))
            result.append(c03_with_projection(
                p1_channel(round_number, self.selected), projection))
            c1 = qualified_colluder_fixture(
                public,
                cohort_sha256=self.selected['rounds'][round_number - 1][
                    'cohort_sha256'],
                attempt_id=self.selected['rounds'][round_number - 1][
                    'attempt_id'],
                contact_authority=digest(
                    'c1-authority-' + str(round_number)).hex())
            meta = {key: value for key, value in c1.items()
                    if key not in ('original', 'invoices',
                                   'decrypted_receipts', 'retry_history',
                                   'closure')}
            records = ([{'stream': 'original', **c1['original']}]
                       + [{'stream': 'invoice', **row}
                          for row in c1['invoices']]
                       + [{'stream': 'decrypted-receipt', **row}
                          for row in c1['decrypted_receipts']]
                       + [{'stream': 'retry', **row}
                          for row in c1['retry_history']])
            result.append(event_wire(
                self._hello(round_number, 'colluder-wallet-capture'),
                meta, records))
        return result

    def _section(self):
        shared_head = digest('shared-head')
        rounds = []
        for index, raw in enumerate(self.raw_projections):
            lineage = {name: digest(name + '-' + str(index + 1))
                       for name in structural.LINEAGE_FIELDS}
            lineage['projection'] = hashlib.sha256(raw).digest()
            lineage['stream_process'] = self.processes[index * 5 + 1]
            lineage['producer_stream_process'] = lineage['stream_process']
            lineage['stream_child_exit'] = self.exits[index * 5 + 1]
            lineage['producer_stream_child_exit'] = \
                lineage['stream_child_exit']
            if index == 0:
                lineage['successor_head'] = shared_head
            else:
                lineage['accepted_input_head'] = shared_head
            rounds.append({
                'lineage': lineage,
                'structural': structural.structural_projection_evidence(raw),
            })
        preimage = (b'KPB_STRUCTURAL_PROJECTION_CONTINUITY_AUTHORITY_V1\n'
                    + self.binding['wire_bytes'] + bytes((1,)))
        for row in rounds:
            preimage += b''.join(row['lineage'][name]
                                 for name in structural.LINEAGE_FIELDS)
            preimage += row['structural'][
                'structural_projection_identity']
        continuity = hashlib.sha256(preimage + bytes((1, 0))).digest()
        value = bytearray(structural.STRUCTURAL_MAGIC)
        value.extend(struct.pack('<II', 1, structural.STRUCTURAL_BYTES))
        value.extend(bytes((1, 1, 0, 2))); value.extend(continuity)
        for row in rounds:
            value.extend(b''.join(row['lineage'][name]
                                  for name in structural.LINEAGE_FIELDS))
            value.extend(b''.join(row['structural'][name]
                                  for name in structural.STRUCTURAL_DIGEST_FIELDS))
            for name in structural.COUNT_FIELDS:
                value.extend(struct.pack('<I', row['structural'][name]))
            for name in structural.SOMPI_FIELDS:
                value.extend(struct.pack('<Q', row['structural'][name]))
        assert len(value) == structural.STRUCTURAL_BYTES
        return bytes(value)

    def _archive(self):
        value = bytearray(archive.structural.CAPSULE_MAGIC)
        value.extend(struct.pack('<I', 2))
        value.extend(digest('trial-capture')); value.extend(digest('permit'))
        value.extend(self.binding['wire_bytes'])
        value.extend(digest('closure'))
        value.extend(digest('producer-process'))
        value.extend(b''.join(self.entries[5][field]
                              for field in archive.WORKER_FIELDS))
        value.extend(self.binding['source_closure'])
        value.extend(digest('manifest-seal'))
        value.append(2)
        for label in ('classification-receipt', 'producer-child-exit',
                      'producer-receipt', 'producer-identity'):
            value.extend(digest(label))
        value.extend(struct.pack('<III', 10, 10, 0))
        for index, role in enumerate(self.p1_roles):
            value.extend(bytes((index + 1, 23 + 5 * index)))
            for item in (
                    self.binding['financial_runs'][index],
                    self.binding['round_attempts'][index],
                    self.binding['round_cohorts'][index],
                    self.binding['round_capture_plans'][index],
                    self.binding['projections'][index],
                    bytes.fromhex(role['source_sha256']),
                    bytes.fromhex(role['build_sha256']),
                    self.entries[1]['runtime_identity'],
                    bytes.fromhex(role['launch_sha256']),
                    self.processes[index * 5 + 3],
                    self.exits[index * 5 + 3],
                    bytes.fromhex(role['model_preimage_sha256']),
                    bytes.fromhex(role['query_store_preimage_sha256']),
                    bytes.fromhex(role['scalar_capture_manifest_sha256'])):
                value.extend(item)
        for index, public in enumerate(self.publics):
            c1_wire = self.wires[index * 5 + 4]
            # meta is the second event frame
            first_size = int.from_bytes(c1_wire[9:17], 'big')
            second = 17 + first_size
            meta_size = int.from_bytes(c1_wire[second + 9:second + 17], 'big')
            meta = json.loads(c1_wire[second + 17:second + 17 + meta_size])
            contacts = [(1 - (index + 1)) % 3,
                        (1 + (index + 1)) % 3,
                        (1 - (index + 1)) % 3]
            qualified = qualified_colluder_fixture(
                public,
                cohort_sha256=self.selected['rounds'][index][
                    'cohort_sha256'],
                attempt_id=self.selected['rounds'][index]['attempt_id'],
                contact_authority=meta['contact_value_authority_sha256'])
            rows = [qualified['invoices'][0], qualified['original'],
                    qualified['decrypted_receipts'][0]]
            operations = [row['source']['operation_id_sha256'] for row in rows]
            value.extend(bytes((index + 1, 24 + 5 * index)))
            for item in (
                    bytes.fromhex(meta['contact_value_authority_sha256']),
                    self.binding['source_closure'],
                    digest('route-manifest-' + str(index)),
                    digest('route-source-' + str(index)),
                    digest('stage-plan-' + str(index)),
                    self.processes[index * 5 + 4],
                    self.exits[index * 5 + 4]):
                value.extend(item)
            value.extend(b''.join(self.entries[2][field]
                                  for field in archive.WORKER_FIELDS))
            value.extend(bytes(contacts))
            value.extend(b''.join(bytes.fromhex(item) for item in operations))
        assert len(value) == archive.PRE_STRUCTURAL_BYTES
        value.extend(self.section); value.append(10)
        offsets = []
        for slot, wire in enumerate(self.wires):
            round_number, kind = slot // 5 + 1, slot % 5 + 1
            component = archive.KIND_COMPONENTS[kind - 1]
            entry = self.entries[component - 1]
            evidence = (p1_evidence(wire, round_number) if kind == 4 else
                        event_evidence(wire, round_number, kind))
            offsets.append(len(value))
            value.extend(bytes((round_number, kind, 20 + slot, component)))
            for field in archive.LEAF_DIGEST_FIELDS[:4]:
                value.extend(entry[field])
            value.extend(self.processes[slot]); value.extend(self.exits[slot])
            value.extend(bytes((1, 1, 1)))
            value.extend(evidence[0]); value.extend(evidence[1])
            value.extend(evidence[2])
            value.extend(struct.pack('<QQQ', *evidence[3:]))
            assert len(value) - offsets[-1] == archive.LEAF_HEADER_BYTES
            value.extend(wire)
        return bytes(value), offsets


class Fd40ArchiveControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = ArchiveFixture()

    def test_full_archive_is_exact_but_nonauthorizing(self):
        parsed = archive.parse_archive(self.fixture.value)
        self.assertEqual(parsed['schema'],
                         'kpb-fd40-typed-archive-parse/v1')
        self.assertEqual(parsed['leaf_count'], 10)
        self.assertEqual(parsed['projection_bytes'],
                         self.fixture.raw_projections)
        self.assertFalse(parsed['authorizes_coverage'])
        self.assertTrue(parsed['requires_consumed_sealed_fd40'])

    def test_valid_public_state_and_nf_history_filter_remain_nonauthorizing(self):
        fixture = ArchiveFixture(
            valid_public_state=True, repeat_ciphertext=True)
        parsed = archive.parse_archive(fixture.value)
        state = archive.inspect_public_state_transitions(parsed)
        self.assertEqual(state['projection_bindings_checked'], 2)
        self.assertEqual([row['verified_nf_insertions']
                          for row in state['rounds']], [3, 3])
        self.assertEqual([row['verified_cm_appends']
                          for row in state['rounds']], [6, 6])
        self.assertFalse(state['authorizes_coverage'])

        projections = [capture.public_projection(value, public)
                       for value, public in zip(
                           fixture.raw_projections, fixture.publics)]
        terminals = [capture.terminal(raw(terminal_fixture(public)), public)
                     for public in fixture.publics]
        models = [codec.assignments(public, codec.empty_constraints())
                  for public in fixture.publics]
        filtered = capture.inspect_fd40_public_state_candidate_filter(
            parsed, models, terminals)
        self.assertEqual((filtered['workload_candidates_before'],
                          filtered['workload_candidates_after'],
                          filtered['pruned_candidates']),
                         (291600, 291600, 0))
        self.assertTrue(filtered['all_candidates_retained'])
        self.assertEqual(filtered['owner_label_fields_consumed'], 0)
        self.assertFalse(filtered['authorizes_coverage'])
        self.assertFalse(filtered['used_for_coverage'])
        observable = capture.inspect_fd40_public_observable_candidate_filters(
            parsed, models, terminals)
        for name in ('ciphertext_component_equalities',
                     'cv_candidate_residuals'):
            self.assertEqual((observable[name]['workload_candidates_before'],
                              observable[name]['workload_candidates_after'],
                              observable[name]['pruned_candidates']),
                             (291600, 291600, 0))
        self.assertTrue(observable['all_candidates_retained'])
        self.assertEqual(
            observable['observed_owner_label_fields_consumed'], 0)
        self.assertFalse(observable['authorizes_coverage'])
        self.assertFalse(observable['used_for_coverage'])
        self.assertTrue(any(
            artifact['inventory']['same_projection_public_byte_equalities'][
                'ciphertext_hash_pairs']
            for artifact in projections))
        for artifact in projections:
            ledger = {(row['category'], row['field_path']): row['status']
                      for row in artifact['leakage_ledger']}
            self.assertEqual(ledger[('state-transition',
                'state.cm_roots_and_append_paths')], 'unmodeled')
            self.assertEqual(ledger[('state-transition',
                'state.nf_roots_predecessors_successors_and_paths')],
                             'unmodeled')
            self.assertEqual(ledger[('state-transition',
                'state.nf_witness_public_history_edges')], 'unmodeled')
        with self.assertRaisesRegex(
                ValueError,
                'structural-continuity-authenticated-fd40-admission-required'):
            capture.public_projection_pair(
                fixture.raw_projections, fixture.publics, state)

        wrong_binding = copy.deepcopy(parsed)
        wrong_binding['binding']['projections'] = (
            bytes(32), wrong_binding['binding']['projections'][1])
        with self.assertRaisesRegex(
                ValueError, 'public-state-projection-binding'):
            archive.inspect_public_state_transitions(wrong_binding)

        invalid_state = copy.deepcopy(parsed)
        changed = bytearray(invalid_state['projection_bytes'][0])
        changed[193 + 3812 + 72] ^= 1
        changed = bytes(changed)
        invalid_state['projection_bytes'][0] = changed
        invalid_state['public_rounds'][0] = \
            archive._public_from_projection(1, changed)
        invalid_state['binding']['projections'] = (
            hashlib.sha256(changed).digest(),
            invalid_state['binding']['projections'][1])
        invalid_state['typed_leaves'][0]['typed'][
            'projection_bytes'] = changed
        with self.assertRaisesRegex(
                ValueError, 'public-state-nf-predecessor-root'):
            archive.inspect_public_state_transitions(invalid_state)

    def test_qualified_c1_fd40_values_filter_but_do_not_authorize(self):
        fixture = ArchiveFixture(valid_public_state=True)
        parsed = archive.parse_archive(fixture.value)
        legacy = [capture.colluder_wallet(
            raw(colluder_fixture(public)), public)
            for public in fixture.publics]
        models = [codec.assignments(public, artifact['constraints'])
                  for public, artifact in zip(fixture.publics, legacy)]
        terminals = [capture.terminal(raw(terminal_fixture(public)), public)
                     for public in fixture.publics]
        result = capture.inspect_fd40_c1_contact_value_candidate_filter(
            parsed, models, terminals)
        self.assertEqual((result['workload_candidates_before'],
                          result['workload_candidates_after'],
                          result['pruned_candidates']), (144, 36, 108))
        self.assertEqual(result['round_candidates_before'], [12, 12])
        self.assertEqual(result['round_candidates_after'], [6, 6])
        self.assertFalse(result['authorizes_coverage'])
        self.assertFalse(result['used_for_coverage'])

        changed = copy.deepcopy(parsed)
        incoming = next(row for row in changed['typed_leaves'][4][
            'typed']['records'] if row['stream'] == 'decrypted-receipt'
            and row['value']['kind'] == 'incoming-payment')
        incoming['value']['amount_sompi'] += 1
        with self.assertRaisesRegex(
                ValueError, 'fd40-archive-c1-source-binding'):
            capture.inspect_fd40_c1_contact_value_candidate_filter(
                changed, models, terminals)

    def test_multiattempt_history_schema_never_synthesizes_missing_attempts(self):
        raws, _ = valid_continuous_public_state_pair()

        def attempt(sequence, attempt_id, outcome, projection, start):
            return {
                'sequence': sequence,
                'attempt_id': attempt_id,
                'attempt_identity_sha256': hashlib.sha256(
                    b'KPB_CAPTURE_ATTEMPT_ID_V1\n' +
                    attempt_id.encode()).hexdigest(),
                'outcome': outcome,
                'source_event_start': start,
                'source_event_end': start + 2,
                'projection_bytes': projection,
            }

        rounds = []
        for round_number, projection in enumerate(raws, 1):
            first = ('00000000-0000-4000-8000-0000000000' +
                     str(10 + round_number * 2 - 1))
            second = ('00000000-0000-4000-8000-0000000000' +
                      str(10 + round_number * 2))
            rounds.append({
                'round': round_number,
                'attempts': [
                    attempt(0, first, 'PUBLIC_PROJECTION_REFUSED',
                            projection, 0),
                    attempt(1, second, 'TERMINAL_PUBLIC_PROJECTION',
                            projection, 3),
                ],
            })
        value = {
            'schema': archive.MULTIATTEMPT_HISTORY_SCHEMA,
            'trial_sha256': digest('multiattempt-trial').hex(),
            'rounds': rounds,
        }
        inspected = archive.inspect_complete_public_multiattempt_history_input(
            value)
        self.assertEqual([row['attempt_count']
                          for row in inspected['rounds']], [2, 2])
        self.assertEqual([row['comparison_pair_count']
                          for row in inspected['rounds']], [1, 1])
        self.assertGreater(sum(row['equality_edge_count']
                               for row in inspected['rounds']), 0)
        self.assertEqual(inspected['synthetic_attempt_count'], 0)
        self.assertFalse(inspected['complete_history_authority_consumed'])
        self.assertFalse(inspected['authorizes_coverage'])

        # A source that supplies only the terminal attempt stays exactly one
        # attempt. The inspector never invents a retry to close equality rows.
        single = copy.deepcopy(value)
        for row in single['rounds']:
            terminal = row['attempts'][-1]
            terminal['sequence'] = 0
            terminal['source_event_start'] = 0
            terminal['source_event_end'] = 2
            row['attempts'] = [terminal]
        inspected_single = \
            archive.inspect_complete_public_multiattempt_history_input(single)
        self.assertEqual([row['attempt_count']
                          for row in inspected_single['rounds']], [1, 1])
        self.assertEqual([row['comparison_pair_count']
                          for row in inspected_single['rounds']], [0, 0])
        self.assertEqual(inspected_single['equality_edges'], [])
        self.assertEqual(inspected_single['synthetic_attempt_count'], 0)

        missing = copy.deepcopy(value)
        missing['rounds'][0]['attempts'][1]['sequence'] = 2
        with self.assertRaisesRegex(
                ValueError, 'multiattempt-attempt-binding'):
            archive.inspect_complete_public_multiattempt_history_input(missing)
        claimed = copy.deepcopy(value)
        claimed['complete'] = True
        with self.assertRaisesRegex(ValueError, 'multiattempt-history-fields'):
            archive.inspect_complete_public_multiattempt_history_input(claimed)

    def test_archive_mutations_refuse_before_authority(self):
        cases = {}
        cases['truncated'] = self.fixture.value[:-1]
        cases['trailing'] = self.fixture.value + b'x'
        reordered = bytearray(self.fixture.value)
        first = self.fixture.leaf_offsets[0]
        reordered[first] = 2
        cases['reordered'] = bytes(reordered)
        wrong_root = bytearray(self.fixture.value)
        wrong_root[first + 199] ^= 1
        cases['wrong-root'] = bytes(wrong_root)
        wrong_end = bytearray(self.fixture.value)
        wrong_end[first + 231] ^= 1
        cases['wrong-end'] = bytes(wrong_end)
        wrong_eof = bytearray(self.fixture.value)
        wrong_eof[first + 263] ^= 1
        cases['wrong-eof'] = bytes(wrong_eof)
        wrong_metadata = bytearray(self.fixture.value)
        wrong_metadata[first + 4] ^= 1
        cases['wrong-metadata'] = bytes(wrong_metadata)
        duplicate = bytearray(self.fixture.value)
        duplicate[self.fixture.leaf_offsets[1]:
                  self.fixture.leaf_offsets[1] + 4] = duplicate[first:first + 4]
        cases['duplicate'] = bytes(duplicate)
        cross_round = bytearray(self.fixture.value)
        cross_round[archive.STRUCTURAL_BYTES + archive.PRE_STRUCTURAL_BYTES] = 9
        cases['leaf-count'] = bytes(cross_round)
        second_projection = self.fixture.wires[5]
        old_cohort = self.fixture.selected['rounds'][1][
            'cohort_sha256'].encode()
        wrong_cohort = self.fixture.selected['rounds'][0][
            'cohort_sha256'].encode()
        self.assertEqual(len(old_cohort), len(wrong_cohort))
        changed_wire = second_projection.replace(
            old_cohort, wrong_cohort, 1)
        self.assertNotEqual(changed_wire, second_projection)
        cases['cross-round-reclosed'] = self.fixture.replace_leaf_wire(
            5, changed_wire)
        public = self.fixture.publics[0]
        wrong_dispatcher = dispatcher_fixture(
            public,
            cohort_sha256=self.fixture.selected['rounds'][0][
                'cohort_sha256'],
            run_sha256=self.fixture.selected['financial_rounds'][0][
                'financial_run_id'],
            construction_attempt_sha256='ff' * 32,
            capture_plan_sha256=self.fixture.binding[
                'round_capture_plans'][0].hex())
        wrong_meta = {key: value for key, value in wrong_dispatcher.items()
                      if key not in ('events', 'retry_history', 'closure')}
        wrong_records = ([{'stream': 'event', 'value': value}
                          for value in wrong_dispatcher['events']] +
                         [{'stream': 'retry', 'value': value}
                          for value in wrong_dispatcher['retry_history']])
        wrong_dispatcher_wire = event_wire(
            self.fixture._hello(1, 'dispatcher-capture'),
            wrong_meta, wrong_records)
        cases['dispatcher-attempt-cross-binding'] = \
            self.fixture.replace_leaf_wire(2, wrong_dispatcher_wire)
        for name, value in cases.items():
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    archive.parse_archive(value)

    def test_selected_reader_is_fd40_only_sealed_and_one_shot(self):
        # Run in a fresh interpreter because the API intentionally closes 40
        # and remembers the consumed memfd identity for the process lifetime.
        script = r'''
import fcntl, os, sys
import privacy_capture_model as m
import privacy_fd40_archive as a
source = int(sys.argv[1])
size = os.fstat(source).st_size
raw = os.pread(source, size, 0)
fd = os.memfd_create('selected-fd40', os.MFD_ALLOW_SEALING)
os.write(fd, raw)
fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
ro = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY)
os.dup2(ro, 40); fcntl.fcntl(40, fcntl.F_SETFD, 0)
selected = a.read_selected_fd40_typed_capture()
assert type(selected).__name__ == '_SelectedFd40TypedCapture'
try:
    a._consume_selected({'authorizes_coverage': True})
except ValueError:
    pass
else:
    raise SystemExit(4)
try:
    m.consume_selected_fd40_structural_models(selected)
except ValueError as error:
    assert 'selected-fd40-native-structural-authority-required' in str(error)
else:
    raise SystemExit(11)
try:
    m.consume_selected_fd40_structural_models(selected)
except ValueError as error:
    assert 'selected-replay' in str(error)
else:
    raise SystemExit(5)
fd2 = os.memfd_create('selected-fd40-final-gate', os.MFD_ALLOW_SEALING)
os.write(fd2, raw)
fcntl.fcntl(fd2, fcntl.F_ADD_SEALS,
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
ro2 = os.open('/proc/self/fd/' + str(fd2), os.O_RDONLY)
os.dup2(ro2, 40); fcntl.fcntl(40, fcntl.F_SETFD, 0)
selected2 = a.read_selected_fd40_typed_capture()
try:
    m.consume_selected_fd40_private_completion_for_prediction(
        selected2, {'completion_ready': True})
except ValueError as error:
    assert 'selected-fd40-native-structural-authority-required' in str(error)
else:
    raise SystemExit(6)
try:
    m.consume_selected_fd40_structural_models(selected2)
except ValueError:
    pass
else:
    raise SystemExit(7)
'''
        source_fd = os.memfd_create('fd40-test-source', os.MFD_CLOEXEC)
        try:
            at = 0
            while at < len(self.fixture.value):
                amount = os.write(source_fd, self.fixture.value[at:])
                self.assertGreater(amount, 0)
                at += amount
            run = subprocess.run(
                [sys.executable, '-c', script, str(source_fd)],
                pass_fds=(source_fd,),
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                env={**os.environ, 'PYTHONPATH': os.getcwd()}, timeout=30,
                check=False)
        finally:
            os.close(source_fd)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_wrong_fd_and_public_wrappers_cannot_mint_selected_capture(self):
        script = r'''
import fcntl, os, sys
import privacy_fd40_archive as a
import privacy_capture_model as m
source = int(sys.argv[1]); size = os.fstat(source).st_size
raw = os.pread(source, size, 0)
fd = os.memfd_create('wrong-fd41', os.MFD_ALLOW_SEALING)
os.write(fd, raw)
fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
ro = os.open('/proc/self/fd/' + str(fd), os.O_RDONLY)
os.dup2(ro, 41); fcntl.fcntl(41, fcntl.F_SETFD, 0)
try:
    a.read_selected_fd40_typed_capture()
except ValueError:
    pass
else:
    raise SystemExit(7)
unsealed = os.memfd_create('unsealed-fd40', os.MFD_ALLOW_SEALING)
os.write(unsealed, raw)
unsealed_ro = os.open('/proc/self/fd/' + str(unsealed), os.O_RDONLY)
os.dup2(unsealed_ro, 40); fcntl.fcntl(40, fcntl.F_SETFD, 0)
try:
    a.read_selected_fd40_typed_capture()
except ValueError:
    pass
else:
    raise SystemExit(10)
assert not hasattr(a, '_test_only_mint_selected_fd40_typed_capture')
for substitute in ({'authorizes_coverage': True}, raw,
                   {'leaf_count': 10, 'structural': True}):
    try:
        a._consume_selected(substitute)
    except ValueError:
        pass
    else:
        raise SystemExit(8)
forged = object.__new__(a._SelectedFd40TypedCapture)
forged._parsed = a.parse_archive(raw)
forged._fd_identity = (1, 2, len(raw))
forged._live = True
try:
    a._consume_selected(forged)
except ValueError:
    pass
else:
    raise SystemExit(9)

# Exact exploit regression: importing the sentinel and mutable registry can
# manufacture the old nominal selected type, but it must still be unable to
# close either structural row.
forged2 = a._SelectedFd40TypedCapture(
    a._SELECTED_CONSTRUCTOR, a.parse_archive(raw), (3, 4, len(raw)))
a._LIVE_SELECTED_OBJECTS[id(forged2)] = forged2
try:
    m.consume_selected_fd40_structural_models(forged2)
except ValueError as error:
    assert 'selected-fd40-native-structural-authority-required' in str(error)
else:
    raise SystemExit(11)

# The formerly private context sentinel is equally forgeable.  Calling the
# internal projection adapter with it must not produce constraint-modeled rows.
parsed = a.parse_archive(raw)
context = m._SelectedFd40StructuralContext(
    m._SELECTED_STRUCTURAL_CONTEXT_CONSTRUCTOR, 291600, 291600)
try:
    m._public_projection_model(
        parsed['projection_bytes'][0], parsed['public_rounds'][0], context)
except ValueError as error:
    assert 'selected-fd40-native-structural-authority-required' in str(error)
else:
    raise SystemExit(12)
'''
        source_fd = os.memfd_create('fd40-wrong-fd-source', os.MFD_CLOEXEC)
        try:
            os.write(source_fd, self.fixture.value)
            run = subprocess.run(
                [sys.executable, '-c', script, str(source_fd)],
                pass_fds=(source_fd,), stdin=subprocess.DEVNULL,
                capture_output=True, text=True,
                env={**os.environ, 'PYTHONPATH': os.getcwd()}, timeout=30,
                check=False)
        finally:
            os.close(source_fd)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
