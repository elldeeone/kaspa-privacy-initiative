#!/usr/bin/env python3
"""Source-only persistent owner-C1 wallet capture supervisor.

The supervisor is deliberately not a launcher and cannot emit an actual
capture receipt.  A trusted future orchestrator may keep one instance alive
across the genuine invoice, pay and scan workers.  Each worker receives one
private, one-shot Unix seqpacket endpoint mounted only in owner C1's bubblewrap
namespace.  Events are written and fsynced as they are produced; sealing only
orders already-captured records and adds the late public-projection binding.
"""
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time
import uuid


MAGIC = b'KPBCEV01'
TAGS = {'hello': 1, 'meta': 2, 'record': 3, 'end': 5}
FIXED_FD = {1: 24, 2: 29}
STAGES = ('invoice', 'pay', 'scan')
MAX_PACKET_BYTES = 1 << 16
EVENT_FRAME_HEADER_BYTES = 17
NO_RETRY_STAGE_RECORD_COUNTS = (1, 2, 2)
NO_RETRY_FINAL_RECORD_COUNT = 5
NO_RETRY_FINAL_FRAME_COUNT = 8
QUALIFIED_NO_RETRY_RECORD_KINDS = (
    'ORIGINAL', 'ISSUED_INVOICE', 'ACCEPTED_INVOICE',
    'INCOMING_RECEIPT', 'CHANGE_RECEIPT',
)
# Exact maxima under the validated fixed schemas. Runtime uint64 fields are
# charged at their full twenty-decimal-digit encoding. These are evidence
# bounds, not operational caps: every valid fixed-workload row fits.
QUALIFIED_NO_RETRY_RECORD_MAX_BYTES = (1202, 983, 983, 1060, 1059)
QUALIFIED_NO_RETRY_STAGE_MAX_BYTES = (983, 2185, 2119)
QUALIFIED_NO_RETRY_HELLO_BYTES = 364
QUALIFIED_NO_RETRY_META_BYTES = 353
QUALIFIED_NO_RETRY_WIRE_MAX_BYTES = 6140
WHOLE_TRIAL_INVALIDATION_NAME = 'WHOLE-TRIAL-INVALIDATION.json'
SOURCE_FIELDS = (
    'observer_stage', 'stage_sequence', 'operation_id_sha256',
    'contact_owner_component', 'contact_binding_qualified',
    'source_event_sequence', 'observed_monotonic_ns',
)
QUALIFIED_SOURCE_FIELDS = (
    'schema', *SOURCE_FIELDS, 'value_binding_qualified', 'value_kind',
    'value_sha256', 'stage_config_sha256',
    'contact_value_authority_sha256', 'source_event_binding_sha256',
)
QUALIFIED_SOURCE_SCHEMA = \
    'kpb-c1-authenticated-contact-value-source/v1'
QUALIFIED_META_SCHEMA = 'kpb-colluder-wallet-observer-capture/v2'
AUTHORITY_PRECURSOR_SCHEMA = \
    'kpb-c1-contact-value-authority-precursor/v2'
AUTHORITY_ID_DOMAIN = b'KPB_C1_CONTACT_VALUE_AUTHORITY_V1\n'
EVENT_BINDING_DOMAIN = b'KPB_C1_CONTACT_VALUE_EVENT_V1\n'
STAGE_CONFIG_DOMAIN = b'KPB_C1_CONTACT_VALUE_STAGE_CONFIG_V1\n'
STAGE_PLAN_DOMAIN = b'KPB_C1_CONTACT_VALUE_STAGE_PLAN_V1\n'
ROUTE_DOMAIN = b'KPB_C1_AUTHENTICATED_INVOICE_ROUTE_V1\n'
PRODUCER_PRECURSOR_DOMAIN = \
    b'KPB_C1_CONTACT_VALUE_PRODUCER_PRECURSOR_V1\n'
CONTACT_VALUE_OFFER_MAGIC = b'KPBC1OF1'
CONTACT_VALUE_OFFER_FIXED_FD = 31
CONTACT_VALUE_OFFER_BYTES = 646
VALUE_KINDS = frozenset((
    'ORIGINAL', 'ISSUED_INVOICE', 'ACCEPTED_INVOICE',
    'INCOMING_RECEIPT', 'CHANGE_RECEIPT',
))


class CaptureRefused(ValueError):
    """A fail-closed source capture protocol refusal."""


class WholeTrialRetryInvalidated(CaptureRefused):
    """Typed controller signal; retained file is evidence, not authority."""


def need(condition, category):
    if not condition:
        raise CaptureRefused('c1-capture-' + category)


def encoded(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                           allow_nan=False) + '\n').encode()
    except (TypeError, ValueError) as error:
        raise CaptureRefused('c1-capture-json') from error


def _parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PACKET_BYTES,
         'packet-size')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate-json-field')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                CaptureRefused('c1-capture-nonfinite-number')))
    except CaptureRefused:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CaptureRefused('c1-capture-json') from error
    need(encoded(value) == raw, 'canonical-json')
    return value


def _exact(value, fields, category):
    need(type(value) is dict and set(value) == set(fields), category)


def _word(value, category='word'):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         category)
    return value


def _uuid4(value, category='uuid4'):
    try:
        parsed = uuid.UUID(value) if type(value) is str else None
    except (ValueError, AttributeError, TypeError) as error:
        raise CaptureRefused('c1-capture-' + category) from error
    need(parsed is not None and parsed.version == 4 and str(parsed) == value,
         category)
    return value


def _operation(value, category='operation-id'):
    return _uuid4(value, category)


def _positive(value, category='positive-amount'):
    need(type(value) is int and 0 < value < (1 << 64), category)
    return value


def _natural(value, category='natural'):
    need(type(value) is int and 0 <= value < (1 << 64), category)
    return value


def _write_all(fd, raw):
    at = 0
    while at < len(raw):
        try:
            count = os.write(fd, raw[at:])
        except InterruptedError:
            continue
        except OSError as error:
            raise CaptureRefused('c1-capture-final-channel-write') from error
        need(count > 0, 'final-channel-write')
        at += count


def _frame(fd, tag, payload=b''):
    need(tag in TAGS and type(payload) is bytes and len(payload) <= MAX_PACKET_BYTES,
         'final-frame')
    _write_all(fd, MAGIC + bytes([TAGS[tag]])
               + struct.pack('>Q', len(payload)) + payload)


@dataclass(frozen=True)
class RunBinding:
    """Prospective identity; the projection does not exist at this point."""
    round: int
    attempt_id: str
    cohort_sha256: str
    financial_run_id: str
    capture_identity: str

    def __post_init__(self):
        need(type(self.round) is int and self.round in FIXED_FD,
             'binding-round')
        _uuid4(self.attempt_id, 'binding-attempt-id')
        _word(self.cohort_sha256, 'binding-cohort')
        _word(self.financial_run_id, 'binding-financial-run')
        _uuid4(self.capture_identity, 'binding-capture-identity')


def _operation_hashes(operations):
    need(type(operations) in (tuple, list) and len(operations) == 3,
         'contact-value-authority-operations')
    checked = []
    for index, value in enumerate(operations):
        checked.append(_operation(
            value, 'contact-value-authority-operation-' + str(index)))
    need(len(set(checked)) == 3,
         'contact-value-authority-distinct-operations')
    return tuple(checked), [hashlib.sha256(value.encode()).hexdigest()
                            for value in checked]


def _stage_plan_sha256(round_number, operations):
    checked, _ = _operation_hashes(operations)
    value = bytearray(STAGE_PLAN_DOMAIN)
    value.extend((round_number, 1))
    for sequence, operation in enumerate(checked):
        value.extend((sequence, sequence + 1))
        value.extend(operation.encode())
        value.append(1 if sequence == 1 else 0)
        value.extend(checked[0].encode() if sequence == 1 else bytes(36))
    return hashlib.sha256(value).hexdigest()


def _route_manifest_sha256(round_number, contacts, operations,
                           route_source_sha256):
    checked, _ = _operation_hashes(operations)
    need(type(contacts) in (tuple, list) and len(contacts) == 3
         and all(type(contact) is int and 0 <= contact < 3
                 and contact != 1 for contact in contacts)
         and contacts[0] == contacts[2] and contacts[0] != contacts[1],
         'contact-value-offer-route-contacts')
    route_source = bytes.fromhex(_word(
        route_source_sha256, 'contact-value-offer-route-source'))
    value = bytearray(ROUTE_DOMAIN)
    value.extend((round_number, 1))
    value.extend(route_source)
    for sequence, operation in enumerate(checked):
        value.extend((sequence, contacts[sequence]))
        value.extend(operation.encode())
        value.append(1 if sequence == 1 else 0)
        value.extend(checked[0].encode() if sequence == 1 else bytes(36))
    return hashlib.sha256(value).hexdigest()


def _offer_digest(raw, start, category):
    end = start + 32
    need(end <= len(raw), 'contact-value-offer-' + category)
    return raw[start:end].hex(), end


def _offer_ascii(raw, start, size, category):
    end = start + size
    need(end <= len(raw), 'contact-value-offer-' + category)
    try:
        result = raw[start:end].decode('ascii')
    except UnicodeDecodeError as error:
        raise CaptureRefused(
            'c1-capture-contact-value-offer-' + category) from error
    return result, end


def _consume_contact_value_offer(fd, binding):
    """Consume the C++-minted, immutable fixed-FD offer exactly once."""
    need(type(fd) is int and fd == CONTACT_VALUE_OFFER_FIXED_FD,
         'contact-value-offer-fixed-fd')
    need(type(binding) is RunBinding, 'contact-value-offer-binding')
    try:
        state = os.fstat(fd)
        required_seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                          fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        need(stat.S_ISREG(state.st_mode) and state.st_uid == os.geteuid()
             and state.st_mode & 0o077 == 0
             and state.st_size == CONTACT_VALUE_OFFER_BYTES
             and fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required_seals ==
                 required_seals,
             'contact-value-offer-sealed-file')
        raw = os.pread(fd, CONTACT_VALUE_OFFER_BYTES + 1, 0)
        need(len(raw) == CONTACT_VALUE_OFFER_BYTES,
             'contact-value-offer-size')
    except CaptureRefused:
        raise
    except OSError as error:
        raise CaptureRefused('c1-capture-contact-value-offer-read') from error
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    need(raw[:8] == CONTACT_VALUE_OFFER_MAGIC
         and raw[8:14] == bytes((2, binding.round, 1,
                                FIXED_FD[binding.round],
                                CONTACT_VALUE_OFFER_FIXED_FD, 3))
         and raw[17] == 0,
         'contact-value-offer-header')
    contacts = tuple(raw[14:17])
    at = 18
    attempt_id, at = _offer_ascii(raw, at, 36, 'attempt')
    capture_identity, at = _offer_ascii(raw, at, 36, 'capture')
    cohort_sha256, at = _offer_digest(raw, at, 'cohort')
    financial_run_id, at = _offer_digest(raw, at, 'financial-run')
    names = ('source_sha256', 'build_sha256', 'runtime_sha256',
             'assets_sha256', 'pinned_executable_sha256',
             'launcher_sha256', 'route_manifest_sha256',
             'route_source_sha256', 'role_launch_sha256',
             'process_sha256', 'stage_plan_sha256')
    fields = {}
    for name in names:
        fields[name], at = _offer_digest(raw, at, name)
    operations = []
    for index in range(3):
        operation, at = _offer_ascii(
            raw, at, 36, 'operation-' + str(index))
        operations.append(operation)
    authority_identity, at = _offer_digest(raw, at, 'authority')
    need(at == len(raw), 'contact-value-offer-trailing-bytes')
    checked_operations, operation_hashes = _operation_hashes(operations)
    need(attempt_id == binding.attempt_id
         and capture_identity == binding.capture_identity
         and cohort_sha256 == binding.cohort_sha256
         and financial_run_id == binding.financial_run_id,
         'contact-value-offer-run-binding')
    need(fields['stage_plan_sha256'] == _stage_plan_sha256(
             binding.round, checked_operations),
         'contact-value-offer-stage-plan')
    need(fields['route_manifest_sha256'] == _route_manifest_sha256(
             binding.round, contacts, checked_operations,
             fields['route_source_sha256']),
         'contact-value-offer-route-manifest')
    precursor = {
        'schema': 'kpb-c1-contact-value-authority-preimage/v2',
        'round': binding.round,
        'financial_run_id': binding.financial_run_id,
        'attempt_id': binding.attempt_id,
        'cohort_sha256': binding.cohort_sha256,
        'capture_identity': binding.capture_identity,
        'owner_component': 1,
        'fixed_fd': FIXED_FD[binding.round],
        'contact_owner_components': list(contacts),
        **fields,
        'operation_id_sha256': operation_hashes,
    }
    expected = hashlib.sha256(
        AUTHORITY_ID_DOMAIN + encoded(precursor)).hexdigest()
    need(hmac.compare_digest(authority_identity, expected),
         'contact-value-offer-authority-identity')
    return {
        'operations': checked_operations,
        'contacts': contacts,
        'identity': authority_identity,
        'precursor': precursor,
    }


class ContactValueProducerEvidence:
    """One-shot Python evidence; never a model-admission authority.

    Admission also requires the live C++ C1PostcaptureAdmissionAuthority and
    ProducerClosureAuthority. This object alone is deliberately insufficient.
    """

    def __init__(self, value):
        need(type(value) is dict, 'producer-evidence-construction')
        self._value = value
        self._consumed = False

    def consume_for_producer(self):
        need(not self._consumed, 'producer-evidence-replay')
        self._consumed = True
        return json.loads(encoded(self._value))


_CONFIG_FIELDS = (
    'schema', 'capture_identity', 'attempt_id', 'cohort_sha256',
    'financial_run_id', 'round', 'owner_component', 'stage',
    'stage_sequence', 'operation_id', 'target_invoice_operation_id',
    'contact_owner_component', 'fixed_fd',
    'contact_value_authority_sha256', 'token',
)
_CONFIG_SIGNED_FIELDS = tuple(name for name in _CONFIG_FIELDS if name != 'token')


def _validate_worker_config(value):
    _exact(value, _CONFIG_FIELDS, 'worker-config-fields')
    need(value['schema'] == 'kpb-c1-capture-stage/v1',
         'worker-config-schema')
    _uuid4(value['capture_identity'], 'worker-capture-identity')
    _uuid4(value['attempt_id'], 'worker-attempt-id')
    _word(value['cohort_sha256'], 'worker-cohort')
    _word(value['financial_run_id'], 'worker-financial-run')
    need(type(value['round']) is int and value['round'] in FIXED_FD
         and value['owner_component'] == 1
         and value['fixed_fd'] == FIXED_FD[value['round']],
         'worker-owner-round-fd')
    need(value['stage'] in STAGES
         and type(value['stage_sequence']) is int
         and value['stage_sequence'] == STAGES.index(value['stage']),
         'worker-stage')
    _operation(value['operation_id'], 'worker-operation-id')
    target = value['target_invoice_operation_id']
    need((value['stage'] == 'pay' and type(target) is str)
         or (value['stage'] != 'pay' and target is None),
         'worker-target-operation-presence')
    if target is not None:
        _operation(target, 'worker-target-operation-id')
    authority = value['contact_value_authority_sha256']
    need(authority is None or _word(
             authority, 'worker-contact-value-authority'),
         'worker-contact-value-authority')
    contact = value['contact_owner_component']
    if authority is None:
        expected_contact = ((1 + value['round']) % 3
                            if value['stage'] == 'pay'
                            else (1 - value['round']) % 3)
        need(type(contact) is int and contact == expected_contact,
             'worker-contact-binding')
    else:
        need(type(contact) is int and 0 <= contact < 3 and contact != 1,
             'worker-authority-contact-binding')
    _word(value['token'], 'worker-token')
    return value


def _config_mac(secret, config):
    signed = {name: config[name] for name in _CONFIG_SIGNED_FIELDS}
    return hmac.new(secret, encoded(signed), hashlib.sha256).hexdigest()


def _stage_config_sha256(config):
    signed = {name: config[name] for name in _CONFIG_SIGNED_FIELDS}
    return hashlib.sha256(STAGE_CONFIG_DOMAIN + encoded(signed)).hexdigest()


def _operation_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _validate_retry(value):
    _exact(value, ('attempt_id', 'start_monotonic_ns',
                   'complete_monotonic_ns', 'outcome'), 'retry-fields')
    need(type(value['attempt_id']) is str
         and re.fullmatch('[A-Za-z0-9_-]{1,128}', value['attempt_id']),
         'retry-attempt-id')
    start = _natural(value['start_monotonic_ns'], 'retry-start')
    complete = _natural(value['complete_monotonic_ns'], 'retry-complete')
    need(complete >= start and value['outcome'] in
         ('refused', 'disconnected', 'completed'), 'retry-outcome')


def _validate_original(value):
    _exact(value, ('input_nf_hex32', 'input_amount_sompi',
                   'created_outputs'), 'original-fields')
    _word(value['input_nf_hex32'], 'original-nf')
    _positive(value['input_amount_sompi'], 'original-input-amount')
    outputs = value['created_outputs']
    need(type(outputs) is list and len(outputs) == 2,
         'original-two-outputs')
    for row, kind in zip(outputs, ('outgoing-payment', 'change')):
        _exact(row, ('kind', 'tuple_sha256', 'amount_sompi'),
               'original-output-fields')
        need(row['kind'] == kind, 'original-output-order')
        _word(row['tuple_sha256'], 'original-output-tuple')
        _positive(row['amount_sompi'], 'original-output-amount')
    need(outputs[0]['tuple_sha256'] != outputs[1]['tuple_sha256'],
         'original-distinct-outputs')


def _validate_invoice(value, binding, stage, operation_id,
                      target_invoice_operation_id, contact_owner_component):
    _exact(value, ('direction', 'source_owner_component',
                   'target_owner_component', 'operation_id_sha256',
                   'amount_sompi'), 'invoice-fields')
    if stage == 'invoice':
        expected = ('issued', contact_owner_component, 1,
                    _operation_hash(operation_id))
    else:
        expected = ('accepted', 1, contact_owner_component,
                    _operation_hash(target_invoice_operation_id))
    need((value['direction'], value['source_owner_component'],
          value['target_owner_component'], value['operation_id_sha256'])
         == expected, 'invoice-binding')
    expected_amount = 500_000_000 if binding.round == 1 else 200_000_000
    need(value['amount_sompi'] == expected_amount,
         'invoice-frozen-workload-amount')


def _validate_receipt(value, binding, ordinal, contact_owner_component):
    _exact(value, ('kind', 'receipt_index', 'creator_owner_component',
                   'tuple_sha256', 'cm_hex32', 'amount_sompi'),
           'receipt-fields')
    expected = (
        ('incoming-payment', 2 * binding.round - 1,
         contact_owner_component),
        ('change', 2 * binding.round, 1),
    )[ordinal]
    need((value['kind'], value['receipt_index'],
          value['creator_owner_component']) == expected,
         'receipt-binding')
    _word(value['tuple_sha256'], 'receipt-tuple')
    _word(value['cm_hex32'], 'receipt-cm')
    _positive(value['amount_sompi'], 'receipt-amount')


def _qualified_value_kind(stream, value):
    need(type(value) is dict, 'qualified-value-body')
    if stream == 'original':
        return 'ORIGINAL'
    if stream == 'invoice':
        result = {
            'issued': 'ISSUED_INVOICE',
            'accepted': 'ACCEPTED_INVOICE',
        }.get(value.get('direction'))
    elif stream == 'decrypted-receipt':
        result = {
            'incoming-payment': 'INCOMING_RECEIPT',
            'change': 'CHANGE_RECEIPT',
        }.get(value.get('kind'))
    else:
        result = None
    need(result in VALUE_KINDS, 'qualified-value-kind')
    return result


def qualified_source_event_sha256(stream, value, source):
    """Recompute the canonical qualified-row binding from typed fields."""
    _exact(source, QUALIFIED_SOURCE_FIELDS, 'qualified-source-fields')
    need(source['schema'] == QUALIFIED_SOURCE_SCHEMA
         and source['contact_binding_qualified'] is True
         and source['value_binding_qualified'] is True
         and source['value_kind'] == _qualified_value_kind(stream, value)
         and source['value_sha256'] ==
             hashlib.sha256(encoded(value)).hexdigest(),
         'qualified-source-value-binding')
    for name in (
            'operation_id_sha256', 'value_sha256', 'stage_config_sha256',
            'contact_value_authority_sha256'):
        _word(source[name], 'qualified-source-' + name)
    preimage = {
        'schema': 'kpb-c1-contact-value-event-binding/v1',
        'contact_value_authority_sha256':
            source['contact_value_authority_sha256'],
        'stage_config_sha256': source['stage_config_sha256'],
        'observer_stage': source['observer_stage'],
        'stage_sequence': source['stage_sequence'],
        'operation_id_sha256': source['operation_id_sha256'],
        'contact_owner_component': source['contact_owner_component'],
        'source_event_sequence': source['source_event_sequence'],
        'observed_monotonic_ns': source['observed_monotonic_ns'],
        'stream': stream,
        'value_kind': source['value_kind'],
        'value_sha256': source['value_sha256'],
    }
    return hashlib.sha256(
        EVENT_BINDING_DOMAIN + encoded(preimage)).hexdigest()


class _StageServer:
    def __init__(self, supervisor, stage, sequence, operation_id,
                 target_invoice_operation_id, config):
        self.supervisor = supervisor
        self.stage = stage
        self.sequence = sequence
        self.operation_id = operation_id
        self.target_invoice_operation_id = target_invoice_operation_id
        self.config = config
        self.socket_path = supervisor.channel_dir / 'events.sock'
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.listener.bind(str(self.socket_path))
        os.chmod(self.socket_path, 0o600)
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.connection = None
        self.done = threading.Event()
        self.aborted = threading.Event()
        self.error = None
        self.records = None
        self.committed = False
        self.thread = threading.Thread(
            target=self._serve,
            name='c1-capture-' + stage,
            daemon=True,
        )
        self.thread.start()

    def _send(self, value):
        raw = encoded(value)
        need(len(raw) <= MAX_PACKET_BYTES, 'response-packet-size')
        self.connection.sendall(raw)

    def _receive(self):
        raw = self.connection.recv(MAX_PACKET_BYTES + 1)
        need(raw != b'', 'worker-crash-or-truncated-stage')
        return _parse(raw)

    def _validate_event(self, message, core_index):
        _exact(message, ('schema', 'type', 'event_sequence', 'stream',
                         'value'), 'event-message-fields')
        need(message['schema'] == 'kpb-c1-capture-stage-message/v1'
             and message['type'] == 'event'
             and type(message['event_sequence']) is int,
             'event-message')
        stream, value = message['stream'], message['value']
        expected = {
            'invoice': ('invoice',),
            'pay': ('invoice', 'original'),
            'scan': ('decrypted-receipt', 'decrypted-receipt'),
        }[self.stage]
        need(core_index < len(expected) and stream == expected[core_index],
             'stage-event-order')
        if self.stage == 'invoice':
            _validate_invoice(value, self.supervisor.binding, self.stage,
                              self.operation_id, None,
                              self.config['contact_owner_component'])
        elif self.stage == 'pay' and core_index == 0:
            _validate_invoice(value, self.supervisor.binding, self.stage,
                              self.operation_id,
                              self.target_invoice_operation_id,
                              self.config['contact_owner_component'])
        elif self.stage == 'pay':
            _validate_original(value)
        else:
            _validate_receipt(value, self.supervisor.binding, core_index,
                              self.config['contact_owner_component'])
        return core_index + 1

    def _source(self, stream, value, event_sequence, observed_monotonic_ns):
        """Trusted envelope: no field is accepted from the worker packet."""
        result = {
            'observer_stage': self.stage,
            'stage_sequence': self.sequence,
            'operation_id_sha256': _operation_hash(self.operation_id),
            'contact_owner_component':
                self.config['contact_owner_component'],
            'source_event_sequence': event_sequence,
            'observed_monotonic_ns': observed_monotonic_ns,
        }
        authority = self.config['contact_value_authority_sha256']
        if authority is None:
            # Legacy caller-supplied contact instruction. It remains explicitly
            # unqualified and is handled by the legacy model adapter only.
            result['contact_binding_qualified'] = False
            return result
        result.update({
            'schema': QUALIFIED_SOURCE_SCHEMA,
            'contact_binding_qualified': True,
            'value_binding_qualified': True,
            'value_kind': _qualified_value_kind(stream, value),
            'value_sha256': hashlib.sha256(encoded(value)).hexdigest(),
            'stage_config_sha256': _stage_config_sha256(self.config),
            'contact_value_authority_sha256': authority,
            'source_event_binding_sha256': '',
        })
        result['source_event_binding_sha256'] = \
            qualified_source_event_sha256(stream, value, result)
        return result

    def _serve(self):
        partial = self.supervisor.spool_dir / (
            f'{self.sequence}-{self.stage}.partial.jsonl')
        committed = self.supervisor.spool_dir / (
            f'{self.sequence}-{self.stage}.committed.jsonl')
        records = []
        try:
            while not self.aborted.is_set():
                try:
                    self.connection, _ = self.listener.accept()
                    break
                except TimeoutError:
                    continue
            need(not self.aborted.is_set() and self.connection is not None,
                 'worker-stage-aborted')
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
            credentials = self.connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _, uid, _ = struct.unpack('3i', credentials)
            need(uid == self.supervisor.expected_uid, 'wrong-peer-uid')
            hello = self._receive()
            _exact(hello, ('schema', 'type', 'config'),
                   'hello-fields')
            need(hello['schema'] == 'kpb-c1-capture-stage-message/v1'
                 and hello['type'] == 'hello'
                 and hello['config'] == self.config,
                 'stage-session-hello')
            _validate_worker_config(hello['config'])
            need(hmac.compare_digest(hello['config']['token'],
                                     _config_mac(self.supervisor.secret,
                                                 hello['config'])),
                 'stage-token')
            self._send({'schema': 'kpb-c1-capture-stage-ack/v1',
                        'status': 'ready', 'next_event_sequence': 0})
            core_index = 0
            event_sequence = 0
            with partial.open('xb', buffering=0) as spool:
                os.chmod(partial, 0o600)
                while True:
                    message = self._receive()
                    observed_monotonic_ns = _positive(
                        time.monotonic_ns(), 'observed-monotonic-ns')
                    if (type(message) is dict
                            and message.get('stream') == 'retry'):
                        self.supervisor._invalidate_whole_trial_for_retry(
                            self.stage, self.sequence, self.operation_id,
                            event_sequence, observed_monotonic_ns, message)
                    if message.get('type') == 'commit':
                        _exact(message, ('schema', 'type', 'event_count'),
                               'commit-fields')
                        need(message['schema'] ==
                             'kpb-c1-capture-stage-message/v1'
                             and message['event_count'] == event_sequence,
                             'commit-count')
                        required = {'invoice': 1, 'pay': 2, 'scan': 2}[
                            self.stage]
                        need(core_index == required
                             and len(records) ==
                                 NO_RETRY_STAGE_RECORD_COUNTS[self.sequence]
                             and sum(len(encoded(record))
                                     for record in records) <=
                                 QUALIFIED_NO_RETRY_STAGE_MAX_BYTES[
                                     self.sequence],
                             'no-retry-stage-schedule')
                        os.fsync(spool.fileno())
                        break
                    need(message.get('event_sequence') == event_sequence,
                         'event-sequence')
                    core_index = self._validate_event(message, core_index)
                    record = {'stream': message['stream'],
                              'source': self._source(
                                  message['stream'], message['value'],
                                  event_sequence,
                                  observed_monotonic_ns),
                              'value': message['value']}
                    raw = encoded(record)
                    kind = _qualified_value_kind(
                        message['stream'], message['value'])
                    maximum = dict(zip(
                        QUALIFIED_NO_RETRY_RECORD_KINDS,
                        QUALIFIED_NO_RETRY_RECORD_MAX_BYTES))[kind]
                    need(len(raw) <= maximum,
                         'no-retry-record-source-bound')
                    spool.write(raw)
                    os.fsync(spool.fileno())
                    records.append(record)
                    event_sequence += 1
                    self._send({
                        'schema': 'kpb-c1-capture-stage-ack/v1',
                        'status': 'recorded',
                        'next_event_sequence': event_sequence,
                    })
            os.replace(partial, committed)
            directory = os.open(self.supervisor.spool_dir,
                                os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            self.records = records
            self.committed = True
            self._send({'schema': 'kpb-c1-capture-stage-ack/v1',
                        'status': 'committed',
                        'event_count': len(records)})
        except BaseException as error:
            self.error = error
            self.supervisor._poison('stage-refused')
        finally:
            if self.connection is not None:
                try:
                    self.connection.close()
                except OSError:
                    pass
            try:
                self.listener.close()
            except OSError:
                pass
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
            self.done.set()

    def abort(self):
        self.aborted.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class StageGrant:
    """One in-memory controller grant; it is not a serializable authority."""
    def __init__(self, supervisor, server):
        self._supervisor = supervisor
        self._server = server
        self._finished = False

    @property
    def worker_config(self):
        return dict(self._server.config)

    @property
    def mount_source(self):
        return self._supervisor.channel_dir

    def finish(self, worker_returncode):
        need(not self._finished, 'stage-grant-replay')
        self._finished = True
        need(type(worker_returncode) is int, 'worker-returncode')
        # The worker process is already gone when the controller calls finish.
        # A successful worker that never committed must not leave accept()
        # waiting forever or permit a late replacement worker.
        missing_commit = not self._server.committed
        if worker_returncode != 0 or missing_commit:
            self._server.abort()
            self._supervisor._poison('worker-crash' if worker_returncode != 0
                                     else 'worker-missing-stage')
        self._server.done.wait()
        # A recorded retry is the stronger disposition: the worker normally
        # exits nonzero after its socket is closed, but the controller must
        # still receive the typed whole-trial invalidation signal.
        if isinstance(self._server.error, WholeTrialRetryInvalidated):
            raise self._server.error
        if worker_returncode != 0:
            raise CaptureRefused('c1-capture-worker-crash')
        if self._server.error is not None:
            if isinstance(self._server.error, CaptureRefused):
                raise self._server.error
            raise CaptureRefused('c1-capture-stage-server') from self._server.error
        need(self._server.committed, 'stage-not-committed')
        self._supervisor._accept_stage(self._server,
                                       self._server.records)


class StageEmitter:
    """C1 worker-side direct event emitter."""
    def __init__(self, worker_config, capture_root=Path('/capture')):
        self.config = _validate_worker_config(dict(worker_config))
        root = Path(capture_root)
        self.connection = socket.socket(socket.AF_UNIX,
                                        socket.SOCK_SEQPACKET)
        try:
            self.connection.connect(str(root / 'events.sock'))
            self._send({'schema': 'kpb-c1-capture-stage-message/v1',
                        'type': 'hello', 'config': self.config})
            ready = self._receive()
            need(ready == {
                'schema': 'kpb-c1-capture-stage-ack/v1',
                'status': 'ready', 'next_event_sequence': 0,
            }, 'stage-ready-ack')
        except BaseException:
            self.connection.close()
            raise
        self.event_sequence = 0
        self.closed = False

    def _send(self, value):
        raw = encoded(value)
        need(len(raw) <= MAX_PACKET_BYTES, 'worker-packet-size')
        try:
            self.connection.sendall(raw)
        except OSError as error:
            raise CaptureRefused('c1-capture-stage-send') from error

    def _receive(self):
        try:
            raw = self.connection.recv(MAX_PACKET_BYTES + 1)
        except OSError as error:
            raise CaptureRefused('c1-capture-stage-receive') from error
        need(raw != b'', 'stage-server-refused')
        return _parse(raw)

    def _event(self, stream, value):
        need(not self.closed, 'event-after-commit')
        try:
            self._send({
                'schema': 'kpb-c1-capture-stage-message/v1',
                'type': 'event',
                'event_sequence': self.event_sequence,
                'stream': stream,
                'value': value,
            })
            self.event_sequence += 1
            need(self._receive() == {
                'schema': 'kpb-c1-capture-stage-ack/v1',
                'status': 'recorded',
                'next_event_sequence': self.event_sequence,
            }, 'recorded-ack')
        except BaseException:
            self.connection.close()
            self.closed = True
            raise

    def issued_invoice(self, amount_sompi):
        need(self.config['stage'] == 'invoice', 'issued-invoice-stage')
        self._event('invoice', {
            'direction': 'issued',
            'source_owner_component':
                self.config['contact_owner_component'],
            'target_owner_component': 1,
            'operation_id_sha256': _operation_hash(
                self.config['operation_id']),
            'amount_sompi': amount_sompi,
        })

    def accepted_invoice(self, amount_sompi):
        need(self.config['stage'] == 'pay', 'accepted-invoice-stage')
        self._event('invoice', {
            'direction': 'accepted',
            'source_owner_component': 1,
            'target_owner_component':
                self.config['contact_owner_component'],
            'operation_id_sha256': _operation_hash(
                self.config['target_invoice_operation_id']),
            'amount_sompi': amount_sompi,
        })

    def original(self, input_nf, input_amount_sompi, outgoing_tuple,
                 outgoing_amount_sompi, change_tuple, change_amount_sompi):
        need(self.config['stage'] == 'pay', 'original-stage')
        need(all(type(value) is bytes and len(value) > 0 for value in
                 (input_nf, outgoing_tuple, change_tuple)),
             'original-direct-bytes')
        need(len(input_nf) == 32, 'original-nf-bytes')
        self._event('original', {
            'input_nf_hex32': input_nf.hex(),
            'input_amount_sompi': input_amount_sompi,
            'created_outputs': [
                {'kind': 'outgoing-payment',
                 'tuple_sha256': hashlib.sha256(outgoing_tuple).hexdigest(),
                 'amount_sompi': outgoing_amount_sompi},
                {'kind': 'change',
                 'tuple_sha256': hashlib.sha256(change_tuple).hexdigest(),
                 'amount_sompi': change_amount_sompi},
            ],
        })

    def decrypted_receipt(self, kind, receipt_index, tuple_bytes, cm,
                          amount_sompi):
        need(self.config['stage'] == 'scan', 'receipt-stage')
        need(type(tuple_bytes) is bytes and len(tuple_bytes) > 0
             and type(cm) is bytes and len(cm) == 32,
             'receipt-direct-bytes')
        self._event('decrypted-receipt', {
            'kind': kind,
            'receipt_index': receipt_index,
            'creator_owner_component': (1 if kind == 'change' else
                                        self.config[
                                            'contact_owner_component']),
            'tuple_sha256': hashlib.sha256(tuple_bytes).hexdigest(),
            'cm_hex32': cm.hex(),
            'amount_sompi': amount_sompi,
        })

    def retry(self, attempt_id, start_monotonic_ns,
              complete_monotonic_ns, outcome):
        self._event('retry', {
            'attempt_id': attempt_id,
            'start_monotonic_ns': start_monotonic_ns,
            'complete_monotonic_ns': complete_monotonic_ns,
            'outcome': outcome,
        })

    def commit(self):
        need(not self.closed, 'duplicate-stage-commit')
        try:
            self._send({'schema': 'kpb-c1-capture-stage-message/v1',
                        'type': 'commit',
                        'event_count': self.event_sequence})
            response = self._receive()
            need(response == {
                'schema': 'kpb-c1-capture-stage-ack/v1',
                'status': 'committed',
                'event_count': self.event_sequence,
            }, 'stage-commit-ack')
        finally:
            self.connection.close()
            self.closed = True


def controller_stage(grant, owner_component, operation_name, operation_id,
                     target_invoice_operation_id):
    """Return the only permitted controller config/mount for a stage.

    The caller must add the returned dictionary only to the selected worker's
    private CONFIG.json.  Owners 0 and 2 never receive either the capability or
    the socket directory.
    """
    _operation(operation_id, 'controller-operation-id')
    if grant is None:
        return {}, []
    need(type(grant) is StageGrant and owner_component == 1,
         'only-owner-c1')
    config = grant.worker_config
    need(operation_name in STAGES
         and config['stage'] == operation_name
         and config['operation_id'] == operation_id
         and config['target_invoice_operation_id'] ==
             target_invoice_operation_id,
         'controller-operation-binding')
    need(grant.mount_source.is_dir()
         and (grant.mount_source / 'events.sock').exists(),
         'controller-live-stage-endpoint')
    return ({'c1_capture': config},
            ['--ro-bind', str(grant.mount_source), '/capture'])


class C1CaptureSupervisor:
    """Persistent source-only state machine for exactly one financial round."""
    def __init__(self, private_root, binding, expected_uid=None,
                 contact_value_offer_fd=None):
        need(type(binding) is RunBinding, 'run-binding-type')
        self.binding = binding
        if contact_value_offer_fd is None:
            self._contact_value = None
        else:
            self._contact_value = _consume_contact_value_offer(
                contact_value_offer_fd, binding)
        self.root = Path(private_root)
        need(not self.root.exists(), 'fresh-private-root')
        self.root.mkdir(mode=0o700)
        self.channel_dir = self.root / 'channel'
        self.spool_dir = self.root / 'spool'
        self.channel_dir.mkdir(mode=0o700)
        self.spool_dir.mkdir(mode=0o700)
        self.secret = os.urandom(32)
        self.expected_uid = os.getuid() if expected_uid is None else expected_uid
        need(type(self.expected_uid) is int and self.expected_uid >= 0,
             'expected-uid')
        self._lock = threading.Lock()
        self._active = None
        self._committed = []
        self._stage_operations = {}
        self._stage_contacts = {}
        self._poisoned = None
        self._sealed = False
        self._producer_authority = None
        self._producer_authority_taken = False
        binding_path = self.root / 'RUN-BINDING.json'
        with binding_path.open('xb') as output:
            os.chmod(binding_path, 0o600)
            output.write(encoded({
                'schema': 'kpb-c1-prospective-run-binding/v1',
                **asdict(binding),
                'owner_component': 1,
                'status': 'CONFIGURED0',
                'launch_authorized': False,
                'actual_receipt_emitted': False,
                'contact_binding_qualified':
                    self._contact_value is not None,
                'value_binding_qualified': self._contact_value is not None,
            }))
            output.flush()
            os.fsync(output.fileno())

    def _poison(self, category):
        with self._lock:
            if self._poisoned is None:
                self._poisoned = category

    def _healthy(self):
        need(self._poisoned is None and not self._sealed,
             'session-poisoned-or-sealed')

    def _invalidate_whole_trial_for_retry(
            self, stage, stage_sequence, operation_id, event_sequence,
            observed_monotonic_ns, message):
        """Durably retain retry evidence, poison this trial, and stop.

        This private file is deliberately not a Python authority. A future
        complete native parent bridge must authenticate and append it to the
        registered failed-trial history before any cross-process claim.
        """
        retry_fields = {
            'schema', 'type', 'event_sequence', 'stream', 'value',
        }
        envelope_valid = (
            type(message) is dict and set(message) == retry_fields
            and message.get('schema') ==
                'kpb-c1-capture-stage-message/v1'
            and message.get('type') == 'event'
            and type(message.get('event_sequence')) is int
            and message.get('event_sequence') == event_sequence
            and message.get('stream') == 'retry')
        value = message.get('value') if type(message) is dict else None
        retry_body_valid = True
        try:
            _validate_retry(value)
        except CaptureRefused:
            retry_body_valid = False
        _positive(observed_monotonic_ns, 'retry-observed-monotonic-ns')
        need(stage in STAGES and stage_sequence == STAGES.index(stage),
             'retry-stage-binding')
        _operation(operation_id, 'retry-operation-binding')
        need(type(event_sequence) is int and event_sequence >= 0,
             'retry-event-sequence')
        evidence = {
            'schema': 'kpb-c1-whole-trial-retry-invalidation/v1',
            'disposition': 'FRESH_TRIAL_REQUIRED',
            'binding': asdict(self.binding),
            'owner_component': 1,
            'stage': stage,
            'stage_sequence': stage_sequence,
            'operation_id_sha256': _operation_hash(operation_id),
            'source_event_sequence': event_sequence,
            'observed_monotonic_ns': observed_monotonic_ns,
            'retry': value,
            'retry_message': message,
            'retry_envelope_valid': envelope_valid,
            'retry_claimed_event_sequence': (
                message.get('event_sequence')
                if type(message) is dict else None),
            'retry_body_valid': retry_body_valid,
            'evidence_scope': 'PRIVATE_TRIAL_HISTORY_ONLY',
            'outer_history_joined': False,
        }
        if self._contact_value is not None:
            evidence['contact_value_authority_sha256'] = \
                self._contact_value['identity']
        raw = encoded(evidence)
        partial = self.root / (WHOLE_TRIAL_INVALIDATION_NAME + '.partial')
        final = self.root / WHOLE_TRIAL_INVALIDATION_NAME
        need(not final.exists(), 'retry-invalidation-replay')
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(partial, flags, 0o600)
            try:
                os.fchmod(fd, 0o600)
                at = 0
                while at < len(raw):
                    try:
                        count = os.write(fd, raw[at:])
                    except InterruptedError:
                        continue
                    need(count > 0, 'retry-invalidation-write')
                    at += count
                os.fsync(fd)
            finally:
                os.close(fd)
            # Hard-link then unlink is the portable create-new publication
            # sequence here: it never replaces prior trial evidence.
            os.link(partial, final, follow_symlinks=False)
            os.unlink(partial)
            directory = os.open(
                self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except CaptureRefused:
            raise
        except OSError as error:
            raise CaptureRefused(
                'c1-capture-retry-invalidation-write') from error
        self._poison('whole-trial-retry')
        raise WholeTrialRetryInvalidated(
            'c1-capture-whole-trial-retry')

    def open_stage(self, stage, operation_id=None,
                   target_invoice_operation_id=None,
                   contact_owner_component=None):
        with self._lock:
            self._healthy()
            need(self._active is None, 'stage-already-active')
            sequence = len(self._committed)
            need(sequence < len(STAGES) and stage == STAGES[sequence],
                 'stage-order')
            if self._contact_value is None:
                _operation(operation_id)
            else:
                need(operation_id is None,
                     'qualified-operation-from-authority')
                operation_id = self._contact_value['operations'][sequence]
            if stage == 'pay':
                if self._contact_value is None:
                    _operation(target_invoice_operation_id,
                               'target-invoice-operation-id')
                else:
                    need(target_invoice_operation_id is None,
                         'qualified-target-operation-from-authority')
                    target_invoice_operation_id = \
                        self._contact_value['operations'][0]
                need(self._stage_operations.get('invoice') ==
                     target_invoice_operation_id,
                     'target-invoice-operation-binding')
            else:
                need(target_invoice_operation_id is None,
                     'unexpected-target-invoice-operation')
            if stage in ('invoice', 'pay'):
                # This is a prospective C1-visible contact instruction, not a
                # creator label recovered from public history or ciphertext.
                # The benchmark schedule constrains which contact may be
                # selected; the HMAC capability then carries that committed
                # contact into receipt capture without accepting a scan-time
                # caller label.
                if self._contact_value is None:
                    expected_contact = ((1 - self.binding.round) % 3
                                        if stage == 'invoice' else
                                        (1 + self.binding.round) % 3)
                    need(type(contact_owner_component) is int
                         and contact_owner_component == expected_contact,
                         'prospective-contact-binding')
                else:
                    need(contact_owner_component is None,
                         'qualified-contact-from-authority')
                    contact_owner_component = \
                        self._contact_value['contacts'][sequence]
            else:
                need(contact_owner_component is None
                     and self._stage_contacts.get('invoice') is not None,
                     'scan-contact-from-committed-invoice')
                contact_owner_component = (
                    self._stage_contacts['invoice']
                    if self._contact_value is None else
                    self._contact_value['contacts'][sequence])
                if self._contact_value is not None:
                    need(contact_owner_component ==
                         self._stage_contacts['invoice'],
                         'qualified-scan-route-binding')
            config = {
                'schema': 'kpb-c1-capture-stage/v1',
                'capture_identity': self.binding.capture_identity,
                'attempt_id': self.binding.attempt_id,
                'cohort_sha256': self.binding.cohort_sha256,
                'financial_run_id': self.binding.financial_run_id,
                'round': self.binding.round,
                'owner_component': 1,
                'stage': stage,
                'stage_sequence': sequence,
                'operation_id': operation_id,
                'target_invoice_operation_id':
                    target_invoice_operation_id,
                'contact_owner_component': contact_owner_component,
                'fixed_fd': FIXED_FD[self.binding.round],
                'contact_value_authority_sha256': (
                    None if self._contact_value is None else
                    self._contact_value['identity']),
                'token': '',
            }
            config['token'] = _config_mac(self.secret, config)
            server = _StageServer(self, stage, sequence, operation_id,
                                  target_invoice_operation_id, config)
            self._active = server
            self._stage_operations[stage] = operation_id
            self._stage_contacts[stage] = contact_owner_component
            return StageGrant(self, server)

    def _accept_stage(self, server, records):
        with self._lock:
            self._healthy()
            need(server is self._active
                 and server.sequence == len(self._committed),
                 'stage-accept-order')
            self._committed.append((server.stage, list(records)))
            self._active = None

    def _ordered_records(self):
        stage_records = {stage: records for stage, records in self._committed}
        need(tuple(len(stage_records[stage]) for stage in STAGES) ==
             NO_RETRY_STAGE_RECORD_COUNTS,
             'no-retry-stage-record-counts')
        invoice = stage_records['invoice']
        pay = stage_records['pay']
        scan = stage_records['scan']
        # Pay arrives as accepted invoice then Original.  Output order follows
        # the already-frozen producer/model contract without reconstructing a
        # record body.
        result = [pay[1], invoice[0], pay[0], scan[0], scan[1]]
        kinds = tuple(_qualified_value_kind(
            row['stream'], row['value']) for row in result)
        need(kinds == QUALIFIED_NO_RETRY_RECORD_KINDS,
             'no-retry-final-record-order')
        return result

    def _validate_cross_stage(self, records):
        original, issued, accepted, incoming, change = (
            row['value'] for row in records[:5])
        need(issued['amount_sompi'] == incoming['amount_sompi']
             and accepted['amount_sompi'] ==
                 original['created_outputs'][0]['amount_sompi']
             and change['amount_sompi'] ==
                 original['created_outputs'][1]['amount_sompi']
             and change['tuple_sha256'] ==
                 original['created_outputs'][1]['tuple_sha256']
             and incoming['tuple_sha256'] not in {
                 row['tuple_sha256'] for row in
                 original['created_outputs']},
             'cross-stage-consistency')

    def seal(self, fd, projection_sha256):
        try:
            with self._lock:
                self._healthy()
                need(self._active is None
                     and [stage for stage, _ in self._committed] ==
                         list(STAGES),
                     'missing-stage')
                need(type(fd) is int and fd == FIXED_FD[self.binding.round],
                     'wrong-fixed-fd')
                _word(projection_sha256, 'projection-seal')
                records = self._ordered_records()
                need(len(records) == NO_RETRY_FINAL_RECORD_COUNT,
                     'no-retry-final-record-count')
                self._validate_cross_stage(records)
                hello = {
                    'schema': 'kpb-capture-event-channel/v1',
                    'round': self.binding.round,
                    'kind': 'colluder-wallet-capture',
                    'attempt_id': self.binding.attempt_id,
                    'cohort_sha256': self.binding.cohort_sha256,
                    'financial_run_id': self.binding.financial_run_id,
                    'capture_identity': self.binding.capture_identity,
                }
                meta = {
                    'schema': (
                        'kpb-colluder-wallet-observer-capture/v1'
                        if self._contact_value is None else
                        QUALIFIED_META_SCHEMA),
                    'round': self.binding.round,
                    'projection_sha256': projection_sha256,
                    'cohort_sha256': self.binding.cohort_sha256,
                    'owner_component': 1,
                }
                if self._contact_value is not None:
                    meta['contact_value_authority_sha256'] = \
                        self._contact_value['identity']
                hello_raw = encoded(hello)
                meta_raw = encoded(meta)
                record_raw = [encoded(record) for record in records]
                if self._contact_value is not None:
                    need(len(hello_raw) == QUALIFIED_NO_RETRY_HELLO_BYTES
                         and len(meta_raw) == QUALIFIED_NO_RETRY_META_BYTES,
                         'qualified-no-retry-envelope-size')
                need(all(len(raw) <= maximum for raw, maximum in zip(
                         record_raw,
                         QUALIFIED_NO_RETRY_RECORD_MAX_BYTES)),
                     'qualified-no-retry-record-size')
                final_wire_bytes = (
                    EVENT_FRAME_HEADER_BYTES + len(hello_raw) +
                    EVENT_FRAME_HEADER_BYTES + len(meta_raw) +
                    sum(EVENT_FRAME_HEADER_BYTES + len(raw)
                        for raw in record_raw) +
                    EVENT_FRAME_HEADER_BYTES)
                need(NO_RETRY_FINAL_FRAME_COUNT ==
                         2 + len(record_raw) + 1
                     and final_wire_bytes <=
                         QUALIFIED_NO_RETRY_WIRE_MAX_BYTES,
                     'qualified-no-retry-wire-size')
                precursor = None
                if self._contact_value is not None:
                    # Each qualified row is checked before any final-channel
                    # byte is emitted. Stage-config identities are taken only
                    # from those already-captured, bound rows.
                    by_stage = {}
                    for row in records:
                        source = row['source']
                        need(qualified_source_event_sha256(
                                 row['stream'], row['value'], source) ==
                             source['source_event_binding_sha256'],
                             'qualified-source-event-binding')
                        prior = by_stage.setdefault(
                            source['observer_stage'],
                            source['stage_config_sha256'])
                        need(prior == source['stage_config_sha256'],
                             'qualified-stage-config-consistency')
                    need(set(by_stage) == set(STAGES),
                         'qualified-stage-config-completeness')
                    precursor = {
                        **self._contact_value['precursor'],
                        'schema': AUTHORITY_PRECURSOR_SCHEMA,
                        'contact_value_authority_sha256':
                            self._contact_value['identity'],
                        'stage_config_sha256': [
                            by_stage[stage] for stage in STAGES],
                    }
                    precursor['precursor_sha256'] = hashlib.sha256(
                        PRODUCER_PRECURSOR_DOMAIN + encoded(precursor)
                    ).hexdigest()
                _frame(fd, 'hello', hello_raw)
                _frame(fd, 'meta', meta_raw)
                for raw in record_raw:
                    _frame(fd, 'record', raw)
                _frame(fd, 'end')
                try:
                    os.close(fd)
                except OSError as error:
                    raise CaptureRefused(
                        'c1-capture-final-channel-close') from error
                self._sealed = True
                if precursor is not None:
                    self._producer_authority = \
                        ContactValueProducerEvidence(precursor)
                result = {
                    'schema': 'kpb-c1-capture-source-status/v1',
                    'status': 'CONFIGURED0',
                    'round': self.binding.round,
                    'owner_component': 1,
                    'committed_stage_count': len(self._committed),
                    'captured_record_count': len(records),
                    'launch_authorized': False,
                    'actual_receipt_emitted': False,
                    'contact_binding_qualified':
                        self._contact_value is not None,
                    'private_bodies_or_hashes_public': False,
                }
                if self._contact_value is not None:
                    result['value_binding_qualified'] = True
                return result
        except BaseException:
            self._poison('seal-refused')
            raise

    def take_contact_value_producer_evidence(self):
        need(self._sealed and self._producer_authority is not None,
             'producer-evidence-not-ready')
        need(not self._producer_authority_taken,
             'producer-evidence-take-replay')
        self._producer_authority_taken = True
        return self._producer_authority


__all__ = (
    'C1CaptureSupervisor', 'CaptureRefused',
    'WholeTrialRetryInvalidated',
    'ContactValueProducerEvidence',
    'CONTACT_VALUE_OFFER_FIXED_FD', 'CONTACT_VALUE_OFFER_BYTES',
    'FIXED_FD', 'RunBinding', 'SOURCE_FIELDS', 'QUALIFIED_SOURCE_FIELDS',
    'NO_RETRY_STAGE_RECORD_COUNTS', 'NO_RETRY_FINAL_RECORD_COUNT',
    'NO_RETRY_FINAL_FRAME_COUNT',
    'QUALIFIED_NO_RETRY_RECORD_MAX_BYTES',
    'QUALIFIED_NO_RETRY_STAGE_MAX_BYTES',
    'QUALIFIED_NO_RETRY_WIRE_MAX_BYTES',
    'StageEmitter', 'StageGrant', 'controller_stage',
    'qualified_source_event_sha256',
)
