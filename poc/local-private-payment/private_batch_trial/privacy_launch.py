#!/usr/bin/env python3
"""Trusted finite network-off launcher. Default validates public inputs only.

Private truth, capsules, counts and captured view leaves are metadata-only host
inputs. Their contents are read only by the selected diagnostic role. Persistent
state derives from the admitted Original trial; a caller cannot choose a new
scoring root, truth path, capsule path or count path.
"""
import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import struct
import subprocess
import socket
import uuid

import privacy_codec as codec
import privacy_observer as observer
import privacy_source_closure as source_closure

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[2]
PRIVATE = Path('/var/tmp/kpi-owner-private-lifecycle-01/private/private-batch-20261028')
BOOTSTRAP_PUBLIC = Path('/var/tmp/kpi-private-batch-bootstrap-20261028')
LIFECYCLE_PUBLIC = Path('/var/tmp/kpi-private-batch-lifecycle-20261028')
METHOD = ROOT / 'research/next-session/local-private-payment/private-batch-2026-10-28/PRIVACY-METHOD-FREEZE.md'
CORE_PINS = {
    row['name']: row['sha256'] for row in
    source_closure.manifest('observer')['members']
}
DOMAIN = 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0'
PROFILE = 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700'
DIAGNOSTIC = 'private-batch-privacy'
need = codec.need
LAUNCH_RECEIPT_FIELDS = (
    'schema', 'operation', 'binding', 'selection_sha256',
    'public_result', 'public_result_sha256', 'persistent_query_consumed',
    'private_bodies_read_or_hashed', 'network_enabled',
    'source_closure_sha256', 'runtime_identity_sha256',
    'python_runtime_sha256', 'namespace_tool_sha256',
    'root_guard_helper_sha256', 'host_runtime_trust_boundary',
)

# Private parent/child transport schema for the two source values which the
# selected Python admission still has before they are reduced to digests:
# binding.attempt_id and the exact diagnostic.run_selection bytes.  These
# bytes are not authority.  Only the C++ authenticated receiver may turn a
# sealed instance from this exact admitted worker into a linear capability.
OWNER_SCORE_LINEAGE_MAGIC = b'KPBOSL02'
OWNER_SCORE_LINEAGE_VERSION = 2
OWNER_SCORE_LINEAGE_HEADER_BYTES = 416
OWNER_SCORE_MEASUREMENT_ATTEMPT_DOMAIN = (
    b'KPB_MEASUREMENT_ATTEMPT_FROM_OUTER_ASCII_V1\n')
OWNER_SCORE_LINEAGE_CLASSIFICATIONS = {
    'ACTUAL_HIDDEN_MAPPING_CANDIDATE': 1,
    'ACTUAL_TRANSPARENT_BASELINE': 2,
}
OWNER_SCORE_LINEAGE_SELECTION_FD = 60
OWNER_SCORE_LINEAGE_CONTROL_FD = 63
OWNER_SCORE_LINEAGE_OFFER_MAGIC = b'KPBOSQ01'
OWNER_SCORE_LINEAGE_RESPONSE_MAGIC = b'KPBOSR01'
OWNER_SCORE_LINEAGE_OFFER_BYTES = 72
OWNER_SCORE_LINEAGE_RESPONSE_BYTES = 80


def validate_launch_receipt(value, operation):
    """No JSON receipt is authority while v2 execute is hard-disabled."""
    need(operation in ('observe', 'score', 'aggregate'),
         'privacy-launch-operation')
    codec.fields(value, LAUNCH_RECEIPT_FIELDS)
    need(value['schema'] == 'kpb-private-diagnostic-launch-result/v1'
         and value['operation'] == operation,
         'privacy-launch-receipt-shape')
    need(False,
         'privacy-v2-execute-authoritative-actual-producer-launch-absent')


def checked(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'privacy-absolute-finite-path')
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'privacy-no-symlink-route')
    return path


def leaf_metadata(path, mode, size=None):
    path = checked(path); row = path.lstat()
    need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and row.st_uid == os.getuid()
         and stat.S_IMODE(row.st_mode) == mode, 'privacy-original-owned-single-link-leaf-metadata')
    need(size is None or row.st_size == size, 'privacy-original-leaf-size-metadata')
    return path


def mkdir(path):
    path = checked(path)
    if not path.exists():
        mkdir(path.parent); path.mkdir(mode=0o700)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'privacy-owned-state-directory')
    return path


def write_new(path, value, mode=0o400):
    path = checked(path); raw = value if type(value) is bytes else codec.encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(raw); handle.flush(); os.fsync(handle.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def public_ref(row, read):
    codec.fields(row, ('path', 'sha256'))
    path, expected = checked(row['path']), codec.word(row['sha256'])
    raw = read(path, expected)
    return path, raw


def named_public(row, read):
    path, raw = public_ref(row, read)
    return path, codec.parse(raw), raw


def owner_directory(root, row):
    component = codec.owner(row['owner_component'])
    path = checked(row['private_output_directory'])
    relative = path.relative_to(root / 'operations')
    need(len(relative.parts) == 2 and relative.parts[-1] == 'owner-' + str(component)
         and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', relative.parts[0]), 'privacy-actual-owner-operation-route')
    return path


def operation(row, read, trial, private, round_number, kind):
    path, value, raw = named_public(row, read)
    need(path.name == 'RESULT.json' and path.parent.parent == LIFECYCLE_PUBLIC,
         'privacy-selected-actual-operation-result-path')
    need(value['schema'] == 'kpb-original-lifecycle-controller-result/v1'
         and value['bootstrap_trial_id'] == trial['trial_id'] and value['operation'] == kind
         and type(value['round']) is int and value['round'] == round_number
         and value['controller_read_or_hashed_private_bodies'] is False
         and value['native_settlement_or_privacy_qualification'] is False
         and [part['owner_component'] for part in value['owners']] == [0, 1, 2],
         'privacy-actual-all-owner-operation-identity')
    codec.need(type(value['operation_id']) is str and bool(value['operation_id']), 'privacy-operation-id')
    for part in value['owners']:
        own = owner_directory(private, part)
        need(own.parent.name == path.parent.name, 'privacy-same-actual-public-private-operation-label')
        receipt = part['status']
        need(receipt['schema'] == 'kpb-original-lifecycle-operation/v1' and receipt['operation'] == kind
             and receipt['private_original_or_witness_exported'] is False
             and receipt['accepted_backing_or_native_settlement'] is False,
             'privacy-typed-actual-owner-operation-receipt')
        public = checked(part['public_receipt'])
        need(public == path.parent / ('owner-' + str(part['owner_component'])) / 'PUBLIC.json',
             'privacy-exact-actual-owner-public-leaf')
        need(codec.parse(read(public)) == receipt, 'privacy-operation-inline-public-receipt-equality')
    return path, value, raw


def admitted_v2(selected, trial_path, trial, private, read):
    bound = selected['binding']
    names = [row['name'] for row in selected['source_members']]
    expected_names = list(
        source_closure.ROLE_MEMBERS['diagnostic-launcher'])
    need(names == expected_names,
         'privacy-v2-exact-diagnostic-source-closure')
    sources = []
    for row in selected['source_members']:
        codec.fields(row, ('name', 'sha256'))
        name, pin = row['name'], codec.word(row['sha256'])
        data = read((HERE / name).resolve(), pin)
        sources.append((name, pin, data))
    need(selected['source_closure_sha256'] ==
            source_closure.all_digests()
         and selected['runtime_identity_sha256'] ==
            source_closure.runtime_digest(),
         'privacy-v2-source-runtime-closure')
    # The source-generated producer receipt and financial refs are selected
    # before capture. Their bodies are public; private capture bodies are not.
    public_ref(selected['capture_producer_receipt'], read)
    need(type(selected['financial_rounds']) is list
         and len(selected['financial_rounds']) == 2
         and type(selected['rounds']) is list
         and len(selected['rounds']) == 2,
         'privacy-v2-two-round-selections')
    rounds = []
    for number, part, financial in zip(
            (1, 2), selected['rounds'], selected['financial_rounds']):
        codec.fields(part, ('round', 'pay_result', 'financial_round'))
        codec.need(part['round'] == number
                   and part['financial_round'] == financial,
                   'privacy-v2-round-financial-binding')
        for name in ('round', 'financial_run_id', 'financial_artifacts',
                     'financial_result', 'retained_projection'):
            codec.need(name in financial,
                       'privacy-v2-financial-selection-field')
        _, payments, _ = operation(
            part['pay_result'], read, trial, private, number, 'pay')
        rounds.append({'round': number, 'payments': payments,
                       'financial': financial})
    codec.need(selected['corrupt_server_view'] == {
        'owner_component': 1,
        'capture_kind': 'corrupt-server-capture',
    }, 'privacy-v2-required-corrupt-server-view')
    return selected, trial_path.parent, private, sources, rounds


def _owner_score_lineage_source_archive(
        selected, bound, run_raw, diagnostic_selection_sha256):
    """Encode the exact admitted values; the archive is never authority."""
    need(selected.get('schema') ==
         'kpb-private-diagnostic-launch-selection/v2',
         'privacy-owner-score-lineage-v2-source')
    need(selected.get('binding') == bound,
         'privacy-owner-score-lineage-binding')
    codec.binding(bound)
    method = bytes.fromhex(codec.word(bound['method_sha256']))
    run_digest = bytes.fromhex(codec.word(bound['selection_sha256']))
    need(hashlib.sha256(run_raw).digest() == run_digest,
         'privacy-owner-score-lineage-exact-run')
    diagnostic = bytes.fromhex(codec.word(diagnostic_selection_sha256))
    source_closure_value = selected['source_closure_sha256']
    need(type(source_closure_value) is dict and source_closure_value
         and all(type(name) is str and bool(name)
                 and codec.word(value) == value
                 for name, value in source_closure_value.items()),
         'privacy-owner-score-lineage-source-closure-map')
    source = hashlib.sha256(codec.encoded(source_closure_value)).digest()
    runtime = bytes.fromhex(codec.word(selected['runtime_identity_sha256']))
    classification = OWNER_SCORE_LINEAGE_CLASSIFICATIONS.get(
        selected['expected_classification'])
    need(classification is not None,
         'privacy-owner-score-lineage-classification')
    trial = bound['trial_id'].encode('ascii')
    attempt = bound['attempt_id'].encode('ascii')
    need(len(trial) == 36 and 1 <= len(attempt) <= 128,
         'privacy-owner-score-lineage-text-size')
    need(all((ord('a') <= byte <= ord('z')) or
             (ord('A') <= byte <= ord('Z')) or
             (ord('0') <= byte <= ord('9')) or
             byte in (ord('_'), ord('-')) for byte in attempt),
         'privacy-owner-score-lineage-attempt-ascii')
    measurement_attempt = hashlib.sha256(
        OWNER_SCORE_MEASUREMENT_ATTEMPT_DOMAIN +
        len(attempt).to_bytes(2, 'little') + attempt).digest()
    total = OWNER_SCORE_LINEAGE_HEADER_BYTES + len(run_raw)
    archive = bytearray(total)
    archive[0:8] = OWNER_SCORE_LINEAGE_MAGIC
    archive[8:12] = OWNER_SCORE_LINEAGE_VERSION.to_bytes(4, 'little')
    archive[12:16] = OWNER_SCORE_LINEAGE_HEADER_BYTES.to_bytes(4, 'little')
    archive[16:24] = total.to_bytes(8, 'little')
    archive[24:56] = method
    archive[56:88] = run_digest
    archive[88:120] = diagnostic
    archive[120:152] = source
    archive[152:184] = runtime
    archive[184:220] = trial
    archive[220] = classification
    archive[221] = 1  # exact private-batch-privacy phase tag
    archive[222:224] = len(attempt).to_bytes(2, 'little')
    archive[224:232] = len(run_raw).to_bytes(8, 'little')
    archive[232:264] = measurement_attempt
    archive[264:264 + len(attempt)] = attempt
    archive[OWNER_SCORE_LINEAGE_HEADER_BYTES:] = run_raw
    return bytes(archive)


def admitted(selection_path, selection_sha256, read, selection_raw=None,
             *, _lineage_sink=None):
    raw = (read(checked(selection_path), codec.word(selection_sha256))
           if selection_raw is None else selection_raw)
    selected = codec.parse(raw)
    if selected.get('schema') == 'kpb-private-diagnostic-launch-selection/v2':
        codec.fields(selected, (
            'schema', 'binding', 'expected_classification',
            'run_selection', 'bootstrap_trial', 'source_members',
            'source_closure_sha256', 'runtime_identity_sha256',
            'capture_producer_receipt', 'financial_rounds', 'rounds',
            'corrupt_server_view'))
        bound = codec.binding(selected['binding'])
        _, run_raw = public_ref(selected['run_selection'], read)
        need(hashlib.sha256(run_raw).hexdigest() ==
                bound['selection_sha256']
             and hashlib.sha256(read(METHOD)).hexdigest() ==
                bound['method_sha256'],
             'privacy-v2-same-frozen-method-run-selection')
        trial_path, trial, _ = named_public(selected['bootstrap_trial'], read)
        need(trial['schema'] ==
                'kpb-fresh-unfunded-private-original-trial/v1'
             and trial['trial_id'] == bound['trial_id']
             and trial['domain_hex32'] == DOMAIN
             and trial['profile_id_hex32'] == PROFILE
             and trial['network_id'] == 'testnet-10'
             and trial['owner_count'] == 3
             and trial['controller_read_or_hashed_private_bodies'] is False,
             'privacy-v2-genuine-new-Original-trial')
        label = trial['label']
        need(type(label) is str and
             re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)
             and trial_path == BOOTSTRAP_PUBLIC / label / 'TRIAL.json',
             'privacy-v2-exact-bootstrap-route')
        private = checked(trial['private_original_parent'])
        need(private == PRIVATE / label,
             'privacy-v2-fixed-Original-trial-parent')
        result = admitted_v2(selected, trial_path, trial, private, read)
        if _lineage_sink is not None:
            archive = _owner_score_lineage_source_archive(
                selected, bound, run_raw, selection_sha256)
            lineage_sink = _lineage_sink
            lineage_sink(archive)
        return result
    codec.fields(selected, ('schema', 'binding', 'run_selection', 'bootstrap_trial', 'source_members',
                            'rounds', 'corrupt_server_view'))
    need(selected['schema'] == 'kpb-private-diagnostic-launch-selection/v1', 'privacy-selected-finite-launch-schema')
    bound = codec.binding(selected['binding'])
    _, run_raw = public_ref(selected['run_selection'], read)
    need(hashlib.sha256(run_raw).hexdigest() == bound['selection_sha256']
         and hashlib.sha256(read(METHOD)).hexdigest() == bound['method_sha256'], 'privacy-same-frozen-method-run-selection')
    trial_path, trial, _ = named_public(selected['bootstrap_trial'], read)
    need(trial['schema'] == 'kpb-fresh-unfunded-private-original-trial/v1'
         and trial['trial_id'] == bound['trial_id'] and trial['domain_hex32'] == DOMAIN
         and trial['profile_id_hex32'] == PROFILE and trial['network_id'] == 'testnet-10'
         and trial['owner_count'] == 3 and trial['controller_read_or_hashed_private_bodies'] is False,
         'privacy-same-genuine-new-Original-trial')
    label = trial['label']; need(type(label) is str and re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label), 'privacy-trial-label')
    need(trial_path == BOOTSTRAP_PUBLIC / label / 'TRIAL.json', 'privacy-exact-bootstrap-public-route')
    private = checked(trial['private_original_parent'])
    need(private == PRIVATE / label, 'privacy-fixed-Original-trial-parent')
    names = [row['name'] for row in selected['source_members']]
    need(names == [*CORE_PINS, 'privacy_launch.py'], 'privacy-finite-exact-launch-source-closure')
    sources = []
    for row in selected['source_members']:
        codec.fields(row, ('name', 'sha256')); name = row['name']; pin = codec.word(row['sha256'])
        need(name not in CORE_PINS or pin == CORE_PINS[name], 'privacy-unchanged-qualified-core-source')
        data = read((HERE / name).resolve(), pin)
        sources.append((name, pin, data))
    need([part['round'] for part in selected['rounds']] == [1, 2], 'privacy-fixed-both-round-selection')
    rounds = []
    for part in selected['rounds']:
        codec.fields(part, ('round', 'invoice_result', 'pay_result', 'projection', 'dispatcher_artifacts'))
        r = part['round']
        invoice_path, invoices, invoice_raw = operation(part['invoice_result'], read, trial, private, r, 'invoice')
        pay_path, payments, pay_raw = operation(part['pay_result'], read, trial, private, r, 'pay')
        projection_path, projection = public_ref(part['projection'], read)
        observer.batch_from_projection(r, projection)
        routes = []
        for component in codec.OWNERS:
            route_path = pay_path.parent / ('owner-' + str(component)) / 'OBSERVED-INVOICE-ROUTE.json'
            route_raw = read(route_path); route = observer.route_record(codec.parse(route_raw))
            target = (component + r) % 3
            need(route['round'] == r and route['source_owner_component'] == component
                 and route['target_owner_component'] == target and route['source_operation_id'] == payments['operation_id']
                 and route['target_invoice_operation_id'] == invoices['operation_id']
                 and checked(route['invoice_leaf_path']) == owner_directory(private, invoices['owners'][target]) / 'INVOICE208.bin',
                 'privacy-actual-trusted-IPC-route-not-asserted-count')
            routes.append((route_path, route_raw))
        for artifact in part['dispatcher_artifacts']:
            codec.fields(artifact, ('kind', 'path', 'sha256', 'route_owner'))
            if artifact['route_owner'] is not None: codec.owner(artifact['route_owner'])
            if artifact['kind'] == 'invoice-route':
                extra_path, extra_raw = public_ref({'path': artifact['path'], 'sha256': artifact['sha256']}, read)
                extra = observer.route_record(codec.parse(extra_raw))
                need(extra_path.is_relative_to(LIFECYCLE_PUBLIC) and extra_path.name == 'OBSERVED-INVOICE-ROUTE.json'
                     and extra['round'] == r and extra['source_owner_component'] == artifact['route_owner']
                     and checked(extra['invoice_leaf_path']).is_relative_to(private / 'operations'),
                     'privacy-retained-additional-actual-route-attempt')
            else:
                need(artifact['kind'] in ('dispatcher-metadata', 'terminal-raw') and artifact['sha256'] is None,
                     'privacy-captured-private-dispatcher-view-no-host-hash')
                capture_root = private / 'diagnostics' / DIAGNOSTIC / 'dispatcher-capture' / ('round-' + str(r))
                need(checked(artifact['path']).is_relative_to(capture_root), 'privacy-fixed-dispatcher-capture-root-no-truth')
        rounds.append({'round': r, 'payments': payments, 'projection': (projection_path, projection), 'routes': routes,
                       'metadata': [(invoice_path, invoice_raw), (pay_path, pay_raw)], 'artifacts': part['dispatcher_artifacts']})
    capture = selected['corrupt_server_view']
    if capture is not None:
        codec.fields(capture, ('owner_component', 'root', 'relative_leaves'))
        need(type(capture['owner_component']) is int and capture['owner_component'] == 1
             and type(capture['relative_leaves']) is list and len(capture['relative_leaves']) == len(set(capture['relative_leaves'])),
             'privacy-only-declared-corrupt-server-one')
        server_root = checked(capture['root'])
        need(server_root == private / 'diagnostics' / DIAGNOSTIC / 'corrupt-server-1',
             'privacy-fixed-corrupt-server-one-capture-root-no-Original')
        for leaf in capture['relative_leaves']:
            need(type(leaf) is str and leaf and not Path(leaf).is_absolute() and '..' not in Path(leaf).parts,
                 'privacy-finite-corrupt-server-capture-leaves')
            checked(server_root / leaf)
    return selected, trial_path.parent, private, sources, rounds


def admitted_owner_score_lineage_source(
        selection_path, selection_sha256, read, selection_raw=None):
    """Return admitted public inputs plus the non-authorizing source archive.

    The fixed-FD Python worker uses this entry point and sends the archive over
    its credentialed parent-owned transport. Callers cannot turn these bytes
    into C++ authority; selection of this exact worker and the outer-attempt
    source-domain join remain absent.
    """
    archives = []
    result = admitted(
        selection_path, selection_sha256, read, selection_raw,
        _lineage_sink=archives.append)
    need(len(archives) == 1,
         'privacy-owner-score-lineage-v2-admission-required')
    return result, archives[0]


def _owner_score_lineage_worker_read(fd):
    before = os.fstat(fd)
    need(stat.S_ISREG(before.st_mode) and before.st_size > 0,
         'privacy-owner-score-lineage-selection-fd')
    raw = bytearray(before.st_size)
    offset = 0
    while offset < len(raw):
        block = os.pread(fd, len(raw) - offset, offset)
        need(bool(block), 'privacy-owner-score-lineage-selection-read')
        raw[offset:offset + len(block)] = block
        offset += len(block)
    after = os.fstat(fd)
    need((before.st_dev, before.st_ino, before.st_mode, before.st_nlink,
          before.st_uid, before.st_gid, before.st_size,
          before.st_mtime_ns, before.st_ctime_ns) ==
         (after.st_dev, after.st_ino, after.st_mode, after.st_nlink,
          after.st_uid, after.st_gid, after.st_size,
          after.st_mtime_ns, after.st_ctime_ns),
         'privacy-owner-score-lineage-selection-stable')
    return bytes(raw)


def owner_score_lineage_worker():
    """Fixed-FD child. Only its credentialed parent can mint authority."""
    control = socket.socket(fileno=OWNER_SCORE_LINEAGE_CONTROL_FD)
    offer, ancillary, flags, _ = control.recvmsg(
        OWNER_SCORE_LINEAGE_OFFER_BYTES,
        socket.CMSG_SPACE(struct.calcsize('3i')))
    need(len(offer) == OWNER_SCORE_LINEAGE_OFFER_BYTES
         and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0
         and offer[:8] == OWNER_SCORE_LINEAGE_OFFER_MAGIC
         and len(ancillary) == 1
         and ancillary[0][0] == socket.SOL_SOCKET
         and ancillary[0][1] == socket.SCM_CREDENTIALS
         and len(ancillary[0][2]) == struct.calcsize('3i'),
         'privacy-owner-score-lineage-parent-offer')
    parent_pid, parent_uid, parent_gid = struct.unpack(
        '3i', ancillary[0][2])
    need(parent_pid == os.getppid() and parent_uid == os.getuid()
         and parent_gid == os.getgid(),
         'privacy-owner-score-lineage-parent-credentials')
    selection_raw = _owner_score_lineage_worker_read(
        OWNER_SCORE_LINEAGE_SELECTION_FD)
    selection_sha = hashlib.sha256(selection_raw).digest()
    need(selection_sha == offer[40:72],
         'privacy-owner-score-lineage-selection-offer')
    read = runpy.run_path(
        '/var/tmp/kpi-root-guard-helper-09.py')['read']
    _, archive = admitted_owner_score_lineage_source(
        '/unused-source-owned-fd', selection_sha.hex(), read,
        selection_raw)
    writer = os.memfd_create(
        'kpb-owner-score-lineage-source',
        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    reader = -1
    try:
        offset = 0
        while offset < len(archive):
            wrote = os.write(writer, archive[offset:])
            need(wrote > 0, 'privacy-owner-score-lineage-archive-write')
            offset += wrote
        os.fchmod(writer, 0o400)
        fcntl.fcntl(
            writer, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
            fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        reader = os.open(
            '/proc/self/fd/' + str(writer),
            os.O_RDONLY | os.O_CLOEXEC)
        response = (OWNER_SCORE_LINEAGE_RESPONSE_MAGIC + offer[8:40] +
                    len(archive).to_bytes(8, 'little') +
                    hashlib.sha256(archive).digest())
        need(len(response) == OWNER_SCORE_LINEAGE_RESPONSE_BYTES,
             'privacy-owner-score-lineage-response-size')
        sent = control.sendmsg(
            [response], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                          array.array('i', [reader]))])
        need(sent == len(response),
             'privacy-owner-score-lineage-response-send')
    finally:
        if reader >= 0:
            os.close(reader)
        os.close(writer)
        control.close()


def read_observation(public, bound, read):
    path = public / 'observe' / 'PUBLIC.json'; raw = read(path); value = codec.parse(raw)
    if value.get('schema') == 'kpb-direct-observation-receipt/v2':
        codec.fields(value, (
            'schema', 'binding', 'comparison_selection_sha256',
            'run_selection_sha256', 'capture_receipt_sha256',
            'capture_manifest_seal_sha256',
            'construction_classification_receipt_sha256',
            'capture_producer_receipt_sha256', 'source_closure_sha256',
            'runtime_identity_sha256', 'terminal_scope',
            'step3_terminal_gate', 'views',
            'predictions_frozen_before_truth',
            'private_view_or_prediction_records_exported'))
        need(value['binding'] == bound
             and value['predictions_frozen_before_truth'] is True
             and value['private_view_or_prediction_records_exported']
                is False
             and [row['view'] for row in value['views']] ==
                list(codec.VIEWS),
             'privacy-v2-observation-count-only-receipt')
        for row in value['views']:
            codec.word(row['capsule_seal_sha256'])
            need(type(row['capsule_bytes']) is int
                 and row['capsule_bytes'] > 32,
                 'privacy-v2-positive-capsule-size')
        return path, raw, value
    codec.fields(value, ('schema', 'binding', 'views', 'predictions_frozen_before_truth', 'private_view_or_prediction_records_exported'))
    need(value['schema'] == 'kpb-direct-observation-receipt/v1' and value['binding'] == bound
         and value['predictions_frozen_before_truth'] is True and value['private_view_or_prediction_records_exported'] is False
         and [row['view'] for row in value['views']] == list(codec.VIEWS), 'privacy-actual-observation-count-only-receipt')
    for row in value['views']:
        codec.word(row['capsule_seal_sha256'])
        need(type(row['capsule_bytes']) is int and row['capsule_bytes'] > 32, 'privacy-positive-capsule-size')
    return path, raw, value


def public_barrier(public, bound, selection_sha256, read):
    _, observation_raw, observation = read_observation(public, bound, read)
    barrier_path = public / 'observe' / 'BARRIER.json'
    leaf_metadata(barrier_path, 0o400); barrier_raw = read(barrier_path)
    if observation['schema'] == 'kpb-direct-observation-receipt/v2':
        expected = {
            'schema': 'kpb-direct-prediction-barrier/v2',
            'binding': bound,
            'comparison_selection_sha256':
                observation['comparison_selection_sha256'],
            'run_selection_sha256': observation['run_selection_sha256'],
            'capture_receipt_sha256':
                observation['capture_receipt_sha256'],
            'capture_manifest_seal_sha256':
                observation['capture_manifest_seal_sha256'],
            'construction_classification_receipt_sha256':
                observation[
                    'construction_classification_receipt_sha256'],
            'capture_producer_receipt_sha256':
                observation['capture_producer_receipt_sha256'],
            'source_closure_sha256':
                observation['source_closure_sha256'],
            'runtime_identity_sha256':
                observation['runtime_identity_sha256'],
            'terminal_scope': observation['terminal_scope'],
            'step3_terminal_gate': observation['step3_terminal_gate'],
            'observation_receipt_sha256':
                hashlib.sha256(observation_raw).hexdigest(),
            'capsules': [{'view': row['view'],
                          'capsule_seal_sha256':
                              row['capsule_seal_sha256']}
                         for row in observation['views']],
        }
        need(codec.parse(barrier_raw) == expected,
             'privacy-v2-public-barrier-precedes-truth')
        launch_path = public / 'observe' / 'LAUNCH.json'
        leaf_metadata(launch_path, 0o400)
        completed = codec.parse(read(launch_path))
        runtime = source_closure.runtime_identity()
        need(completed['schema'] ==
                'kpb-private-diagnostic-launch-result/v1'
             and completed['operation'] == 'observe'
             and completed['binding'] == bound
             and completed['selection_sha256'] == selection_sha256
             and completed['public_result_sha256'] ==
                hashlib.sha256(observation_raw).hexdigest()
             and completed['source_closure_sha256'] ==
                source_closure.all_digests()
             and completed['runtime_identity_sha256'] ==
                source_closure.runtime_digest()
             and completed['python_runtime_sha256'] ==
                runtime['python_runtime_sha256']
             and completed['namespace_tool_sha256'] ==
                runtime['namespace_tool_sha256']
             and completed['root_guard_helper_sha256'] ==
                runtime['root_guard_helper_sha256']
             and completed['host_runtime_trust_boundary'] ==
                runtime['host_runtime_trust_boundary']
             and completed['persistent_query_consumed'] is True
             and completed['private_bodies_read_or_hashed'] is False
             and completed['network_enabled'] is False,
             'privacy-v2-completed-observer-before-truth')
        return observation_raw, observation, barrier_raw
    need(codec.parse(barrier_raw) == {'schema': 'kpb-direct-prediction-barrier/v1', 'binding': bound,
         'observation_receipt_sha256': hashlib.sha256(observation_raw).hexdigest(),
         'capsules': [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in observation['views']]},
         'privacy-public-barrier-exactly-precedes-truth-join')
    launch_path = public / 'observe' / 'LAUNCH.json'
    leaf_metadata(launch_path, 0o400); completed = codec.parse(read(launch_path))
    need(completed['schema'] == 'kpb-private-diagnostic-launch-result/v1'
         and completed['operation'] == 'observe' and completed['binding'] == bound
         and completed['selection_sha256'] == selection_sha256
         and completed['public_result_sha256'] == hashlib.sha256(observation_raw).hexdigest()
         and completed['persistent_query_consumed'] is True
         and completed['private_bodies_read_or_hashed'] is False and completed['network_enabled'] is False,
         'privacy-actual-completed-observer-before-truth')
    return observation_raw, observation, barrier_raw


def capture_chain_v2(public, private, selected, selection_sha256, read):
    capture_public_path = public / 'capture' / 'PUBLIC.json'
    capture_raw = read(capture_public_path)
    capture = codec.parse(capture_raw)
    construction_path = public / 'capture' / 'CONSTRUCTION.json'
    construction_raw = read(construction_path)
    construction = codec.parse(construction_raw)
    launch_path = public / 'capture' / 'LAUNCH.json'
    launch_raw = read(launch_path)
    launch = codec.parse(launch_raw)
    need(capture['schema'] == 'kpb-privacy-actual-capture-receipt/v2'
         and construction['schema'] ==
            'kpb-financial-construction-classification/v1'
         and launch['schema'] == 'kpb-actual-capture-launch/v2'
         and launch['operation'] == 'actual-capture'
         and capture['binding'] == selected['binding'] == launch['binding']
         and launch['diagnostic_selection_sha256'] == selection_sha256
         and launch['capture_receipt_sha256'] ==
            hashlib.sha256(capture_raw).hexdigest()
         and launch['construction_classification_receipt_sha256'] ==
            hashlib.sha256(construction_raw).hexdigest() ==
            capture['construction_classification_receipt_sha256']
         and launch['capture_manifest_seal_sha256'] ==
            capture['capture_manifest_seal_sha256']
         and launch['source_closure_sha256'] ==
            selected['source_closure_sha256']
         and launch['runtime_identity_sha256'] ==
            selected['runtime_identity_sha256']
         and launch['financial_host_crypto_rechecked'] is True
         and launch['network_enabled'] is False
         and launch['predictions_or_truth_mounted'] is False
         and launch['private_artifact_paths_hashes_or_bodies_exported']
            is False
         and launch['terminal_scope'] ==
            'PRIVATE_BATCH_TERMINAL_ONLY_EXIT_LINKABILITY_UNMEASURED'
         and launch['step3_terminal_gate'] ==
            'REQUIRED_SEPARATE_EXIT_LINKABILITY_GATE_BEFORE_STEP3',
         'privacy-v2-selected-capture-launch-chain')
    capture_identity = capture['capture_identity']
    need(type(capture_identity) is str and
         str(uuid.UUID(capture_identity)) == capture_identity,
         'privacy-v2-capture-identity')
    models = (private / 'diagnostics' / DIAGNOSTIC / 'actual-capture' /
              capture_identity / 'state' / 'MODELS.json')
    leaf_metadata(models, 0o600)
    return {
        'comparison_selection_sha256':
            launch['comparison_selection_sha256'],
        'run_selection_sha256': launch['run_selection_sha256'],
        'capture': (capture_public_path, capture_raw),
        'construction': (construction_path, construction_raw),
        'models': models,
        'step3_terminal_gate': launch['step3_terminal_gate'],
    }


def run(operation_name, selection_path, selection_sha256, owner_component=None, execute=False):
    need(operation_name in ('observe', 'score', 'aggregate'), 'privacy-finite-launch-operation')
    need((operation_name == 'score' and type(owner_component) is int and owner_component in codec.OWNERS)
         or (operation_name != 'score' and owner_component is None), 'privacy-exact-single-scorer-owner')
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    selection_raw = read(
        checked(selection_path), codec.word(selection_sha256))
    selection = codec.parse(selection_raw)
    # Source-only v2 artifacts are not actual launch authority.  Refuse before
    # admission can inspect private routes or any one-shot state is consumed.
    need(not (execute and selection.get('schema') ==
              'kpb-private-diagnostic-launch-selection/v2'),
         'privacy-v2-execute-authoritative-actual-producer-launch-absent')
    selected, trial_public, private, sources, rounds = admitted(
        selection_path, selection_sha256, read, selection_raw)
    bound = selected['binding']; public = trial_public / 'privacy-diagnostics'
    v2 = selected['schema'] == 'kpb-private-diagnostic-launch-selection/v2'
    capture_v2 = (capture_chain_v2(
        public, private, selected, selection_sha256, read) if v2 else None)
    state_root = private / 'diagnostics' / DIAGNOSTIC
    state = (private / ('owner-' + str(owner_component)) / 'diagnostics' / DIAGNOSTIC
             if operation_name == 'score' else state_root / operation_name)
    output = public / (operation_name + ('-owner-' + str(owner_component) if operation_name == 'score' else ''))
    if not execute:
        return {'schema': 'kpb-private-diagnostic-launch-plan/v1', 'operation': operation_name,
                'binding': bound, 'executed': False, 'private_bodies_read_or_hashed': False}
    frozen_public = None
    if operation_name != 'observe':
        # Public-only qualification happens before consuming a score slot. The
        # fixed consume below still precedes all capsule/truth content reads.
        frozen_public = public_barrier(public, bound, selection_sha256, read)
        leaf_metadata(state_root / 'observe' / 'OBSERVATION-CLOSED', 0o400)
    mkdir(state); need(not output.exists(), 'privacy-no-repeated-diagnostic-public-output')
    mkdir(output); shared = mkdir(output / 'selected-public')
    # A launcher failure consumes the same persistent query too. Neither a new
    # output path nor a fresh attempt ID resets this fixed Original trial state.
    write_new(state / 'LAUNCH-CLOSED', {'operation': operation_name, 'binding': bound, 'selection_sha256': selection_sha256})
    mounts, source_members = [], []
    for index, (name, pin, raw) in enumerate(sources):
        if v2 and name not in source_closure.ROLE_MEMBERS['observer']:
            continue
        leaf = shared / ('source-' + str(index)); write_new(leaf, raw)
        alias = str((source_closure.NAMESPACE_SOURCE_ROOT / name).resolve())
        mounts += ['--ro-bind', str(leaf), alias]
        source_members.append({**({'name': name} if v2 else {}),
                               'path': alias, 'sha256': pin})
    config = {'binding': bound, 'source_members': source_members}
    runtime = None
    if v2:
        runtime = source_closure.runtime_identity()
        mounts.extend([
            '--ro-bind', str(source_closure.ROOT_GUARD),
            str(source_closure.NAMESPACE_SOURCE_ROOT /
                'root_guard_helper.py')])
        config.update({
            'schema': 'kpb-private-diagnostic-role-config/v2',
            'comparison_selection_sha256':
                capture_v2['comparison_selection_sha256'],
            'run_selection_sha256': capture_v2['run_selection_sha256'],
            'diagnostic_selection_sha256': selection_sha256,
            'source_closure_sha256': selected['source_closure_sha256'],
            'runtime_identity_sha256': selected['runtime_identity_sha256'],
            'python_runtime_sha256': runtime['python_runtime_sha256'],
            'namespace_tool_sha256': runtime['namespace_tool_sha256'],
            'root_guard_helper_sha256':
                runtime['root_guard_helper_sha256'],
            'host_runtime_trust_boundary':
                runtime['host_runtime_trust_boundary'],
            'step3_terminal_gate': capture_v2['step3_terminal_gate'],
        })
    def public_mount(name, raw):
        leaf = shared / name; pin = write_new(leaf, raw); alias = '/public/' + name
        mounts.extend(['--ro-bind', str(leaf), alias]); return {'path': alias, 'sha256': pin}
    def private_mount(path, alias, mode, size=None):
        leaf_metadata(path, mode, size); mounts.extend(['--ro-bind', str(path), alias]); return alias
    if operation_name == 'observe':
        if v2:
            config['capture_receipt'] = public_mount(
                'CAPTURE.json', capture_v2['capture'][1])
            config['construction_classification'] = public_mount(
                'CONSTRUCTION.json', capture_v2['construction'][1])
            config['capture_models'] = private_mount(
                capture_v2['models'], '/capture/MODELS.json', 0o600)
        else:
            parts = []
            for part in rounds:
                r = part['round']; projection = public_mount('projection-' + str(r) + '.bin', part['projection'][1])
                artifacts = []
                for index, (_, raw) in enumerate(part['metadata']):
                    ref = public_mount('metadata-' + str(r) + '-' + str(index) + '.json', raw)
                    artifacts.append({'kind': 'dispatcher-metadata', **ref, 'route_owner': None})
                for component, (_, raw) in enumerate(part['routes']):
                    ref = public_mount('route-' + str(r) + '-' + str(component) + '.json', raw)
                    artifacts.append({'kind': 'invoice-route', **ref, 'route_owner': component})
                for index, artifact in enumerate(part['artifacts']):
                    if artifact['kind'] == 'invoice-route':
                        raw = read(checked(artifact['path']), artifact['sha256'])
                        ref = public_mount('extra-route-' + str(r) + '-' + str(index) + '.json', raw)
                        artifacts.append({**artifact, **ref})
                    else:
                        path = private_mount(checked(artifact['path']), '/dispatcher/' + str(r) + '-' + str(index), 0o600)
                        artifacts.append({**artifact, 'path': path})
                colluder = owner_directory(private, part['payments']['owners'][1]) / 'COLLUDER-CONSTRAINTS.json'
                facts = private_mount(colluder, '/colluder/round' + str(r) + '.json', 0o600) if colluder.exists() else None
                parts.append({'round': r, 'projection': projection, 'artifacts': artifacts, 'colluder_constraints': facts})
            server_artifacts = []
            if selected['corrupt_server_view'] is not None:
                capture = selected['corrupt_server_view']
                for index, leaf in enumerate(capture['relative_leaves']):
                    path = private_mount(checked(capture['root']) / leaf, '/corrupt-server/leaf-' + str(index), 0o600)
                    server_artifacts.append({'kind': 'corrupt-server-raw', 'path': path, 'sha256': None, 'route_owner': None})
            config['views'] = []
            for view in codec.VIEWS:
                values = []
                for part in parts:
                    artifacts = []
                    if view in ('dispatcher', 'union'): artifacts.extend(part['artifacts'])
                    if view in ('corrupt-server-plus-wallet', 'union'): artifacts.extend(server_artifacts)
                    values.append({**part, 'artifacts': artifacts,
                        'colluder_constraints': part['colluder_constraints'] if view in ('corrupt-server-plus-wallet', 'union') else None})
                config['views'].append({'view': view, 'rounds': values})
    else:
        observation_raw, observation, barrier_raw = frozen_public
        config['barrier'] = public_mount('BARRIER.json', barrier_raw)
        config['observation_receipt'] = public_mount('OBSERVATION.json', observation_raw)
        config['capsules'] = []
        for row in observation['views']:
            view = row['view']; alias = '/capsules/' + view + '.bin'
            private_mount(state_root / 'observe' / ('PREDICTIONS-' + view + '.bin'), alias, 0o400, row['capsule_bytes'])
            config['capsules'].append({'view': view, 'path': alias})
        if operation_name == 'score':
            config['owner_component'] = owner_component; config['truth_commitments'] = []
            for part in rounds:
                r = part['round']; own = owner_directory(private, part['payments']['owners'][owner_component])
                private_mount(own / 'PRIVACY-TRUTH.json', '/truth/round' + str(r) + '.json', 0o600)
                commit_path = checked(part['payments']['owners'][owner_component]['public_receipt']).parent / 'PRIVACY-COMMITMENT.json'
                commit_raw = read(commit_path); commit = codec.parse(commit_raw)
                need(commit['schema'] == 'kpb-owner-truth-commitment/v1' and commit['binding'] == bound
                     and commit['owner_component'] == owner_component and commit['round'] == r
                     and commit['truth_or_identifiers_exported'] is False, 'privacy-original-public-own-truth-commitment')
                config['truth_commitments'].append(public_mount('commit-' + str(r) + '.json', commit_raw))
        else:
            config['count_files'] = []
            for component in codec.OWNERS:
                leaf = private / ('owner-' + str(component)) / 'diagnostics' / DIAGNOSTIC / 'COUNTS.json'
                config['count_files'].append(private_mount(leaf, '/counts/owner-' + str(component) + '.json', 0o400))
    config_path, marker_path = state / 'PRIVATE-CONFIG.json', state / 'PRIVATE-NAMESPACE.json'
    write_new(config_path, config, 0o600)
    write_new(marker_path, {'schema': 'kpb-private-diagnostic-namespace/v1', 'operation': operation_name,
        'network': 'disabled', 'truth_owner_slots': 1 if operation_name == 'score' else 0,
        'colluder_owner_slots': 1 if operation_name == 'observe' else 0,
        'corrupt_server_slots': 1 if operation_name == 'observe' else 0})
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', *mounts,
        '--ro-bind', str(config_path), '/CONFIG.json', '--ro-bind', str(marker_path), '/NAMESPACE.json',
        '--bind', str(state), '/state', '--bind', str(output), '/out',
        '/usr/bin/python3', '-B', '-S',
        str(source_closure.NAMESPACE_SOURCE_ROOT / 'privacy_roles.py'),
        operation_name]
    # These FD-only private logs/configs are never reopened or hashed by host.
    write_new(state / 'PRIVATE-PLAN.json', {'command': command}, 0o600)
    with (state / 'PRIVATE-STDOUT.log').open('xb') as stdout, (state / 'PRIVATE-STDERR.log').open('xb') as stderr:
        process = subprocess.run(command, stdout=stdout, stderr=stderr, env={'PATH': '/usr/bin:/bin'})
    need(process.returncode == 0, 'privacy-isolated-role-incomplete-retain-used-query')
    if operation_name == 'observe':
        _, obs_raw, observation = read_observation(public, bound, read)
        for row in observation['views']:
            leaf_metadata(state / ('PREDICTIONS-' + row['view'] + '.bin'), 0o400, row['capsule_bytes'])
        if v2:
            write_new(output / 'BARRIER.json', {
                'schema': 'kpb-direct-prediction-barrier/v2',
                'binding': bound,
                'comparison_selection_sha256':
                    observation['comparison_selection_sha256'],
                'run_selection_sha256':
                    observation['run_selection_sha256'],
                'capture_receipt_sha256':
                    observation['capture_receipt_sha256'],
                'capture_manifest_seal_sha256':
                    observation['capture_manifest_seal_sha256'],
                'construction_classification_receipt_sha256':
                    observation[
                        'construction_classification_receipt_sha256'],
                'capture_producer_receipt_sha256':
                    observation['capture_producer_receipt_sha256'],
                'source_closure_sha256':
                    observation['source_closure_sha256'],
                'runtime_identity_sha256':
                    observation['runtime_identity_sha256'],
                'terminal_scope': observation['terminal_scope'],
                'step3_terminal_gate':
                    observation['step3_terminal_gate'],
                'observation_receipt_sha256':
                    hashlib.sha256(obs_raw).hexdigest(),
                'capsules': [{
                    'view': row['view'],
                    'capsule_seal_sha256': row['capsule_seal_sha256'],
                } for row in observation['views']],
            })
        else:
            write_new(output / 'BARRIER.json', {'schema': 'kpb-direct-prediction-barrier/v1', 'binding': bound,
                'observation_receipt_sha256': hashlib.sha256(obs_raw).hexdigest(),
                'capsules': [{'view': row['view'], 'capsule_seal_sha256': row['capsule_seal_sha256']} for row in observation['views']]})
    elif operation_name == 'score':
        leaf_metadata(state / 'COUNTS.json', 0o400)
    receipt_path = output / 'PUBLIC.json'; receipt_raw = read(receipt_path); receipt = codec.parse(receipt_raw)
    expected = ({'score': 'kpb-private-score-completed/v2',
                 'aggregate': 'kpb-public-all-view-direct-counts/v2',
                 'observe': 'kpb-direct-observation-receipt/v2'}
                if v2 else
                {'score': 'kpb-private-score-completed/v1',
                 'aggregate': 'kpb-public-all-view-direct-counts/v1',
                 'observe': 'kpb-direct-observation-receipt/v1'})[
                    operation_name]
    need(receipt['schema'] == expected and receipt['binding'] == bound, 'privacy-exact-public-role-completion')
    launch = {'schema': 'kpb-private-diagnostic-launch-result/v1', 'operation': operation_name,
        'binding': bound, 'selection_sha256': selection_sha256, 'public_result': str(receipt_path),
        'public_result_sha256': hashlib.sha256(receipt_raw).hexdigest(), 'persistent_query_consumed': True,
        'private_bodies_read_or_hashed': False, 'network_enabled': False}
    if v2:
        launch.update({
            'source_closure_sha256': source_closure.all_digests(),
            'runtime_identity_sha256': source_closure.runtime_digest(),
            'python_runtime_sha256': runtime['python_runtime_sha256'],
            'namespace_tool_sha256': runtime['namespace_tool_sha256'],
            'root_guard_helper_sha256':
                runtime['root_guard_helper_sha256'],
            'host_runtime_trust_boundary':
                runtime['host_runtime_trust_boundary'],
        })
    write_new(output / 'LAUNCH.json', launch)
    return launch


def main():
    os.umask(0o077)
    if len(os.sys.argv) == 2 and \
            os.sys.argv[1] == '--owner-score-lineage-worker':
        try:
            owner_score_lineage_worker()
            return
        except BaseException:
            raise SystemExit(
                'private diagnostic lineage worker incomplete')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('observe', 'score', 'aggregate'))
    parser.add_argument('--selection', required=True); parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--owner-component', type=int, choices=(0, 1, 2)); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    try: print(json.dumps(run(args.operation, args.selection, args.selection_sha256, args.owner_component, args.execute), sort_keys=True))
    except BaseException: raise SystemExit('private diagnostic incomplete; preserve fixed consumed state')


if __name__ == '__main__': main()
