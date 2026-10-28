"""Public fake-data controls. No project import, tool, network or private IO.

The reviewed caller supplies admitted adapter bytes to run_controls(); only
listed pure functions and literal constants are compiled from that source.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import uuid
from urllib.parse import urlsplit


def run_controls(raw):
    names = {'need', 'encoded', 'sha', 'parse', 'hex_width', 'binding_check',
             'transport_check', 'without_caches', 'normalized_exact', 'native_outcomes', 'receiver_candidate',
             'publication_clocks', 'receiver_names', 'receiver_order', 'public_file', 'no_symlink_ancestors', 'save'}
    names.add('proof_outcome')
    tree = ast.parse(raw)
    selected = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names
                or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name)
                    and target.id == 'REQUEST_POLICY' for target in node.targets)]
    space = {'copy': copy, 'hashlib': hashlib, 'json': json, 'uuid': uuid, 'urlsplit': urlsplit,
             'time': time, 'os': os, 'Path': Path, 'stat': stat}
    exec(compile(ast.Module(body=selected, type_ignores=[]), '<public-pure-method03-controls>', 'exec'), space)
    controls = []
    def check(name, value):
        if not value:
            raise AssertionError(name)
        controls.append(name)
    def refused(name, call):
        try:
            call()
        except (ValueError, TypeError, KeyError, OSError):
            controls.append(name)
            return
        raise AssertionError(name)
    binding = {'method_sha256': '01' * 32, 'selection_sha256': '02' * 32,
        'trial_id': 'a005921c-7e9e-4c5f-8470-2ea68c80c379',
        'attempt_id': 'ba1995be-f006-466c-b6fa-01cfac41e36e', 'phase': 'private-exit-route-03'}
    space['binding_check'](binding); controls.append('exact-new-method03-binding')
    for field, replacement in [('phase', 'private-payout-linkage-02'), ('trial_id', 'not-a-uuid'),
                               ('selection_sha256', 'ab' * 31)]:
        value = {**binding, field: replacement}
        refused('binding-refuses-' + field, lambda value=value: space['binding_check'](value))
    refused('binding-refuses-caller-pass-field', lambda: space['binding_check']({**binding, 'accepted': True}))
    refused('duplicate-json-refused', lambda: space['parse'](b'{"accepted":false,"accepted":true}'))
    refused('nan-json-refused', lambda: space['parse'](b'{"x":NaN}'))
    proof = '03' * 128
    projection = '04' * 1844
    record = {'schema': 'kpb-exit-transport-arrival/v1', 'scope': 'UNTRUSTED_PUBLIC_TRANSPORT_ONLY',
        'financial_validation': 'NOT_RUN', 'broadcast': False, 'framing': 'PASS', 'http_status': 202,
        'received_body_bytes': 4096, 'arrival_sequence': 5, 'projection_hex': projection,
        'proof_hex128': proof, 'frame_sha256': '05' * 32,
        'exit_id': hashlib.sha256(bytes.fromhex(projection)).hexdigest()}
    check('receiver-retains-actual-positive-global-ordinal', space['receiver_candidate'](record)[0].hex() == projection
          and record['arrival_sequence'] == 5)
    sequences = [5, 2, 6, 1, 4, 3]
    names = ['arrival-%08d.json' % number for number in sequences]
    unordered = [{**record, 'arrival_sequence': number} for number in sequences]
    ordered = space['receiver_order'](names, unordered)
    check('filesystem-list-order-is-not-accepted-arrival-order', [item['arrival_sequence'] for item in ordered] == list(range(1, 7)))
    check('private-original-directory-enumeration-preserved', names == ['arrival-%08d.json' % number for number in sequences])
    refused('capture-refuses-extra-leaf-before-body-read', lambda: space['receiver_names'](names + ['OTHER.json']))
    refused('capture-refuses-sequence-filename-mismatch', lambda: space['receiver_order'](names[::-1], unordered))
    refused('capture-refuses-duplicate-global-sequence',
            lambda: space['receiver_order'](names, [*unordered[:-1], unordered[0]]))
    for field, replacement in [('arrival_sequence', True), ('arrival_sequence', 0), ('received_body_bytes', 4095),
                               ('projection_hex', '04' * 1796), ('proof_hex128', '03' * 127),
                               ('exit_id', '00' * 32), ('financial_validation', 'PASS')]:
        value = {**record, field: replacement}
        refused('receiver-refuses-' + field + '-' + str(len(controls)),
                lambda value=value: space['receiver_candidate'](value))
    report = {'isolation': 'PASS', 'Full': {'accepted': True},
              'all_input_engines_accepted': True, 'per_input_ScriptEngine': [{'accepted': True}]}
    check('complete-actual-report-positive-predicate', space['native_outcomes'](report, 0) == (True, True))
    check('direct-proof-result-positive-predicate', space['proof_outcome']({'accepted': True}, 0) is True)
    for name, result, code in [('boolean-returncode', {'accepted': True}, False),
                               ('nonzero-returncode', {'accepted': True}, 1),
                               ('missing-result', None, 0), ('false-result', {'accepted': False}, 0)]:
        check('proof-refuses-' + name, space['proof_outcome'](result, code) is False)
    for name, value, code in [('missing', None, 0), ('bare-accepted', {'accepted': True}, 0),
        ('wrong-isolation', {**report, 'isolation': 'FAIL'}, 0), ('nonzero-process', report, 1),
        ('boolean-process-code', report, False)]:
        check('native-refuses-' + name, space['native_outcomes'](value, code) == (False, False))
    for name, value in [('empty-engines', []), ('missing-engine-result', [{}]),
                        ('one-refusal', [{'accepted': False}]), ('extra-engine', [{'accepted': True}] * 2)]:
        check('native-refuses-' + name, space['native_outcomes']({**report, 'per_input_ScriptEngine': value}, 0)[1] is False)
    case = {'transaction': {'id': '00', 'mass': 0, 'payload': '1234', 'outputs': [{'value': 19}],
                            'inputs': [{'signatureScript': '0506'}]}, 'entries': [{'amount': 20}]}
    normalized = {'case': copy.deepcopy(case), 'financial_projection_hex': '07', 'exit_statement_hex152': '08'}
    normalized['case']['transaction'].update(id='99', mass=123)
    check('only-id-mass-normalization-permitted', space['normalized_exact'](case, normalized, b'\x07', b'\x08'))
    for field in ('payload', 'outputs', 'inputs'):
        value = copy.deepcopy(normalized); value['case']['transaction'][field] = 'tampered'
        check('normalization-refuses-' + field, not space['normalized_exact'](case, value, b'\x07', b'\x08'))
    value = copy.deepcopy(normalized); value['case']['entries'][0]['amount'] = 21
    check('normalization-refuses-reserve-change', not space['normalized_exact'](case, value, b'\x07', b'\x08'))
    value = {**normalized, 'financial_projection_hex': '09'}
    check('normalization-refuses-projection-change', not space['normalized_exact'](case, value, b'\x07', b'\x08'))
    value = {**normalized, 'exit_statement_hex152': '09'}
    check('normalization-refuses-statement-change', not space['normalized_exact'](case, value, b'\x07', b'\x08'))
    parameters = {'transport_source_sha256': '88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4',
        'receiver_source_sha256': '0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac',
        'tor_binary_sha256': '0a' * 32, 'curl_binary_sha256': '0b' * 32,
        'onion_endpoint': 'http://' + 'a' * 56 + '.onion/exit', 'request_policy': space['REQUEST_POLICY']}
    space['transport_check']({'A': parameters, 'B': parameters}); controls.append('actual-one-session-transport-shape')
    value = {**parameters, 'request_policy': {**parameters['request_policy'], 'retries': 1}}
    refused('transport-refuses-retry-retune', lambda: space['transport_check']({'A': value, 'B': value}))
    refused('transport-refuses-distinct-arm-parameters',
            lambda: space['transport_check']({'A': parameters, 'B': {**parameters, 'curl_binary_sha256': '0c' * 32}}))
    value = {**parameters, 'onion_endpoint': 'https://example.com/exit'}
    refused('transport-refuses-non-onion', lambda: space['transport_check']({'A': value, 'B': value}))
    check('index-written-after-public-exports', raw.index(b"result_ref = save(public_output")
          < raw.index(b"save(output, 'INDEX.json'"))
    check('index-never-self-hashes', b"sha(encoded(index))" not in raw and b"index_sha256" not in raw)
    clock = {'boot_id': 'a005921c-7e9e-4c5f-8470-2ea68c80c379', 'time_namespace': 'time:[7]',
             'time_for_children_namespace': 'time:[7]', 'timens_offsets': 'monotonic 0 0\nboottime 0 0\n'}
    evidence = space['publication_clocks'](clock, copy.deepcopy(clock))
    check('publication-clock-stable-observations-only', evidence['stable'] is True and evidence['boot_id'] == clock['boot_id'])
    for field in clock:
        value = {**clock, field: 'changed'}
        evidence = space['publication_clocks'](clock, value)
        check('publication-clock-retains-changed-' + field, evidence['stable'] is False
              and evidence['after'][field] == 'changed' and evidence['before'][field] == clock[field])
    with tempfile.TemporaryDirectory(prefix='kpb-method03-native-public-controls-') as directory:
        root = Path(directory); destination = root / 'output'; destination.mkdir()
        outside = root / 'outside'; outside.mkdir(); (destination / 'redirect').symlink_to(outside, target_is_directory=True)
        refused('artifact-symlink-ancestor-refused-before-write',
                lambda: space['save'](destination, 'redirect/CASE.json', {'public': True}))
        check('symlink-target-not-mutated', not (outside / 'CASE.json').exists())
        refused('artifact-traversal-refused', lambda: space['save'](destination, '../CASE.json', {'public': True}))
        ref = space['save'](destination, 'checks/CASE.json', {'known_public': True})
        check('exclusive-owned-single-link-artifact-roundtrip', ref['path'] == 'checks/CASE.json'
              and (destination / ref['path']).lstat().st_nlink == 1)
        refused('artifact-overwrite-refused', lambda: space['save'](destination, ref['path'], {'changed': True}))
    check('unknown-capture-names-checked-before-bodies', raw.index(b'receiver_names(names)  # Reject')
          < raw.index(b'records = [parse(public_file(capture / name))'))
    for forbidden in (b"'/original'", b"'/candidate'", b"'/home/luke/.codex'", b"'/home/luke/.ssh'"):
        check('boundary-forbidden-alias-' + forbidden.decode(), forbidden in raw)
    # Execute only the top-level status wrapper with a synthetic local error;
    # never invoke produce(), namespace checks, tools or input readers.
    import argparse
    import contextlib
    import io
    import sys
    main_node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
    def refused_producer(_args):
        raise ValueError('PRIVATE_BODY_SENTINEL_NEVER_PUBLISH')
    wrapper = {'os': os, 'argparse': argparse, 'json': json, '__doc__': 'public fake status control',
               'produce': refused_producer}
    exec(compile(ast.Module(body=[main_node], type_ignores=[]), '<public-fake-status-wrapper>', 'exec'), wrapper)
    captured, stderr = io.StringIO(), io.StringIO()
    previous = sys.argv
    try:
        sys.argv = ['method03_native.py', '--specification', '/public/SPEC.json', '--specification-sha256', '00' * 32]
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(stderr):
            code = wrapper['main']()
    finally:
        sys.argv = previous
    check('fixed-refusal-nonzero-no-private-traceback', code == 1 and stderr.getvalue() == ''
          and json.loads(captured.getvalue()) == {'schema': 'kpb-method03-native-completion/v1',
              'status': 'REFUSED', 'actual_checks_passed': False, 'fullpacket_available': False}
          and 'PRIVATE_BODY_SENTINEL' not in captured.getvalue())
    return {'schema': 'kpb-method03-native-public-controls/v1', 'source_sha256': hashlib.sha256(raw).hexdigest(),
        'status': 'PASS', 'controls': controls, 'count': len(controls),
        'actual_native_calls': 0, 'actual_proof_calls': 0, 'private_input_reads': 0, 'network_calls': 0,
        'classification': 'PUBLIC_FAKE_PURE_FUNCTION_SOURCE_CONTROLS_ONLY'}
