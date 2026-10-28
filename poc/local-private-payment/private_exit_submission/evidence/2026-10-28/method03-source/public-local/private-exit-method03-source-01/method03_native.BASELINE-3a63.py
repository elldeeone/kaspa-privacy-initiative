#!/usr/bin/env python3
"""METHOD03 received-byte proof/Native producer; SOURCE CANDIDATE ONLY.

Run only in the separately selected, network-off capture role. Its controller
may inspect the fixed completion and output metadata, never INDEX.json or its
hash. The entry and ce guard must be externally admitted/preloaded first.
No setup, proving key, Original, accepted-chain or broadcast API exists here.
"""
import argparse
import copy
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import stat
import sys
import time
import types
import uuid
from urllib.parse import urlsplit


ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
WALLET = ROOT / 'poc/local-private-payment/private_batch_trial'
FROZEN_SELECTION = ROOT / '.local/private-payout-linkage-02/original-paired-03/SELECTION.json'
FROZEN_SELECTION_SHA = 'bd9c1c02e918f6a11286d17c7cb0910e14eacf9b9233252b944eaeda78dc9b93'
HELPER_SHA = 'e64db83fa2feeec491105c2b9f59a5c288b9e57e8978e317eb37ffce0a46ea8b'
GUARD_SHA = 'ce86998d7ddfe404cc1c194cda064d369ca1bd78c8df674e43b2381da1d3a4b1'
PINS = {
    'codec': 'cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7',
    'engine': '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061',
    'verifier': '930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6',
    'parameters': '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751',
    'manifest': 'bc41c97e06f07a06ee9ab2af59ef1ba8c5190a126dfb0eb120d586667aaddd8f',
    'tail': '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d',
}
IDENTITY = (
    'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
    'd68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf',
    'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700',
    'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0',
    'ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5',
)
REQUEST_POLICY = {'method': 'POST', 'http_version': '1.0', 'frame_bytes': 4096,
    'success_status': 202, 'redirects': 0, 'retries': 0, 'proxy': 'SOCKS5_HOSTNAME',
    'isolate_socks_auth': True, 'socks_timeout_seconds': 900, 'fallback': 'NONE',
    'user_agent': 'kpb-exit-transport/1', 'accept': 'application/octet-stream',
    'content_type': 'application/octet-stream', 'expect': ''}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    def nonfinite(_value):
        raise ValueError('nonfinite-json')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def hex_width(value, size):
    return type(value) is str and len(value) == size * 2 and all(c in '0123456789abcdef' for c in value)


def binding_check(value):
    need(type(value) is dict and set(value) == {
        'method_sha256', 'selection_sha256', 'trial_id', 'phase', 'attempt_id'}, 'method03-binding-fields')
    need(hex_width(value['method_sha256'], 32) and hex_width(value['selection_sha256'], 32)
         and value['phase'] == 'private-exit-route-03', 'method03-binding-scope')
    for field in ('trial_id', 'attempt_id'):
        need(type(value[field]) is str and str(uuid.UUID(value[field])) == value[field], 'canonical-trial-identity')


def transport_check(value):
    need(type(value) is dict and set(value) == {'A', 'B'} and value['A'] == value['B'],
         'both-arms-one-actual-session-parameters')
    fields = {'transport_source_sha256', 'tor_binary_sha256', 'curl_binary_sha256',
              'onion_endpoint', 'receiver_source_sha256', 'request_policy'}
    for row in value.values():
        need(type(row) is dict and set(row) == fields
             and all(hex_width(row[field], 32) for field in fields if field.endswith('_sha256'))
             and row['transport_source_sha256'] == '88cb8d0c0eb7c8a533556f7323d30c115a56a97a53b45263b3f0932dbbeba4f4'
             and row['receiver_source_sha256'] == '0375401b3f3b2844c60e78bf4450cf1ad7f8e574462bc98b71395078d07601ac'
             and type(row['request_policy']) is dict and encoded(row['request_policy']) == encoded(REQUEST_POLICY),
             'actual-fixed-transport-parameters')
        need(type(row['onion_endpoint']) is str, 'onion-endpoint-type')
        endpoint = urlsplit(row['onion_endpoint'])
        host = endpoint.hostname or ''
        need(endpoint.scheme == 'http' and len(host) == 62 and host.endswith('.onion')
             and all(c in 'abcdefghijklmnopqrstuvwxyz234567' for c in host[:-6])
             and endpoint.port in (None, 80) and endpoint.path == '/exit'
             and endpoint.username is None and endpoint.password is None
             and not endpoint.query and not endpoint.fragment, 'actual-one-session-onion-endpoint')


def public_file(path):
    """Stable owned single-link leaf. Used only INSIDE the capture-only role."""
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(path)
         and not any(item.is_symlink() for item in (path, *path.parents)), 'capture-leaf-path')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1,
         'capture-owned-regular-single-link')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        after = os.fstat(fd)
    finally:
        os.close(fd)
    key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                        info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    need(key(before) == key(after) == key(path.lstat()), 'capture-leaf-changed')
    return raw


def save(root, relative, value, *, raw=False):
    path = root / relative
    need(not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'artifact-relative-path')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = value if raw else encoded(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, 'wb') as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need(public_file(path) == data, 'generated-artifact-readback')
    return {'path': relative, 'sha256': sha(data)}


def observed_clock():
    return {'monotonic_ns': time.monotonic_ns(), 'unix_ns': time.time_ns(),
            'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME)}


def clock_evidence():
    # These are observed kernel identities/offset text, not a synchronization
    # claim. Namespace comparison and any uncertainty belong to the scorer.
    with open('/proc/self/timens_offsets', 'r', encoding='ascii') as source:
        offsets = source.read()
    return {'time_namespace': os.readlink('/proc/self/ns/time'),
        'time_for_children_namespace': os.readlink('/proc/self/ns/time_for_children'),
        'timens_offsets': offsets, 'kernel_clock_ids': {
            'monotonic': time.CLOCK_MONOTONIC, 'boottime': time.CLOCK_BOOTTIME, 'realtime': time.CLOCK_REALTIME}}


def without_caches(case):
    value = copy.deepcopy(case)
    for field in ('id', 'mass'):
        value['transaction'].pop(field, None)
    return value


def normalized_exact(before, normalized, projection, statement):
    return (type(normalized) is dict and normalized.get('financial_projection_hex') == projection.hex()
        and normalized.get('exit_statement_hex152') == statement.hex()
        and encoded(without_caches(normalized['case'])) == encoded(without_caches(before)))


def native_outcomes(report, returncode):
    """Only a real selected process and its complete report can be positive."""
    isolated = type(report) is dict and report.get('isolation') == 'PASS'
    full = isolated and type(report.get('Full')) is dict and report['Full'].get('accepted') is True
    scripts = (isolated and report.get('all_input_engines_accepted') is True
        and type(report.get('per_input_ScriptEngine')) is list
        and len(report['per_input_ScriptEngine']) == 1
        and all(type(item) is dict and item.get('accepted') is True for item in report['per_input_ScriptEngine']))
    return type(returncode) is int and returncode == 0 and full, type(returncode) is int and returncode == 0 and scripts


def receiver_candidate(record):
    need(type(record) is dict and record.get('schema') == 'kpb-exit-transport-arrival/v1'
         and record.get('scope') == 'UNTRUSTED_PUBLIC_TRANSPORT_ONLY'
         and record.get('financial_validation') == 'NOT_RUN' and record.get('broadcast') is False
         and record.get('framing') == 'PASS' and record.get('http_status') == 202
         and record.get('received_body_bytes') == 4096, 'actual-receiver037-pass-record')
    need(type(record.get('arrival_sequence')) is int and record['arrival_sequence'] >= 1
         and hex_width(record.get('projection_hex'), 1844)
         and hex_width(record.get('proof_hex128'), 128)
         and hex_width(record.get('frame_sha256'), 32)
         and hex_width(record.get('exit_id'), 32), 'strict-continuing-received-widths')
    projection = bytes.fromhex(record['projection_hex'])
    need(sha(projection) == record['exit_id'], 'received-projection-identity')
    return projection, bytes.fromhex(record['proof_hex128'])


def load_helpers():
    """Use the exact reviewed 30-source closure, never the live project tree."""
    # The selected caller preloads these exact ce bytes before this entry.
    need('payout_linkage_guard' in sys.modules, 'externally-admitted-ce-preload-required')
    for module in tuple(sys.modules.values()):
        source = getattr(module, '__file__', None)
        if source and str(Path(source).absolute()).startswith(str(ROOT) + '/'):
            need(str(Path(source).absolute()) in (str(Path(__file__).absolute()),
                 str(WALLET / 'payout_linkage_guard.py')), 'unexpected-preloaded-project-source')
    from payout_linkage_guard import load_guard
    import payout_linkage_guard
    payout_linkage_guard.PRIVATE_ROOTS = tuple(dict.fromkeys((*payout_linkage_guard.PRIVATE_ROOTS,
        Path('/var/tmp/kpi-local-private-payment-01/assets/ingress-runtime/tor-state'))))
    guard = load_guard()
    read = guard['read']
    need(sha(read(Path(payout_linkage_guard.__file__), GUARD_SHA)) == GUARD_SHA, 'selected-ce-guard')
    selection = parse(read(FROZEN_SELECTION, FROZEN_SELECTION_SHA))
    shared = Path(selection['public']) / 'selected-public'
    frozen = {str(Path(row['path']).absolute()): read(shared / ('source-' + str(row['index'])), row['sha256'])
              for row in selection['source_members']}
    need(len(frozen) == 30, 'exact-retained-public-source-closure')
    previous_get_code = importlib.machinery.SourceFileLoader.get_code
    previous_exec = importlib.machinery.SourceFileLoader.exec_module

    def selected_read(path, expected=None):
        name = str(Path(path).absolute())
        if name in frozen:
            data = frozen[name]
            need(expected is None or sha(data) == expected, 'frozen-source-digest')
            return data
        return read(path, expected)

    def get_code(loader, fullname):
        name = str(Path(loader.path).absolute())
        if name in frozen:
            return compile(frozen[name], name, 'exec')
        need(not name.startswith(str(ROOT) + '/'), 'unselected-project-import')
        return previous_get_code(loader, fullname)

    selected_guard = lambda: {**guard, 'read': selected_read}
    def exec_module(loader, module):
        previous_exec(loader, module)
        if str(Path(loader.path).absolute()) == str(WALLET / 'payout_linkage_guard.py'):
            module.load_guard = selected_guard

    importlib.machinery.SourceFileLoader.get_code = get_code
    importlib.machinery.SourceFileLoader.exec_module = exec_module
    payout_linkage_guard.load_guard = selected_guard
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(WALLET))
    helper_path = WALLET / 'payout_linkage_native.py'
    helper = types.ModuleType('_method03_selected_received_native_helpers')
    helper.__file__ = str(helper_path)
    sys.modules[helper.__name__] = helper
    exec(compile(selected_read(helper_path, HELPER_SHA), str(helper_path), 'exec'), helper.__dict__)
    return helper, guard, selected_read


def make_case(native, body, projection, proof, redeem, emitted):
    signature = b'\x4c\x80' + proof + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
    outputs = native.exit_wire.parse_projection(projection)[2]
    return {'transaction': {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': {'transactionId': body.context.point[:32].hex(),
            'index': int.from_bytes(body.context.point[32:], 'little')},
            'signatureScript': signature.hex(), 'sequence': (1 << 64) - 1, 'computeBudget': 1800}],
        'outputs': [{'value': amount, 'scriptPublicKey': spk.hex(), 'covenant': None} for amount, spk in outputs],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': body.raw.hex(), 'mass': 0},
        'entries': [{'amount': body.context.reserve, 'scriptPublicKey': emitted['script_public_key'],
            'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}]}


def check_one(native, read, record, ordinal, binding, pins, contexts, parameters, tail, manifest, output):
    projection, proof = receiver_candidate(record)
    body = native.exit_wire.validate_public(projection)
    need(sum(body.context == context for context in contexts.values()) == 1, 'received-selected-public-context')
    native.exit_wire.require_current_head(projection, body.context, tail)
    need(body.new_reserve > 0 and body.fee == 1 and body.payout == 199_999_999
         and body.context.reserve == 6_000_000_000 and body.context.cm_count == 3 and body.context.nf_count == 1,
         'frozen-method03-economic-shape-no-fee-retune')
    statement = native.exit_wire.statement(projection)
    request = {'operation': 'verify', 'role': 'new-auth-exit',
        'profile': {'domain_hex32': body.context.domain.hex(), 'profile_id_hex32': body.context.profile.hex()},
        'statement_hex': statement.hex(), 'proof_hex128': proof.hex(),
        'parameters': {'manifest': '/parameters/MANIFEST.json', 'manifest_sha256': PINS['manifest']}}
    proof_process = native.tool(native.bootstrap.BINARY, request,
        mounts=['--ro-bind', str(manifest), '/parameters/MANIFEST.json'], require_success=False)
    try:
        proof_result = parse(proof_process.stdout)
    except (ValueError, TypeError):
        proof_result = None
    proof_passed = proof_process.returncode == 0 and type(proof_result) is dict and proof_result.get('accepted') is True
    prefix = 'checks/%06d/' % ordinal
    proof_ref = save(output, prefix + 'proof-result.json', {
        'schema': 'kpb-method03-direct-AuthExit-verification/v1', 'request': request,
        'returncode': proof_process.returncode, 'actual_result': proof_result,
        'stdout_sha256': sha(proof_process.stdout), 'stderr_sha256': sha(proof_process.stderr)})
    emitted = parse(native.tool(native.study.CODEC, {'operation': 'emit', 'parameters': parameters,
                                                  'state_hex112': body.context.state().hex()}))
    redeem = bytes.fromhex(emitted['redeem_hex'])
    need(redeem == b'\x4c\x70' + body.context.state() + tail, 'actual-selected-redeem')
    case = make_case(native, body, projection, proof, redeem, emitted)
    normalized_raw = native.tool(native.study.CODEC, {'operation': 'normalize', 'parameters': parameters, 'case': case})
    normalized = parse(normalized_raw)
    need(normalized_exact(case, normalized, projection, statement), 'exact-financial-case-only-cache-normalization')
    case_ref = save(output, prefix + 'CASE.json', normalized['case'])
    normalization_ref = save(output, prefix + 'normalization.json', normalized_raw, raw=True)
    destination = output / ('checks/%06d' % ordinal)
    case_path = output / case_ref['path']
    native_out = destination / 'actual-native'
    process = native.tool(native.study.NATIVE,
        mounts=['--ro-bind', str(case_path), str(case_path), '--bind', str(destination), str(destination)],
        arguments=['validate-transaction', str(case_path), str(native_out)], require_success=False)
    report_path = native_out / 'native-validation.json'
    report = None
    if report_path.exists():
        report_raw = read(report_path)
        try:
            report = parse(report_raw)
        except (ValueError, TypeError):
            pass
        report_ref = save(output, prefix + 'native-report.json', report_raw, raw=True)
    else:
        report_ref = save(output, prefix + 'native-report-missing.json', {
            'schema': 'kpb-method03-missing-native-report/v1', 'actual_result': None,
            'returncode': process.returncode})
    full, scripts = native_outcomes(report, process.returncode)
    row = {'schema': 'kpb-method03-received-native-check/v1', 'binding': binding, 'ordinal': ordinal,
        'receiver_row_sha256': sha(encoded(record)), 'projection_sha256': sha(projection), 'proof_sha256': sha(proof),
        'source_pins': pins, 'actual_native_returncode': process.returncode, 'native_full_accepted': full,
        'all_scripts_passed': scripts, 'actual_public_proof_verified': proof_passed,
        'isolation': {'network': 'none', 'input_scope': 'unlabelled-public-received-exits', 'originals_mounted': False},
        'artifact_refs': {'case': case_ref, 'normalization': normalization_ref,
                          'native_report': report_ref, 'proof_result': proof_ref}}
    save(output, prefix + 'CHECK.json', row)
    return row, body.nf


def produce(args):
    # Only the fixed closed-role launcher can create this readonly marker and
    # mounts. It is not a caller-supplied acceptance or financial capability.
    need(public_file(Path('/NO-ORIGINAL-METHOD03-NATIVE')) == b'METHOD03_CAPTURE_ONLY_NETWORK_OFF\n',
         'selected-closed-capture-role-required')
    native, guard, read = load_helpers()
    specification = parse(read(Path(args.specification), args.specification_sha256))
    need(type(specification) is dict and set(specification) == {
        'schema', 'binding', 'source_pins', 'public_notes', 'transport_parameters'}
        and specification['schema'] == 'kpb-method03-received-native-specification/v1', 'exact-method03-native-specification')
    binding = specification['binding']; binding_check(binding)
    pins = {'adapter': sha(read(Path(__file__))), **PINS}
    need(specification['source_pins'] == pins, 'externally-selected-exact-adapter-and-tool-pins')
    notes_ref = specification['public_notes']
    need(type(notes_ref) is dict and set(notes_ref) == {'path', 'sha256'} and hex_width(notes_ref['sha256'], 32),
         'selected-public-notes-reference')
    notes_raw = read(Path(notes_ref['path']), notes_ref['sha256']); notes = parse(notes_raw)
    need(type(notes) is dict and set(notes) == {'schema', 'binding', 'arms'}
         and notes['schema'] == 'kpb-method03-unlabelled-notes/v1' and notes['binding'] == binding
         and type(notes['arms']) is dict and set(notes['arms']) == {'A', 'B'}, 'bound-unlabelled-public-notes')
    contexts = {}
    for arm in ('A', 'B'):
        value = notes['arms'][arm]
        need(type(value) is dict and set(value) == {'context_hex276', 'rows_hex520'}
             and hex_width(value['context_hex276'], 276) and type(value['rows_hex520']) is list
             and len(value['rows_hex520']) == 3 and all(hex_width(row, 520) for row in value['rows_hex520']),
             'selected-public-arm-head')
        context = native.exit_wire.HeadContext.parse(bytes.fromhex(value['context_hex276']))
        need(tuple(field.hex() for field in (context.chain, context.pool, context.profile, context.domain, context.service))
             == IDENTITY, 'fixed-existing-profile-identity')
        contexts[arm] = context
    need(contexts['A'].cm_root != contexts['B'].cm_root and contexts['A'].point != contexts['B'].point,
         'independent-contexts')
    transport = specification['transport_parameters']
    transport_check(transport)
    for path, pin in ((native.study.CODEC, PINS['codec']), (native.study.NATIVE, PINS['engine']),
                      (native.bootstrap.BINARY, PINS['verifier'])):
        read(path, pin)  # Verify selected bytes BEFORE any tool invocation.
    parameters = parse(read(native.study.PARAMETERS, PINS['parameters']))
    tail = read(native.study.TAIL, PINS['tail'])
    manifest = native.lifecycle.EXIT_PARAMETERS / 'MANIFEST.json'
    read(manifest, PINS['manifest'])
    capture, output, public_output = Path(args.capture), Path(args.output), Path(args.public_output)
    need(capture == Path('/capture/arrivals') and capture.is_dir() and not capture.is_symlink(), 'fixed-capture-only-alias')
    need(output == Path('/native/result') and not output.exists(), 'fresh-private-native-output-alias')
    need(public_output == Path('/public-output/result') and not public_output.exists(), 'fresh-public-export-alias')
    output.mkdir(mode=0o700)
    public_output.mkdir(mode=0o700)
    # Preserve actual directory enumeration/file order. The accepted ordinal
    # is arrival_sequence, never this list's position or an arm/owner order.
    names = os.listdir(capture)
    need(len(names) == 6 and set(names) == {'arrival-%08d.json' % index for index in range(1, 7)},
         'all-six-actual-receiver-files-no-filtering')
    records = [parse(public_file(capture / name)) for name in names]
    need({record.get('arrival_sequence') for record in records} == set(range(1, 7))
         and all(name == 'arrival-%08d.json' % record['arrival_sequence'] for name, record in zip(names, records)),
         'actual-receiver-capture-order')
    notes_artifact = save(output, 'PUBLIC-NOTES.json', notes_raw, raw=True)
    checks, nfs, errors = [], [], []
    for record in records:
        ordinal = record['arrival_sequence']
        try:
            check, nf = check_one(native, read, record, ordinal, binding, pins, contexts, parameters, tail, manifest, output)
            checks.append(check); nfs.append(nf)
        except (ValueError, TypeError, KeyError, OSError) as error:
            # Never manufacture a report or silently drop the original record.
            # Missing checks force extractor refusal; every original is kept.
            errors.append({'ordinal': ordinal, 'category': type(error).__name__})
    passed = (len(checks) == 6 and len(set(nfs)) == 6 and all(row['native_full_accepted']
        and row['all_scripts_passed'] and row['actual_public_proof_verified'] for row in checks))
    save(output, 'PRIVATE-COMPLETION.json', {'all_six_actual_checks_passed': passed, 'errors': errors})
    # Only chain-visible projection/proof/statement bytes cross to the public
    # export. Verify public context counts, preserve actual raw record order,
    # and publish no private path, owner, arm label or graph.
    public_records, context_counts = [], {'A': 0, 'B': 0}
    for record in records:
        projection, proof = receiver_candidate(record)
        body = native.exit_wire.validate_public(projection)
        matches = [arm for arm, context in contexts.items() if body.context == context]
        need(len(matches) == 1, 'public-export-exact-context-partition')
        context_counts[matches[0]] += 1
        public_records.append({'ordinal': record['arrival_sequence'],
            'projection_hex': projection.hex(), 'proof_hex128': proof.hex(),
            'statement_hex152': native.exit_wire.statement(projection).hex(), 'exit_id': sha(projection)})
    need(set(context_counts.values()) == {3}, 'three-received-projections-per-public-context')
    kernel_clocks = clock_evidence()
    publication_started = observed_clock()
    exits_ref = save(public_output, 'EXITS.json', {'schema': 'kpb-method03-unlabelled-exits/v1',
                                                'binding': binding, 'records': public_records})
    public_result = {'schema': 'kpb-method03-received-native-result/v1', 'binding': binding,
        'source_pins': pins, 'records_seen': len(records), 'checks_completed': len(checks),
        'all_six_actual_checks_passed': passed, 'records': checks,
        'artifact_scope': 'PRIVATE_CAPTURE_ROLE_RELATIVE_NATIVE_ARTIFACTS',
        'public_exits': exits_ref, 'fullpacket_available': False,
        'classification': 'INDIVIDUAL_UNFUNDED_SUPPLIED_CONTEXTS_NO_CHAIN_OR_PRIVACY_AUTHORITY'}
    result_ref = save(public_output, 'NATIVE-RESULT.json', public_result)
    publication_finished = observed_clock()
    publication = {'schema': 'kpb-method03-native-publication/v1', 'pid': os.getpid(),
        'clock_evidence': kernel_clocks, 'before_public_write': publication_started,
        'after_public_fsync': publication_finished,
        'public_artifacts': {'exits': exits_ref, 'native_result': result_ref}}
    index = {'schema': 'kpb-method03-receiver-index/v1', 'binding': binding, 'records': records,
        'transport_parameters': transport,
        'public_heads': [{'arm': arm, 'context_hex276': contexts[arm].encode().hex(),
                          'evidence_ref': notes_artifact} for arm in ('A', 'B')],
        'native_reports': checks, 'publication_metadata': publication}
    save(output, 'INDEX.json', index)
    index_info = (output / 'INDEX.json').lstat()
    # Fixed metadata-only host return: no body, projection/packet/id/index hash,
    # owner label, or candidate-labelled proof/report digest crosses this seam.
    return {'schema': 'kpb-method03-native-completion/v1', 'status': 'COMPLETE' if passed else 'UNQUALIFIED',
        'records_seen': len(records), 'checks_completed': len(checks), 'actual_checks_passed': passed,
        'index_path': '/native/result/INDEX.json', 'fullpacket_available': False,
        'private_index': {'path': '/native/result/INDEX.json', 'metadata': {
            'device': index_info.st_dev, 'inode': index_info.st_ino, 'size': index_info.st_size,
            'mode': stat.S_IMODE(index_info.st_mode), 'uid': index_info.st_uid, 'nlink': index_info.st_nlink,
            'mtime_ns': index_info.st_mtime_ns, 'ctime_ns': index_info.st_ctime_ns}},
        'public_exits': {'path': str(public_output / exits_ref['path']), 'sha256': exits_ref['sha256']},
        'native_public_result': {'path': str(public_output / result_ref['path']), 'sha256': result_ref['sha256']},
        'classification': 'INDIVIDUAL_UNFUNDED_SUPPLIED_CONTEXTS_NO_CHAIN_OR_PRIVACY_AUTHORITY'}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--specification', required=True)
    parser.add_argument('--specification-sha256', required=True)
    parser.add_argument('--capture', default='/capture/arrivals')
    parser.add_argument('--output', default='/native/result')
    parser.add_argument('--public-output', default='/public-output/result')
    print(json.dumps(produce(parser.parse_args()), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
