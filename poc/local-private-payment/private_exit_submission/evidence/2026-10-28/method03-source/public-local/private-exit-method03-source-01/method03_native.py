#!/usr/bin/env python3
"""METHOD03 received-byte proof/Native producer; SOURCE CANDIDATE ONLY.

Run only in the separately selected, network-off capture role. Its controller
may inspect the fixed completion and output metadata, never INDEX.json or its
hash. The outer launcher must guard-admit all public bytes before staging.
No setup, proving key, Original, accepted-chain or broadcast API exists here.
"""
import argparse
import copy
import errno
import fcntl
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import time
import types
import uuid
from urllib.parse import urlsplit


CODEC, ENGINE, VERIFIER = (Path('/tools') / name for name in ('codec', 'engine', 'verifier'))
PARAMETERS, MANIFEST, TAIL = (Path('/parameters') / name for name in
    ('PARAMETERS.json', 'MANIFEST.json', 'IMMUTABLE-TAIL.bin'))
WIRE_SOURCES = {
    '/app/trial/exit_wire.py': 'fabf7361f030e25ec4a52a72691fef4bcfe03f6fef369ff33b8fa55dd01ccb6a',
    '/app/verification/wire.py': '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8',
}
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


def no_symlink_ancestors(path):
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(path), 'canonical-output-path')
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        need(not stat.S_ISLNK(info.st_mode), 'output-symlink-before-mutation')


def close_setup_fds():
    # Exact owner7d startup rule: close bwrap's setup descriptors before any
    # capture/project read. Only listdir's own already-closed FD may be EBADF.
    for text in os.listdir('/proc/self/fd'):
        descriptor = int(text)
        if descriptor > 2:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise


def capture_boundary():
    ambient = []
    for text in os.listdir('/proc/self/fd'):
        descriptor = int(text)
        if descriptor > 2:
            try:
                os.fstat(descriptor)
                ambient.append(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
    need(not ambient, 'capture-role-no-ambient-descriptors')
    stdin, stdout = os.fstat(0), os.fstat(1)
    need(stat.S_ISCHR(stdin.st_mode) and stdin.st_rdev == os.makedev(1, 3), 'capture-role-stdin-devnull')
    flags = fcntl.fcntl(1, fcntl.F_GETFL)
    need(stat.S_ISFIFO(stdout.st_mode) and flags & os.O_ACCMODE == os.O_WRONLY
         and not flags & os.O_NONBLOCK, 'capture-role-status-only-blocking-stdout')
    interfaces = socket.if_nameindex()
    need([name for _index, name in interfaces] == ['lo'], 'capture-role-no-network-interface')
    with open('/proc/net/route', 'r', encoding='ascii') as source:
        routes = source.read()
    need(len(routes.splitlines()) == 1, 'capture-role-no-network-route')
    for forbidden in ('/owner', '/Original', '/original', '/candidate', '/PK',
                      '/home/luke/.codex', '/home/luke/.ssh', '/var/tmp/kpi-owner-private-lifecycle-01',
                      '/var/tmp/kpi-four-wallet-local-rehearsal-01', '/var/tmp/kpi-four-wallet-live-01'):
        need(not os.path.lexists(forbidden), 'capture-role-no-owner-original-pk-mount')
    need(set(os.listdir('/tools')) == {'codec', 'engine', 'verifier'}
         and set(os.listdir('/parameters')) == {'PARAMETERS.json', 'MANIFEST.json', 'IMMUTABLE-TAIL.bin'},
         'capture-role-finite-public-tools-and-parameters-no-pk')
    return {'schema': 'kpb-method03-observed-native-boundary/v1', 'pid': os.getpid(),
        'network_namespace': os.readlink('/proc/self/ns/net'), 'interfaces': interfaces,
        'route_table': routes, 'ambient_descriptors': ambient,
        'launcher_mount_authority_required': True}


def save(root, relative, value, *, raw=False):
    path = root / relative
    need(type(relative) is str and relative == Path(relative).as_posix() and relative not in ('', '.')
         and not Path(relative).is_absolute() and '..' not in Path(relative).parts, 'artifact-relative-path')
    no_symlink_ancestors(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    no_symlink_ancestors(path)
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
    with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as source:
        boot_id = source.read().strip()
    need(str(uuid.UUID(boot_id)) == boot_id, 'actual-canonical-kernel-boot-identity')
    return {'boot_id': boot_id, 'time_namespace': os.readlink('/proc/self/ns/time'),
        'time_for_children_namespace': os.readlink('/proc/self/ns/time_for_children'),
        'timens_offsets': offsets}


def publication_clocks(before, after):
    return {'boot_id': before['boot_id'], 'before': before, 'after': after, 'stable': before == after,
        'kernel_clock_ids': {'monotonic': time.CLOCK_MONOTONIC,
                            'boottime': time.CLOCK_BOOTTIME, 'realtime': time.CLOCK_REALTIME}}


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


def proof_outcome(result, returncode):
    return type(returncode) is int and returncode == 0 and type(result) is dict and result.get('accepted') is True


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


def receiver_names(names):
    need(len(names) == 6 and set(names) == {'arrival-%08d.json' % index for index in range(1, 7)},
         'all-six-actual-receiver-files-no-filtering')


def receiver_order(names, records):
    receiver_names(names)
    need(len(records) == 6 and all(type(record) is dict for record in records), 'exact-six-receiver-objects')
    need(all(type(record.get('arrival_sequence')) is int for record in records)
         and {record['arrival_sequence'] for record in records} == set(range(1, 7))
         and all(name == 'arrival-%08d.json' % record['arrival_sequence'] for name, record in zip(names, records)),
         'actual-receiver-capture-order')
    return sorted(records, key=lambda record: record['arrival_sequence'])


def admitted_read(path, expected=None):
    data = public_file(path)
    need(expected is None or sha(data) == expected, 'selected-closed-role-leaf-digest')
    return data


def load_wire():
    """Two pure selected sources, preserving exit_wire's relative layout."""
    frozen = {name: admitted_read(Path(name), pin) for name, pin in WIRE_SOURCES.items()}
    previous = importlib.machinery.SourceFileLoader.get_code
    def selected_code(loader, fullname):
        name = str(Path(loader.path).absolute())
        if name in frozen:
            return compile(frozen[name], name, 'exec')
        need(not name.startswith('/app/'), 'unselected-application-source')
        return previous(loader, fullname)
    importlib.machinery.SourceFileLoader.get_code = selected_code
    sys.dont_write_bytecode = True
    wire = types.ModuleType('_method03_selected_exit_wire')
    wire.__file__ = '/app/trial/exit_wire.py'
    sys.modules[wire.__name__] = wire
    exec(compile(frozen[wire.__file__], wire.__file__, 'exec'), wire.__dict__)
    return wire


def tool(binary, payload=None, *, mounts=(), arguments=(), require_success=True):
    # Same selected e64 tool boundary: no shell/network/private mounts; each
    # tool sees only its exact public request and explicitly listed leaves.
    argv = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin', '--symlink', 'usr/lib', '/lib',
        '--symlink', 'usr/lib64', '/lib64', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
        '--ro-bind', str(binary), '/public/tool', *mounts, '--chdir', '/tmp',
        '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'LANG', 'C.UTF-8', '/public/tool', *arguments]
    result = subprocess.run(argv, input=None if payload is None else encoded(payload),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
    if require_success:
        need(result.returncode == 0, 'selected-public-tool-refused')
        return result.stdout
    return result


def make_case(wire, body, projection, proof, redeem, emitted):
    signature = b'\x4c\x80' + proof + b'\x4d' + len(redeem).to_bytes(2, 'little') + redeem
    outputs = wire.parse_projection(projection)[2]
    return {'transaction': {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': {'transactionId': body.context.point[:32].hex(),
            'index': int.from_bytes(body.context.point[32:], 'little')},
            'signatureScript': signature.hex(), 'sequence': (1 << 64) - 1, 'computeBudget': 1800}],
        'outputs': [{'value': amount, 'scriptPublicKey': spk.hex(), 'covenant': None} for amount, spk in outputs],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': body.raw.hex(), 'mass': 0},
        'entries': [{'amount': body.context.reserve, 'scriptPublicKey': emitted['script_public_key'],
            'blockDaaScore': 0, 'isCoinbase': False, 'covenantId': None}]}


def check_one(wire, record, ordinal, binding, pins, contexts, parameters, tail, output):
    projection, proof = receiver_candidate(record)
    body = wire.validate_public(projection)
    need(sum(body.context == context for context in contexts.values()) == 1, 'received-selected-public-context')
    wire.require_current_head(projection, body.context, tail)
    need(body.new_reserve > 0 and body.fee == 1 and body.payout == 199_999_999
         and body.context.reserve == 6_000_000_000 and body.context.cm_count == 3 and body.context.nf_count == 1,
         'frozen-method03-economic-shape-no-fee-retune')
    statement = wire.statement(projection)
    request = {'operation': 'verify', 'role': 'new-auth-exit',
        'profile': {'domain_hex32': body.context.domain.hex(), 'profile_id_hex32': body.context.profile.hex()},
        'statement_hex': statement.hex(), 'proof_hex128': proof.hex(),
        'parameters': {'manifest': '/parameters/MANIFEST.json', 'manifest_sha256': PINS['manifest']}}
    proof_process = tool(VERIFIER, request,
        mounts=['--ro-bind', str(MANIFEST), '/parameters/MANIFEST.json'], require_success=False)
    try:
        proof_result = parse(proof_process.stdout)
    except (ValueError, TypeError):
        proof_result = None
    proof_passed = proof_outcome(proof_result, proof_process.returncode)
    prefix = 'checks/%06d/' % ordinal
    proof_ref = save(output, prefix + 'proof-result.json', {
        'schema': 'kpb-method03-direct-AuthExit-verification/v1', 'request': request,
        'returncode': proof_process.returncode, 'actual_result': proof_result,
        'stdout_sha256': sha(proof_process.stdout), 'stderr_sha256': sha(proof_process.stderr)})
    emitted = parse(tool(CODEC, {'operation': 'emit', 'parameters': parameters,
                                                  'state_hex112': body.context.state().hex()}))
    redeem = bytes.fromhex(emitted['redeem_hex'])
    need(redeem == b'\x4c\x70' + body.context.state() + tail, 'actual-selected-redeem')
    case = make_case(wire, body, projection, proof, redeem, emitted)
    normalized_raw = tool(CODEC, {'operation': 'normalize', 'parameters': parameters, 'case': case})
    normalized = parse(normalized_raw)
    need(normalized_exact(case, normalized, projection, statement), 'exact-financial-case-only-cache-normalization')
    case_ref = save(output, prefix + 'CASE.json', normalized['case'])
    normalization_ref = save(output, prefix + 'normalization.json', normalized_raw, raw=True)
    destination = output / ('checks/%06d' % ordinal)
    case_path = output / case_ref['path']
    native_out = destination / 'actual-native'
    process = tool(ENGINE,
        mounts=['--ro-bind', str(case_path), str(case_path), '--bind', str(destination), str(destination)],
        arguments=['validate-transaction', str(case_path), str(native_out)], require_success=False)
    report_path = native_out / 'native-validation.json'
    report = None
    if report_path.exists():
        report_raw = admitted_read(report_path)
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
    close_setup_fds()
    boundary = capture_boundary()
    need(public_file(Path('/NO-ORIGINAL-METHOD03-NATIVE')) == b'METHOD03_CAPTURE_ONLY_NETWORK_OFF\n',
         'selected-closed-capture-role-required')
    wire = load_wire()
    specification = parse(admitted_read(Path(args.specification), args.specification_sha256))
    need(type(specification) is dict and set(specification) == {
        'schema', 'binding', 'source_pins', 'public_notes', 'transport_parameters'}
        and specification['schema'] == 'kpb-method03-received-native-specification/v1', 'exact-method03-native-specification')
    binding = specification['binding']; binding_check(binding)
    pins = {'adapter': sha(admitted_read(Path(__file__))), **PINS}
    need(specification['source_pins'] == pins, 'externally-selected-exact-adapter-and-tool-pins')
    notes_ref = specification['public_notes']
    need(type(notes_ref) is dict and set(notes_ref) == {'path', 'sha256'} and hex_width(notes_ref['sha256'], 32),
         'selected-public-notes-reference')
    notes_raw = admitted_read(Path(notes_ref['path']), notes_ref['sha256']); notes = parse(notes_raw)
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
        context = wire.HeadContext.parse(bytes.fromhex(value['context_hex276']))
        need(tuple(field.hex() for field in (context.chain, context.pool, context.profile, context.domain, context.service))
             == IDENTITY, 'fixed-existing-profile-identity')
        contexts[arm] = context
    need(contexts['A'].cm_root != contexts['B'].cm_root and contexts['A'].point != contexts['B'].point,
         'independent-contexts')
    transport = specification['transport_parameters']
    transport_check(transport)
    for path, pin in ((CODEC, PINS['codec']), (ENGINE, PINS['engine']), (VERIFIER, PINS['verifier'])):
        admitted_read(path, pin)  # Verify selected bytes BEFORE any invocation.
    parameters = parse(admitted_read(PARAMETERS, PINS['parameters']))
    tail = admitted_read(TAIL, PINS['tail'])
    admitted_read(MANIFEST, PINS['manifest'])
    capture, output, public_output = Path(args.capture), Path(args.output), Path(args.public_output)
    need(capture == Path('/capture/arrivals') and capture.is_dir() and not capture.is_symlink(), 'fixed-capture-only-alias')
    need(output == Path('/native/result') and not output.exists(), 'fresh-private-native-output-alias')
    need(public_output == Path('/public-output/result') and not public_output.exists(), 'fresh-public-export-alias')
    no_symlink_ancestors(output); no_symlink_ancestors(public_output)
    output.mkdir(mode=0o700)
    public_output.mkdir(mode=0o700)
    save(output, 'BOUNDARY.json', boundary)
    # Record actual enumeration privately, then use the receiver's actual
    # accepted sequence. Neither filesystem order nor owner/arm is an ordinal.
    names = os.listdir(capture)
    receiver_names(names)  # Reject unknown leaves BEFORE reading any body.
    records = [parse(public_file(capture / name)) for name in names]
    records = receiver_order(names, records)
    save(output, 'DIRECTORY-ENUMERATION.json', {'actual_names': names})
    notes_artifact = save(output, 'PUBLIC-NOTES.json', notes_raw, raw=True)
    checks, nfs, errors = [], [], []
    for record in records:
        ordinal = record['arrival_sequence']
        try:
            check, nf = check_one(wire, record, ordinal, binding, pins, contexts, parameters, tail, output)
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
        body = wire.validate_public(projection)
        matches = [arm for arm, context in contexts.items() if body.context == context]
        need(len(matches) == 1, 'public-export-exact-context-partition')
        context_counts[matches[0]] += 1
        public_records.append({'ordinal': record['arrival_sequence'],
            'projection_hex': projection.hex(), 'proof_hex128': proof.hex(),
            'statement_hex152': wire.statement(projection).hex(), 'exit_id': sha(projection)})
    need(set(context_counts.values()) == {3}, 'three-received-projections-per-public-context')
    kernel_clocks_before = clock_evidence()
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
    kernel_clocks_after = clock_evidence()
    publication = {'schema': 'kpb-method03-native-publication/v1', 'pid': os.getpid(),
        'clock_evidence': publication_clocks(kernel_clocks_before, kernel_clocks_after),
        'before_public_write': publication_started,
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
    try:
        result = produce(parser.parse_args())
    except BaseException:
        # Retain protected partial artifacts, but never put exception bodies,
        # capture data or paths into the blind controller's status stream.
        print('{"schema":"kpb-method03-native-completion/v1","status":"REFUSED",'
              '"actual_checks_passed":false,"fullpacket_available":false}', flush=True)
        return 1
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
