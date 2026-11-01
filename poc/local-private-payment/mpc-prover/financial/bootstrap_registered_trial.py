#!/usr/bin/env python3
"""Create one fresh, unfunded registered-financial trial identity.

The command generates a three-server TLS roster, a typed registration and
three matching empty journal/anchor pairs, then atomically publishes one trial
root.  It never configures or starts the financial driver, opens an owner
listener, runs MPC, contacts a node, or broadcasts a transaction.  A failed
staging root is never reused as another trial.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import uuid


HERE = Path(__file__).resolve().parent
SOURCE_ROOT = HERE.parent
SOURCES = (
    'history/epoch_journal.hpp',
    'history/epoch_journal.cpp',
    'financial/registered_trial_init.cpp',
    'financial/bootstrap_registered_trial.py',
)
SCOPE = 'UNFUNDED_REGISTERED_RESEARCH_TRIAL_BOOTSTRAP_ONLY'
REGISTRATION_TAG = b'KPB/REGISTERED-UNFUNDED-TRIAL/REGISTRATION/v1\0'
KEY_TAG = b'KPBHKEY1'
JOURNAL_TAG = b'KPBHLOG1'
KEY_CONSTANTS = {
    'chain_hex32': 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370',
    'pool_hex32': 'd68068e3eecfe9fe1b2fcc63026fe7a5268829efa37f4f64c2e7374798e94adf',
    'domain_hex32': 'a0a1b4fbf4ce8505f17b24b354ffa81fc4201dc1e130b0358e3bc849611186e0',
    'profile_hex32': 'ea19260a60a8d0a54b8ad9848f82317c1d84059a1881be34d318bcca42493700',
    'service_hex32': 'ce821210834e870b6eebe3851b0b003b1b33cf343b1a17a996987f35dda514b5',
    'epoch_hex32': '1719a11d82194639da551cd7302ad3ea94e42a0e424962ac40719f5634d38b94',
}
FLAGS = (
    '-std=c++20', '-O1', '-g0', '-Wall', '-Wextra', '-Werror',
    '-DKPI_HISTORY_UNFUNDED_SETUP', '-DKPI_REGISTERED_TRIAL_BOOTSTRAP',
)
AT_FDCWD = -100
RENAME_NOREPLACE = 1


def need(condition, category):
    if not condition:
        raise ValueError('registered-trial-bootstrap-' + category)


def fields(value, names, category='exact-fields'):
    need(type(value) is dict and set(value) == set(names), category)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def encoded(value):
    return canonical(value) + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def word(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value),
         'canonical-word')
    return value


def plain(path, *, exists=None):
    path = Path(path)
    need(path.is_absolute() and path == Path(os.path.normpath(path)),
         'canonical-absolute-path')
    for current in (path, *path.parents):
        if current.exists() or current.is_symlink():
            need(not current.is_symlink(), 'nonsymlink-path')
        if current == current.parent:
            break
    if exists is True:
        need(path.exists(), 'existing-path')
    elif exists is False:
        need(not path.exists(), 'fresh-path')
    return path


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                 os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish_new(source, target):
    """Atomically publish a directory without replacing a raced target."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, 'renameat2', None)
    need(renameat2 is not None, 'renameat2-required')
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD,
                       os.fsencode(target), RENAME_NOREPLACE)
    if result != 0:
        error = ctypes.get_errno()
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            raise ValueError('registered-trial-bootstrap-raced-target')
        raise OSError(error, os.strerror(error), str(target))


def write_new(path, raw, mode=0o400):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def read_stable(path, *, expected_mode=None, expected_hash=None,
                expected_uid=None):
    path = plain(path, exists=True)
    before = path.lstat()
    if expected_uid is None:
        expected_uid = os.getuid()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == expected_uid
         and before.st_nlink == 1, 'owned-single-link-file')
    if expected_mode is not None:
        need(stat.S_IMODE(before.st_mode) == expected_mode, 'exact-file-mode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as source:
        opened = os.fstat(source.fileno())
        raw = source.read()
        after = os.fstat(source.fileno())
    keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
            'st_mode', 'st_nlink', 'st_uid')
    need(all(getattr(before, name) == getattr(opened, name) ==
             getattr(after, name) for name in keys)
         and len(raw) == before.st_size, 'stable-file')
    if expected_hash is not None:
        need(sha(raw) == word(expected_hash), 'selected-file-hash')
    return raw


def read_json(path, *, expected_hash=None):
    raw = read_stable(path, expected_mode=0o400,
                      expected_hash=expected_hash)
    value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(
        ValueError('registered-trial-bootstrap-nonfinite-json')))
    need(encoded(value) == raw, 'canonical-json')
    return value, raw


def private_leaf_metadata(path, mode):
    path = plain(path, exists=True)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
         and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode,
         'private-leaf-metadata')
    # Deliberately do not open or hash the private body.


def directory(path, mode=0o700):
    path = plain(path, exists=True)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == mode,
         'owned-directory-mode')
    return path


def command(argv, log_root, name, *, capture_stdout=False):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
             'LC_ALL': 'C.UTF-8'})
    write_new(log_root / (name + '.stdout'), result.stdout, 0o600)
    write_new(log_root / (name + '.stderr'), result.stderr, 0o600)
    need(result.returncode == 0, 'command-' + name)
    return result.stdout if capture_stdout else b''


def key_bytes(certificates):
    order = ('chain_hex32', 'pool_hex32', 'domain_hex32', 'profile_hex32',
             'service_hex32', 'epoch_hex32')
    return KEY_TAG + b''.join(bytes.fromhex(KEY_CONSTANTS[name])
                             for name in order) + b''.join(
                                 bytes.fromhex(value) for value in certificates)


def parse_state(raw, registration, certificates):
    text = raw.decode('ascii')
    lines = text.splitlines()
    need(len(lines) == 7 and lines[0] == 'KPB_REGISTERED_TRIAL_STATE_V1'
         and lines[1] == 'REGISTRATION ' + registration
         and lines[2] == 'KEY ' + sha(key_bytes(certificates))
         and lines[-1] == 'END', 'initializer-state-header')
    expected_checkpoint = sha(JOURNAL_TAG + bytes.fromhex(registration) +
                              key_bytes(certificates))
    result = []
    for party, line in enumerate(lines[3:6]):
        need(line == 'PARTY ' + str(party) + ' 0 ' + expected_checkpoint +
             ' READY', 'initializer-party-state')
        result.append({'party': party, 'sequence': 0,
                       'checkpoint_hex32': expected_checkpoint,
                       'phase': 'READY'})
    return result


def source_snapshot(stage):
    snapshot = stage / 'public/source'
    snapshot.mkdir(mode=0o700)
    selected = {}
    originals = {}
    for relative in SOURCES:
        source = SOURCE_ROOT / relative
        raw = read_stable(source)
        originals[relative] = (source, sha(raw))
        target = snapshot / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(target, raw)
        selected[relative] = {'path': relative, 'sha256': sha(raw),
                              'bytes': len(raw)}
    for path in sorted(snapshot.rglob('*'), reverse=True):
        if path.is_dir():
            path.chmod(0o500)
    snapshot.chmod(0o500)
    return snapshot, selected, originals


def tool(path):
    path = Path(path).resolve(strict=True)
    raw = read_stable(path, expected_uid=0)
    return {'path': str(path), 'sha256': sha(raw), 'bytes': len(raw)}


def create_certificates(stage, trial_id, nonce, openssl):
    public = stage / 'public/certificates'
    logs = stage / 'private/logs'
    ca_private = stage / 'private/ca'
    public.mkdir(mode=0o700); logs.mkdir(mode=0o700)
    ca_private.mkdir(mode=0o700)
    ca_key, ca_pem = ca_private / 'ca.key', public / 'ca.pem'
    command([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-sha256', '-days', '30', '-keyout', str(ca_key), '-out', str(ca_pem),
        '-subj', '/CN=KPI-REGISTERED-TRIAL-' + trial_id], logs, 'ca')
    ca_key.chmod(0o600); ca_pem.chmod(0o400)
    private_leaf_metadata(ca_key, 0o600)
    ca_raw = read_stable(ca_pem, expected_mode=0o400)
    ca_der = command([openssl, 'x509', '-in', str(ca_pem), '-outform',
                      'DER'], logs, 'ca-der', capture_stdout=True)
    ca_record = {'certificate_path': None,
                 'certificate_pem_sha256': sha(ca_raw),
                 'certificate_der_sha256': sha(ca_der),
                 'private_key_path': None,
                 'private_key_body_exported_or_hashed_in_public_receipts': False}
    records = []
    for party in range(3):
        role = 'P' + str(party)
        private = stage / 'private' / ('party-' + str(party))
        tls = private / 'tls'; candidates = private / 'candidates'
        tls.mkdir(mode=0o700, parents=True); candidates.mkdir(mode=0o700)
        private.chmod(0o700); tls.chmod(0o700); candidates.chmod(0o700)
        key = tls / (role + '.key'); csr = tls / (role + '.csr')
        extension = tls / (role + '.ext')
        write_new(extension,
            ('basicConstraints=critical,CA:FALSE\n'
             'keyUsage=critical,digitalSignature,keyEncipherment\n'
             'extendedKeyUsage=serverAuth,clientAuth\n'
             'subjectAltName=DNS:' + role + '\n').encode(), 0o600)
        command([openssl, 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-sha256', '-keyout', str(key), '-out', str(csr),
            '-subj', '/CN=' + role], logs, role + '-csr')
        serial = int(sha(bytes.fromhex(nonce) + bytes([party]))[:32], 16)
        command([openssl, 'x509', '-req', '-sha256', '-days', '30',
            '-in', str(csr), '-CA', str(ca_pem), '-CAkey', str(ca_key),
            '-set_serial', str(serial), '-out', str(public / (role + '.pem')),
            '-extfile', str(extension)], logs, role + '-certificate')
        key.chmod(0o600); csr.chmod(0o600)
        certificate = public / (role + '.pem'); certificate.chmod(0o400)
        private_leaf_metadata(key, 0o600)
        pem = read_stable(certificate, expected_mode=0o400)
        need(pem.count(b'-----BEGIN CERTIFICATE-----') == 1 and
             pem.count(b'-----END CERTIFICATE-----') == 1,
             'one-public-certificate')
        der = command([openssl, 'x509', '-in', str(certificate),
                       '-outform', 'DER'], logs, role + '-der',
                      capture_stdout=True)
        key_public = command([openssl, 'pkey', '-in', str(key), '-pubout'],
            logs, role + '-key-public', capture_stdout=True)
        certificate_public = command([openssl, 'x509', '-in',
            str(certificate), '-pubkey', '-noout'], logs,
            role + '-certificate-public', capture_stdout=True)
        need(key_public == certificate_public,
             'certificate-private-key-match-' + role)
        command([openssl, 'x509', '-in', str(certificate), '-checkhost', role,
                 '-noout'], logs, role + '-hostname')
        records.append({'party': party, 'role': role,
            'certificate_path': None, 'certificate_pem_sha256': sha(pem),
            'certificate_der_sha256': sha(der), 'private_key_path': None,
            'private_key_body_exported_or_hashed_in_public_receipts': False})
    need(len({row['certificate_der_sha256'] for row in records}) == 3,
         'three-distinct-certificates')
    command([openssl, 'verify', '-CAfile', str(ca_pem),
             *[str(public / ('P' + str(party) + '.pem'))
               for party in range(3)]], logs, 'certificate-chain')
    return records, ca_record


def make_state_directories(stage):
    (stage / 'state').mkdir(mode=0o700)
    for party in range(3):
        base = stage / 'state' / ('party-' + str(party))
        base.mkdir(mode=0o700)
        (base / 'journal').mkdir(mode=0o700)
        (base / 'anchor').mkdir(mode=0o700)


def build_initializer(stage, snapshot, source_selection, originals, compiler):
    build = stage / 'public/build'; build.mkdir(mode=0o700)
    binary = build / 'registered-trial-init'
    command([compiler, *FLAGS,
        str(snapshot / 'history/epoch_journal.cpp'),
        str(snapshot / 'financial/registered_trial_init.cpp'),
        '-pthread', '-lcrypto', '-o', str(binary)],
        stage / 'private/logs', 'compile-initializer')
    binary.chmod(0o500)
    for _, (path, expected) in originals.items():
        need(sha(read_stable(path)) == expected, 'source-changed-during-build')
    receipt = {'schema': 'kpb-registered-trial-bootstrap-build/v1',
        'scope': SCOPE, 'source_selection_sha256': source_selection,
        'flags': list(FLAGS), 'compiler': tool(compiler),
        'initializer_sha256': sha(read_stable(binary, expected_mode=0o500)),
        'registered_driver_configured': False,
        'owner_input_mpc_network_or_settlement_executed': False}
    write_new(build / 'BUILD.json', encoded(receipt))
    return binary, receipt


def verify_trial(root, *, declared_root=None):
    root = directory(plain(Path(root).absolute(), exists=True))
    declared_root = plain(Path(declared_root).absolute()) \
        if declared_root is not None else root
    selection, selection_raw = read_json(root / 'public/SELECTION-CANDIDATE.json')
    receipt, _ = read_json(root / 'public/BOOTSTRAP.json')
    registration_file, registration_raw = read_json(
        root / 'public/registration/REGISTRATION.json')
    fields(selection, ('schema', 'scope', 'status', 'trial_id', 'trial_root',
        'registration_file', 'registration_file_sha256',
        'registration_sha256', 'epoch_key', 'certificates',
        'certificate_authority', 'private_ca_key_path', 'state',
        'source_selection_sha256', 'source_closure', 'initializer',
        'registered_driver_configured', 'network_node_contacted',
        'owner_input_or_mpc_executed',
        'native_broadcast_or_settlement_executed'))
    need(selection['schema'] ==
         'kpb-registered-financial-trial-selection-candidate/v1'
         and selection['status'] == 'UNCONFIGURED_BOOTSTRAPPED'
         and selection['scope'] == SCOPE
         and selection['trial_root'] == str(declared_root)
         and selection['registered_driver_configured'] is False
         and selection['network_node_contacted'] is False
         and selection['owner_input_or_mpc_executed'] is False
         and selection['native_broadcast_or_settlement_executed'] is False,
         'selection-boundary')
    need(str(uuid.UUID(selection['trial_id'])) == selection['trial_id'],
         'canonical-trial-id')
    need(receipt == {'schema': 'kpb-registered-trial-bootstrap-result/v1',
         'scope': SCOPE, 'status': 'COMPLETE_UNCONFIGURED',
         'trial_id': selection['trial_id'], 'trial_root': str(declared_root),
         'selection_candidate_sha256': sha(selection_raw),
         'registration_file_sha256': sha(registration_raw),
         'registration_sha256': selection['registration_sha256'],
         'source_selection_sha256': selection['source_selection_sha256'],
         'initializer_sha256': selection['initializer']['sha256'],
         'three_certificates_and_journals_initialized': True,
         'private_key_bodies_exported_or_hashed_in_public_receipts': False,
         'registered_driver_configured': False,
         'network_owner_input_mpc_broadcast_or_settlement_executed': False},
         'exact-bootstrap-receipt')
    need(registration_file['schema'] ==
         'kpb-registered-unfunded-trial-registration/v1'
         and set(registration_file) ==
             {'schema', 'registration', 'registration_sha256'},
         'registration-schema')
    registration = registration_file['registration']
    fields(registration, ('scope', 'status', 'trial_id',
        'registration_nonce_hex32', 'epoch_key', 'certificates',
        'certificate_authority', 'source_selection_sha256',
        'registered_financial_service_identity',
        'registered_driver_configured', 'testnet_research_only',
        'network_or_owner_input_executed'))
    registration_sha = sha(REGISTRATION_TAG + canonical(registration))
    need(registration_sha == word(registration_file['registration_sha256'])
         and registration_sha == selection['registration_sha256']
         and registration['trial_id'] == selection['trial_id']
         and registration['scope'] == SCOPE
         and registration['status'] == 'BOOTSTRAP_ONLY_UNCONFIGURED'
         and registration['registered_financial_service_identity'] is True
         and registration['registered_driver_configured'] is False
         and registration['testnet_research_only'] is True
         and registration['network_or_owner_input_executed'] is False,
         'registration-binding')
    word(registration['registration_nonce_hex32'])
    expected_registration_path = declared_root / \
        'public/registration/REGISTRATION.json'
    need(selection['registration_file'] == str(expected_registration_path)
         and selection['registration_file_sha256'] == sha(registration_raw),
         'registration-fixed-path-and-file-hash')
    need(registration['epoch_key'] == selection['epoch_key']
         and {**KEY_CONSTANTS,
              'server_certificate_sha256': [row['certificate_der_sha256']
                  for row in selection['certificates']]} ==
             selection['epoch_key'], 'selected-epoch-key')
    certificates = []
    need(len(selection['certificates']) == 3, 'three-certificates')
    for party, record in enumerate(selection['certificates']):
        fields(record, ('party', 'role', 'certificate_path',
            'certificate_pem_sha256', 'certificate_der_sha256',
            'private_key_path',
            'private_key_body_exported_or_hashed_in_public_receipts'),
            'certificate-record-fields')
        role = 'P' + str(party)
        certificate = root / 'public/certificates' / (role + '.pem')
        declared_certificate = declared_root / 'public/certificates' / (role + '.pem')
        key = root / 'private' / ('party-' + str(party)) / 'tls' / (role + '.key')
        declared_key = declared_root / 'private' / ('party-' + str(party)) / 'tls' / (role + '.key')
        need(record['party'] == party and record['role'] == role
             and record['certificate_path'] == str(declared_certificate)
             and record['private_key_path'] == str(declared_key)
             and record[
                'private_key_body_exported_or_hashed_in_public_receipts']
                is False,
             'certificate-fixed-path')
        pem = read_stable(certificate, expected_mode=0o400,
                          expected_hash=record['certificate_pem_sha256'])
        try:
            der = ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))
        except (ValueError, UnicodeDecodeError):
            raise ValueError('registered-trial-bootstrap-certificate-DER') from None
        need(sha(der) == word(record['certificate_der_sha256']),
             'certificate-DER-hash')
        private_leaf_metadata(key, 0o600)
        certificates.append(record['certificate_der_sha256'])
    authority = selection['certificate_authority']
    fields(authority, ('certificate_path', 'certificate_pem_sha256',
        'certificate_der_sha256', 'private_key_path',
        'private_key_body_exported_or_hashed_in_public_receipts'),
        'CA-record-fields')
    ca_certificate = root / 'public/certificates/ca.pem'
    need(authority['certificate_path'] ==
            str(declared_root / 'public/certificates/ca.pem')
         and authority['private_key_path'] ==
            str(declared_root / 'private/ca/ca.key')
         and authority[
            'private_key_body_exported_or_hashed_in_public_receipts']
            is False,
         'fixed-CA-paths')
    ca_pem = read_stable(ca_certificate, expected_mode=0o400,
                         expected_hash=authority['certificate_pem_sha256'])
    try:
        ca_der = ssl.PEM_cert_to_DER_cert(ca_pem.decode('ascii'))
    except (ValueError, UnicodeDecodeError):
        raise ValueError('registered-trial-bootstrap-CA-DER') from None
    need(sha(ca_der) == word(authority['certificate_der_sha256'])
         and registration['certificate_authority'] == {
            name: authority[name] for name in
            ('certificate_pem_sha256', 'certificate_der_sha256')},
         'CA-registration-binding')
    ca_key = root / 'private/ca/ca.key'
    need(selection['private_ca_key_path'] ==
         str(declared_root / 'private/ca/ca.key'), 'fixed-CA-key-path')
    private_leaf_metadata(ca_key, 0o600)
    need(len(set(certificates)) == 3 and registration['certificates'] ==
         [{name: row[name] for name in ('party', 'role',
              'certificate_pem_sha256', 'certificate_der_sha256')}
          for row in selection['certificates']], 'registration-certificates')
    source_root = root / 'public/source'
    source_selection, source_selection_raw = read_json(
        root / 'public/SOURCE-SELECTION.json')
    fields(source_selection, ('schema', 'scope', 'sources', 'flags',
        'compiler', 'openssl', 'python'), 'source-selection-fields')
    need(source_selection['schema'] ==
            'kpb-registered-trial-bootstrap-source-selection/v1'
         and source_selection['scope'] == SCOPE
         and sha(source_selection_raw) == selection['source_selection_sha256']
         and registration['source_selection_sha256'] ==
            selection['source_selection_sha256']
         and source_selection['sources'] == selection['source_closure'],
         'source-selection-binding')
    for record in selection['source_closure']:
        fields(record, ('path', 'sha256', 'bytes'),
               'source-record-fields')
        relative = Path(record['path'])
        need(relative.is_relative_to('history') or
             relative.is_relative_to('financial'), 'source-relative-path')
        source_raw = read_stable(source_root / relative, expected_mode=0o400,
                                 expected_hash=record['sha256'])
        need(len(source_raw) == record['bytes'], 'source-record-size')
    initializer = root / 'public/build/registered-trial-init'
    fields(selection['initializer'], ('path', 'sha256'),
           'initializer-fields')
    need(selection['initializer']['path'] ==
         str(declared_root / 'public/build/registered-trial-init'),
         'initializer-fixed-path')
    read_stable(initializer, expected_mode=0o500,
                expected_hash=selection['initializer']['sha256'])
    build, _ = read_json(root / 'public/build/BUILD.json')
    fields(build, ('schema', 'scope', 'source_selection_sha256', 'flags',
        'compiler', 'initializer_sha256', 'registered_driver_configured',
        'owner_input_mpc_network_or_settlement_executed'),
        'build-receipt-fields')
    need(build['schema'] == 'kpb-registered-trial-bootstrap-build/v1'
         and build['scope'] == SCOPE
         and build['source_selection_sha256'] ==
            selection['source_selection_sha256']
         and build['flags'] == source_selection['flags'] == list(FLAGS)
         and build['compiler'] == source_selection['compiler']
         and build['initializer_sha256'] ==
            selection['initializer']['sha256']
         and build['registered_driver_configured'] is False
         and build['owner_input_mpc_network_or_settlement_executed'] is False,
         'build-receipt-binding')
    need(len(selection['state']) == 3, 'three-state-records')
    for party, record in enumerate(selection['state']):
        journal = root / 'state' / ('party-' + str(party)) / 'journal'
        anchor = root / 'state' / ('party-' + str(party)) / 'anchor'
        private = root / 'private' / ('party-' + str(party))
        declared = declared_root / 'state' / ('party-' + str(party))
        need(record['party'] == party and
             record['journal_directory'] == str(declared / 'journal') and
             record['anchor_directory'] == str(declared / 'anchor') and
             record['private_directories'] == [str(declared_root / 'private' /
                 ('party-' + str(party)))] and
             record['sequence'] == 0 and record['phase'] == 'READY',
             'state-fixed-path')
        directory(journal); directory(anchor); directory(private)
        private_leaf_metadata(journal / 'journal.bin', 0o600)
        private_leaf_metadata(anchor / 'latest.bin', 0o600)
    result = subprocess.run([str(initializer), 'verify', str(root),
        registration_sha, *certificates], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
             'LC_ALL': 'C.UTF-8'})
    need(result.returncode == 0 and result.stderr == b'',
         'direct-journal-verification')
    states = parse_state(result.stdout, registration_sha, certificates)
    for expected, selected in zip(states, selection['state']):
        need(all(selected[name] == expected[name] for name in
                 ('party', 'sequence', 'checkpoint_hex32', 'phase')),
             'journal-state-receipt')
    return receipt


def bootstrap(output):
    output = plain(Path(output).absolute(), exists=False)
    parent = directory(output.parent, stat.S_IMODE(output.parent.stat().st_mode))
    need(not (output.parent.stat().st_mode & stat.S_IWOTH),
         'output-parent-not-world-writable')
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '.staging-',
                                 dir=parent))
    stage.chmod(0o700)
    try:
        (stage / 'public').mkdir(mode=0o700)
        (stage / 'private').mkdir(mode=0o700)
        trial_id = str(uuid.uuid4())
        nonce = secrets.token_hex(32)
        openssl_record = tool('/usr/bin/openssl')
        compiler_record = tool('/usr/bin/g++')
        interpreter_record = tool(sys.executable)
        snapshot, sources, originals = source_snapshot(stage)
        source_selection = {'schema':
            'kpb-registered-trial-bootstrap-source-selection/v1',
            'scope': SCOPE, 'sources': list(sources.values()),
            'flags': list(FLAGS), 'compiler': compiler_record,
            'openssl': openssl_record, 'python': interpreter_record}
        source_selection_sha = sha(encoded(source_selection))
        records, ca_record = create_certificates(
            stage, trial_id, nonce, openssl_record['path'])
        final_certificates = []
        for record in records:
            party, role = record['party'], record['role']
            final_certificates.append({**record,
                'certificate_path': str(output / 'public/certificates' /
                                        (role + '.pem')),
                'private_key_path': str(output / 'private' /
                    ('party-' + str(party)) / 'tls' / (role + '.key'))})
        final_ca = {**ca_record,
            'certificate_path': str(output / 'public/certificates/ca.pem'),
            'private_key_path': str(output / 'private/ca/ca.key')}
        epoch_key = {**KEY_CONSTANTS,
            'server_certificate_sha256':
                [row['certificate_der_sha256'] for row in final_certificates]}
        registration = {'scope': SCOPE, 'status':
            'BOOTSTRAP_ONLY_UNCONFIGURED', 'trial_id': trial_id,
            'registration_nonce_hex32': nonce, 'epoch_key': epoch_key,
            'certificates': [{name: row[name] for name in ('party', 'role',
                'certificate_pem_sha256', 'certificate_der_sha256')}
                for row in final_certificates],
            'certificate_authority': {name: final_ca[name] for name in
                ('certificate_pem_sha256', 'certificate_der_sha256')},
            'source_selection_sha256': source_selection_sha,
            'registered_financial_service_identity': True,
            'registered_driver_configured': False,
            'testnet_research_only': True,
            'network_or_owner_input_executed': False}
        registration_sha = sha(REGISTRATION_TAG + canonical(registration))
        registration_file = {'schema':
            'kpb-registered-unfunded-trial-registration/v1',
            'registration': registration,
            'registration_sha256': registration_sha}
        registration_directory = stage / 'public/registration'
        registration_directory.mkdir(mode=0o700)
        registration_raw = encoded(registration_file)
        write_new(registration_directory / 'REGISTRATION.json',
                  registration_raw)
        write_new(stage / 'public/SOURCE-SELECTION.json',
                  encoded(source_selection))
        make_state_directories(stage)
        initializer, build_receipt = build_initializer(
            stage, snapshot, source_selection_sha, originals,
            compiler_record['path'])
        initialized = command([str(initializer), 'initialize', str(stage),
            registration_sha, *epoch_key['server_certificate_sha256']],
            stage / 'private/logs', 'initialize-state',
            capture_stdout=True)
        states = parse_state(initialized, registration_sha,
                             epoch_key['server_certificate_sha256'])
        verified = command([str(initializer), 'verify', str(stage),
            registration_sha, *epoch_key['server_certificate_sha256']],
            stage / 'private/logs', 'verify-state', capture_stdout=True)
        need(verified == initialized, 'initialize-verify-state-agreement')
        write_new(stage / 'public/STATE-INITIALIZATION.txt', initialized)
        selected_state = []
        for state in states:
            party = state['party']; base = output / 'state' / ('party-' + str(party))
            selected_state.append({**state,
                'journal_directory': str(base / 'journal'),
                'anchor_directory': str(base / 'anchor'),
                'private_directories': [str(output / 'private' /
                    ('party-' + str(party)))]})
        selection = {'schema':
            'kpb-registered-financial-trial-selection-candidate/v1',
            'scope': SCOPE, 'status': 'UNCONFIGURED_BOOTSTRAPPED',
            'trial_id': trial_id, 'trial_root': str(output),
            'registration_file': str(output /
                'public/registration/REGISTRATION.json'),
            'registration_file_sha256': sha(registration_raw),
            'registration_sha256': registration_sha,
            'epoch_key': epoch_key, 'certificates': final_certificates,
            'certificate_authority': final_ca,
            'private_ca_key_path': str(output / 'private/ca/ca.key'),
            'state': selected_state,
            'source_selection_sha256': source_selection_sha,
            'source_closure': list(sources.values()),
            'initializer': {'path': str(output /
                'public/build/registered-trial-init'),
                'sha256': build_receipt['initializer_sha256']},
            'registered_driver_configured': False,
            'network_node_contacted': False,
            'owner_input_or_mpc_executed': False,
            'native_broadcast_or_settlement_executed': False}
        selection_raw = encoded(selection)
        write_new(stage / 'public/SELECTION-CANDIDATE.json', selection_raw)
        result = {'schema': 'kpb-registered-trial-bootstrap-result/v1',
            'scope': SCOPE, 'status': 'COMPLETE_UNCONFIGURED',
            'trial_id': trial_id, 'trial_root': str(output),
            'selection_candidate_sha256': sha(selection_raw),
            'registration_file_sha256': sha(registration_raw),
            'registration_sha256': registration_sha,
            'source_selection_sha256': source_selection_sha,
            'initializer_sha256': build_receipt['initializer_sha256'],
            'three_certificates_and_journals_initialized': True,
            'private_key_bodies_exported_or_hashed_in_public_receipts': False,
            'registered_driver_configured': False,
            'network_owner_input_mpc_broadcast_or_settlement_executed': False}
        write_new(stage / 'public/BOOTSTRAP.json', encoded(result))
        for path in (stage / 'private/logs').iterdir():
            path.chmod(0o600)
        for directory_path in sorted(
                [path for path in stage.rglob('*') if path.is_dir()],
                key=lambda path: len(path.parts), reverse=True):
            sync_directory(directory_path)
        sync_directory(stage)
        staged_result = verify_trial(stage, declared_root=output)
        need(staged_result == result, 'complete-staged-trial-verification')
        # Publish only a fully initialized root. A failed staging directory is
        # retained under its unique name and can never be reused as OUTPUT.
        publish_new(stage, output)
        sync_directory(parent)
        verified_result = verify_trial(output)
        need(verified_result == result, 'published-trial-verification')
        return result
    except Exception:
        # Never delete or recycle a partial security-relevant identity.
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--verify-only', action='store_true')
    args = parser.parse_args()
    result = verify_trial(args.output) if args.verify_only else bootstrap(args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        raise SystemExit('registered unfunded trial bootstrap refused') from None
