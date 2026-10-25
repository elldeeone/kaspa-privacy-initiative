"""Selected local-payment dependencies and strict owner-local boundaries.

This module performs no networking. The controller must stage only the finite
selected public source/assets before starting an isolated owner worker.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

DOMAIN = bytes.fromhex('b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c')
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
MIN_NOTE = 60_000_000
MAX_VALUE = 2_870_000_000_000_000_000
RECIPIENT_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC', 'RAYON_NUM_THREADS': '2'}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def parse(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-JSON-field')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-JSON'))


def fields(value, names, code):
    need(type(value) is dict and set(value) == set(names), code)


def hx(value, width):
    need(type(value) is str and len(value) == width * 2
         and all(c in '0123456789abcdef' for c in value), 'canonical-hex-width')
    return bytes.fromhex(value)


def uint(value, bits=64):
    need(type(value) is int and 0 <= value < 1 << bits, 'unsigned-integer')
    return value


def amount(value):
    need(MIN_NOTE <= uint(value) <= MAX_VALUE, 'bounded-note-value')
    return value


def fee_amount(value):
    need(0 < uint(value) <= MAX_VALUE, 'positive-bounded-fee')
    return value


def scalar(raw):
    need(type(raw) is bytes and len(raw) == 32 and int.from_bytes(raw, 'little') < Q,
         'canonical-blinding-scalar')
    return raw


def checked(path):
    path = Path(path)
    need('..' not in path.parts, 'canonical-path')
    path = path.absolute()
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink-path')
    return path


def _identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, expected=None, *, private=False):
    """Read one explicitly selected file, rejecting races and symlink aliases.

    Public files here must already be admitted by the controller's metadata
    guard and finite source stage. Private reads occur only in the owner worker.
    """
    path = checked(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and (not private or (before.st_nlink == 1
         and stat.S_IMODE(before.st_mode) in (0o400, 0o600))), 'selected-file-type-mode')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        need(_identity(os.fstat(fd)) == _identity(before), 'file-swapped-before-read')
        with os.fdopen(os.dup(fd), 'rb') as source:
            raw = source.read()
        need(_identity(os.fstat(fd)) == _identity(before) and len(raw) == before.st_size,
             'file-mutated-during-read')
    finally:
        os.close(fd)
    need(expected is None or digest(raw) == hx(expected, 32).hex(), 'external-whole-file-pin')
    return raw


def write_new(path, raw, mode=0o400):
    path = checked(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def selected_module(row, name):
    fields(row, ('path', 'sha256'), 'selected-source-fields')
    raw = read(row['path'], row['sha256'])
    need(name not in sys.modules, 'fresh-module-name')
    result = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    result.__file__ = str(checked(row['path']))
    sys.modules[name] = result
    try:
        exec(compile(raw, result.__file__, 'exec'), result.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return result


class Program:
    def __init__(self, row):
        fields(row, ('path', 'sha256'), 'selected-program-fields')
        self.path, self.sha256 = checked(row['path']), hx(row['sha256'], 32).hex()
        self.check()

    def check(self):
        info = self.path.lstat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500,
             'selected-readonly-program-mode')
        need(read(self.path, self.sha256)[:4] == b'\x7fELF', 'selected-ELF-program')

    def call(self, args=(), request=None):
        self.check()
        process = subprocess.run([str(self.path), *map(str, args)],
            input=None if request is None else encoded(request), capture_output=True, env=CLEAN)
        need(process.returncode == 0, 'selected-program-refused')
        return parse(process.stdout)


class Relations:
    """All fresh-domain roles are externally selected before secret input."""
    def __init__(self, assets, prove_roles=()):
        self.assets = assets
        self.program = Program(assets['relation'])
        info = self.program.call(('public-info',))
        need(info['schema'] == 'kpxa-local-private-public-info/v1'
             and info['domain_hex32'] == DOMAIN.hex()
             and info['scalar_modulus_decimal'] == str(Q)
             and info['note_floor_sompi'] == str(MIN_NOTE)
             and info['max_value_sompi'] == str(MAX_VALUE), 'compiled-local-relation-identity')
        self.parameters = {}
        for role in ('spend', 'output', 'exit'):
            row = assets[role]
            fields(row, ('manifest', 'manifest_sha256', 'pk', 'pk_sha256'), 'parameter-selection-fields')
            value = parse(read(row['manifest'], row['manifest_sha256']))
            need(value['schema'] == 'kpxa-local-private-parameters/v1'
                 and value['domain_hex32'] == DOMAIN.hex() and value['role'] == role
                 and value['pk_sha256'] == row['pk_sha256']
                 and value['executable_sha256'] == assets['relation']['sha256']
                 and value['curve_parameters_sha256'] == info['curve_parameters_sha256']
                 and digest(hx(value['vk_hex328'], 328)) == value['vk_sha256'],
                 'selected-fresh-role-manifest')
            if role in prove_roles:
                raw = read(row['pk'], row['pk_sha256'])
                need(len(raw) == value['pk_bytes'], 'whole-PK-before-secret-input')
            self.parameters[role] = (row, value)
        need(len({m['vk_sha256'] for _, m in self.parameters.values()}) == 3,
             'independent-role-parameters')

    def commit(self, value, blind):
        result = self.program.call(('commit',), {'schema': 'kpxa-private-value-commitment/v1',
            'value_sompi': str(amount(value)), 'blind_hex32': scalar(blind).hex()})
        fields(result, ('cv_hex64',), 'value-commitment-response')
        return hx(result['cv_hex64'], 64)

    def verify(self, role, statement, proof):
        _, value = self.parameters[role]
        result = self.program.call(('verify-' + role, '--vk', value['vk_hex328'],
                                   '--statement', statement.hex(), '--proof', proof.hex()))
        need(result == {'verified': True}, 'genuine-component-verification')

    def prove(self, role, statement, witness):
        row, _ = self.parameters[role]
        result = self.program.call(('prove-' + role, '--pk', row['pk'], '--pk-sha256', row['pk_sha256'],
            '--manifest', row['manifest'], '--manifest-sha256', row['manifest_sha256'],
            '--statement', statement.hex()), witness)
        fields(result, ('schema', 'role', 'statement_hex', 'proof_hex128', 'genuine_proof_verified'),
               'component-proof-response-fields')
        need(result['schema'] == 'kpxa-local-private-component-proof/v1'
             and result['role'] == role and result['statement_hex'] == statement.hex(),
             'component-proof-statement')
        proof = hx(result['proof_hex128'], 128)
        self.verify(role, statement, proof)
        return proof

    def output(self, row):
        need(type(row) is bytes and len(row) == 520
             and digest(row[96:360]) == row[360:392].hex(), 'complete-output-and-CFH')
        self.verify('output', b'KPXAOU01' + DOMAIN + row[:96] + row[360:392], row[392:])

    def balance(self, inputs, outputs, fee, delta):
        result = self.program.call(('balance',), {'schema': 'kpxa-public-value-balance/v1',
            'input_cv_hex64': [v.hex() for v in inputs], 'output_cv_hex64': [v.hex() for v in outputs],
            'fee_sompi': str(fee_amount(fee)), 'delta_hex32': scalar(delta).hex()})
        need(result == {'balanced': True}, 'public-value-conservation')


class Assets:
    def __init__(self, raw, expected_sha256, *, prove_roles=()):
        need(digest(raw) == hx(expected_sha256, 32).hex(), 'external-wallet-assets-pin')
        value = parse(raw)
        fields(value, ('schema', 'domain_hex32', 'relation', 'crypto', 'recipient', 'wire', 'trees',
                       'spend', 'output', 'exit', 'native_tail_hex'), 'wallet-assets-fields')
        need(value['schema'] == 'kpxa-local-wallet-assets/v1' and value['domain_hex32'] == DOMAIN.hex(),
             'local-wallet-assets-identity')
        need(value['recipient']['sha256'] == RECIPIENT_SHA and value['crypto']['sha256'] == CRYPTO_SHA,
             'established-recipient-and-crypto-selection')
        self.value = value
        self.relation = Relations(value, prove_roles)
        self.recipient = selected_module(value['recipient'], '_kpxa_receipt_' + str(id(self)))
        self.wire = selected_module(value['wire'], '_kpxa_wire_' + str(id(self)))
        self.trees = selected_module(value['trees'], '_kpxa_trees_' + str(id(self)))
        need(self.wire.DOMAIN == self.trees.DOMAIN == DOMAIN, 'selected-code-domain')
        self.tail = bytes.fromhex(value['native_tail_hex'])
        need(self.tail and self.tail.hex() == value['native_tail_hex'], 'canonical-selected-native-tail')
        program = Program(value['crypto'])
        v2 = self.recipient

        class Crypto(v2.Crypto):
            def __init__(self):
                self.executable = program.path

            def call(self, op, *, secret=None, public=None, payload=None):
                request = {'op': op}
                for key, item in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
                    if item is not None:
                        request[key] = item.hex()
                program.check()
                result = subprocess.run([str(program.path)], input=encoded(request),
                                        capture_output=True, env=CLEAN)
                try:
                    value = parse(result.stdout)
                except (ValueError, TypeError, UnicodeError):
                    raise v2.Invalid('crypto-adapter') from None
                if result.returncode or type(value) is not dict or 'error' in value:
                    if op == 'unseal' and value == {'error': 'unseal'}:
                        raise v2.Invalid('crypto-unseal') from None
                    if op == 'derive-xonly' and value == {'error': 'scalar'}:
                        raise v2.Invalid('crypto-scalar') from None
                    raise v2.Invalid('crypto-adapter') from None
                fields(value, ('hex',), 'crypto-result-fields')
                text = value['hex']
                need(type(text) is str and len(text) % 2 == 0
                     and all(c in '0123456789abcdef' for c in text), 'crypto-result-hex')
                return bytes.fromhex(text)
        self.crypto = Crypto()

    def receiver(self, seed):
        return self.recipient.Receiver(seed, DOMAIN, self.crypto)
