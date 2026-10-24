"""Fixed existing note/crypto reuse and externally pinned component APIs."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys

from paths import ROOT, checked, digest, encoded, fields, hx, need, parse, stable_read

DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')
Q = 2736030358979909402780800718157159386076813972158567259200215660948447373041
MIN_NOTE = 60_000_000
MAX_VALUE = 2_870_000_000_000_000_000
RECIPIENT = 'poc/future-recipient/v2/recipient.py'
RECIPIENT_SHA = '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'
CRYPTO_SHA = '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def amount(value):
    need(type(value) is int and MIN_NOTE <= value <= MAX_VALUE, 'bounded-note-value')
    return value


def scalar(value):
    need(type(value) is bytes and len(value) == 32 and int.from_bytes(value, 'little') < Q,
         'canonical-BabyJubjub-scalar')
    return value


def module(path, expected, name):
    path = checked(path); raw = stable_read(path)
    need(digest(raw) == hx(expected, 32).hex() and name not in sys.modules,
         'selected-fixed-public-module')
    result = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    result.__file__ = str(path); sys.modules[name] = result
    try:
        exec(compile(raw, str(path), 'exec'), result.__dict__)
    except BaseException:
        sys.modules.pop(name, None); raise
    return result


def recipient():
    key = '_kpx8_selected_receipt'
    return sys.modules.get(key) or module(ROOT / RECIPIENT, RECIPIENT_SHA, key)


class Program:
    def __init__(self, path, expected):
        self.path, self.expected = checked(path), hx(expected, 32).hex()
        self.check()

    def check(self):
        info = self.path.lstat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500,
             'selected-readonly-program-mode')
        raw = stable_read(self.path)
        need(raw[:4] == b'\x7fELF' and digest(raw) == self.expected, 'selected-program-identity')

    def call(self, argv=(), request=None):
        self.check()
        result = subprocess.run([str(self.path), *map(str, argv)],
            input=None if request is None else encoded(request), capture_output=True, env=CLEAN)
        need(result.returncode == 0, 'selected-program-refused')
        return parse(result.stdout)


def crypto(path):
    v2 = recipient(); program = Program(path, CRYPTO_SHA)
    class Crypto(v2.Crypto):
        def __init__(self):
            self.executable = program.path

        def call(self, op, *, secret=None, public=None, payload=None):
            request = {'op': op}
            for key, value in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
                if value is not None:
                    request[key] = value.hex()
            program.check()
            process = subprocess.run([str(program.path)], input=encoded(request),
                capture_output=True, env=CLEAN)
            try:
                result = parse(process.stdout)
            except (ValueError, TypeError, UnicodeError):
                raise v2.Invalid('crypto-adapter') from None
            if process.returncode or type(result) is not dict or 'error' in result:
                if (op == 'derive-xonly' and type(result) is dict
                        and result == {'error': 'scalar'}):
                    raise v2.Invalid('crypto-scalar') from None
                if (op == 'unseal' and type(result) is dict
                        and result == {'error': 'unseal'}):
                    raise v2.Invalid('crypto-unseal') from None
                raise v2.Invalid('crypto-adapter') from None
            fields(result, ('hex',), 'selected-crypto-response')
            raw = result['hex']
            need(type(raw) is str and len(raw) % 2 == 0
                 and all(c in '0123456789abcdef' for c in raw), 'crypto-response-hex')
            return bytes.fromhex(raw)
    return Crypto()


class Relations:
    """Private requests stay in this owner namespace; producer flags ignored."""
    def __init__(self, assets, mode):
        self.assets = assets
        self.program = Program(assets['relation']['path'], assets['relation']['sha256'])
        profile_raw = stable_read(assets['component_profile'])
        need(digest(profile_raw) == hx(assets['component_profile_sha256'], 32).hex(),
             'selected-component-profile-bytes')
        profile = parse(profile_raw)
        need(profile['schema'] == 'kpx8-owner-private-component-profile/v1'
             and profile['selected'] is True and profile['domain_hex32'] == DOMAIN.hex()
             and type(profile['spend_count']) is int and profile['spend_count'] == 3
             and type(profile['output_count']) is int and profile['output_count'] == 6
             and profile['note_floor_sompi'] == MIN_NOTE and profile['max_value_sompi'] == MAX_VALUE
             and profile['body_bytes'] == 10780 and profile['journal_bytes'] == 104,
             'selected-component-profile-policy')
        info = self.program.call(('public-info',))
        need(info['domain_hex32'] == DOMAIN.hex()
             and info['scalar_modulus_decimal'] == str(Q)
             and info['note_floor_sompi'] == str(MIN_NOTE) and info['max_value_sompi'] == str(MAX_VALUE)
             and all(info[key] == profile[key] for key in
                 ('value_generator_hex64', 'blinding_generator_hex64', 'curve_parameters_sha256')),
             'profile-and-compiled-Pedersen-parameters')
        self.parameters = {}
        # Both manifests establish the same public component profile even
        # while prepare needs only the Output PK. No Spend PK is read here.
        roles = ('output', 'spend', 'exit')
        for role in roles:
            row = assets[role]
            raw = stable_read(row['manifest'])
            need(digest(raw) == hx(row['manifest_sha256'], 32).hex(), 'component-manifest-pin')
            value = parse(raw)
            need(value['role'] == role and value.get('domain_hex32', value.get('domain_hex')) == DOMAIN.hex(),
                 'component-role-and-domain')
            vk = hx(value['vk_hex328'], 328)
            need(digest(vk) == value['vk_sha256'], 'component-VK-pin')
            selected = profile[role]
            need(selected['vk_hex328'] == value['vk_hex328']
                 and selected['vk_sha256'] == value['vk_sha256']
                 and selected['parameter_manifest_sha256'] == row['manifest_sha256']
                 and value['executable_sha256'] == assets['relation']['sha256']
                 and value['curve_parameters_sha256'] == profile['curve_parameters_sha256'],
                 'component-profile-manifest-and-executable-join')
            if ((role == 'output' and mode == 'prepare')
                    or (role == 'spend' and mode == 'authorize')
                    or (role == 'exit' and mode == 'exit')):
                pk = stable_read(row['pk'])
                need(len(pk) == value['pk_bytes'] and digest(pk) == row['pk_sha256'] == value['pk_sha256'],
                     'whole-component-PK-ready-before-private-input')
            self.parameters[role] = (row, value)

    def commit(self, value, blind):
        result = self.program.call(('commit',), {'schema': 'kpx8-private-value-commitment/v1',
            'value_sompi': str(amount(value)), 'blind_hex32': scalar(blind).hex()})
        fields(result, ('cv_hex64',), 'CV-response')
        return hx(result['cv_hex64'], 64)

    def prove(self, role, statement, witness):
        row, value = self.parameters[role]
        result = self.program.call(('prove-' + role, '--pk', row['pk'], '--pk-sha256', row['pk_sha256'],
            '--manifest', row['manifest'], '--manifest-sha256', row['manifest_sha256'],
            '--statement', statement.hex()), witness)
        fields(result, ('schema', 'role', 'statement_hex', 'proof_hex128', 'genuine_proof_verified'),
               'component-proof-response')
        need(result['schema'] == 'kpx8-owner-private-component-proof/v1'
             and result['role'] == role and result['statement_hex'] == statement.hex(), 'component-context')
        proof = hx(result['proof_hex128'], 128)
        self.verify(role, statement, proof)
        return proof

    def verify(self, role, statement, proof):
        _, manifest = self.parameters[role]
        result = self.program.call(('verify-' + role, '--vk', manifest['vk_hex328'],
            '--statement', statement.hex(), '--proof', proof.hex()))
        need(result == {'verified': True}, 'genuine-component-verification')

    def output(self, row):
        need(type(row) is bytes and len(row) == 520 and digest(row[96:360]) == row[360:392].hex(),
             'complete-output-tuple-and-CFH')
        statement = b'KPX8OU01' + DOMAIN + row[:96] + row[360:392]
        self.verify('output', statement, row[392:])

    def balance(self, inputs, outputs, fee, delta):
        need(type(fee) is int and 0 < fee <= MAX_VALUE, 'positive-bounded-fee')
        result = self.program.call(('balance',), {'schema': 'kpx8-public-value-balance/v1',
            'input_cv_hex64': [v.hex() for v in inputs],
            'output_cv_hex64': [v.hex() for v in outputs],
            'fee_sompi': str(fee), 'delta_hex32': scalar(delta).hex()})
        need(result == {'balanced': True}, 'global-value-conservation')
