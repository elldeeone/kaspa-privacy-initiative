"""Pinned ordinary software for public quotes and one-key offline signing."""
import copy
import json
import os
from pathlib import Path
import stat
import subprocess

from gn3_common import (CLEAN, GENESIS, HERE, checked, digest, encoded, hx,
                        need, parse, public_bytes, reference, regular, write_new)

GENERIC = {
    'crypto': (Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto'),
        '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'),
    'node': (Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node'),
        'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'),
    'native-validator': (Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator'),
        '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061')}
SDK_DIR = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
SDK_PINS = {'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
    'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
    'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'}


class Executable:
    """ADR0054 trusted immutable host/release; no hostile-host guarantee."""
    def __init__(self, path, expected, forbidden=()):
        self.path, self.expected, self.forbidden = checked(path), expected, tuple(forbidden)
        self.check()

    def check(self):
        path, info = regular(self.path, self.forbidden)
        need(stat.S_IMODE(info.st_mode) == 0o500 and os.access(path, os.X_OK), 'readonly-selected-executable')
        raw = public_bytes(path, self.forbidden)
        need(raw[:4] == b'\x7fELF' and digest(raw) == self.expected, 'selected-executable-bytes')

    def run(self, arguments=(), request=None, allow_failure=False):
        self.check()
        result = subprocess.run([str(self.path), *map(str, arguments)], env=dict(CLEAN),
            input=None if request is None else json.dumps(request), text=True, capture_output=True)
        need(allow_failure or result.returncode == 0, 'selected-offline-runtime-refused')
        return result


class Runtime:
    def __init__(self, paths=None, sdk_dir=None, forbidden=(), require_native=True):
        self.paths = {name: Path(paths[name]) if paths and name in paths else default
                      for name, (default, _) in GENERIC.items()}
        self.sdk_dir = Path(sdk_dir) if sdk_dir else SDK_DIR
        self.forbidden = tuple(forbidden)
        roles = ('crypto', 'node', 'native-validator') if require_native else ('crypto', 'node')
        # All metadata precedes the first listed public byte, protecting the
        # owner backup if a caller aliases any executable/SDK file to it.
        for path in [*(self.paths[r] for r in roles),
                     *(self.sdk_dir / n for n in SDK_PINS), HERE / 'sdk.mjs']:
            regular(path, self.forbidden)
        self.executables = {r: Executable(self.paths[r], GENERIC[r][1], self.forbidden) for r in roles}
        for name, expected in SDK_PINS.items():
            need(digest(public_bytes(self.sdk_dir / name, self.forbidden)) == expected, 'selected-SDK21-file')
        self.sdk_source = public_bytes(HERE / 'sdk.mjs', self.forbidden)
        self.crypto = self._crypto()

    def _crypto(self):
        module, handle = reference('recipient'), self.executables['crypto']

        class SelectedCrypto(module.Crypto):
            def __init__(self):
                self.executable = handle.path

            def call(self, op, *, secret=None, public=None, payload=None):
                request = {'op': op}
                for key, value in (('secret_hex', secret), ('public_hex', public), ('payload_hex', payload)):
                    if value is not None:
                        request[key] = value.hex()
                process = handle.run(request=request, allow_failure=True)
                result = parse(process.stdout)
                need(type(result) is dict, 'selected-crypto-reply')
                if process.returncode or (type(result) is dict and 'error' in result):
                    # Preserve the established scalar retry category used by
                    # Receiver.keys; never interpolate a private request.
                    raise module.Invalid('crypto-' + str(result.get('error', 'adapter')))
                need(type(result) is dict and set(result) == {'hex'}, 'selected-crypto-reply')
                return hx(result['hex'])

        return SelectedCrypto()

    def sdk(self, operation, **items):
        need(public_bytes(HERE / 'sdk.mjs', self.forbidden) == self.sdk_source, 'installed-SDK-helper-mutated')
        for name, expected in SDK_PINS.items():
            need(digest(public_bytes(self.sdk_dir / name, self.forbidden)) == expected, 'selected-SDK21-file')
        request = {'schema': 'kpxa-offline-GN3-sdk/v1', 'network_id': 'testnet-10',
            'genesis_hash_hex': GENESIS, 'operation': operation, **items}
        return parse(self.executables['node'].run([HERE / 'sdk.mjs', self.sdk_dir], request).stdout)

    def address(self, public_key):
        value = self.sdk('address', xonly_hex32=public_key.hex())
        need(value['xonly_hex32'] == public_key.hex()
             and value['script_public_key'] == '000020' + public_key.hex() + 'ac'
             and type(value['address']) is str and value['address'].startswith('kaspatest:'),
             'funding-public-key-address-binding')
        return value

    @staticmethod
    def sdk_body(case):
        body = copy.deepcopy(case['transaction'])
        for row in body['inputs']:
            row['sequence'] = str(row['sequence'])
        for row in body['outputs']:
            row['value'] = str(row['value'])
        body['lockTime'], body['gas'] = str(body['lockTime']), str(body['gas'])
        body['storageMass'] = str(body.pop('mass'))
        contexts = [{'amount_sompi': str(r['amount']), 'script_public_key': r['scriptPublicKey'],
            'block_daa_score': str(r['blockDaaScore']), 'is_coinbase': r['isCoinbase'],
            'covenant_id': r['covenantId']} for r in case['entries']]
        return body, contexts

    def roundtrip(self, case):
        body, contexts = self.sdk_body(case)
        result = self.sdk('roundtrip', transaction=body, contexts=contexts)
        need(result['transaction'] == body and result['lossless_safe_roundtrip'] is True,
             'official-SDK-GN3-roundtrip')

    def signature(self, case, index, own_funding_key):
        body, contexts = self.sdk_body(case)
        result = self.sdk('sign-input', transaction=body, contexts=contexts,
            input_index=index, funding_secret_hex32=own_funding_key.hex())
        need(result['input_index'] == index and result['network_or_broadcast'] is False
             and result['secret_material_emitted'] is False, 'own-only-input-signature')
        signature = hx(result['signature_script_hex66'], 66)
        need(signature[:1] == b'\x41' and signature[-1:] == b'\x01', 'ordinary-ALL-signature-format')
        return signature

    def normalize(self, case, output):
        output = checked(output)
        need(not output.exists(), 'fresh-native-normalization-directory')
        output.mkdir(parents=True, mode=0o700)
        source = output / 'case.json'
        write_new(source, encoded(case) + b'\n')
        self.executables['native-validator'].run(['control-normalize-freeze', source, output / 'normalized'])
        actual = parse((output / 'normalized/transaction.json').read_bytes())
        metrics = parse((output / 'normalized/metrics.json').read_bytes())
        expected = copy.deepcopy(case['transaction'])
        expected['id'], expected['mass'] = actual['id'], actual['mass']
        need(actual == expected, 'native-normalizer-only-ID-and-storage-mass')
        return {'transaction': actual, 'entries': copy.deepcopy(case['entries'])}, metrics

    def validate(self, case, output):
        output = checked(output)
        need(not output.exists(), 'fresh-native-Full-directory')
        output.mkdir(parents=True, mode=0o700)
        source = output / 'case.json'
        write_new(source, encoded(case) + b'\n')
        self.executables['native-validator'].run(['validate-transaction', source, output / 'native'])
        report = parse((output / 'native/native-validation.json').read_bytes())
        metrics = parse((output / 'native/metrics.json').read_bytes())
        need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
             and report['all_input_engines_accepted'] is True
             and len(report['per_input_ScriptEngine'])==len(case['transaction']['inputs'])
             and all(r['accepted'] is True for r in report['per_input_ScriptEngine']),
             'ordinary-GN3-Full-and-all-engines')
        return report, metrics
