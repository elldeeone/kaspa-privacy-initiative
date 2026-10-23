"""Selected public byte emitter, exact official normalization and native checks.

No chain acceptance/currentness claim follows from a supplied ValidationCase.
Calling this module executes native checks, so its caller owns resource release.
The ordinary ELF/readonly source immutability and trusted-host premises remain
explicit; hashes do not defend against a malicious host writer after checking.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from primitives import MAX, amount, fixed, h, need, u64
from receiver import no_symlinks

ROOT = Path(__file__).resolve().parents[2]
DOMAIN = bytes.fromhex('35ee940cae12aec848a773738de04feaef80c17798a686f1d5aa808179584fd6')
EMITTER = Path('/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-native-target/selected-release-01/emitter')
EMITTER_SHA = '2ed7562656cfa8344c4b3d3176278b789e0392861732a5526c9c34db9f6f469c'
NATIVE = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
NATIVE_SHA = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
NODE = Path('/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node')
NODE_SHA = 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'
SDK = ROOT / 'poc/private-cashout-trial/sdk.mjs'
SDK_SHA = '7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63'
SDK_DIR = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
SDK_FILES = tuple(SDK_DIR / name for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json'))
GENESIS = 'f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370'
G16_ZERO = 'ZkIntegrity("ARK serialization error: the input buffer contained invalid data")'
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}
QUOTE_TAG = b'KPX4/COMPACT-BATCH/ACTUAL-BODY-QUOTE/v1\0'


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as file:
        file.write(encoded(value) + b'\n')
    path.chmod(0o600)


def public_case(transaction, contexts):
    def decimal(value, ceiling, positive=False):
        need(type(value) is str and len(value) <= 20
             and re.fullmatch('0|[1-9][0-9]*', value) is not None, 'canonical-context-integer')
        parsed = int(value)
        need((0 < parsed if positive else 0 <= parsed) and parsed <= ceiling, 'context-integer-range')
        return parsed
    entries = []
    need(type(contexts) is list and len(contexts) == len(transaction['inputs']), 'exact-context-count')
    for row in contexts:
        need(type(row) is dict and set(row) == {'amount_sompi', 'script_public_key',
             'block_daa_score', 'is_coinbase', 'covenant_id'}
             and row['is_coinbase'] is False and row['covenant_id'] is None,
             'exact-context-fields-and-flags')
        script = row['script_public_key']
        need(type(script) is str and len(script) >= 4 and len(script) % 2 == 0
             and all(c in '0123456789abcdef' for c in script), 'canonical-context-SPK')
        entries.append({'amount': decimal(row['amount_sompi'], MAX, True), 'scriptPublicKey': script,
            'blockDaaScore': decimal(row['block_daa_score'], (1 << 64) - 1),
            'isCoinbase': row['is_coinbase'], 'covenantId': row['covenant_id']})
    return {'transaction': transaction, 'entries': entries}


def p2sh(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def context(reserve, redeem, daa=0):
    amount(reserve)
    need(type(daa) is int and 0 <= daa < 1 << 64, 'actual-context-DAA')
    return {'amount_sompi': str(reserve), 'script_public_key': p2sh(redeem),
            'block_daa_score': str(daa), 'is_coinbase': False, 'covenant_id': None}


def tx(previous, outputs, payload, signature, budget):
    from actions import point_bytes
    point_bytes(previous)
    need(type(budget) is int and 0 <= budget < 1 << 16, 'transaction-budget')
    for value, _ in outputs:
        need(0 < amount(value) <= MAX, 'positive-native-output')
    return {'version': 1, 'id': '00' * 32,
        'inputs': [{'previousOutpoint': previous, 'signatureScript': signature.hex(),
                    'sequence': (1 << 64) - 1, 'computeBudget': budget}],
        'outputs': [{'value': value, 'scriptPublicKey': script, 'covenant': None}
                    for value, script in outputs],
        'lockTime': 0, 'subnetworkId': '00' * 20, 'gas': 0, 'payload': payload.hex(), 'mass': 0}


def push(raw):
    need(type(raw) is bytes and len(raw) <= 65535, 'canonical-push-width')
    return ((bytes([len(raw)]) if len(raw) <= 75 else b'\x4c' + bytes([len(raw)])
             if len(raw) <= 255 else b'\x4d' + len(raw).to_bytes(2, 'little')) + raw)


def quote_id(transaction, contexts, rate):
    """Exclude only proof bytes and derived ID; preserve every other field.

    The SDK/native normalizers independently recompute the derived transaction
    ID. Setting it to zero here avoids trusting an ID cache when replacing the
    proof; this is not permission to omit any transaction/context bytes.
    """
    need(type(rate) is int and 0 < rate < 1 << 64, 'fee-rate')
    body = copy.deepcopy(transaction)
    frame = bytearray.fromhex(body['inputs'][0]['signatureScript'])
    need(len(body['inputs']) == 1 and len(frame) >= 199
         and frame[:66] == push(bytes(65)) and frame[66:68] == b'\x4c\x80'
         and frame[196] == 0x4d and len(frame) == 199 + int.from_bytes(frame[197:199], 'little'),
         'exact-proof-normalization-frame')
    frame[68:196] = bytes(128)
    body['inputs'][0]['signatureScript'] = frame.hex()
    body['id'] = '00' * 32
    raw = encoded(public_case(body, contexts))
    return h(QUOTE_TAG, u64(len(raw)), raw, u64(rate)).hex()


class Executable:
    def __init__(self, path, expected):
        self.path = no_symlinks(path)
        info = self.path.stat()
        need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o500
             and os.access(self.path, os.X_OK) and not os.access(self.path, os.W_OK),
             'selected-readonly-0500-executable')
        raw = self.path.read_bytes()
        need(raw.startswith(b'\x7fELF') and hashlib.sha256(raw).hexdigest() == expected,
             'selected-executable-identity')
        self.sha256 = expected

    def run(self, args=(), request=None):
        result = subprocess.run([str(self.path), *map(str, args)],
            input=None if request is None else json.dumps(request), capture_output=True, text=True,
            env=dict(CLEAN))
        need(result.returncode == 0, 'selected-public-runtime-failed')
        return result


class Runtime:
    def __init__(self):
        self.emitter = Executable(EMITTER, EMITTER_SHA)
        self.native = Executable(NATIVE, NATIVE_SHA)
        self.node = Executable(NODE, NODE_SHA)
        need(hashlib.sha256(no_symlinks(SDK).read_bytes()).hexdigest() == SDK_SHA,
             'selected-offline-SDK-source')

    def emit(self, state, compact_vk, wide_vk):
        request = {'operation': 'emit', 'state_hex112': fixed(state, 112).hex(),
                   'compact_vk_hex328': fixed(compact_vk, 328).hex(),
                   'wide_vk_hex328': fixed(wide_vk, 328).hex()}
        result = json.loads(self.emitter.run(request=request).stdout)
        redeem = bytes.fromhex(result['redeem_hex'])
        need(result['domain_hex32'] == DOMAIN.hex() and result['state_hex112'] == state.hex()
             and result['redeem_bytes'] == len(redeem)
             and h(redeem).hex() == result['redeem_sha256']
             and redeem[:2] == b'\x4c\x70' and redeem[2:114] == state,
             'exact-selected-two-role-program')
        return redeem

    def genesis(self, note, cipher, compact_vk, wide_vk):
        request = {'operation': 'genesis', 'note_hex168': fixed(note, 168).hex(),
                   'cipher_hex264': fixed(cipher, 264).hex(),
                   'compact_vk_hex328': fixed(compact_vk, 328).hex(),
                   'wide_vk_hex328': fixed(wide_vk, 328).hex()}
        result = json.loads(self.emitter.run(request=request).stdout)
        from primitives import singleton
        snapshot = singleton(DOMAIN, note, cipher)
        redeem = self.emit(snapshot.state(DOMAIN), compact_vk, wide_vk)
        payload = b'KPX2GN01' + DOMAIN + note + snapshot.deliveries[0].cm + cipher + h(cipher)
        need(result['state_hex112'] == snapshot.state(DOMAIN).hex()
             and result['redeem_hex'] == redeem.hex() and result['payload_hex536'] == payload.hex()
             and result['reserve_sompi'] == int.from_bytes(note[64:72], 'little'),
             'strict-singleton-GN-value-roots-and-wire')
        return snapshot, redeem, payload

    def normalize(self, body, contexts, output):
        output = no_symlinks(output)
        need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-normalization-outside-Git')
        output.mkdir(parents=True, mode=0o700)
        case = output / 'case.json'
        save(case, public_case(body, contexts))
        self.native.run(['control-normalize-freeze', case, output / 'normalized'])
        actual = json.loads((output / 'normalized/transaction.json').read_bytes())
        metrics = json.loads((output / 'normalized/metrics.json').read_bytes())
        expected = copy.deepcopy(body)
        expected['id'], expected['mass'] = actual['id'], actual['mass']
        need(actual == expected, 'normalizer-only-derived-ID-and-storage-mass')
        return actual, metrics

    def validate(self, body, contexts, output, expect_zero_proof=False):
        output = no_symlinks(output)
        need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-native-output-outside-Git')
        output.mkdir(parents=True, mode=0o700)
        case = output / 'case.json'
        save(case, public_case(body, contexts))
        self.native.run(['validate-transaction', case, output / 'native'])
        report = json.loads((output / 'native/native-validation.json').read_bytes())
        metrics = json.loads((output / 'native/metrics.json').read_bytes())
        engines = report['per_input_ScriptEngine']
        need(report['isolation'] == 'PASS' and len(engines) == len(body['inputs']),
             'official-native-isolation-and-engine-coverage')
        if expect_zero_proof:
            need(report['Full']['accepted'] is False
                 and report['Full']['typed_error'] == 'SignatureInvalid(' + G16_ZERO + ')'
                 and report['all_input_engines_accepted'] is False
                 and all(row['accepted'] is False and row['typed_error'] == G16_ZERO for row in engines),
                 'zero-proof-last-G16-seam')
        else:
            need(report['Full']['accepted'] is True and report['all_input_engines_accepted'] is True
                 and all(row['accepted'] is True for row in engines), 'official-native-Full-rejected')
        return report, metrics

    def sdk(self, body, contexts, funding_secret=None):
        raw = copy.deepcopy(body)
        for row in raw['inputs']:
            row['sequence'] = str(row['sequence'])
        for row in raw['outputs']:
            row['value'] = str(row['value'])
        for key in ('lockTime', 'gas'):
            raw[key] = str(raw[key])
        raw['storageMass'] = str(raw.pop('mass'))
        request = {'schema': 'kpx3-offline-sdk-body/v1', 'network_id': 'testnet-10',
                   'genesis_hash_hex': GENESIS, 'mode': 'sign-founding' if funding_secret else 'roundtrip',
                   'transaction': raw, 'contexts': contexts}
        if funding_secret:
            request['funding_secret_hex32'] = fixed(funding_secret).hex()
        result = json.loads(self.node.run([SDK], request=request).stdout)
        need(result['lossless_safe_roundtrip'] is True, 'official-SDK-roundtrip')
        actual = result['transaction']
        for row in actual['inputs']:
            row['sequence'] = int(row['sequence'])
        for row in actual['outputs']:
            row['value'] = int(row['value'])
        actual['lockTime'], actual['gas'] = int(actual['lockTime']), int(actual['gas'])
        actual['mass'] = int(actual.pop('storageMass'))
        expected = copy.deepcopy(body)
        if funding_secret:
            expected['inputs'][0]['signatureScript'] = actual['inputs'][0]['signatureScript']
        need(actual == expected, 'SDK-only-authorized-signature-mutation')
        return actual

    def body(self, candidate, previous, reserve, compact_vk, wide_vk, proof=bytes(128), daa=0):
        before = candidate.auth[76:188]
        redeem = self.emit(before, compact_vk, wide_vk)
        signature = push(bytes(65)) + push(fixed(proof, 128)) + push(redeem)
        need(len(signature) == 199 + len(redeem), 'canonical-common-private-frame')
        outputs = []
        if candidate.reserve_after:
            next_redeem = self.emit(candidate.auth[364:476], compact_vk, wide_vk)
            outputs.append((candidate.reserve_after, p2sh(next_redeem)))
        if candidate.payout:
            outputs.append((candidate.payout, candidate.auth[492:528].hex()))
        return tx(previous, outputs, candidate.payload(), signature, 1600), [context(reserve, redeem, daa)]

    def quote(self, candidate, previous, reserve, compact_vk, wide_vk, output, rate=100, daa=0):
        output = no_symlinks(output)
        need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-quote-outside-Git')
        output.mkdir(parents=True, mode=0o700)
        body, contexts = self.body(candidate, previous, reserve, compact_vk, wide_vk, daa=daa)
        body, metrics = self.normalize(body, contexts, output / 'normalized')
        self.sdk(body, contexts)
        _, checked = self.validate(body, contexts, output / 'zero-proof', expect_zero_proof=True)
        need(metrics == checked and metrics['actual_fee_sompi'] == candidate.fee
             and candidate.fee == rate * metrics['mining_mass'], 'exact-official-minimum-fee-required')
        result = {'transaction': body, 'contexts': contexts, 'rate': rate,
                  'quote_id': quote_id(body, contexts, rate), 'metrics': metrics,
                  'actual_candidate_only': True, 'zero_proof_expected_final_G16_failure': True}
        save(output / 'SELECTED-QUOTE.json', result)
        return result

    def finalize(self, candidate, previous, reserve, compact_vk, wide_vk, proof, quoted, output, daa=0):
        output = no_symlinks(output)
        need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-final-output-outside-Git')
        output.mkdir(parents=True, mode=0o700)
        body, contexts = self.body(candidate, previous, reserve, compact_vk, wide_vk, proof, daa)
        body, metrics = self.normalize(body, contexts, output / 'normalized')
        expected = copy.deepcopy(quoted['transaction'])
        expected['inputs'][0]['signatureScript'] = body['inputs'][0]['signatureScript']
        expected['id'] = body['id']  # Independently recomputed derived ID only.
        need(body == expected and contexts == quoted['contexts']
             and quote_id(body, contexts, quoted['rate']) == quoted['quote_id']
             and metrics == quoted['metrics'], 'exact-proof-only-substitution-and-quote')
        self.sdk(body, contexts)
        report, checked = self.validate(body, contexts, output / 'full')
        need(metrics == checked and candidate.fee == quoted['rate'] * metrics['mining_mass'],
             'final-exact-official-fee')
        for name, value in [('transaction.json', body), ('supplied-context.json', contexts),
                            ('native-validation.json', report), ('metrics.json', metrics),
                            ('validation-case.json', public_case(body, contexts))]:
            save(output / name, value)
        return body, contexts, report, metrics
