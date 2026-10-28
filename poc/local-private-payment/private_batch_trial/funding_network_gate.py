#!/usr/bin/env python3
"""Fresh public whole-CASE/NativeFull gate for the new network worker.

This runs inside the public namespace, with no Original, key, PK or private
wallet mount. It executes the selected native validator, never an imported
acceptance Boolean, then emits lossless SDK-boundary decimal strings.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid

import genesis

NATIVE_PIN = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'
OUTPUT_BINARY_PIN = '930972ac461ec4d9300836d4127212a594c55b90b56b8732bc9bfd98507a6fa6'
OUTPUT_MANIFEST_PIN = '1e24b8d3e22692b7445822d533b28f8ab7a09ddc4050c6e785941717e3e6fc82'


def need(value, code):
    if not value:
        raise ValueError(code)


def parse(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate-public-JSON-key'); value[key] = item
        return value
    def invalid(_):
        raise ValueError('nonfinite-public-JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def read(path, expected=None):
    path = Path(path)
    need(not any(item.is_symlink() for item in (path, *path.parents)), 'public-network-nonsymlink-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as handle:
        before = os.fstat(handle.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, 'public-network-regular-single-link')
        raw = handle.read(); after = os.fstat(handle.fileno())
        need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
             == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns), 'public-network-stable-read')
    if expected is not None:
        need(hashlib.sha256(raw).hexdigest() == expected, 'public-network-selected-file')
    return raw


def call_native(arguments):
    info = Path('/runtime/native-validator').lstat()
    need(stat.S_IMODE(info.st_mode) == 0o500, 'selected-native-executable-mode')
    read('/runtime/native-validator', NATIVE_PIN)
    result = subprocess.run(['/runtime/native-validator', *map(str, arguments)], stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
    need(result.returncode == 0, 'actual-selected-native-validator-refused')


def sdk_body(case):
    # Reuse Runtime.sdk_body's explicit integer-to-SDK boundary. No JSON.parse
    # of a large sompi number occurs in JavaScript before this conversion.
    body = copy.deepcopy(case['transaction'])
    for row in body['inputs']:
        row['sequence'] = str(genesis.uint(row['sequence']))
    for row in body['outputs']:
        row['value'] = str(genesis.amount(row['value']))
    body['lockTime'], body['gas'] = str(genesis.uint(body['lockTime'])), str(genesis.uint(body['gas']))
    body['storageMass'] = str(genesis.uint(body.pop('mass')))
    contexts = [{'amount_sompi': str(genesis.amount(row['amount'])), 'script_public_key': row['scriptPublicKey'],
        'block_daa_score': str(genesis.uint(row['blockDaaScore'])), 'is_coinbase': row['isCoinbase'],
        'covenant_id': row['covenantId']} for row in case['entries']]
    return body, contexts


def consolidate(case, identity, component):
    need(type(component) is int and component in (0, 1, 2), 'new-own-consolidation-component')
    body, entries = case['transaction'], case['entries']
    own = identity['owners'][component]['funding_spk_hex36']
    need(type(body['inputs']) is list and body['inputs'] and len(body['inputs']) == len(entries)
         and body['outputs'] and len(body['outputs']) == 1, 'whole-own-consolidation-shape')
    payload = b'KPBAMF01' + genesis.EXPECTED_IDENTITY[3] + uuid.UUID(identity['trial_id']).bytes + genesis.EXPECTED_IDENTITY[1]
    need(body['payload'] == payload.hex() and body['version'] == 1 and type(body['version']) is int
         and body['lockTime'] == 0 and type(body['lockTime']) is int and body['gas'] == 0 and type(body['gas']) is int
         and body['subnetworkId'] == '00' * 20, 'explicit-new-consolidation-payload-and-header')
    points = set()
    for source, entry in zip(body['inputs'], entries):
        genesis.fields(source, ('previousOutpoint', 'signatureScript', 'sequence', 'computeBudget'))
        genesis.fields(source['previousOutpoint'], ('transactionId', 'index'))
        genesis.hx(source['previousOutpoint']['transactionId'], 32); genesis.uint(source['previousOutpoint']['index'], 32)
        point = (source['previousOutpoint']['transactionId'], source['previousOutpoint']['index'])
        need(point not in points, 'distinct-own-consolidation-sources'); points.add(point)
        signature = genesis.hx(source['signatureScript'], 66)
        need(signature[:1] == b'\x41' and signature[-1:] == b'\x01'
             and genesis.uint(source['sequence']) == (1 << 64) - 1 and genesis.uint(source['computeBudget'], 16) == 10,
             'own-consolidation-ALL-frame-sequence-budget')
        genesis.fields(entry, ('amount', 'scriptPublicKey', 'blockDaaScore', 'isCoinbase', 'covenantId'))
        genesis.amount(entry['amount']); genesis.uint(entry['blockDaaScore'])
        need(entry['scriptPublicKey'] == own and entry['isCoinbase'] is True and entry['covenantId'] is None,
             'own-consolidation-only-selected-coinbase-contexts')
    need(body['outputs'][0] == {'value': body['outputs'][0]['value'], 'scriptPublicKey': own, 'covenant': None}
         and genesis.amount(body['outputs'][0]['value']) >= 2_100_000_000, 'ordinary-own-consolidation-output')


def run():
    need(not Path('/original').exists() and not Path('/etc/ssl/private').exists()
         and not Path('/home/luke/.codex').exists(), 'public-network-no-private-mounts')
    job = parse(read('/NETWORK-JOB.json'))
    identity = parse(read('/IDENTITY.json', job['identity_sha256']))
    raw = read('/inputs/CASE.json', job['case_sha256'])
    case = parse(raw)
    genesis.trial_uuid(identity['trial_id'])
    need(tuple(bytes.fromhex(identity[name]) for name in ('genesis_hash_hex', 'pool_lineage_hex32',
        'profile_id_hex32', 'domain_hex32', 'service_policy_hex32')) == genesis.EXPECTED_IDENTITY,
        'public-network-five-new-identities')
    mode = job['case_mode']
    if mode == 'consolidation':
        consolidate(case, identity, job['owner_component'])
    else:
        need(mode == 'genesis', 'closed-new-financial-entry-mode')
        profile = genesis.wallet.Profile(genesis.EXPECTED_IDENTITY[3], genesis.EXPECTED_IDENTITY[2])
        verifier = genesis.NamespaceGenesisVerifier(profile, '/runtime/prover', OUTPUT_BINARY_PIN,
            '/parameters/OUTPUT-MANIFEST.json', OUTPUT_MANIFEST_PIN, read_public=read)
        selected = genesis.Selection.from_component(read('/component/PROFILE.json', identity['component_profile_sha256']),
            identity['component_profile_sha256'], read('/component/IMMUTABLE-TAIL.bin', identity['native_tail_sha256']), verifier)
        genesis.validate_case(case, selected, identity['trial_id'], signed=True)
    output = Path('/out/offline-gate')
    output.mkdir(mode=0o700)
    source = output / 'CASE.json'; source.write_bytes(raw)
    call_native(['control-normalize-freeze', source, output / 'normalized'])
    normalized = parse(read(output / 'normalized/transaction.json'))
    need(normalized == case['transaction'], 'exact-whole-CASE-native-ID-and-mass')
    call_native(['validate-transaction', source, output / 'native'])
    report = parse(read(output / 'native/native-validation.json'))
    metrics = parse(read(output / 'native/metrics.json'))
    need(report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine']) == len(case['transaction']['inputs'])
         and all(row['accepted'] is True for row in report['per_input_ScriptEngine']), 'fresh-actual-NativeFull-all-inputs')
    rate = genesis.amount(job['fee_rate_sompi_per_mass'])
    fee = genesis.amount(sum(row['amount'] for row in case['entries']) - sum(row['value'] for row in case['transaction']['outputs']))
    need(fee == genesis.uint(metrics['mining_mass']) * rate, 'exact-selected-native-fee-quote')
    body, contexts = sdk_body(case)
    result = {'schema': 'kpb-network-native-candidate/v1', 'trial_id': identity['trial_id'],
        'identity_sha256': job['identity_sha256'], 'case_sha256': job['case_sha256'],
        'case_mode': mode, 'owner_component': job['owner_component'], 'transaction': body, 'contexts': contexts,
        'native_report_sha256': hashlib.sha256(read(output / 'native/native-validation.json')).hexdigest(),
        'native_metrics_sha256': hashlib.sha256(read(output / 'native/metrics.json')).hexdigest(),
        'fee_sompi': fee, 'network_or_broadcast': False}
    (output / 'SDK-CANDIDATE.json').write_bytes(encoded(result))
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))


if __name__ == '__main__':
    try:
        run()
    except BaseException:
        sys.stderr.write('new public whole-CASE gate refused\n')
        raise SystemExit(2)
