#!/usr/bin/env python3
"""Same-proof financial binding controls for a genuine selected-profile mixed case."""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, sha):
    p = Path(path)
    need(p.is_absolute() and p.is_relative_to('/public') and p.stat().st_nlink == 1
         and not any(x.is_symlink() for x in (p, *p.parents)), 'public-file')
    raw = p.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == sha, 'public-SHA')
    return raw


def save(path, value):
    b = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(b)
    return hashlib.sha256(b).hexdigest()


def mutations(original):
    rows = []
    def add(label, modify, zk=False, operation='canonicalize'):
        c = deepcopy(original)
        modify(c)
        rows.append((label, c, zk, operation))
    def byte(c, at):
        b = bytearray.fromhex(c['transaction']['payload'])
        b[at] ^= 1
        c['transaction']['payload'] = b.hex()
    def head(c):
        q = c['transaction']['inputs'][0]['previousOutpoint']
        b = bytearray.fromhex(q['transactionId']);b[0] ^= 1;q['transactionId'] = b.hex()
        body = bytearray.fromhex(c['transaction']['payload']);body[112:144] = b
        c['transaction']['payload'] = body.hex()
    def reserve(c):
        c['entries'][0]['amount'] += 1
        b = bytearray.fromhex(c['transaction']['payload'])
        for at in (260, 388):
            b[at:at + 8] = (int.from_bytes(b[at:at + 8], 'little') + 1).to_bytes(8, 'little')
        c['transaction']['payload'] = b.hex()
    def root(c, at):
        b = bytearray.fromhex(c['transaction']['payload']);b[at] ^= 1
        c['transaction']['payload'] = b.hex()
        frame = bytes.fromhex(c['transaction']['inputs'][0]['signatureScript'])
        tail = frame[133 + 114:]
        redeem = b'\x4c\x70' + bytes(b[268:380]) + tail
        c['transaction']['outputs'][0]['scriptPublicKey'] = (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()
    def tail(c):
        output = c['transaction']['outputs'][0]
        b = bytearray.fromhex(output['scriptPublicKey']);b[4] ^= 1
        output['scriptPublicKey'] = b.hex()
    def extra(c):
        output = c['transaction']['outputs'][0]
        second = deepcopy(output);second['value'] = 60_000_000
        output['value'] -= 60_000_000
        c['transaction']['outputs'].append(second)
    def output_order(c):
        b = bytearray.fromhex(c['transaction']['payload'])
        left, right = bytes(b[724:1244]), bytes(b[1244:1764])
        b[724:1244], b[1244:1764] = right, left
        c['transaction']['payload'] = b.hex()
    add('changed-CF-byte', lambda c: byte(c, 900), True)
    add('changed-Spend-proof-byte', lambda c: byte(c, 10436), True)
    add('changed-head-and-matching-body', head, True)
    add('changed-reserve-and-matching-fee', reserve, True)
    add('changed-successor-NF-root-and-matching-SPK', lambda c: root(c, 344), True)
    add('changed-successor-CM-root-and-matching-SPK', lambda c: root(c, 308), True)
    add('changed-global-Delta', lambda c: byte(c, 404), True)
    add('changed-complete-output-order', output_order, True)
    add('changed-old-state', lambda c: byte(c, 188))
    add('changed-fee-only', lambda c: byte(c, 388))
    add('changed-successor-tail', tail)
    add('changed-sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', 0))
    add('changed-locktime', lambda c: c['transaction'].__setitem__('lockTime', 1))
    add('extra-fee-preserving-output', extra)
    add('valid-native-genesis-output-covenant', lambda c: None, operation='genesis-output-covenant')
    add('unauthorized-payout', lambda c: byte(c, 396))
    return rows


def main():
    p = argparse.ArgumentParser()
    for name in ('engine', 'control-codec', 'case'):
        p.add_argument('--' + name, required=True)
        p.add_argument('--' + name + '-sha', required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    need(Path(a.out) == Path('/out') and not Path('/home').exists() and not Path('/var').exists(), 'closed-public-layout')
    read(a.engine, a.engine_sha);read(a.control_codec, a.control_codec_sha)
    original = json.loads(read(a.case, a.case_sha))
    frame = bytes.fromhex(original['transaction']['inputs'][0]['signatureScript'])
    need(hashlib.sha256(frame[133 + 114:]).hexdigest() == '2e9e00aa4ba7d9a25db4aff5246d58213b336e7a0c7689de8cc36498bcd09bf6', 'selected-lifecycle-tail')
    need(frame[:2] == b'\x4c\x80' and frame[2:130] != bytes(128)
         and original['transaction']['inputs'][0]['computeBudget'] == 1800, 'genuine-selected-native-proof')
    results = []
    for ordinal, (label, case, zk, operation) in enumerate([('genuine-selected-baseline', original, False, 'canonicalize'), *mutations(original)]):
        normal = subprocess.run([a.control_codec], input=json.dumps({'operation': operation, 'case': case}).encode(), capture_output=True)
        need(normal.returncode == 0, 'test-only-upstream-canonicalization')
        case = json.loads(normal.stdout)['case']
        need(case['transaction']['inputs'][0]['signatureScript'] == original['transaction']['inputs'][0]['signatureScript'], 'same-genuine-native-proof')
        folder = Path('/out') / f'control-{ordinal:02}'
        folder.mkdir(mode=0o700)
        digest = save(folder / 'CASE.json', case)
        done = subprocess.run([a.engine, 'validate-transaction', str(folder / 'CASE.json'), str(folder / 'native')], capture_output=True)
        (folder / 'stdout.log').write_bytes(done.stdout);(folder / 'stderr.log').write_bytes(done.stderr)
        report = json.loads((folder / 'native/native-validation.json').read_bytes())
        engine = report['per_input_ScriptEngine'][0]
        if ordinal == 0:
            need(done.returncode == 0 and report['Full']['accepted'] is True and engine['accepted'] is True, 'actual-selected-positive')
        else:
            need(report['Full']['accepted'] is False and engine['accepted'] is False, 'actual-same-proof-rejection')
            if zk:
                need('ZkIntegrity' in engine.get('typed_error', ''), 'coherent-effects-must-reach-ZK-integrity')
        results.append({'label': label, 'case_sha256': digest, 'Full_accepted': report['Full']['accepted'],
                        'script_accepted': engine['accepted'], 'script_units': engine.get('units'),
                        'typed_error': engine.get('typed_error'), 'same_genuine_proof_preserved': True})
    value = {'schema': 'kpx8-selected-mixed-native-binding-controls/v1',
             'classification': 'GENUINE_SELECTED_TAIL_SUPPLIED_CONTEXT_FINANCIAL_BINDING_NOT_CHAIN_CONFIRMATION',
             'source_case_sha256': a.case_sha, 'engine_sha256': a.engine_sha, 'control_codec_sha256': a.control_codec_sha,
             'positive_count': 1, 'negative_count': len(results) - 1, 'results': results,
             'financial_core_or_authorization_changed': False, 'privacy_experiment_or_funding_or_broadcast': False}
    digest = save(Path('/out/RESULT.json'), value)
    print(json.dumps({'positive_count': 1, 'unchanged-proof_negative_count': len(results) - 1, 'result_sha256': digest}))


if __name__ == '__main__':
    main()
