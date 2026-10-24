#!/usr/bin/env python3
"""Genuine direct-Exit Native Full controls in a public-only closed namespace.

The supplied contexts and known keys are synthetic. No wallet/seed/prover/network
is available. Production codec guards stay unchanged; only the test codec uses
upstream Transaction normalization to isolate native-script rejection reasons.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, sha=None):
    p = Path(path)
    need(p.is_absolute() and p.is_relative_to('/public') and p.stat().st_nlink == 1
         and not any(x.is_symlink() for x in (p, *p.parents)), 'public-only-file')
    b = p.read_bytes()
    need(sha is None or hashlib.sha256(b).hexdigest() == sha, 'public-file-SHA')
    return b


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw)
    return hashlib.sha256(raw).hexdigest()


def mutations(baseline, mode):
    rows = []
    def add(label, action, *, zk=False, operation='canonicalize'):
        c = deepcopy(baseline)
        action(c)
        rows.append((label, c, zk, operation))
    def payload(c, at):
        raw = bytearray.fromhex(c['transaction']['payload'])
        raw[at] ^= 1
        c['transaction']['payload'] = raw.hex()
    def destination(c):
        o = c['transaction']['outputs'][-1]
        raw = bytearray.fromhex(o['scriptPublicKey'])
        raw[5] ^= 1
        o['scriptPublicKey'] = raw.hex()
        b = bytearray.fromhex(c['transaction']['payload'])
        b[404:440] = raw
        c['transaction']['payload'] = b.hex()
    def point(c):
        o = c['transaction']['inputs'][0]['previousOutpoint']
        raw = bytearray.fromhex(o['transactionId'])
        raw[0] ^= 1
        o['transactionId'] = raw.hex()
        b = bytearray.fromhex(c['transaction']['payload'])
        b[112:144] = raw
        c['transaction']['payload'] = b.hex()
    def extra(c):
        outputs = c['transaction']['outputs']
        o = deepcopy(outputs[-1])
        outputs[-1]['value'] -= 60_000_000
        o['value'] = 60_000_000
        outputs.append(o)
    def continuation(c):
        o = c['transaction']['outputs'][0]
        raw = bytearray.fromhex(o['scriptPublicKey'])
        raw[4] ^= 1
        o['scriptPublicKey'] = raw.hex()
    add('changed-actual-head-and-matching-body', point, zk=True)
    add('changed-payout-destination-and-matching-body', destination, zk=True)
    add('changed-exit-session', lambda c: payload(c, 48), zk=True)
    add('changed-old-state', lambda c: payload(c, 148 + 76))
    add('changed-new-NF-root', lambda c: payload(c, 344))
    add('changed-new-CM-root', lambda c: payload(c, 308))
    add('changed-NF', lambda c: payload(c, 440))
    add('changed-NF-predecessor-path', lambda c: payload(c, 472 + 72 + 8))
    add('changed-NF-empty-append-path', lambda c: payload(c, 472 + 616 + 8))
    add('changed-fee', lambda c: payload(c, 388))
    add('changed-payout-amount', lambda c: payload(c, 396))
    add('changed-native-reserve', lambda c: c['entries'][0].__setitem__('amount', c['entries'][0]['amount'] + 1))
    add('changed-domain', lambda c: payload(c, 16))
    add('changed-mode', lambda c: payload(c, 14))
    add('changed-sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', 0))
    add('changed-locktime', lambda c: c['transaction'].__setitem__('lockTime', 1))
    add('extra-fee-preserving-output', extra)
    add('valid-genesis-covenant-on-output-zero', lambda c: None, operation='genesis-output-covenant')
    if mode == 'continuing':
        add('changed-continuing-tail', continuation)
        add('valid-genesis-covenant-on-payout', lambda c: None, operation='genesis-last-output-covenant')
    return rows


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--engine', required=True)
    p.add_argument('--engine-sha', required=True)
    p.add_argument('--control-codec', required=True)
    p.add_argument('--control-codec-sha', required=True)
    p.add_argument('--out', required=True)
    args = p.parse_args()
    need(Path(args.out) == Path('/out') and not Path('/home').exists() and not Path('/var').exists(), 'closed-public-layout')
    read(args.engine, args.engine_sha)
    read(args.control_codec, args.control_codec_sha)
    results = []
    for mode in ('continuing', 'terminal'):
        baseline = json.loads(read('/public/' + mode + '-case.json'))
        cases = [('genuine-baseline', baseline, False, 'canonicalize'), *mutations(baseline, mode)]
        for index, (label, case, zk, operation) in enumerate(cases):
            done = subprocess.run([args.control_codec], input=json.dumps({'operation': operation, 'case': case}).encode(), capture_output=True)
            need(done.returncode == 0, 'test-codec-canonicalization')
            canonical = json.loads(done.stdout)['case']
            need(canonical['transaction']['inputs'][0]['signatureScript'] == baseline['transaction']['inputs'][0]['signatureScript'], 'same-genuine-proof-required')
            folder = Path('/out') / mode / f'control-{index:02}'
            folder.mkdir(mode=0o700, parents=True)
            digest = save(folder / 'case.json', canonical)
            done = subprocess.run([args.engine, 'validate-transaction', str(folder / 'case.json'), str(folder / 'native')], capture_output=True)
            (folder / 'stdout.log').write_bytes(done.stdout)
            (folder / 'stderr.log').write_bytes(done.stderr)
            report = json.loads((folder / 'native/native-validation.json').read_bytes())
            engine = report['per_input_ScriptEngine'][0]
            if index == 0:
                need(done.returncode == 0 and report['Full']['accepted'] is True and engine['accepted'] is True, 'genuine-Full-and-script-positive')
            else:
                need(report['Full']['accepted'] is False and engine['accepted'] is False, 'same-proof-Full-and-script-negative')
                if zk:
                    need('ZkIntegrity' in engine.get('typed_error', ''), 'effect-mutation-must-reach-ZK-integrity')
            results.append({'mode': mode, 'label': label, 'case_sha256': digest, 'native_Full_accepted': report['Full']['accepted'],
                            'script_accepted': engine['accepted'], 'script_error': engine.get('typed_error'),
                            'script_units': engine.get('units'), 'same_genuine_proof_preserved': True})
    save(Path('/out/RESULTS.json'), {'schema': 'kpx8-direct-exit-genuine-native-controls/v1',
         'classification': 'PUBLIC_SYNTHETIC_KNOWN_KEYS_SUPPLIED_CONTEXT_NOT_ACCEPTED_BACKING_OR_CONFIRMATION',
         'engine_sha256': args.engine_sha, 'control_codec_sha256': args.control_codec_sha,
         'positive_count': sum(r['native_Full_accepted'] for r in results),
         'negative_count': sum(not r['native_Full_accepted'] for r in results), 'results': results,
         'native_VM_executed': True, 'funding_or_broadcast': False, 'original_wallet_secrets_read': False})
    print(json.dumps({'native_Full_positive_count': 2, 'unchanged-proof_negative_count': len(results) - 2}))


if __name__ == '__main__':
    main()
