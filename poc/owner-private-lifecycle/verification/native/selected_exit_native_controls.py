#!/usr/bin/env python3
"""Bounded same-proof financial checks on the actual selected native Exit tail.

Only public, retained LOCAL Exit01/Exit09 cases are available in this closed
namespace. The test codec normalizes upstream IDs/mass, never authorizes value.
No owner secrets, proving keys, new proofs, RPC, funding or broadcast are used.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess


TAIL_SHA = '2e9e00aa4ba7d9a25db4aff5246d58213b336e7a0c7689de8cc36498bcd09bf6'
FINANCIAL_SHA = '69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f'
DOMAIN = bytes.fromhex('be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480')


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, sha):
    p = Path(path)
    need(p.is_absolute() and p.is_relative_to('/public') and p.stat().st_nlink == 1
         and not any(x.is_symlink() for x in (p, *p.parents)), 'closed-public-file')
    raw = p.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == sha, 'public-file-sha')
    return raw


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def body(case):
    return bytearray.fromhex(case['transaction']['payload'])


def put_body(case, raw):
    case['transaction']['payload'] = raw.hex()


def add_u64(raw, at, difference):
    value = int.from_bytes(raw[at:at + 8], 'little') + difference
    need(0 <= value < 2**64, 'bounded-control-u64')
    raw[at:at + 8] = value.to_bytes(8, 'little')


def script_for_redeem(redeem):
    return (b'\0\0\xaa\x20' + hashlib.blake2b(redeem, digest_size=32).digest() + b'\x87').hex()


def mutations(continuing, terminal):
    rows = []

    def add(label, mode, modify, *, zk=False, proof_mode=None):
        case = deepcopy(continuing if mode == 'continuing' else terminal)
        modify(case)
        rows.append((label, mode, case, zk, proof_mode or mode))

    def destination(case):
        raw = body(case)
        spk = bytearray.fromhex(case['transaction']['outputs'][1]['scriptPublicKey'])
        spk[5] ^= 1
        case['transaction']['outputs'][1]['scriptPublicKey'] = spk.hex()
        raw[404:440] = spk
        put_body(case, raw)

    def payout(case):
        raw = body(case)
        add_u64(raw, 396, 1)
        add_u64(raw, 380, -1)
        case['transaction']['outputs'][1]['value'] += 1
        case['transaction']['outputs'][0]['value'] -= 1
        put_body(case, raw)

    def fee(case):
        raw = body(case)
        add_u64(raw, 388, 1)
        add_u64(raw, 380, -1)
        case['transaction']['outputs'][0]['value'] -= 1
        put_body(case, raw)

    def point(case):
        current = case['transaction']['inputs'][0]['previousOutpoint']
        point_id = bytearray.fromhex(current['transactionId'])
        point_id[0] ^= 1
        current['transactionId'] = point_id.hex()
        raw = body(case)
        raw[112:144] = point_id
        put_body(case, raw)

    def old_state(case):
        # Change the old NF root coherently in body, mutable redeem prefix and
        # supplied input SPK. The original insertion witness must still reject.
        raw = body(case)
        raw[148 + 76] ^= 1
        frame = bytearray.fromhex(case['transaction']['inputs'][0]['signatureScript'])
        frame[133 + 2:133 + 114] = raw[148:260]
        case['transaction']['inputs'][0]['signatureScript'] = frame.hex()
        case['entries'][0]['scriptPublicKey'] = script_for_redeem(frame[133:])
        put_body(case, raw)

    def nf_path(case):
        raw = body(case)
        raw[472 + 72 + 8] ^= 1
        put_body(case, raw)

    def replay(case):
        # Retain the earlier Exit01 proof verbatim in the later genuine Exit09
        # current point/state/outputs/NF witness. This is a supplied-context replay
        # check, not evidence that either LOCAL point exists on chain.
        original = bytes.fromhex(continuing['transaction']['inputs'][0]['signatureScript'])
        frame = bytearray.fromhex(case['transaction']['inputs'][0]['signatureScript'])
        frame[2:130] = original[2:130]
        case['transaction']['inputs'][0]['signatureScript'] = frame.hex()

    def extra_successor(case):
        raw = body(case)
        frame = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
        successor = b'\x4c\x70' + bytes(raw[268:380]) + frame[133 + 114:]
        case['transaction']['outputs'][0]['value'] -= 60_000_000
        case['transaction']['outputs'].append({
            'covenant': None, 'scriptPublicKey': script_for_redeem(successor),
            'value': 60_000_000})

    add('coherent-payout-destination-and-body', 'continuing', destination, zk=True)
    add('coherent-payout-plus-one-successor-minus-one', 'continuing', payout, zk=True)
    add('coherent-fee-plus-one-successor-minus-one', 'continuing', fee, zk=True)
    add('coherent-current-point-and-body', 'continuing', point, zk=True)
    add('coherent-old-NF-state-redeem-and-input-SPK', 'continuing', old_state)
    add('changed-NF-predecessor-sibling', 'continuing', nf_path)
    add('earlier-genuine-proof-replayed-in-later-terminal-state', 'terminal', replay,
        zk=True, proof_mode='continuing')
    add('terminal-extra-fee-preserving-reserve-successor', 'terminal', extra_successor)
    return rows


def main():
    parser = argparse.ArgumentParser()
    for name in ('engine', 'control-codec', 'continuing', 'terminal'):
        parser.add_argument('--' + name, required=True)
        parser.add_argument('--' + name + '-sha', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    need(Path(args.out) == Path('/out') and not Path('/home').exists()
         and not Path('/var').exists(), 'public-only-layout')
    read(args.engine, args.engine_sha)
    read(args.control_codec, args.control_codec_sha)
    originals = {mode: json.loads(read(getattr(args, mode), getattr(args, mode + '_sha')))
                 for mode in ('continuing', 'terminal')}
    original_proofs = {}
    for mode, original in originals.items():
        frame = bytes.fromhex(original['transaction']['inputs'][0]['signatureScript'])
        raw = body(original)
        need(frame[:2] == b'\x4c\x80' and frame[130] == 0x4d
             and len(frame[2:130]) == 128 and frame[2:130] != bytes(128)
             and hashlib.sha256(frame[133 + 114:]).hexdigest() == TAIL_SHA,
             'selected-tail-and-existing-genuine-proof')
        need(len(raw) == 1632 and raw[:8] == b'KPX8XB01' and raw[16:48] == DOMAIN
             and len(original['transaction']['inputs']) == len(original['entries']) == 1
             and original['transaction']['inputs'][0]['computeBudget'] == 1800,
             'selected-exit-shape-domain-budget')
        original_proofs[mode] = frame[2:130]

    cases = [('genuine-continuing-positive', 'continuing', originals['continuing'], False, 'continuing'),
             ('genuine-terminal-positive', 'terminal', originals['terminal'], False, 'terminal'),
             *mutations(originals['continuing'], originals['terminal'])]
    results = []
    for ordinal, (label, mode, case, zk, proof_mode) in enumerate(cases):
        normal = subprocess.run([args.control_codec],
                                input=json.dumps({'operation': 'canonicalize', 'case': case}).encode(),
                                capture_output=True)
        need(normal.returncode == 0, 'upstream-test-codec-normalization')
        canonical = json.loads(normal.stdout)['case']
        if ordinal < 2:
            need(canonical == originals[mode], 'positive-CASE-exactly-preserved')
        frame = bytes.fromhex(canonical['transaction']['inputs'][0]['signatureScript'])
        need(frame[2:130] == original_proofs[proof_mode]
             and hashlib.sha256(frame[133 + 114:]).hexdigest() == TAIL_SHA,
             'original-genuine-proof-and-selected-tail-preserved')
        folder = Path('/out') / f'control-{ordinal:02}'
        folder.mkdir(mode=0o700)
        case_sha = save(folder / 'CASE.json', canonical)
        done = subprocess.run([args.engine, 'validate-transaction', str(folder / 'CASE.json'),
                               str(folder / 'native')], capture_output=True)
        (folder / 'stdout.log').write_bytes(done.stdout)
        (folder / 'stderr.log').write_bytes(done.stderr)
        report = json.loads((folder / 'native/native-validation.json').read_bytes())
        need(report['isolation'] == 'PASS' and len(report['per_input_ScriptEngine']) == 1,
             'native-isolation-and-all-input-script-execution')
        engine = report['per_input_ScriptEngine'][0]
        if ordinal < 2:
            need(done.returncode == 0 and report['Full']['accepted'] is True
                 and report['all_input_engines_accepted'] is True and engine['accepted'] is True,
                 'actual-selected-tail-genuine-Full-every-input-positive')
        else:
            need(report['Full']['accepted'] is False
                 and report['all_input_engines_accepted'] is False and engine['accepted'] is False,
                 'actual-selected-tail-unchanged-proof-Full-every-input-rejection')
            if zk:
                need('ZkIntegrity' in engine.get('typed_error', ''), 'coherent-mutation-reaches-Groth16')
        results.append({'label': label, 'mode': mode, 'case_sha256': case_sha,
                        'normalized_transaction_id': canonical['transaction']['id'],
                        'source_transaction_id': originals[mode]['transaction']['id'],
                        'source_case_sha256': getattr(args, mode + '_sha'),
                        'unchanged_proof_source_mode': proof_mode,
                        'unchanged_proof_sha256': hashlib.sha256(original_proofs[proof_mode]).hexdigest(),
                        'selected_immutable_tail_sha256': TAIL_SHA,
                        'native_Full_accepted': report['Full']['accepted'],
                        'all_input_engines_accepted': report['all_input_engines_accepted'],
                        'Full_result': report['Full'], 'per_input_ScriptEngine': report['per_input_ScriptEngine'],
                        'typed_error': engine.get('typed_error'), 'units': engine.get('units'),
                        'same_original_genuine_proof_preserved': True,
                        'upstream_transaction_id_and_mass_normalized': True})
    result = {'schema': 'kpx8-selected-exit-native-binding-controls/v1',
              'classification': 'GENUINE_SELECTED_TAIL_LOCAL_SUPPLIED_CONTEXT_NOT_CHAIN_CONFIRMATION',
              'financial_profile_sha256': FINANCIAL_SHA, 'selected_immutable_tail_sha256': TAIL_SHA,
              'engine_sha256': args.engine_sha, 'control_codec_sha256': args.control_codec_sha,
              'source_continuing_case_sha256': args.continuing_sha,
              'source_terminal_case_sha256': args.terminal_sha,
              'positive_count': 2, 'unchanged_proof_negative_count': len(results) - 2, 'results': results,
              'native_Full_and_all_input_scripts_executed': True,
              'new_proofs_or_wallet_private_reads': False,
              'financial_source_or_profile_changed': False,
              'privacy_experiment_or_funding_or_broadcast': False}
    digest = save(Path('/out/RESULT.json'), result)
    print(json.dumps({'positive_count': 2, 'unchanged_proof_negative_count': len(results) - 2,
                      'result_sha256': digest}))


if __name__ == '__main__':
    main()
