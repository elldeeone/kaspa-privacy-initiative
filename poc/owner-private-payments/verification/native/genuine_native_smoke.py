#!/usr/bin/env python3
"""Actual-proof native077 baseline and same-proof binding controls.

Host selects and guards every public file before copying it into a closed
namespace. This program cannot mount owner data, obtain a proof, or broadcast.
Every mutant is canonicalized using pinned upstream Transaction methods; the
production financial codec is deliberately not relaxed to admit invalid cases.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def need(ok, code):
    if not ok:
        raise ValueError(code)


def parse(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate-public-control-key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-json')))


def public_bytes(path, expected_sha, *, executable=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.is_relative_to('/public')
         and not any(p.is_symlink() for p in (path, *path.parents)), 'closed-public-path')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
         and (not executable or before.st_mode & 0o111), 'single-link-public-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        need(tuple(getattr(before, k) for k in keys) == tuple(getattr(opened, k) for k in keys),
             'public-file-swapped')
        raw = handle.read()
        after = os.fstat(handle.fileno())
    need(tuple(getattr(before, k) for k in keys) == tuple(getattr(after, k) for k in keys)
         and hashlib.sha256(raw).hexdigest() == expected_sha, 'selected-public-file-identity')
    return raw


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
    path.chmod(0o400)
    return hashlib.sha256(raw).hexdigest()


def canonicalize(executable, case, *, genesis=False):
    request = {'operation': 'genesis-output-covenant' if genesis else 'canonicalize', 'case': case}
    result = subprocess.run([str(executable)], input=json.dumps(request, allow_nan=False).encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    need(result.returncode == 0, 'test-only-upstream-canonicalization-failed')
    value = parse(result.stdout)
    need(value.get('schema') == 'kpx7-test-only-native-control-codec/v1'
         and value.get('native_VM_executed') is False
         and value.get('component_or_outer_G16_verified') is False, 'control-codec-scope')
    return value['case']


def mutations(baseline):
    rows = []
    def add(label, change, *, zk=False, genesis=False):
        case = deepcopy(baseline)
        change(case)
        rows.append((label, case, zk, genesis))
    def payload(case, at):
        raw = bytearray.fromhex(case['transaction']['payload'])
        raw[at] ^= 1
        case['transaction']['payload'] = raw.hex()
    def point(case):
        value = case['transaction']['inputs'][0]['previousOutpoint']
        raw = bytearray.fromhex(value['transactionId']); raw[0] ^= 1
        value['transactionId'] = raw.hex()
    def successor(case):
        value = case['transaction']['outputs'][0]
        raw = bytearray.fromhex(value['scriptPublicKey']); raw[4] ^= 1
        value['scriptPublicKey'] = raw.hex()
    # These pass native framing. Only the outer receipt's authenticated journal
    # can reject a changed opaque output cipher or Spend proof byte here.
    add('changed-output-CF-byte', lambda c: payload(c, 724 + 32 + 64 + 80), zk=True)
    add('changed-Spend-proof-byte', lambda c: payload(c, 10396 + 40), zk=True)
    add('changed-actual-previous-Q', point)
    add('changed-body-old-state', lambda c: payload(c, 148 + 40))
    add('changed-entry-reserve', lambda c: c['entries'][0].__setitem__('amount', c['entries'][0]['amount'] + 1))
    add('changed-successor-SPK', successor)
    add('changed-body-fee', lambda c: payload(c, 388))
    add('changed-body-payout', lambda c: payload(c, 396))
    add('changed-sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', 0))
    add('changed-lock-time-header', lambda c: c['transaction'].__setitem__('lockTime', 1))
    add('changed-output-count', lambda c: c['transaction']['outputs'].append(deepcopy(c['transaction']['outputs'][0])))
    # This is a VALID covenant genesis binding, not a random invalid covenant ID.
    # Same amount/SPK/proof; OpOutputAuthorizingInput must reject Some vs None.
    add('valid-genesis-output-covenant', lambda c: None, genesis=True)
    return rows


def run(args):
    need(Path(__file__).resolve().is_relative_to('/public') and Path(args.out) == Path('/out'),
         'closed-public-layout')
    need(not Path('/home').exists() and not Path('/var').exists(), 'host-private-paths-unmounted')
    for name in ('engine', 'codec', 'control_codec'):
        public_bytes(getattr(args, name), getattr(args, name + '_sha'), executable=True)
    source = parse(public_bytes(args.case, args.case_sha))
    proof = public_bytes(args.outer_proof, args.outer_proof_sha)
    need(len(proof) == 128 and proof != bytes(128), 'actual-nonzero-outer-proof128-required')
    image, component = bytes.fromhex(args.image_hex), bytes.fromhex(args.component_sha)
    need(len(image) == len(component) == 32, 'selected-new-image-component-width')
    module_path = Path('/public/verification/native_case.py')
    spec = importlib.util.spec_from_file_location('_kpx7_genuine_native_case', module_path)
    helper = importlib.util.module_from_spec(spec);sys.modules[spec.name] = helper
    spec.loader.exec_module(helper)
    codec = helper.NativeCodec(Path(args.codec), args.codec_sha)
    baseline, projection, journal, info = helper.replace_outer_proof(codec, source, proof, image, component)
    need(baseline['transaction']['inputs'][0]['computeBudget'] == 1800
         and info['metrics']['actual_fee_sompi'] == 19332300, 'selected-preauthorization-budget-fee')
    need(baseline == canonicalize(args.control_codec, baseline), 'baseline-upstream-canonical-roundtrip')
    original_witness = baseline['transaction']['inputs'][0]['signatureScript']
    output = Path(args.out)
    save(output / 'projection-and-journal.json', {
        'projection_hex10973': projection.hex(), 'journal_hex104': journal.hex(),
        'outer_image_hex32': image.hex(), 'component_profile_sha256': component.hex(),
        'classification': 'UNFUNDED_GENUINE_PROOF_NATIVE_BINDING_CONTROLS'})
    rows = [('genuine-baseline', baseline, None, False), *mutations(baseline)]
    results = []
    for index, (label, case, zk, genesis) in enumerate(rows):
        if index:
            case = canonicalize(args.control_codec, case, genesis=genesis)
        need(case['transaction']['inputs'][0]['signatureScript'] == original_witness,
             'every-control-retains-exact-same-outer-proof-and-redeem')
        if genesis:
            binding = case['transaction']['outputs'][0]['covenant']
            need(type(binding) is dict and binding['authorizingInput'] == 0
                 and len(bytes.fromhex(binding['covenantId'])) == 32,
                 'upstream-populated-valid-genesis-binding')
        folder = output / f'control-{index:02}'
        folder.mkdir(mode=0o700)
        case_sha = save(folder / 'case.json', case)
        completed = subprocess.run([args.engine, 'validate-transaction', str(folder / 'case.json'),
                                    str(folder / 'native')], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, check=False)
        with (folder / 'stdout.log').open('xb') as handle:handle.write(completed.stdout)
        with (folder / 'stderr.log').open('xb') as handle:handle.write(completed.stderr)
        report = parse((folder / 'native/native-validation.json').read_bytes())
        metrics = parse((folder / 'native/metrics.json').read_bytes())
        engines = report['per_input_ScriptEngine']
        need(len(engines) == 1 and type(engines[0]['accepted']) is bool, 'one-real-input-engine-report')
        engine = engines[0]
        if index == 0:
            need(completed.returncode == 0 and report['isolation'] == 'PASS'
                 and report['Full']['accepted'] is True
                 and report['all_input_engines_accepted'] is True
                 and engine['accepted'] is True, 'genuine-baseline-must-pass-actual-Full-and-script')
        else:
            need(report['Full']['accepted'] is False
                 and report['all_input_engines_accepted'] is False and engine['accepted'] is False,
                 'same-proof-mutant-must-fail-actual-Full-and-script')
            error = engine.get('typed_error')
            need(type(error) is str and error, 'typed-real-script-failure')
            need(('ZkIntegrity' in error) if zk else (error == 'VerifyError'),
                 'expected-receipt-integrity-or-earlier-native-policy-rejection')
        quote = [q for q in metrics['quotes'] if q['rate'] == 100]
        need(len(quote) == 1, 'one-selected-rate100-observation')
        results.append({'label': label, 'case_sha256': case_sha,
                        'Full_accepted': report['Full']['accepted'],
                        'input_engine_accepted': engine['accepted'], 'isolation': report['isolation'],
                        'typed_error': engine.get('typed_error'), 'engine_units': engine['units'],
                        'same_outer_proof_and_redeem': True, 'canonical_upstream_transaction': True,
                        'mining_mass': metrics['mining_mass'], 'rate100_quote': quote[0]})
    result = {'schema': 'kpx7-genuine-native-binding-controls/v1',
              'classification': 'UNFUNDED_ACTUAL_NEW_PROFILE_G16_NATIVE_FULL_AND_SAME_PROOF_CONTROLS',
              'source_case_sha256': args.case_sha, 'outer_proof_sha256': args.outer_proof_sha,
              'image_hex32': image.hex(), 'component_profile_sha256': component.hex(),
              'engine_sha256': args.engine_sha, 'codec_sha256': args.codec_sha,
              'control_codec_sha256': args.control_codec_sha,
              'projection_sha256': hashlib.sha256(projection).hexdigest(),
              'journal_sha256': hashlib.sha256(journal).hexdigest(),
              'compute_budget': 1800, 'fee_sompi': 19332300,
              'positive_count': 1, 'same_proof_negative_count': len(rows) - 1,
              'results': results, 'host_private_paths_unmounted': True,
              'network_or_funding_or_broadcast': False,
              'accepted_backing_or_chain_currentness': False,
              'cryptographic_correctness_or_production_security_claim': False}
    save(output / 'RESULTS.json', result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('codec', 'codec-sha', 'control-codec', 'control-codec-sha', 'engine', 'engine-sha',
                 'case', 'case-sha', 'outer-proof', 'outer-proof-sha', 'image-hex', 'component-sha', 'out'):
        parser.add_argument('--' + name, required=True)
    run(parser.parse_args())
