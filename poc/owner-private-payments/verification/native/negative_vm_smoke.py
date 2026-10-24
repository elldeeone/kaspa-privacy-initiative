#!/usr/bin/env python3
"""Closed-namespace native077 smoke with deliberately invalid outer proof.

No genuine proof, positive native acceptance, funding or chain claim. Host must
stage this finite public closure using all old/new metadata-only exclusions.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


def need(ok, code):
    if not ok:
        raise ValueError(code)


def parse(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate-engine-output-key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-engine-output')))


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as f:
        f.write(raw)
    path.chmod(0o400)


def run(args):
    public = Path('/public')
    need(Path(__file__).resolve().is_relative_to(public) and Path(args.out) == Path('/out'), 'closed-public-layout')
    need(not Path('/home').exists() and not Path('/var').exists(), 'host-home-and-var-unmounted')
    engine = Path(args.engine)
    need(engine.is_relative_to(public) and hashlib.sha256(engine.read_bytes()).hexdigest() == args.engine_sha,
         'selected-engine-copy')
    fixture_path = public / 'verification/native/test_case.py'
    spec = importlib.util.spec_from_file_location('_kpx7_native_smoke_fixture', fixture_path)
    fixture = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixture
    spec.loader.exec_module(fixture)
    codec = fixture.c.NativeCodec(Path(args.codec), args.codec_sha)
    # These are public arbitrary identifiers, not a selected real R0 image.
    image, component = bytes([71]) * 32, bytes([81]) * 32
    baseline, projection, journal, body_report = fixture.c.make_case(
        codec, fixture.body_fixture(), image, component, 3000)
    rows = [('baseline-zero-outer-proof', baseline)]
    def add(label, change):
        case = deepcopy(baseline)
        change(case)
        rows.append((label, case))
    def payload_byte(case, at):
        raw = bytearray.fromhex(case['transaction']['payload']);raw[at] ^= 1
        case['transaction']['payload'] = raw.hex()
    add('changed-sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', 0))
    add('changed-declared-fee', lambda c: payload_byte(c, 388))
    add('changed-prior-state', lambda c: payload_byte(c, 148 + 40))
    add('changed-payout', lambda c: payload_byte(c, 396))
    add('changed-previous-index', lambda c: c['transaction']['inputs'][0]['previousOutpoint'].__setitem__('index', 1))
    def successor_spk(case):
        raw = bytearray.fromhex(case['transaction']['outputs'][0]['scriptPublicKey']);raw[4] ^= 1
        case['transaction']['outputs'][0]['scriptPublicKey'] = raw.hex()
    add('changed-successor-SPK', successor_spk)
    def extra_frame(case):
        case['transaction']['inputs'][0]['signatureScript'] += '00'
    add('extra-witness-byte', extra_frame)
    out = Path(args.out)
    save(out / 'projection-and-journal.json', {
        'projection_hex': projection.hex(), 'journal_hex104': journal.hex(),
        'scope': 'PUBLIC_SYNTHETIC_INVALID_PROOFS_NOT_AUTHORITY'})
    outcomes = []
    for index, (label, case) in enumerate(rows):
        folder = out / f'control-{index:02}'
        folder.mkdir(mode=0o700)
        path = folder / 'case.json';save(path, case)
        result = subprocess.run([str(engine), 'validate-transaction', str(path), str(folder / 'native')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        with (folder / 'stdout.log').open('xb') as f:f.write(result.stdout)
        with (folder / 'stderr.log').open('xb') as f:f.write(result.stderr)
        report_path = folder / 'native/native-validation.json'
        metrics_path = folder / 'native/metrics.json'
        need(report_path.is_file() and metrics_path.is_file(), 'native-engine-report-missing')
        report, metrics = parse(report_path.read_bytes()), parse(metrics_path.read_bytes())
        engines = report['per_input_ScriptEngine']
        need(type(report['Full']['accepted']) is bool and report['Full']['accepted'] is False
             and report['all_input_engines_accepted'] is False and len(engines) == 1
             and engines[0]['accepted'] is False, 'zero-proof-or-mutation-must-never-accept')
        error = engines[0].get('typed_error', '')
        need(type(error) is str and error, 'typed-native-failure-required')
        if index == 0:
            need(report['isolation'] == 'PASS' and 'Zk' in error,
                 'baseline-must-pass-framing-and-reach-Zk-dispatch')
        else:
            need('Zk' not in error, 'header-mutation-must-fail-before-Zk-dispatch')
        outcomes.append({'label': label, 'Full_accepted': False, 'input_engine_accepted': False,
                         'isolation': report['isolation'], 'typed_error': error,
                         'engine_units': engines[0]['units'], 'engine_returncode': result.returncode,
                         'mining_mass': metrics['mining_mass'], 'actual_fee_sompi': metrics['actual_fee_sompi']})
    result = {'schema': 'kpx7-negative-native-smoke/v1',
              'classification': 'PUBLIC_SYNTHETIC_ZERO_OUTER_PROOF_TYPED_REJECTIONS_ONLY',
              'case_count': len(rows), 'outcomes': outcomes,
              'temporary_compute_budget': 3000,
              'temporary_budget_is_final_financial_selection': False,
              'baseline_codec_metrics': body_report['metrics'],
              'host_home_and_var_unmounted': True, 'native_VM_executed': True,
              'genuine_component_or_outer_G16_verified': False,
              'positive_native_acceptance_or_backing_claimed': False}
    save(out / 'RESULTS.json', result)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--codec', required=True);p.add_argument('--codec-sha', required=True)
    p.add_argument('--engine', required=True);p.add_argument('--engine-sha', required=True)
    p.add_argument('--out', required=True)
    run(p.parse_args())
