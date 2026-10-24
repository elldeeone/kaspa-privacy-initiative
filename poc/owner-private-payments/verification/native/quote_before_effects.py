#!/usr/bin/env python3
"""New P0 budget/rate100 quote before actual session or Spend authorization.

Runs only a synthetic zero-proof NEGATIVE VM case in a closed public namespace.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys


def need(ok, code):
    if not ok:
        raise ValueError(code)


def save(path, value):
    with path.open('x') as f:
        json.dump(value, f, sort_keys=True, indent=2);f.write('\n')
    path.chmod(0o400)


def run(a):
    need(Path(__file__).resolve().is_relative_to(Path('/public')) and Path(a.out) == Path('/out')
         and not Path('/home').exists() and not Path('/var').exists(), 'closed-public-layout')
    raw = Path(a.component_profile).read_bytes()
    need(hashlib.sha256(raw).hexdigest() == a.component_sha, 'selected-component-profile')
    need(hashlib.sha256(Path(a.engine).read_bytes()).hexdigest() == a.engine_sha, 'selected-engine-copy')
    spec = importlib.util.spec_from_file_location('_kpx7_budget_fixture', Path('/public/verification/native/test_case.py'))
    fixture = importlib.util.module_from_spec(spec);sys.modules[spec.name] = fixture;spec.loader.exec_module(fixture)
    codec = fixture.c.NativeCodec(Path(a.codec), a.codec_sha)
    image = bytes.fromhex(a.image_hex)
    need(len(image) == 32 and type(a.budget) is int and 1 <= a.budget <= 65535, 'new-budget-image')
    body = fixture.body_fixture()
    initial_state_sha = None
    if a.initial_state is not None:
        initial_raw = Path(a.initial_state).read_bytes()
        initial_state_sha = hashlib.sha256(initial_raw).hexdigest()
        need(initial_state_sha == a.initial_state_sha, 'selected-initial-state')
        initial = fixture.w.parse_state(initial_raw)
        need(initial.cm_count == 3 and initial.nf_count == 1 and type(a.reserve) is int, 'initial-P0-context')
        staged = bytearray(body)
        staged[148:260] = initial_raw
        staged[260:268] = a.reserve.to_bytes(8, 'little')
        staged[380:388] = (a.reserve - 10_000_000).to_bytes(8, 'little')
        body = bytes(staged)
    _, _, _, initial = fixture.c.make_case(codec, body, image, bytes.fromhex(a.component_sha), a.budget)
    fee = initial['metrics']['mining_mass'] * 100
    reserve = fixture.w.parse_body(body).old_reserve
    updated = bytearray(body)
    updated[380:388] = (reserve - fee).to_bytes(8, 'little')
    updated[388:396] = fee.to_bytes(8, 'little')
    case, projection, journal, report = fixture.c.make_case(codec, bytes(updated), image, bytes.fromhex(a.component_sha), a.budget)
    need(report['metrics']['mining_mass'] * 100 == fee and report['metrics']['actual_fee_sompi'] == fee,
         'rate100-exact-before-effects-fee')
    out = Path(a.out);save(out / 'case.json', case)
    result = subprocess.run([a.engine, 'validate-transaction', str(out / 'case.json'), str(out / 'native')],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (out / 'stdout.log').write_bytes(result.stdout);(out / 'stderr.log').write_bytes(result.stderr)
    validation = json.loads((out / 'native/native-validation.json').read_bytes())
    metrics = json.loads((out / 'native/metrics.json').read_bytes())
    engines = validation['per_input_ScriptEngine']
    need(validation['isolation'] == 'PASS' and validation['Full']['accepted'] is False
         and validation['all_input_engines_accepted'] is False and len(engines) == 1
         and engines[0]['accepted'] is False and 'Zk' in engines[0]['typed_error'],
         'zero-proof-reaches-Zk-under-new-budget-never-accepts')
    for key in ('compute_mass', 'transient_mass', 'storage_mass', 'mining_mass', 'actual_fee_sompi'):
        need(metrics[key] == report['metrics'][key], 'independent-native-metrics-join')
    selected_quote = [q for q in metrics['quotes'] if q['rate'] == 100]
    need(len(selected_quote) == 1 and selected_quote[0]['passes'] is True
         and selected_quote[0]['required_sompi'] == fee and selected_quote[0]['actual_sompi'] == fee,
         'native-rate100-quote-join')
    used = engines[0]['units'];allowed = report['metrics']['allowed_script_units']
    # Both fixed native crypto charges precede proof decoding in pinned upstream.
    fixed_precompile_units = 14_000_000 + 6 * 250_000
    need(fixed_precompile_units < used < allowed, 'fully-charged-negative-units-and-allowance')
    final = {'schema': 'kpx7-new-budget-before-effects/v1',
        'classification': 'SYNTHETIC_ZERO_PROOF_NEGATIVE_ONLY_NOT_GENUINE_NATIVE_ACCEPTANCE',
        'component_profile_sha256': a.component_sha, 'image_hex32': image.hex(),
        'initial_state_sha256': initial_state_sha, 'reserve_sompi': reserve,
        'successor_roots_are_representative_not_a_genuine_transition': True,
        'image_is_actual_new_guest': a.actual_image, 'compute_budget': a.budget,
        'allowed_script_units': allowed, 'zero_proof_measured_units': used,
        'fixed_native_G16_precompile_units': fixed_precompile_units,
        'post_success_true_push_additional_units': 1,
        'headroom_over_negative_plus_success_push': allowed - used - 1,
        'native_typed_error': engines[0]['typed_error'], 'rate_sompi_per_mass': 100,
        'fee_sompi': fee, 'mining_mass': metrics['mining_mass'],
        'native_estimated_serialized_bytes': metrics['estimated_bytes'],
        'projection_sha256': hashlib.sha256(projection).hexdigest(),
        'journal_sha256': hashlib.sha256(journal).hexdigest(),
        'phase': 'BEFORE_ACTUAL_SESSION_AND_SPEND_AUTHORIZATION',
        'native_VM_executed': True, 'genuine_G16_or_positive_native_acceptance': False,
        'accepted_backing_or_currentness': False}
    save(out / 'RESULTS.json', final);print(json.dumps(final, sort_keys=True))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for name in ('codec','codec-sha','engine','engine-sha','component-profile','component-sha','image-hex','out'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--budget', required=True, type=int);p.add_argument('--actual-image', action='store_true')
    p.add_argument('--initial-state');p.add_argument('--initial-state-sha');p.add_argument('--reserve', type=int)
    run(p.parse_args())
