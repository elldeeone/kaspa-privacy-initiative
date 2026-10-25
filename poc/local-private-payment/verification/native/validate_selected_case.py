#!/usr/bin/env python3
"""Attach one native proof without changing effects, or validate one direct Exit.

Runs only in a public-only namespace with selected immutable code/parameters.
Native Full and each input script must both accept. No funding, RPC, broadcast,
wallet backup, note opening, signing key or proving key is supported.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'


def need(ok, code):
    if not ok:
        raise ValueError(code)


def read(path, expected):
    p = Path(path)
    need(p.is_absolute() and p.is_relative_to('/public') and p.stat().st_nlink == 1
         and not any(x.is_symlink() for x in (p, *p.parents)), 'closed-public-file')
    b = p.read_bytes()
    need(hashlib.sha256(b).hexdigest() == expected, 'public-file-sha')
    return b


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-public-JSON-key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('noninteger-public-JSON-number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with path.open('xb') as handle:
        handle.write(raw)
    return hashlib.sha256(raw).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mode', choices=('mixed-attach', 'direct-exit'), required=True)
    for name in ('engine', 'codec', 'case', 'projection', 'journal', 'component', 'selection'):
        p.add_argument('--' + name, required=True)
        p.add_argument('--' + name + '-sha', required=True)
    p.add_argument('--proof')
    p.add_argument('--proof-sha')
    p.add_argument('--financial-profile-sha', required=True)
    p.add_argument('--compute-budget', required=True, type=int)
    p.add_argument('--fee-rate-sompi-per-mass', required=True, type=int)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    need(Path(a.out) == Path('/out') and not Path('/home').exists() and not Path('/var').exists(), 'public-only-layout')
    for name in ('engine', 'codec'):
        read(getattr(a, name), getattr(a, name + '_sha'))
    source = parse(read(a.case, a.case_sha))
    expected_projection = read(a.projection, a.projection_sha)
    expected_journal = read(a.journal, a.journal_sha)
    component = parse(read(a.component, a.component_sha))
    selection = parse(read(a.selection, a.selection_sha))
    need(component['schema'] == 'local-private-payment-component-profile/v1'
         and component['classification'] == 'RESEARCH_TESTNET_ONLY'
         and component['selected'] is True and component['domain_hex32'] == DOMAIN
         and selection['schema'] == 'local-private-payment-outer-selection/v1'
         and selection['classification'] == 'RESEARCH_TESTNET_ONLY'
         and selection['selected'] is True and selection['component_profile_sha256'] == a.component_sha,
         'selected-component-and-image')
    image = bytes.fromhex(selection['image_id_hex32'])
    component_sha = bytes.fromhex(a.component_sha)
    exit_vk = bytes.fromhex(component['exit']['vk_hex328'])
    need(len(image) == 32 and len(exit_vk) == 328
         and hashlib.sha256(exit_vk).hexdigest() == component['exit']['vk_sha256'], 'selected-exit-key')
    need(len(source['transaction']['inputs']) == len(source['entries']) == 1
         and 1 <= a.compute_budget <= 65535
         and source['transaction']['inputs'][0]['computeBudget'] == a.compute_budget, 'selected-one-input-budget')
    verification = Path('/public/verification')
    helper = load('_kpxa_selected_native_case', verification / 'native_case.py')
    wire = load('_kpxa_selected_native_wire', verification / 'wire.py')
    codec = helper.NativeCodec(Path(a.codec), a.codec_sha)
    baseline, before, journal, before_info = helper.project(codec, source, image, component_sha, exit_vk)
    need(baseline == source and before == expected_projection and journal == expected_journal, 'exact-original-case-projection-journal')
    need(1 <= a.fee_rate_sompi_per_mass <= (1 << 64) - 1, 'selected-native-fee-rate')
    quoted_minimum_fee = before_info['metrics']['mining_mass'] * a.fee_rate_sompi_per_mass
    need(before_info['metrics']['actual_fee_sompi'] >= quoted_minimum_fee, 'actual-native-fee-below-selected-quote')
    original_txid = source['transaction']['id']
    original_point = source['transaction']['inputs'][0]['previousOutpoint']
    if a.mode == 'mixed-attach':
        need(a.proof is not None and a.proof_sha is not None and before_info['mode'] == 'mixed', 'mixed-proof-selection')
        proof = read(a.proof, a.proof_sha)
        frame = bytes.fromhex(source['transaction']['inputs'][0]['signatureScript'])
        need(frame[:2] == b'\x4c\x80' and frame[2:130] == bytes(128)
             and len(proof) == 128 and proof != bytes(128), 'fresh-zero-slot-and-genuine-native-proof')
        final, after, after_journal, after_info = helper.replace_proof(codec, source, proof, image, component_sha, exit_vk)
        expected = deepcopy(source)
        expected['transaction']['inputs'][0]['signatureScript'] = (frame[:2] + proof + frame[130:]).hex()
        need(final == expected, 'only-proof-witness-may-change')
        wire.validate_public(after)
    else:
        need(a.proof is None and a.proof_sha is None and before_info['mode'] == 'exit', 'direct-exit-has-own-proof')
        final, after, after_journal, after_info = baseline, before, journal, before_info
        wire.validate_exit_public(after)
    need(after == before == expected_projection and after_journal == journal == expected_journal
         and final['transaction']['id'] == original_txid
         and final['transaction']['inputs'][0]['previousOutpoint'] == original_point
         and final['transaction']['payload'] == source['transaction']['payload']
         and final['transaction']['mass'] == source['transaction']['mass']
         and final['transaction']['outputs'] == source['transaction']['outputs']
         and after_info['metrics'] == before_info['metrics'], 'financial-context-id-and-effects-unchanged')
    output = Path('/out')
    case_sha = save(output / 'CASE.json', final)
    (output / 'PROJECTION.bin').write_bytes(after)
    (output / 'JOURNAL.bin').write_bytes(after_journal)
    done = subprocess.run([a.engine, 'validate-transaction', '/out/CASE.json', '/out/native'], capture_output=True)
    (output / 'stdout.log').write_bytes(done.stdout)
    (output / 'stderr.log').write_bytes(done.stderr)
    report = json.loads((output / 'native/native-validation.json').read_bytes())
    metrics = json.loads((output / 'native/metrics.json').read_bytes())
    need(done.returncode == 0 and report['isolation'] == 'PASS' and report['Full']['accepted'] is True
         and report['all_input_engines_accepted'] is True
         and len(report['per_input_ScriptEngine']) == len(final['transaction']['inputs'])
         and all(e['accepted'] is True for e in report['per_input_ScriptEngine']), 'actual-Native-Full-and-all-input-scripts')
    need(report['Full']['fee_sompi'] == after_info['metrics']['actual_fee_sompi']
         and metrics['actual_fee_sompi'] == after_info['metrics']['actual_fee_sompi'], 'independent-exact-native-fee')
    need(metrics['mining_mass'] == after_info['metrics']['mining_mass'], 'independent-exact-native-mass')
    need(all(metrics.get(name) is True for name in ('source_adapted_default_relay_fee', 'source_adapted_block_mass_caps', 'source_adapted_sigop_policy', 'standard_script_classes')), 'independent-source-adapted-native-admission-policy')
    result = {'schema': 'kpxa-selected-profile-native-validation/v1', 'mode': a.mode,
              'classification': 'GENUINE_SELECTED_PROFILE_SUPPLIED_CONTEXT_NATIVE_FULL_NOT_CHAIN_CONFIRMATION',
              'financial_profile_sha256': a.financial_profile_sha, 'component_profile_sha256': a.component_sha,
              'outer_image_hex32': selection['image_id_hex32'], 'engine_sha256': a.engine_sha,
              'codec_sha256': a.codec_sha, 'source_case_sha256': a.case_sha, 'validated_case_sha256': case_sha,
              'projection_sha256': a.projection_sha, 'journal_sha256': a.journal_sha,
              'native_proof_sha256': a.proof_sha, 'transaction_id': original_txid,
              'selected_compute_budget': a.compute_budget,
              'selected_fee_rate_sompi_per_mass': a.fee_rate_sompi_per_mass,
              'quoted_minimum_fee_sompi': quoted_minimum_fee,
              'proof_attachment_changed_only_witness': a.mode == 'mixed-attach',
              'all_financial_contexts_and_effects_unchanged': True, 'native_Full_accepted': True,
              'all_input_scripts_accepted': True, 'per_input_ScriptEngine': report['per_input_ScriptEngine'],
              'fee_sompi': report['Full']['fee_sompi'], 'native_metrics': metrics,
              'wallet_private_contents_read': False, 'funding_or_broadcast': False,
              'accepted_backing_or_chain_confirmation': False}
    digest = save(output / 'RESULT.json', result)
    print(json.dumps({'actual_Native_Full': True, 'all_input_scripts': True, 'mode': a.mode,
                      'result_sha256': digest, 'transaction_id': original_txid}))


if __name__ == '__main__':
    main()
