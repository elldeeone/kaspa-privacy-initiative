#!/usr/bin/env python3
"""ADR59 public host/native codec gate; no proving, PK, backup or broadcast.

Raw selected public cases/reports stay outside Git. Published output is a
finite sanitized outcome summary. UNSAFE oracle acceptances are byte-codec
diagnostics, never actual receipt-W or financial acceptance.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

from native_adapter import NativeCodec
from policy import Head
from selected import child_profile, parse
from virtual import InstalledProfile, check_outer, financial_projection, outer_case
from wire import h, hexbytes, need, transaction_id

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from public_native import normalize, validate


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def selected(path, expected):
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'selected_public_path_symlink')
    raw = path.read_bytes()
    need(h(raw).hex() == expected, 'externally_selected_public_input')
    return raw


def record(raw):
    if len(raw) == 4048:
        return raw
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema', 'classification', 'role', 'fee_context',
         'auth_hex528', 'payload_hex', 'proof_hex128', 'public_case'}
         and value['schema'] == 'kpx4-selected-public-payment-component/v1'
         and value['role'] == 'compact2'
         and value['classification'] == 'UNVERIFIED_COMPONENT_EXTERNAL_SETTLEMENT_POLICY_REQUIRED',
         'public_component_schema')
    payload, proof = hexbytes(value['payload_hex'], 3920), hexbytes(value['proof_hex128'], 128)
    need(payload[:528] == hexbytes(value['auth_hex528'], 528), 'public_component_auth_identity')
    return payload + proof


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as output:
        output.write(encoded(value) + b'\n')


def error_class(engine):
    text = engine.get('typed_error', '')
    if 'VerifyError' in text: return 'VerifyError'
    if 'ZkIntegrity' in text: return 'ZkIntegrity'
    return 'OTHER_OR_NONE'


def evaluate(profile_path, profile_sha, records, head_data, image, raw_output, *, run_VM=False):
    need(raw_output.is_absolute() and not raw_output.resolve().is_relative_to(ROOT.resolve())
         and not raw_output.exists() and not any(part.is_symlink() for part in (raw_output, *raw_output.parents)),
         'fresh_raw_public_output_outside_Git')
    raw_output.mkdir(parents=True, mode=0o700)
    child, metadata = child_profile(profile_path, profile_sha, allow_no_append_exit=True)
    need(set(head_data) == {'classification', 'transaction_id', 'index', 'state_hex112', 'reserve_sompi'}
         and head_data['classification'] == 'EXTERNALLY_SELECTED_SYNTHETIC_HEAD', 'given_head_scope')
    head = Head(head_data['transaction_id'], head_data['index'], hexbytes(head_data['state_hex112'], 112),
                head_data['reserve_sompi'], domain=child.domain)
    wrapper_domain = hexbytes(metadata['wrapper_domain_hex32'], 32)
    actual = NativeCodec(image, profile_sha)
    diagnostic = NativeCodec(image, profile_sha, unsafe_unfunded_hash_oracle=True)
    actual_profile = InstalledProfile(wrapper_domain, child, actual.emit)
    oracle_profile = InstalledProfile(wrapper_domain, child, diagnostic.emit)
    actual_case = outer_case(actual_profile, head, records)
    actual_host = check_outer(actual_profile, actual_case, head, verify)
    actual_body = actual.body(actual_case)
    need(actual_host['journal_hex424'] == actual_body['journal_hex424']
         and hexbytes(actual_body['financial_projection_hex']) == financial_projection(actual_case),
         'Python_Rust_actual_W_journal_and_projection_exact')
    oracle_case = outer_case(oracle_profile, head, records)
    oracle_host = check_outer(oracle_profile, oracle_case, head, verify)
    oracle_body = diagnostic.body(oracle_case)
    need(oracle_host['journal_hex424'] == oracle_body['journal_hex424']
         and hexbytes(oracle_body['financial_projection_hex']) == financial_projection(oracle_case),
         'Python_Rust_UNSAFE_oracle_journal_and_projection_exact')
    actual_script = actual.emit(head.state)
    oracle_script = diagnostic.emit(head.state)
    need(actual_script != oracle_script and h(actual_script) != h(oracle_script)
         and actual_case['entries'][0]['scriptPublicKey'] != oracle_case['entries'][0]['scriptPublicKey'],
         'unsafe_oracle_never_actual_W_program_or_SPK')
    expected_hash = hexbytes(oracle_host['journal_sha256'], 32)
    frame = bytearray.fromhex(oracle_case['transaction']['inputs'][0]['signatureScript'])
    frame[68:196] = expected_hash + bytes(96)
    oracle_case['transaction']['inputs'][0]['signatureScript'] = frame.hex()
    need(oracle_case['transaction']['id'] == transaction_id(oracle_case['transaction'], oracle_case['entries'][0])
         and diagnostic.body(oracle_case)['journal_hex424'] == oracle_host['journal_hex424'],
         'unsafe_expected_hash_slot_excluded_no_cycle')
    for name, case, host, body in [('actual-W', actual_case, actual_host, actual_body),
                                    ('UNSAFE-oracle', oracle_case, oracle_host, oracle_body)]:
        save(raw_output / name / 'validation-case.json', case)
        save(raw_output / name / 'host.json', host)
        save(raw_output / name / 'body-codec.json', body)
    results = []

    def native_case(label, case, accepted, seam=False, isolation_required=True):
        normalized = normalize(case)['transaction']
        checked = {'transaction': normalized, 'entries': case['entries']}
        outcome = validate(checked)
        report, metrics = outcome['report'], outcome['metrics']
        need(len(report['per_input_ScriptEngine']) == 1
             and (not isolation_required or report['isolation'] == 'PASS'),
             'actual_native_isolation_and_engine_count')
        engine = report['per_input_ScriptEngine'][0]
        need(report['Full']['accepted'] is accepted and engine['accepted'] is accepted,
             'actual_native_expected_outcome_' + label)
        if seam:
            need(error_class(engine) == 'ZkIntegrity' and engine['units'] >= 15500000,
                 'actual_W_zero_outer_proof_reaches_final_G16')
        elif not accepted:
            need(error_class(engine) == 'VerifyError', 'exact_native_binding_VerifyError_' + label)
        save(raw_output / label / 'validation-case.json', checked)
        save(raw_output / label / 'native-report.json', report)
        save(raw_output / label / 'metrics.json', metrics)
        results.append({'label': label, 'Full_accepted': accepted, 'engine_accepted': accepted,
                        'isolation_PASS': report['isolation'] == 'PASS',
                        'engine_units': engine['units'], 'engine_error_class': error_class(engine),
                        'public_case_sha256': h(encoded(checked)).hex(),
                        'mining_mass': metrics['mining_mass'], 'actual_fee_sompi': metrics['actual_fee_sompi']})

    if run_VM:
        native_case('actual-W-ZERO-outer-proof-final-G16-only', actual_case, False, True)
        native_case('UNSAFE-byte-codec-oracle-positive-NOT-financial', oracle_case, True)
        mutations = [
            ('point', lambda c: c['transaction']['inputs'][0]['previousOutpoint'].__setitem__('index', head.index + 1)),
            ('input-reserve', lambda c: c['entries'][0].__setitem__('amount', head.reserve + 1)),
            ('output-reserve', lambda c: c['transaction']['outputs'][0].__setitem__('value',
                c['transaction']['outputs'][0]['value'] - 1)),
            ('output-SPK', lambda c: c['transaction']['outputs'][0].__setitem__('scriptPublicKey',
                '0000aa20' + '11' * 32 + '87')),
            ('locktime', lambda c: c['transaction'].__setitem__('lockTime', 1)),
            ('gas', lambda c: c['transaction'].__setitem__('gas', 1)),
            ('subnetwork', lambda c: c['transaction'].__setitem__('subnetworkId', '01' + '00' * 19)),
            ('sequence', lambda c: c['transaction']['inputs'][0].__setitem__('sequence', (1 << 64) - 2)),
        ]
        for label, operation in mutations:
            changed = copy.deepcopy(oracle_case); operation(changed)
            # Gas/subnetwork/header mutations may also fail transaction
            # isolation. The separately executed ScriptEngine must still give
            # the exact public binding rejection; no isolation pass is invented.
            native_case('UNSAFE-oracle-unchanged-expected-hash-' + label, changed, False,
                        isolation_required=label not in ('locktime', 'gas', 'subnetwork', 'sequence'))
        for label, offset in [('record-proof', 12 + 3920), ('record-NF-witness', 12 + 600),
                              ('record-CM', 12 + 2848), ('record-CF', 12 + 2912),
                              ('second-virtual-point', 12 + 4048 + 40)]:
            changed = copy.deepcopy(oracle_case)
            payload = bytearray.fromhex(changed['transaction']['payload']); payload[offset] ^= 1
            changed['transaction']['payload'] = payload.hex()
            native_case('UNSAFE-oracle-unchanged-expected-hash-' + label, changed, False)
        changed = copy.deepcopy(oracle_case)
        proof = bytearray.fromhex(changed['transaction']['inputs'][0]['signatureScript']); proof[68] ^= 1
        changed['transaction']['inputs'][0]['signatureScript'] = proof.hex()
        native_case('UNSAFE-oracle-wrong-expected-hash', changed, False)
    return {'schema': 'kpx5-public-native-body-binding-gate/v1',
        'classification': 'PUBLIC_SUPPLIED_UTXO_CODEC_GATE_NOT_FINANCIAL_W_ACCEPTANCE',
        'profile': metadata, 'outer_image_hex32': image.hex(),
        'outer_image_authority_or_actual_guest_receipt_proved_by_this_gate': False,
        'actual_W_redeem_bytes': len(actual_script), 'actual_W_redeem_sha256': h(actual_script).hex(),
        'UNSAFE_oracle_redeem_bytes': len(oracle_script), 'UNSAFE_oracle_redeem_sha256': h(oracle_script).hex(),
        'actual_host_and_Rust_journal_exact': True, 'UNSAFE_host_and_Rust_journal_exact': True,
        'journal_bytes': 424, 'financial_projection_bytes': 8301, 'payload_bytes': 8108,
        'actual_W_journal_sha256': actual_host['journal_sha256'],
        'UNSAFE_oracle_journal_sha256': oracle_host['journal_sha256'],
        'child_proof_sha256s': [child_result['cryptographic']['proof_sha256'] for child_result in actual_host['children']],
        'child_authorization_sha256s': [child_result['cryptographic']['authorization_sha256'] for child_result in actual_host['children']],
        'actual_outer_fee_sompi': actual_host['actual_outer_fee_sompi'], 'actual_W_metrics': actual_body['metrics'],
        'actual_native_validation_cases': len(results),
        'internal_Full_and_separate_engine_execution_count_not_measured': None, 'native_outcomes': results,
        'unsafe_oracle_is_financial_program_or_has_funding_authority': False,
        'actual_genuine_outer_proof_or_receipt_W_acceptance': False,
        'new_owner_proof_PK_backup_private_witness_main_or_hidden_truth_read': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', type=Path, required=True); p.add_argument('--profile-sha256', required=True)
    p.add_argument('--record', type=Path, action='append', required=True)
    p.add_argument('--record-sha256', action='append', required=True)
    p.add_argument('--head', type=Path, required=True); p.add_argument('--head-sha256', required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--raw-output', type=Path, required=True); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--run-native-VM', action='store_true')
    a = p.parse_args()
    need(len(a.record) == len(a.record_sha256) == 2 and not a.output.exists(), 'two_selected_records_new_output')
    records = [record(selected(path, digest)) for path, digest in zip(a.record, a.record_sha256)]
    head = parse(selected(a.head, a.head_sha256))
    result = evaluate(a.profile, a.profile_sha256, records, head, hexbytes(a.image, 32), a.raw_output,
                      run_VM=a.run_native_VM)
    save(a.output, result)
    print(json.dumps({'exact_host_Rust_journal424': True, 'native_validation_cases': result['actual_native_validation_cases'],
        'actual_R0_receipt_W_acceptance': False, 'unsafe_oracle_only_codec': True}))
