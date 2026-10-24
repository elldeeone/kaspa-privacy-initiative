#!/usr/bin/env python3
"""Insert a pinned PUBLIC genuine outer proof, preserve exact body and run Full.

No proof generation, PK, owner witness, backup, signer, broadcast or currentness
oracle. Native verifies the actual fixed W's R0 claim, not an oracle template.
"""
import argparse
import copy
import json
from pathlib import Path
import sys

from native_adapter import NativeCodec
from native_gate import encoded, error_class, save, selected
from policy import Head, public_material
from selected import child_profile, parse
from virtual import InstalledProfile, check_outer, decode_payload
from wire import h, hexbytes, need

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from public_native import normalize, validate


def finalize(case, proof, profile_path, profile_sha, image, expected_journal_sha256, raw_output):
    need(raw_output.is_absolute() and not raw_output.exists()
         and not raw_output.resolve().is_relative_to(ROOT.resolve())
         and not any(part.is_symlink() for part in (raw_output, *raw_output.parents)),
         'fresh_genuine_raw_public_output_outside_Git')
    need(type(proof) is bytes and len(proof) == 128 and proof != bytes(128), 'selected_genuine_outer_proof128')
    child, metadata = child_profile(profile_path, profile_sha, allow_no_append_exit=True)
    codec = NativeCodec(image, profile_sha)  # ACTUAL_R0_W only, never hash oracle.
    profile = InstalledProfile(hexbytes(metadata['wrapper_domain_hex32'], 32), child, codec.emit)
    record0 = decode_payload(hexbytes(case['transaction']['payload']))[0]
    auth = record0[:528]
    # This starting head is only a given supplied-context premise. Its exact
    # complete case is independently pinned by the caller, not chosen by a proof.
    head = Head(auth[40:72].hex(), int.from_bytes(auth[72:76], 'little'), auth[76:188],
                int.from_bytes(auth[188:196], 'little'), domain=child.domain)
    before = check_outer(profile, case, head, verify)
    need(before['journal_sha256'] == expected_journal_sha256, 'externally_selected_expected_journal')
    original_frame = hexbytes(case['transaction']['inputs'][0]['signatureScript'])
    need(original_frame[68:196] == bytes(128), 'original_exact_zero_outer_proof_slot')
    changed = copy.deepcopy(case)
    frame = bytearray(original_frame); frame[68:196] = proof
    changed['transaction']['inputs'][0]['signatureScript'] = frame.hex()
    actual = normalize(changed)
    need(actual['transaction'] == changed['transaction'], 'only_outer_proof_changed_ID_mass_and_body_fixed')
    need(actual['metrics']['actual_fee_sompi'] == 100 * actual['metrics']['mining_mass'],
         'actual_genuine_body_exact_reference100_fee')
    after = check_outer(profile, changed, head, verify)
    body = codec.body(changed)
    need(before['journal_hex424'] == after['journal_hex424'] == body['journal_hex424']
         and body['template_kind'] == 'ACTUAL_R0_W', 'genuine_proof_preserves_exact_actual_W_journal')
    raw_output.mkdir(parents=True, mode=0o700)
    outcomes = []

    def execute(label, candidate, expected, expected_error=None):
        normalized = normalize(candidate)
        checked = {'transaction': normalized['transaction'], 'entries': candidate['entries']}
        # Retain the exact input and observed result before testing expectations:
        # a genuine verifier/converter mismatch must leave reviewable evidence.
        save(raw_output / label / 'validation-case.json', checked)
        outcome = validate(checked)
        report, metrics = outcome['report'], outcome['metrics']
        save(raw_output / label / 'native-report.json', report)
        save(raw_output / label / 'metrics.json', metrics)
        need(report['isolation'] == 'PASS' and len(report['per_input_ScriptEngine']) == 1,
             'actual_W_Full_isolation_single_engine')
        engine = report['per_input_ScriptEngine'][0]
        need(report['Full']['accepted'] is expected and engine['accepted'] is expected,
             'genuine_actual_W_expected_Full_outcome_' + label)
        if expected_error:
            need(error_class(engine) == expected_error, 'typed_actual_W_rejection_' + label)
        outcomes.append({'label': label, 'Full_accepted': expected, 'engine_accepted': expected,
                         'isolation_PASS': True, 'engine_error_class': error_class(engine),
                         'engine_units': engine['units'], 'public_case_sha256': h(encoded(checked)).hex(),
                         'actual_fee_sompi': metrics['actual_fee_sompi'], 'mining_mass': metrics['mining_mass']})

    execute('genuine-R0-receipt-ACTUAL-W-POSITIVE', changed, True)
    # Leave the genuine canonical outer proof unchanged, but change its public
    # claim. Rejection therefore checks verification binding, not point parsing.
    for label, offset in [('changed-CF-genuine-proof-unchanged', 12 + 2912),
                          ('changed-inner-proof-genuine-outer-unchanged', 12 + 3920)]:
        bad = copy.deepcopy(changed)
        data = bytearray.fromhex(bad['transaction']['payload']); data[offset] ^= 1
        bad['transaction']['payload'] = data.hex()
        execute(label, bad, False, 'ZkIntegrity')
    bad = copy.deepcopy(changed)
    bad['transaction']['outputs'][0]['value'] -= 1
    execute('changed-native-reserve-genuine-proof-unchanged', bad, False, 'VerifyError')
    bad = copy.deepcopy(changed)
    bad['transaction']['inputs'][0]['previousOutpoint']['index'] += 1
    execute('wrong-current-point-genuine-proof-unchanged', bad, False, 'VerifyError')
    bad = copy.deepcopy(changed)
    bad['transaction']['outputs'].append({'value': 1, 'scriptPublicKey': '000020' + '11' * 32 + 'ac', 'covenant': None})
    execute('unauthorized-extra-native-payout', bad, False, 'VerifyError')
    save(raw_output / 'exact-host-journal.json', after)
    save(raw_output / 'exact-native-journal.json', body)
    return {'schema': 'kpx5-genuine-public-R0-native-W-result/v1',
        'classification': 'GENUINE_COMPRESSED_RECEIPT_NATIVE_FULL_SUPPLIED_CONTEXTS_ONLY',
        'child_profile': metadata, 'outer_image_hex32': image.hex(),
        'actual_outer_proof_sha256': h(proof).hex(), 'actual_W_journal_sha256': after['journal_sha256'],
        'actual_W_redeem_sha256': h(original_frame[199:]).hex(),
        'actual_W_immutable_tail_sha256': h(original_frame[313:]).hex(),
        'initial_reserve_sompi': after['initial_reserve_sompi'],
        'final_reserve_sompi': after['final_reserve_sompi'],
        'exact_actual_outer_fee_sompi': after['actual_outer_fee_sompi'],
        'actual_native_validation_cases': len(outcomes), 'native_outcomes': outcomes,
        'two_private_owner_proofs_plus_genuine_outer_receipt_native_Full': True,
        'unsafe_hash_oracle_accepted_as_actual_W': False,
        'SDK_receipt_verification_is_external_separate_evidence': True,
        'accepted_chain_backing_currentness_private_fallback_fee_or_privacy_qualification': False,
        'new_proof_PK_owner_backup_private_witness_main_or_hidden_truth_read': False}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for field in ('case', 'proof', 'profile', 'raw-output', 'output'): p.add_argument('--' + field, type=Path, required=True)
    for field in ('case-sha256', 'proof-sha256', 'profile-sha256', 'image', 'expected-journal-sha256'):
        p.add_argument('--' + field, required=True)
    a = p.parse_args(); need(not a.output.exists(), 'fresh_genuine_W_summary')
    case = parse(selected(a.case, a.case_sha256)); proof = selected(a.proof, a.proof_sha256)
    value = finalize(case, proof, a.profile, a.profile_sha256, hexbytes(a.image, 32),
                     a.expected_journal_sha256, a.raw_output)
    save(a.output, value)
    print(json.dumps({'genuine_actual_W_Full': True, 'native_validation_cases': value['actual_native_validation_cases'],
                      'exact_outer_fee_sompi': value['exact_actual_outer_fee_sompi'],
                      'accepted_chain_or_private_fallback_qualified': False}))
