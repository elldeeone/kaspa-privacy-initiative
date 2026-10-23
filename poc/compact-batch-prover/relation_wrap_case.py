#!/usr/bin/env python3
"""An additional coherent wrapped-small-sum direct-CS control (case15).

Preserves the previously frozen14 controls and their generator. Every nominal
secret is a deterministic PUBLIC_SYNTHETIC_DO_NOT_FUND fixture. All individual
values, input-total/reserve and public reserve equations are legal. Only the
exact aggregate output balance is false; wrapping u64 arithmetic would hide it.
No CS, proof, setup, native, RPC or private-input hashing is performed here.
"""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/compact-batch-lifecycle'))
from synthetic import DOMAIN, SCHEMA, box, note, sample  # noqa: E402
from primitives import (MAX, NOTE_FLOOR, ZERO, dummy_nf, fixed, h, insert_nf,
                        need, note_cm, real_nf, singleton, u32, u64)  # noqa: E402

LABEL = 'relation-controls15/WRAPPED_SMALL_SUM/PUBLIC_SYNTHETIC_DO_NOT_FUND'
FEE = 1000
WRAPPED_OUTPUT_TOTAL = 1_000_000_000
EXACT_OUTPUT_TOTAL = (1 << 64) + WRAPPED_OUTPUT_TOTAL


def fixture():
    quotient, remainder = divmod(EXACT_OUTPUT_TOTAL, 32)
    values = [quotient] * 31 + [quotient + remainder]
    source_value = WRAPPED_OUTPUT_TOTAL + FEE
    need(sum(values) == EXACT_OUTPUT_TOTAL and sum(values) % (1 << 64) == WRAPPED_OUTPUT_TOTAL,
         'exact-versus-wrapped-output-sum')
    need(all(NOTE_FLOOR <= value <= MAX for value in values), 'all-individual-values-legal')
    need(source_value <= MAX and WRAPPED_OUTPUT_TOTAL >= NOTE_FLOOR, 'input-reserve-and-tail-legal')

    source, owner_secret, nf_secret = note(LABEL + '/input', source_value)
    before = singleton(DOMAIN, source, box(LABEL + '/initial', 0))
    cm_tree, _ = before.roots()
    real = real_nf(DOMAIN, nf_secret, note_cm(DOMAIN, source), 0)
    dummy_key, dummy_seed = sample(LABEL, 'dummy-key'), sample(LABEL, 'dummy-seed')
    dummy = dummy_nf(DOMAIN, dummy_key, dummy_seed, 1)
    after, first = insert_nf(before, real)
    after, second = insert_nf(after, dummy)
    notes = [note(f'{LABEL}/output/{slot}', value)[0] for slot, value in enumerate(values)]
    ciphers = [box(LABEL, slot) for slot in range(32)]
    need(len({note_cm(DOMAIN, raw) for raw in notes}) == 32, 'all-CMs-distinct')
    after, start, boundary = after.append(DOMAIN, notes, ciphers)
    metadata = bytes([32]) + bytes(3) + u32(start) + bytes(24)
    auth = (b'KPX4AU01' + DOMAIN + sample(LABEL, 'FAKE_DO_NOT_FUND_PREVIOUS_TRANSACTION') + u32(0)
            + before.state(DOMAIN) + u64(source_value) + u64(FEE) + real + dummy
            + h(*(note_cm(DOMAIN, raw) for raw in notes)) + metadata + h(*ciphers)
            + after.state(DOMAIN) + u64(WRAPPED_OUTPUT_TOTAL) + u64(0) + bytes(36))
    fixed(auth, 528)
    real_input = {'real': True, 'note_hex168': source.hex(), 's_hex32': owner_secret.hex(),
        'k_hex32': nf_secret.hex(), 'position': 0,
        'cm_path_hex': [row.hex() for row in cm_tree.path(0)],
        'dummy_key_hex32': ZERO.hex(), 'dummy_seed_hex32': ZERO.hex()}
    dummy_input = {'real': False, 'note_hex168': bytes(168).hex(), 's_hex32': ZERO.hex(),
        'k_hex32': ZERO.hex(), 'position': 0, 'cm_path_hex': [ZERO.hex()] * 16,
        'dummy_key_hex32': dummy_key.hex(), 'dummy_seed_hex32': dummy_seed.hex()}
    request = {'schema': SCHEMA, 'auth_hex528': auth.hex(), 'inputs': [real_input, dummy_input],
        'outputs': [{'note_hex168': raw.hex()} for raw in notes]}
    summary = {'schema': 'kpx4-small-wrapped-sum-direct-control/v1',
        'classification': 'PUBLIC_SYNTHETIC_DO_NOT_FUND', 'role': 'wide32',
        'label': 'wide-small-wrapped-sum-coherent', 'expected_relation_satisfied': False,
        'required_result_kind': 'DIRECT_CONSTRAINT_UNSAT',
        'parser_rejection_does_not_count_as_direct_UNSAT': True,
        'original14_control_predictions_and_bytes_unchanged': True,
        'input_total_sompi': source_value, 'reserve_sompi': source_value,
        'fee_sompi': FEE, 'reserve_after_sompi': WRAPPED_OUTPUT_TOTAL, 'payout_sompi': 0,
        'exact_output_sum_sompi': EXACT_OUTPUT_TOTAL,
        'wrapping_u64_output_sum_sompi': WRAPPED_OUTPUT_TOTAL,
        'minimum_output_sompi': min(values), 'maximum_output_sompi': max(values),
        'all_individual_values_in_range': True, 'input_total_equals_reserve_and_is_in_range': True,
        'public_reserve_equation_balanced': True, 'wrapping_private_balance_would_appear_balanced': True,
        'ordered_CM_digest_and_all32_distinct_CMs_recomputed': True,
        'prior_CM_membership_original_NFs_and_successor_roots_recomputed': True,
        'cm_cursor_before': before.cm_cursor, 'aligned_start': start, 'cm_cursor_after': after.cm_cursor,
        'NF_count_after': len(after.nullifiers), 'boundary_path_hash_count': len(boundary),
        'native_NF_witness_bytes': len(first + second),
        'private_witness_or_input_hash_emitted': False,
        'CS_setup_proof_native_or_RPC_execution': False}
    return request, summary


def create(output):
    output = output.absolute()
    need(not output.is_relative_to(ROOT) and not output.exists(), 'fresh-output-outside-Git')
    need(not any(p.is_symlink() for p in (output, *output.parents)), 'output-symlink')
    need(json.loads((ROOT / 'research/next-session/compact-batch/PUBLIC-INSTANCE-01.json').read_bytes())['domain_hex32'] == DOMAIN.hex(),
         'selected-domain')
    output.mkdir(mode=0o700, parents=True)
    request, summary = fixture()
    descriptor = os.open(output / 'wide-small-wrapped-sum.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as file:
        json.dump(request, file, separators=(',', ':'))
        file.write('\n')
    with (output / 'CONTROL-PREDICTION.json').open('x') as file:
        json.dump(summary, file, indent=2, sort_keys=True)
        file.write('\n')
    print(json.dumps({'new_additive_case': 15, 'expected_direct_constraint_result': 'UNSAT',
        'exact_output_sum_sompi': EXACT_OUTPUT_TOTAL,
        'wrapping_u64_output_sum_sompi': WRAPPED_OUTPUT_TOTAL,
        'CS_setup_proof_native_or_RPC_execution': False,
        'private_witness_or_input_hash_emitted': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    create(parser.parse_args().output)
