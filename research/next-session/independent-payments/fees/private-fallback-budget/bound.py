#!/usr/bin/env python3
"""Source-only complete-input upper bound for the exact selected W private arm.

No VM, emitter, crypto, proof, PK, backup or network operation. Both sides of
every private conditional are overapproximated, including forbidden mode32.
"""
import argparse
import hashlib
import json
from pathlib import Path

import abstract_meter as core

HERE = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check(value, message):
    if not value:
        raise ValueError(message)


def walk(nodes):
    for node in nodes:
        if node[0] == 'if':
            yield node
            yield from walk(node[1])
            yield from walk(node[2])
        else:
            yield node


def calculate(program, inputs):
    expected = inputs['program']
    check(len(program) == expected['bytes'] == 16202
          and sha(program) == expected['sha256']
          and program[:2] == b'\x4c\x70'
          and sha(program[114:]) == expected['immutable_tail_after_state112_sha256'],
          'exact-selected-actual-W-program-and-tail')
    tree = core.ast(program)
    check(tree[0][1] == program[2:114] and len(tree[0][1]) == 112
          and core.decode_number(tree[0][1]) is None and tree[1][0] == 0x75
          and tree[-1][0] == 'if', 'state112-literal-and-final-W-dispatch')
    private = tree[-1][2]
    check(len([n for n in walk(private) if n[0] != 'if' and n[0] == 0xa6]) == 1,
          'exactly-one-private-Groth16-opcode')
    check(sum(n[0] == 0x82 for n in walk(tree[:-1])) == 2
          and not any(n[0] == 0x82 for n in walk(private)), 'only-fixed-initial-private-SIZE-uses')
    m = core.Meter([core.Item(65, exact_length=True), core.Item(128, exact_length=True)])
    # Entire input execution, not only redeem execution:
    # L+65+128 literal witness bytes (free upstream, charged here), 2L P2SH
    # BLAKE2b preimage units, its32-byte result/32-byte expected literal/1-byte
    # comparison result, plus a 35*100 input-SPK overcharge (actual standard
    # locking program is free). These sum to 3L+258+3500.
    overhead = 3 * len(program) + 258 + 3500
    m.units = overhead
    m.run(tree[:-1])
    m.pop()                         # Final dispatch condition was charged above.
    m.run(private)                  # W ELSE is the compact private fallback.
    check(len(m.stack) == 1 and not m.alt, 'one-private-success-item-no-alt')
    units = m.units
    allowance = 1500 * 10000 + 9999
    private_nodes = list(walk(private))
    return {'schema': 'kpx5-complete-input-private-source-upper-bound/v1',
        'classification': 'CONDITIONAL_SOURCE_BOUND_NOT_NATIVE_FEE_OR_SECURITY_QUALIFICATION',
        'program_sha256': sha(program), 'program_bytes': len(program),
        'immutable_tail_after_state112_sha256': sha(program[114:]),
        'complete_input_script_units_upper_bound': units,
        'overhead_units_included_before_W_execution': overhead,
        'private_Groth16_exact_units': 14_000_000 + 3 * 250_000,
        'budget_candidate': 1500, 'allowance_including_free9999': allowance,
        'remaining_units': allowance - units, 'source_bound_fits_candidate': units <= allowance,
        'unknown_numeric_serialization_width_bytes': 9,
        'OP_SIZE_exact_initial_uses': 2, 'OP_SIZE_private_arm_uses': 0,
        'OP_SIZE_on_upper_bound_only_width_refused': True,
        'all_private_conditionals_explore_both_arms': True,
        'unreachable_mode32_work_also_overapproximated': True,
        'private_conditional_nodes_including_unreachable': sum(n[0] == 'if' for n in private_nodes),
        'covered_semantics': ['mode0_Rprime_positive_P_positive_noappend',
            'mode0_Rprime_zero_P_positive_terminal', 'mode2_P_zero_invoice_and_change',
            'mode2_Rprime_positive_P_positive_private_change',
            'either_one_or_two_real_inputs_under_same_fixed_two_NF_native_path'],
        'scope': 'Any successful private execution of this exact W immutable tail with a fixed112-byte state prefix; ordinary monetary/proof/state validity remains separate.',
        'script_engine_charged_prelude_or_postlude_excluded': False,
        'native_VM_proof_PK_backup_private_witness_or_network_used': False,
        'aggregate_zero_proof_seam_units_external_result': inputs['aggregate_zero_proof_seam_script_units'],
        'aggregate_genuine_accepted_units_external_result': inputs['aggregate_genuine_accepted_script_units_external_result'],
        'aggregate_budget_selected_by_this_analysis': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-upstream', type=Path)
    args = parser.parse_args()
    inputs = json.loads((HERE / 'INPUTS.json').read_bytes())
    if args.check_upstream:
        for row in inputs['upstream_files']:
            raw = (args.check_upstream / row['path']).read_bytes()
            check(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'pinned-upstream-source-bytes')
    result = calculate((HERE / inputs['program']['path']).read_bytes(), inputs)
    result['inputs_sha256'] = sha((HERE / 'INPUTS.json').read_bytes())
    result['abstract_meter_sha256'] = sha((HERE / 'abstract_meter.py').read_bytes())
    result['calculator_sha256'] = sha(Path(__file__).read_bytes())
    result['upstream_files_reauthenticated_this_run'] = len(inputs['upstream_files']) if args.check_upstream else 0
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
