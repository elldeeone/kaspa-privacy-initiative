#!/usr/bin/env python3
"""Native budget slack on existing PUBLIC genuine proofs; no reproof or fee qualification."""
from pathlib import Path
import argparse
import copy
import json
import re

from public_g16 import digest
from public_native import normalize, validate

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'research/next-session/compact-batch/lifecycle/public-native-canaries-01'


def run(output):
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    rows = []
    for name in ('compact-continuing', 'compact-terminal', 'wide32'):
        original = json.loads((FIXTURES/name/'validation-case.json').read_bytes())
        for budget in (1600, 1500, 1475):
            case = copy.deepcopy(original)
            case['transaction']['inputs'][0]['computeBudget'] = budget
            normalized = normalize(case)
            body, metrics = normalized['transaction'], normalized['metrics']
            expected = copy.deepcopy(original['transaction'])
            expected['inputs'][0]['computeBudget'] = budget
            expected['mass'] = body['mass']
            assert body == expected  # ID, payload, proof, outputs and all other fields unchanged.
            case['transaction'] = body
            checked = validate(case)
            assert metrics == checked['metrics']
            report = checked['report']
            assert report['isolation'] == 'PASS' and len(report['per_input_ScriptEngine']) == 1
            engine = report['per_input_ScriptEngine'][0]
            expected_accept = budget != 1475
            assert report['Full']['accepted'] is expected_accept
            assert report['all_input_engines_accepted'] is expected_accept
            assert engine['accepted'] is expected_accept
            assert engine['allowed_script_units'] == budget*10000+9999
            if not expected_accept:
                # The precompile wraps meter errors using Display inside
                # ZkIntegrity rather than preserving the Rust Debug variant.
                error = re.fullmatch(r'ZkIntegrity\("Kaspa txscript error: script units exceeded the amount committed in the input: used=(\d+), limit=(\d+)"\)', engine['typed_error'])
                assert error and int(error[1]) > int(error[2]) == engine['allowed_script_units']
            assert metrics['actual_fee_sompi'] == 1000
            quote = next(row for row in metrics['quotes'] if row['rate'] == 100)
            assert quote['passes'] is False
            label = name+'-B'+str(budget)
            result = {'case': label, 'expected_native_accept': expected_accept,
                'transaction_id_unchanged': True, 'only_compute_budget_and_derived_mass_changed': True,
                'proof_reused_byte_identical': True, 'authorization_payload_byte_identical': True,
                'Full': report['Full'], 'engine': engine, 'metrics': metrics,
                'normalization_VM_calls': 0, 'native_validation_calls': 1,
                'native_elf_sha256': checked['native_elf_sha256']}
            rows.append(result)
            directory = output/label
            directory.mkdir(mode=0o700)
            for file, value in [('validation-case.json',case),('native-validation.json',report),('metrics.json',metrics)]:
                (directory/file).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    pairs=[]
    for name in ('compact-continuing','compact-terminal','wide32'):
        base=next(row for row in rows if row['case']==name+'-B1600')
        lower=next(row for row in rows if row['case']==name+'-B1500')
        assert base['engine']['units']==lower['engine']['units']
        pairs.append({'case':name,'actual_units':lower['engine']['units'],
            'B1500_slack_SU':15009999-lower['engine']['units'],
            'reference_rate100_required_sompi_B1600':base['metrics']['quotes'][0]['required_sompi'],
            'reference_rate100_required_sompi_B1500':lower['metrics']['quotes'][0]['required_sompi'],
            'observed_reference_fee_floor_difference_sompi':base['metrics']['quotes'][0]['required_sompi']-lower['metrics']['quotes'][0]['required_sompi']})
    summary={'schema':'kpx5-public-native-budget-controls/v1',
        'classification':'PUBLIC_SYNTHETIC_DO_NOT_FUND_INTEROPERABILITY_ONLY_UNDERPAID_FEE1000',
        'all_expected_outcomes':True,'actual_native_validation_calls':len(rows),
        'B1600_baselines':3,'B1500_genuine_proof_native_positives':3,
        'B1475_specific_committed_script_budget_rejections':3,
        'old_params_proof_Auth_or_body_ID_changed':False,
        'uniform_policy_bound_complete_lifecycle_fee_or_relay_qualification':False,
        'new_proof_PK_setup_backup_or_owner_witness_reads':False,
        'comparisons':pairs,'cases':rows,
        'source_sha256':{'controls':digest(Path(__file__).read_bytes()),
                         'public_native':digest((Path(__file__).parent/'public_native.py').read_bytes())}}
    (output/'RESULTS.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'all_expected_outcomes':True,'actual_native_validation_calls':len(rows),'comparisons':pairs},sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    run(parser.parse_args().output)
