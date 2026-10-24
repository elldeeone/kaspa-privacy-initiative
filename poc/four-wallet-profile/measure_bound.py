#!/usr/bin/env python3
"""Reuse the reviewed complete-input source meter on the exact fresh W bytes.

No VM, proof, PK, owner backup or network. Primary meter files are authenticated
against the exact selected upstream Git commit, not a current master checkout.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = ROOT / 'research/next-session/independent-payments/fees/private-fallback-budget'
COMMIT = '01b532e8b553523216471682649693af92f0fd16'
BASELINE = 'b7b41ab066807d7859499b3491a663ab110fedf9'


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public_path(path):
    path = Path(path)
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-public-meter-path')
    return path


def main(emission_path, expected_sha256, upstream, output):
    output = public_path(output)
    need(not output.exists() and output.parent.is_dir(), 'fresh-source-bound-output')
    raw = public_path(emission_path).read_bytes()
    need(sha(raw) == expected_sha256, 'externally-selected-W-emission')
    emission = json.loads(raw)
    need(emission['template_kind'] == 'ACTUAL_R0_W', 'actual-W-not-oracle')
    program = bytes.fromhex(emission['redeem_hex'])
    need(sha(program) == emission['redeem_sha256'], 'actual-W-byte-hash')
    prior = json.loads((OLD / 'INPUTS.json').read_bytes())
    helpers = []
    for name in ('bound.py', 'abstract_meter.py', 'INPUTS.json'):
        p = OLD / name
        original = subprocess.run(['git', 'show', BASELINE + ':' + str(p.relative_to(ROOT))],
            cwd=ROOT, capture_output=True, check=True).stdout
        need(original == p.read_bytes(), 'reviewed-meter-helper-preimage')
        helpers.append({'path': str(p.relative_to(ROOT)), 'sha256': sha(original)})
    upstream = public_path(upstream)
    head = subprocess.run(['git', '-C', str(upstream), 'rev-parse', 'HEAD'],
        capture_output=True, text=True, check=True).stdout.strip()
    need(head == COMMIT, 'selected-upstream-commit')
    primary = []
    for row in prior['upstream_files']:
        blob = subprocess.run(['git', '-C', str(upstream), 'show', COMMIT + ':' + row['path']],
            capture_output=True, check=True).stdout
        actual = (upstream / row['path']).read_bytes()
        need(actual == blob and len(blob) == row['bytes'] and sha(blob) == row['sha256'],
             'exact-primary-meter-source')
        primary.append({**row, 'exact_commit_blob_and_live_worktree_reverified': True})
    sys.path.insert(0, str(OLD))
    spec = importlib.util.spec_from_file_location('reviewed_private_W_source_bound', OLD / 'bound.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inputs = {'program': {'bytes': len(program), 'sha256': sha(program),
                'immutable_tail_after_state112_sha256': sha(program[114:])},
        'aggregate_zero_proof_seam_script_units': None,
        'aggregate_genuine_accepted_script_units_external_result': None}
    result = module.calculate(program, inputs)
    result.update({'financial_profile_id': '68312927-f203-4317-9816-c47c020eed16',
        'exact_new_W_emission_sha256': expected_sha256,
        'new_aggregate_measurement_performed_or_budget_selected': False,
        'native_upstream_commit': COMMIT, 'primary_meter_files': primary,
        'reviewed_helpers': helpers, 'old_program_or_tail_used_as_new_authority': False})
    with output.open('x') as file:
        json.dump(result, file, sort_keys=True, indent=2)
        file.write('\n')
    print(json.dumps({'program_sha256': result['program_sha256'],
        'private_complete_input_bound': result['complete_input_script_units_upper_bound'],
        'candidate_budget': result['budget_candidate'],
        'remaining_units': result['remaining_units'],
        'fits': result['source_bound_fits_candidate'],
        'result_sha256': sha(output.read_bytes())}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emission', type=Path, required=True)
    parser.add_argument('--emission-sha256', required=True)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    main(args.emission, args.emission_sha256, args.upstream, args.output)
