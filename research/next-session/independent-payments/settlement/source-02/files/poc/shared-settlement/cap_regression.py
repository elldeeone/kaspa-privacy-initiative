#!/usr/bin/env python3
"""Recheck two EXISTING PUBLIC capacity exits with the selected fresh profile."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from capacity_g16 import verify
from policy import Head, public_material
from selected import child_profile, parse
from transcript import check
from wire import h, need

PROFILE_SHA = '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd'
PUBLIC_CASES = (
    ('native-first', '6b0550dd718c93ead10160bb74240736a32032f577d3630e44a7d4a2a46b9a6a'),
    ('native-terminal', 'fe9f8783820d68c861af800042b3d5494ae306c90852ece812364ca357e7f21f'))


def run():
    policy, metadata = child_profile(ROOT / 'poc/shared-settlement-proof/child-profile.json',
                                    PROFILE_SHA, allow_no_append_exit=True)
    cases = []
    for name, expected in PUBLIC_CASES:
        raw = (Path('/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-genuine-01') / name / 'case.json').read_bytes()
        need(h(raw).hex() == expected, 'selected_existing_PUBLIC_capacity_case')
        cases.append(parse(raw))
    auth, _ = public_material(cases[0])
    given = Head(auth[40:72].hex(), int.from_bytes(auth[72:76], 'little'), auth[76:188],
                 int.from_bytes(auth[188:196], 'little'), domain=policy.domain)
    result = check(policy, given, [('compact2', case) for case in cases], verify)
    need(result['accepted'] is True and result['final_reserve_sompi'] == 0
         and result['outcomes'][0]['effects']['mode'] == 0
         and result['outcomes'][0]['effects']['reserve_after_sompi'] == 1000000000,
         'fresh_noappend_positive_reserve_then_terminal_regression')
    return {'schema': 'kpx5-existing-capacity-public-regression/v1', 'profile': metadata,
            'classification': 'EXISTING_PUBLIC_UNFUNDED_CASES_FRESH_G16_AND_PUBLIC_SEMANTICS_ONLY',
            'selected_public_case_sha256s': [digest for _, digest in PUBLIC_CASES], 'transcript': result,
            'new_proof_native_VM_main_or_owner_witness_read': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    need(not args.output.exists(), 'fresh_regression_output')
    result = run()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as output:
        json.dump(result, output, sort_keys=True, separators=(',', ':')); output.write('\n')
    print(json.dumps({'two_existing_genuine_proofs_verified': True,
        'mode0_positive_reserve_then_terminal': True, 'native_VM_new_proof_or_private_data': False}))
