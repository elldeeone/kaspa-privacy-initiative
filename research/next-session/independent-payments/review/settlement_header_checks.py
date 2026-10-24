#!/usr/bin/env python3
"""Independent fixed-public-body coherent header mutations; no native VM.

Official normalization computes each new ID. Actual selected Groth16 checks
still pass; public native semantics must reject the altered fixed headers.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement'))
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
import fixtures
import policy
import public_g16
import public_native


def run():
    selected, cases = fixtures.install()
    case = cases['compact']
    head = fixtures.given_head(case)
    rows = []
    for label, field, value in [('gas', 'gas', 1), ('locktime', 'lockTime', 1),
            ('subnetwork', 'subnetworkId', '01' + '00' * 19), ('sequence', None, 0)]:
        changed = copy.deepcopy(case)
        if field:
            changed['transaction'][field] = value
        else:
            changed['transaction']['inputs'][0]['sequence'] = value
        changed['transaction'] = public_native.normalize(changed)['transaction']
        result = policy.inspect(selected, changed, head, 'compact2', public_g16.verify)
        assert result['cryptographic']['verified'] is True
        assert result['accepted'] is False
        assert result['public_error'] == 'native_fixed_header_and_sequence'
        rows.append({'case': label, 'genuine_proof_valid': True,
                     'mirror_accepted': False, 'public_error': result['public_error'],
                     'ID_coherently_recomputed': True, 'native_VM_run': False})
    source = ROOT / 'poc/shared-settlement/policy.py'
    return {'schema': 'independent-settlement-header-gap/v1',
            'classification': 'PUBLIC_FIXED_CANARIES_ONLY_NO_NATIVE_VM_NO_OWNER_INPUTS',
            'postfix_all_expected': True,
            'policy_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
            'rows': rows, 'actual_G16_calls': len(rows), 'native_VM_calls': 0}


if __name__ == '__main__':
    print(json.dumps(run(), indent=2, sort_keys=True))
