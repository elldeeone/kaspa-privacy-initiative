#!/usr/bin/env python3
"""Actual public same-sigs/ID budget RED/GREEN; no W or chain acceptance claim."""
import argparse
import copy
import importlib.util
from pathlib import Path
import sys

from gn2 import EntrySelection, validate_accepted_genesis, validate_genesis
from gn2_common import ROOT, digest, encoded, need, outside, parse, public_bytes, write_new
from gn2_runtime import Runtime

OLD_SHA = 'e443aced630ef49104241f5630c0f8c92ed1cd7196777b03cbc4f61068a124b7'
TRIAL = '6010c7dd-c83d-4a73-9a76-fc89cc40a193'


def run(control, output):
    output = outside(output)
    need(not output.exists(), 'fresh-public-budget-control-output')
    output.mkdir(parents=True, mode=0o700)
    base = parse(public_bytes(control / 'selected-case.json'))
    changed = parse(public_bytes(control / 'budget-not-sighash-covered/case.json'))
    native = parse(public_bytes(control / 'budget-not-sighash-covered/native/native-validation.json'))
    payload = bytes.fromhex(base['transaction']['payload'])
    selected = EntrySelection(payload[8:40].hex(), payload[40:72], b'\x51')
    need(base['transaction']['id'] == changed['transaction']['id']
         and [r['signatureScript'] for r in base['transaction']['inputs']]
             == [r['signatureScript'] for r in changed['transaction']['inputs']]
         and native['Full']['accepted'] is True and native['all_input_engines_accepted'] is True,
         'actual-same-signatures-ID-native-valid-budget-mutation')
    expected_body = copy.deepcopy(base)
    expected_body['transaction']['inputs'][0]['computeBudget'] = 11
    need(expected_body == changed, 'only-selected-budget-changed')
    old_path = ROOT / 'research/next-session/four-wallet-testnet/bootstrap/accepted-budget-controls-01/source-before/gn2.py'
    raw = public_bytes(old_path)
    need(digest(raw) == OLD_SHA, 'retained-old-executed-validator-preimage')
    name = '_gn2_before_accepted_budget_fix'
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(name, loader=None))
    module.__file__ = str(old_path); sys.modules[name] = module
    exec(compile(raw, str(old_path), 'exec'), module.__dict__)
    red = None
    try:module.validate_genesis(changed, selected, TRIAL, signed=True)
    except ValueError as error:red = str(error)
    need(red is not None, 'calibrated-old-history-rejection')
    baseline = validate_accepted_genesis(base, selected, TRIAL)
    green = validate_accepted_genesis(changed, selected, TRIAL)
    need(baseline == green, 'same-financial-history-derived-after-budget-fix')
    strict = False
    try:validate_genesis(changed, selected, TRIAL, signed=True)
    except ValueError:strict = True
    need(strict, 'campaign-budget-remains-exact-ten')
    negative = copy.deepcopy(changed)
    negative['transaction']['outputs'][1]['value'] -= 1
    negative['transaction']['outputs'][2]['value'] += 1
    allocation_refused = False
    try:validate_accepted_genesis(negative, selected, TRIAL)
    except ValueError:allocation_refused = True
    need(allocation_refused, 'accepted-history-owner-allocation-check-preserved')
    # Canonical u16 is not native validity. Actual under-budget execution must
    # still reject, which the calling accepted-chain layer is required to run.
    runtime = Runtime()
    under = copy.deepcopy(base); under['transaction']['inputs'][0]['computeBudget'] = 0
    under, _ = runtime.normalize(under, output / 'underbudget-normalized')
    case_path = output / 'underbudget-case.json'
    write_new(case_path, encoded(under) + b'\n')
    runtime.executables['native-validator'].run(['validate-transaction', case_path, output / 'underbudget-native'])
    under_report = parse(public_bytes(output / 'underbudget-native/native-validation.json'))
    need(under_report['Full']['accepted'] is False, 'underbudget-still-native-invalid')
    result = {'schema': 'kpx6-accepted-GN2-budget-red-green/v1',
        'classification': 'PUBLIC_UNSAFE_ORDINARY_INPUT_CONTROL_NOT_ACTUAL_W_OR_CHAIN_CURRENTNESS',
        'old_validator_sha256': OLD_SHA, 'old_rejection_category': red,
        'same_genuine_two_ALL_signatures_and_transaction_ID': True,
        'budget10_to11_actual_Native_Full_and_both_engines_accept': True,
        'accepted_facade_derives_exact_same_state_reserve_points_allocations': True,
        'campaign_facade_still_rejects_budget11': strict,
        'accepted_facade_still_rejects_fee_redistribution': allocation_refused,
        'budget0_actual_Native_Full_rejects': True,
        'pure_history_does_not_assert_native_acceptance_or_currentness': True,
        'PK_proof_private_owner_files_funding_or_network': False}
    write_new(output / 'RESULTS.json', encoded(result) + b'\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(encoded(run(args.control, args.output)).decode())
