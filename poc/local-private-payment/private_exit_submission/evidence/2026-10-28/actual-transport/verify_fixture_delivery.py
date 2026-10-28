#!/usr/bin/env python3
"""Verify exact delivered public fixtures through the existing selected native CLI.

This is fixture-only, public-only receive/verify evidence. It provides no
broadcast, accepted-head, settlement, funding or anonymity authority. The entry
and shared guard must be externally admitted before execution, as in METHOD02.
"""
import argparse
import hashlib
import importlib.machinery
import json
import os
from pathlib import Path
import sys
import tempfile
import types

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/continuation')
WALLET = ROOT / 'poc/local-private-payment/private_batch_trial'
sys.dont_write_bytecode = True
sys.pycache_prefix = tempfile.mkdtemp(prefix='kpb-public-receive-pyc-')
sys.path.insert(0, str(WALLET))

from payout_linkage_guard import load_guard

guard = load_guard()
read = guard['read']
selection_path = ROOT / '.local/private-payout-linkage-02/original-paired-03/SELECTION.json'
selection_sha = 'bd9c1c02e918f6a11286d17c7cb0910e14eacf9b9233252b944eaeda78dc9b93'
selection = json.loads(read(selection_path, selection_sha))
shared = Path(selection['public']) / 'selected-public'
frozen = {str(Path(row['path']).absolute()):
    read(shared / ('source-' + str(row['index'])), row['sha256'])
    for row in selection['source_members']}
original_get_code = importlib.machinery.SourceFileLoader.get_code
original_exec_module = importlib.machinery.SourceFileLoader.exec_module


def get_code(loader, fullname):
    path = str(Path(loader.path).absolute())
    if path in frozen:
        return compile(frozen[path], path, 'exec')
    if path.startswith(str(ROOT) + '/'):
        raise ImportError('unselected project source')
    return original_get_code(loader, fullname)


def selected_read(path, expected=None):
    canonical = str(Path(path).absolute())
    if canonical in frozen:
        raw = frozen[canonical]
        if expected is not None and hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError('selected source digest')
        return raw
    return read(path, expected)


# This is the source22 entry's existing frozen-code mechanism. Initial ce guard
# bytes are still externally admitted before this entry, as documented above.
importlib.machinery.SourceFileLoader.get_code = get_code
import payout_linkage_guard

selected_guard = lambda: {**guard, 'read': selected_read}
payout_linkage_guard.load_guard = selected_guard


def exec_module(loader, module):
    original_exec_module(loader, module)
    if str(Path(loader.path).absolute()) == str(WALLET / 'payout_linkage_guard.py'):
        module.load_guard = selected_guard


importlib.machinery.SourceFileLoader.exec_module = exec_module
native_path = WALLET / 'payout_linkage_native.py'
native_raw = selected_read(native_path, 'e64db83fa2feeec491105c2b9f59a5c288b9e57e8978e317eb37ffce0a46ea8b')
native = types.ModuleType('selected_public_native_delivery_helpers')
native.__file__ = str(native_path)
sys.modules[native.__name__] = native
exec(compile(native_raw, str(native_path), 'exec'), native.__dict__)

CODEC = Path('/var/tmp/kpi-local-private-native-target-01/release/kpi-private-batch-native')
ENGINE = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def verify(args):
    selector = native.boundary.parse(selected_read(Path(args.selector).absolute(), args.selector_sha256))
    delivered_raw = selected_read(Path(args.delivery).absolute(), args.delivery_sha256)
    delivered = native.boundary.parse(delivered_raw)
    need(selector['schema'] == 'kpb-public-exit-fixture-selection/v1', 'selected-public-fixture-schema')
    fields = {'projection_hex', 'proof_hex128', 'statement_hex152', 'exit_id'}
    need(type(delivered) is dict and set(delivered) == fields, 'exact-four-public-delivery-fields')
    matches = [row for row in selector['fixtures'] if row['exit_id'] == delivered['exit_id']]
    need(len(matches) == 1, 'fixture-only-unselected-delivery')
    selected = matches[0]
    need(delivered == {key: selected[key] for key in fields}, 'delivered-public-bytes-differ-from-selected-fixture')
    need(hashlib.sha256(bytes.fromhex(delivered['projection_hex'])).hexdigest() == delivered['exit_id'],
         'received-projection-exit-identity')
    profile = selector['existing_profile']
    read(CODEC, profile['codec_sha256'])
    read(ENGINE, profile['NativeFull_sha256'])
    parameters = native.boundary.parse(read(Path(profile['native_parameters']), profile['native_parameters_sha256']))
    case = native.boundary.parse(read(Path(selected['source_case']), selected['source_case_sha256']))
    signature = bytes.fromhex(case['transaction']['inputs'][0]['signatureScript'])
    need(signature[:2] == b'\x4c\x80' and signature[2:130].hex() == delivered['proof_hex128'],
         'received-proof-exactly-the-native-witness')
    normalized_raw = native.tool(CODEC, {'operation': 'normalize', 'parameters': parameters, 'case': case})
    normalized = native.boundary.parse(normalized_raw)
    need(normalized['financial_projection_hex'] == delivered['projection_hex']
         and normalized['exit_statement_hex152'] == delivered['statement_hex152']
         and native.boundary.encoded(native.without_caches(normalized['case']))
             == native.boundary.encoded(native.without_caches(case)),
         'received-projection-statement-and-native-case-exact')
    output = Path(args.output).absolute()
    need(not output.exists() and not any(p.is_symlink() for p in (output, *output.parents))
         and all(not output.is_relative_to(p) and not p.is_relative_to(output)
                 for p in guard['m'].GUARD.directories), 'fresh-public-only-output')
    output.mkdir(parents=True, mode=0o700)
    case_path = output / 'CASE.json'
    case_sha = native.bootstrap.save(case_path, normalized['case'])
    native_output = output / 'actual-native'
    process = native.tool(ENGINE,
        mounts=['--ro-bind', str(case_path), str(case_path), '--bind', str(output), str(output)],
        arguments=['validate-transaction', str(case_path), str(native_output)], require_success=False)
    report_path = native_output / 'native-validation.json'
    report_raw = read(report_path) if report_path.exists() else None
    report = native.boundary.parse(report_raw) if report_raw is not None else None
    accepted = native.native_report_passed(report, process.returncode)
    engines = report.get('per_input_ScriptEngine') if type(report) is dict else None
    genuine_zk_refusal = (process.returncode == 0 and type(report) is dict
        and report.get('isolation') == 'PASS' and type(report.get('Full')) is dict
        and report['Full'].get('accepted') is False and report.get('all_input_engines_accepted') is False
        and type(engines) is list and len(engines) == 1
        and any(type(row) is dict and row.get('accepted') is False
                and 'Groth16 verification failed' in str(row.get('typed_error', '')) for row in engines))
    expected = selected['expected_native_Full_all_input_engines']
    need(type(expected) is bool, 'selected-expected-native-outcome')
    result = {'schema': 'kpb-public-fixture-delivery-verification/v1',
        'classification': 'FIXTURE_ONLY_UNFUNDED_OFFLINE_RECEIVE_VERIFY_NOT_CHAIN_ACCEPTANCE',
        'selector_sha256': args.selector_sha256, 'delivery_sha256': args.delivery_sha256,
        'exit_id': delivered['exit_id'], 'fixture_id': selected['fixture_id'],
        'source_case_sha256': selected['source_case_sha256'],
        'normalized_case': {'path': str(case_path), 'sha256': case_sha},
        'normalized_response_sha256': hashlib.sha256(normalized_raw).hexdigest(),
        'native_report': {'path': str(report_path),
            'sha256': None if report_raw is None else hashlib.sha256(report_raw).hexdigest(), 'actual_result': report},
        'native_process_returncode': process.returncode, 'native_accepted': accepted,
        'actual_Groth16_ScriptEngine_refusal': genuine_zk_refusal,
        'expected_outcome_matched': accepted if expected else genuine_zk_refusal,
        'accepted_head_settlement_broadcast_or_anonymity_authority': False}
    pin = native.bootstrap.save(output / 'RESULT.json', result)
    return {'result': str(output / 'RESULT.json'), 'sha256': pin,
        'native_accepted': accepted, 'expected_outcome_matched': result['expected_outcome_matched']}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selector', required=True)
    parser.add_argument('--selector-sha256', required=True)
    parser.add_argument('--delivery', required=True)
    parser.add_argument('--delivery-sha256', required=True)
    parser.add_argument('--output', required=True)
    print(json.dumps(verify(parser.parse_args()), sort_keys=True))


if __name__ == '__main__':
    main()
