#!/usr/bin/env python3
"""Real Native Full controls for an explicitly unfunded direct-Exit component.

The payment image/component metadata are opaque and UNSELECTED. This runner
does not select a full financial profile or manufacture an aggregate key.
It checks the genuine AuthExit parameter lineage before using the unchanged
public Native Full control runner and emits a separate conditional result.
"""
import argparse
import hashlib
import json
from pathlib import Path

import run_native_controls as native

CLASS = 'UNFUNDED_EXIT_COMPONENT_ONLY_UNSELECTED_PAYMENT_METADATA'


def run(plan, plan_sha):
    native.fields(plan, ('schema', 'classification', 'payment_profile_selected',
        'auth_exit_parameter_manifest', 'expected_auth_exit_source_sha256',
        'expected_auth_exit_matrix_sha256', 'reference_fee_rate_sompi_per_mass', 'native_vm_plan'))
    native.need(plan['schema'] == 'private-batch-unfunded-exit-component-controls/v1'
        and plan['classification'] == CLASS and plan['payment_profile_selected'] is False,
        'explicit-unfunded-exit-component-plan')
    manifest = native.parse(native.read(plan['auth_exit_parameter_manifest']))
    native.need(manifest.get('schema') == 'kpb-new-wallet-parameters/v1'
        and manifest.get('role') == 'new-auth-exit'
        and manifest.get('instances') == 3
        and manifest.get('source_sha256') == plan['expected_auth_exit_source_sha256']
        and manifest.get('matrix_sha256') == plan['expected_auth_exit_matrix_sha256'],
        'genuine-selected-auth-exit-role-model-source')
    vm = plan['native_vm_plan']
    native.need(type(vm) is dict and vm.get('scope') == 'exit', 'exit-branch-only-plan')
    # Authenticate every executable before even the preliminary fee quotation.
    # native.run repeats admission before the actual Native Full controls.
    native.read(vm['codec'])
    native.read(vm['engine'])
    parameters = native.parse(native.read(vm['parameters']))
    native.need(parameters.get('schema') == 'private-batch-exit-component-parameters/v1'
        and parameters.get('classification') == CLASS
        and parameters.get('payment_profile_selected') is False
        and parameters.get('domain_hex32') == manifest['domain_hex32']
        and parameters.get('profile_hex32') == manifest['profile_id_hex32']
        and parameters.get('auth_exit') == {
            'vk_hex328': manifest['vk_hex328'],
            'vk_sha256': manifest['vk_sha256'],
            'parameter_manifest_sha256': plan['auth_exit_parameter_manifest']['sha256']},
        'component-parameters-match-genuine-role-manifest')
    native.need(hashlib.sha256(bytes.fromhex(manifest['vk_hex328'])).hexdigest()
        == manifest['vk_sha256'], 'genuine-exit-verification-key-hash')
    native.need(all(case.get('mode') == 'exit' for case in vm['cases']),
        'no-payment-case-in-component-probe')
    rate = plan['reference_fee_rate_sompi_per_mass']
    native.need(type(rate) is int and rate == 100, 'selected-source-reference-fee-rate')
    positive_branches = set()
    for case in vm['cases']:
        if case['expected'] != 'accept':
            continue
        source = native.parse(native.read(case['case']))
        payload = bytes.fromhex(source['transaction']['payload'])
        native.need(len(payload) == 1604 and payload[:8] == b'KPBXEF01',
            'new-auth-exit-positive-body')
        positive_branches.add('terminal' if int.from_bytes(payload[352:360], 'little') == 0
            else 'continuing')
        quoted = native.codec(vm['codec']['path'], parameters, 'body', source)
        metrics = quoted['metrics']
        native.need(quoted.get('classification') == CLASS
            and quoted.get('payment_profile_selected') is False
            and type(metrics['mining_mass']) is int and type(metrics['actual_fee_sompi']) is int
            and metrics['actual_fee_sompi'] >= metrics['mining_mass'] * rate,
            'actual-positive-source-native-fee-quote')
    native.need(positive_branches == {'terminal', 'continuing'},
        'actual-terminal-and-continuing-positive-cases-required')
    # The original runner insists on actual positive Native Full + all input
    # ScriptEngines, and actual negative ScriptEngine rejection. A process exit
    # or host-codec refusal cannot earn a rejection result.
    native.run(vm, plan_sha)
    raw = (Path('/out') / 'RESULT.json').read_bytes()
    result = native.parse(raw)
    native.need(result.get('actual_positive_native_full_and_scripts') is True
        and result.get('actual_negative_script_rejections') is True,
        'actual-native-component-results-required')
    conditional = {
        'schema': 'private-batch-unfunded-exit-component-native-result/v1',
        'classification': CLASS,
        'plan_sha256': plan_sha,
        'actual_native_vm_result_sha256': hashlib.sha256(raw).hexdigest(),
        'actual_native_vm_result': result,
        'auth_exit_parameter_manifest': plan['auth_exit_parameter_manifest'],
        'auth_exit_source_sha256': manifest['source_sha256'],
        'auth_exit_matrix_sha256': manifest['matrix_sha256'],
        'auth_exit_vk_sha256': manifest['vk_sha256'],
        'domain_hex32': manifest['domain_hex32'],
        'profile_id_hex32': manifest['profile_id_hex32'],
        'payment_profile_selected': False,
        'aggregate_key_or_payment_receipt_qualified': False,
        'accepted_liability_ledger_or_chain_currentness': False,
        'funding_or_broadcast': False,
        'conditional_exit_branch_only': True,
        'positive_branches': sorted(positive_branches),
        'reference_fee_rate_sompi_per_mass': rate,
        'actual_node_minimum_fee_claim': False,
    }
    digest = native.save(Path('/out') / 'CONDITIONAL-RESULT.json', conditional)
    print(json.dumps({'conditional_result_sha256': digest,
        'classification': CLASS, 'scope': 'exit', 'case_count': len(result['cases'])}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha', required=True)
    arguments = parser.parse_args()
    native.need(Path('/out').is_dir() and not Path('/home').exists()
        and not Path('/var').exists(), 'isolated-public-only-namespace')
    raw = native.read({'path': arguments.plan, 'sha256': arguments.plan_sha})
    run(native.parse(raw), arguments.plan_sha)


if __name__ == '__main__':
    main()
