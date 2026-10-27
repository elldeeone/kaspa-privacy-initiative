"""Public controls for current-head cache selection and consumed-action resume."""
import copy
from pathlib import Path
import unittest
from unittest.mock import patch

import campaign_cached as campaign
import launch_cached_campaign


def selected(name):
    return {'path': '/known-public/' + name, 'sha256': '11' * 32}


class CachedCallerControls(unittest.TestCase):
    def test_existing_cached_unit_receipt_refuses_before_detached_service_start(self):
        producer = launch_cached_campaign.Producer.__new__(launch_cached_campaign.Producer)
        proposal = selected('proposal')
        materialization = selected('materialization')
        cold = selected('cold')
        selection = selected('selection')
        activation = {'path': '/known-public/trials/trial-02/live-01/ACTIVATE-HANDOFF.json', 'sha256': '22' * 32}
        template = {'activation': activation}
        values = {materialization['path']: {'schema': 'kpxa-campaign-materialization/v1', 'proposal': proposal,
            'actual_download_and_inventory_and_finite_closures_verified': True,
            'campaign_selection': selection, 'cold_selector': cold},
            selection['path']: dict(template, cold={}), cold['path']: {}}
        producer.frozen_proposal = lambda row: {'campaign_selection_template': template,
            'caller_source': selected('caller')}
        producer.read = lambda row: campaign.encoded(values[row['path']])

        class PublicFakeCaller:
            def __init__(self, *args):
                pass

            def cold_entries(self, **kwargs):
                return []

        import subprocess
        probe = subprocess.CompletedProcess([], 0, stdout='not-found\n')
        with patch.object(campaign, 'Campaign', PublicFakeCaller), patch.object(Path, 'is_dir', return_value=True), \
             patch.object(Path, 'exists', return_value=True), \
             patch.object(launch_cached_campaign.subprocess, 'run', return_value=probe) as invoke:
            with self.assertRaisesRegex(ValueError, 'fresh-cached-unit-public-launch-receipt'):
                producer.launch(proposal, materialization, campaign.PRIVATE / 'known-public-caller',
                    Path('/known-public/run'), campaign.PRIVATE / 'trial-02',
                    'local-payment-public-control', execute=True, resume=True)
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(invoke.call_args.args[0][:3], ['/usr/bin/systemctl', '--user', 'show'])

    def test_current_baseline_and_only_retained_CACHE_are_passed(self):
        head = {'fetch.json': selected('current-prefix/fetch.json')}
        argv = campaign.current_baseline_args(head)
        self.assertEqual(argv, ['--baseline-fetch', '/known-public/current-prefix/fetch.json',
            '--baseline-fetch-sha256', '11' * 32, '--baseline-bundle-directory', '/known-public/current-prefix'])
        self.assertNotIn('--baseline-cache', argv)
        head['CACHE.json'] = selected('retained/CACHE.json')
        argv = campaign.current_baseline_args(head)
        self.assertEqual(argv[-4:], ['--baseline-cache', '/known-public/retained/CACHE.json',
                                    '--baseline-cache-sha256', '11' * 32])
        with self.assertRaises(KeyError):
            campaign.current_baseline_args({'CACHE.json': selected('publicly-discovered/CACHE.json')})

    def test_cache_authority_is_mandatory_and_explicitly_selected(self):
        policy = {'admission': selected('ADMISSION.json'), 'runtime_source': selected('RUNTIME.json')}
        argv = campaign.cache_policy_args(policy)
        self.assertEqual(argv, ['--trusted-local-cache', '--cache-admission', '/known-public/ADMISSION.json',
            '--cache-admission-sha256', '11' * 32, '--runtime-source', '/known-public/RUNTIME.json',
            '--runtime-source-sha256', '11' * 32])
        for malformed in ({}, {'admission': policy['admission']}, dict(policy, optional_cache=selected('forged'))):
            with self.assertRaises(ValueError):
                campaign.cache_policy_args(malformed)

    def test_consumed_second_action_only_confirms_with_current_head_not_activation(self):
        c = campaign.Campaign.__new__(campaign.Campaign)
        c.selection = {'trial_id': 'KNOWN-PUBLIC-TRIAL', 'scripts': {
            'submit': selected('submit_cached.mjs'), 'confirm': selected('confirm_cached.py')},
            'node': selected('node')}
        c.cache_policy = {'admission': selected('ADMISSION.json'), 'runtime_source': selected('RUNTIME.json')}
        c.activation = {name: selected(name) for name in ('selection', 'descriptor', 'assets', 'parameters', 'codec')}
        c.activation['selectors'] = {'fetch.json': selected('initial-activation/fetch.json')}
        c.private = campaign.PRIVATE / 'known-public-fixture-caller'
        case = selected('unchanged-CASE.json')
        c.row = lambda row: campaign.encoded({'transaction': {'id': '22' * 32}}) if row == case else b'PUBLIC SOURCE'
        handoff = {'accepted_whole_CASE_equals_expected': True, 'expected_transaction_id': '22' * 32}
        c.public_read = lambda path: campaign.encoded(handoff)
        calls = []
        c.call = lambda argv, **kwargs: calls.append(list(map(str, argv)))
        state = {'head': {'fetch.json': selected('current-confirmed-prefix/fetch.json'),
                         'CACHE.json': selected('current-confirmed-prefix/CACHE.json')},
                 'submission_consumed': True, 'qualified_case': case, 'next_action': 1}
        snapshot = copy.deepcopy(state)
        with patch.object(campaign, 'private_save', side_effect=AssertionError('consumed-state-reset')):
            c.settle(Path('/known-public/action-0002'), 'action-0002', case, state)
        self.assertEqual(state, snapshot)
        self.assertEqual(len(calls), 1)
        self.assertIn('/known-public/confirm_cached.py', calls[0])
        self.assertNotIn('/known-public/submit_cached.mjs', calls[0])
        self.assertIn('/known-public/current-confirmed-prefix/fetch.json', calls[0])
        self.assertIn('/known-public/current-confirmed-prefix/CACHE.json', calls[0])
        self.assertNotIn('/known-public/initial-activation/fetch.json', calls[0])
        self.assertIn('--runtime-source', calls[0])

    def test_run_does_not_build_or_reprove_consumed_second_action(self):
        c = campaign.Campaign.__new__(campaign.Campaign)
        c.private, c.output = Path('/known-public-dummy-private-caller'), Path('/known-public-output')
        plan = campaign.make_plan(['/known-public/backup0', '/known-public/backup1', '/known-public/backup2'])
        state = {'schema': 'kpxa-private-campaign-state/v1', 'next_action': 1,
                 'head': {'fetch.json': selected('current/fetch.json')}, 'submission_consumed': True,
                 'qualified_case': selected('existing-qualified-second-CASE.json')}
        values = {'PLAN.json': plan, 'STATE.json': state,
            'INVOICES.json': {'schema': 'kpxa-private-campaign-invoice-intent/v1',
                             'paths': ['/known-public/private-invoice-' + str(i) for i in range(6)]}}
        c.cold_entries = lambda **kwargs: []
        c.build = lambda *args, **kwargs: self.fail('consumed action rebuilt or reproved')
        c.owner = lambda *args, **kwargs: self.fail('consumed action asked owner for authority')
        calls = []

        def settle(directory, label, case, actual_state):
            calls.append((str(directory), label, case, copy.deepcopy(actual_state)))
            raise RuntimeError('PUBLIC-CONTROL-STOP-AFTER-FIRST-CONFIRMATION-CALL')

        c.settle = settle
        with patch.object(Path, 'exists', return_value=True), \
             patch.object(campaign, 'read', lambda path, **kwargs: campaign.encoded(values[path.name])):
            with self.assertRaisesRegex(RuntimeError, 'PUBLIC-CONTROL-STOP'):
                c.run()
        self.assertEqual(calls[0][1], 'action-0002')
        self.assertEqual(calls[0][2], state['qualified_case'])
        self.assertTrue(calls[0][3]['submission_consumed'])


if __name__ == '__main__':
    unittest.main()
