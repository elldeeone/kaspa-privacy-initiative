"""Public controls: proposal/template cannot enter owner or detached launch."""
from pathlib import Path
import unittest
from unittest.mock import patch

import campaign
import launch_campaign


class LaunchControls(unittest.TestCase):
    def test_template_selector_cannot_materialize(self):
        producer = launch_campaign.Producer.__new__(launch_campaign.Producer)
        producer.frozen_proposal = lambda row: {'campaign_selection_template': {}}
        producer.read = lambda row: campaign.encoded({'classification': 'TEMPLATE_ONLY_NOT_DOWNLOADED_OR_CAMPAIGN_RELEASED',
                                                     'cold': {'files': [], 'download_receipt': {}}})
        with patch.object(campaign, 'Campaign', side_effect=AssertionError('owner-or-caller-created')), \
             patch.object(launch_campaign.subprocess, 'run', side_effect=AssertionError('process-started')):
            with self.assertRaisesRegex(ValueError, 'actual-materialized-cold-selector'):
                producer.materialize({}, {}, Path('/known-public-fixture/selection.json'))

    def test_cold_gate_failure_precedes_prepare_and_service_start(self):
        producer = launch_campaign.Producer.__new__(launch_campaign.Producer)
        proposal_row = {'path': '/known-public/proposal', 'sha256': '11' * 32}
        cold_row = {'path': '/known-public/cold', 'sha256': '22' * 32}
        selected_row = {'path': '/known-public/selection', 'sha256': '33' * 32}
        activation = {'path': '/known-public/trials/trial-02/live-01/ACTIVATE-HANDOFF.json', 'sha256': '44' * 32}
        template = {'activation': activation, 'cold': {'schema': 'PENDING'}}
        cold = {'files': [], 'download_receipt': {}}
        materialization = {'schema': 'kpxa-campaign-materialization/v1', 'proposal': proposal_row,
            'actual_download_and_inventory_and_finite_closures_verified': True,
            'campaign_selection': selected_row, 'cold_selector': cold_row}
        producer.frozen_proposal = lambda row: {'campaign_selection_template': template, 'caller_source': {}}
        producer.read = lambda row: campaign.encoded(materialization if row['path'] == '/known-public/materialization'
            else dict(template, cold=cold) if row == selected_row else cold)

        class RefusedCold:
            def __init__(self, *args):
                pass

            def cold_entries(self, **kwargs):
                raise ValueError('actual-download-rejected')

        with patch.object(campaign, 'Campaign', RefusedCold), \
             patch.object(launch_campaign.subprocess, 'run', side_effect=AssertionError('process-started')):
            with self.assertRaisesRegex(ValueError, 'actual-download-rejected'):
                producer.launch(proposal_row, {'path': '/known-public/materialization', 'sha256': '55' * 32},
                    campaign.PRIVATE / 'caller-control-02', Path('/known-public/output'),
                    campaign.PRIVATE / 'trial-02', 'local-payment-control', execute=True)


if __name__ == '__main__':
    unittest.main()
