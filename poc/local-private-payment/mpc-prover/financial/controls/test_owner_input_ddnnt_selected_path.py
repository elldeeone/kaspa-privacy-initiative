from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[2]


class SelectedDdnntPathControls(unittest.TestCase):
    """Finite source/compile control; runtime evidence is reported separately."""

    def test_complete_five_value_server_supply_and_offset_derivation(self):
        source = ((SOURCE / 'owner_inputs_active.cpp').read_text() +
                  (SOURCE / 'owner_input_ddnnt.cpp').read_text() +
                  (SOURCE / 'owner_input_ddnnt.hpp').read_text())
        for required in (
            'DDNNT_ACTIVE_5N', 'OWNER_DDNNT_MULTIPLICATION_BATCH',
            'preprocessing.get_three(', 'DATA_TRIPLE, s[index], r[index], w[index]',
            'ScalarCaptureSite::OwnerDdnntRandomV, count',
            'ScalarCaptureSite::OwnerDdnntProductU, v, r',
            'context.check_field_pending()',
            'ScalarCaptureSite::OwnerDdnntTripleS, s',
            'ScalarCaptureSite::OwnerDdnntTripleR, r',
            'ScalarCaptureSite::OwnerDdnntTripleW, w',
            'DDNNT_S', 'DDNNT_R', 'DDNNT_W', 'DDNNT_V', 'DDNNT_U',
            'owner_input_preprocessing_share_frame(',
            'owner_input_offset_frame(',
            'owner-ddnnt-offset-length-valid', 'owner-ddnnt-common-offset',
            'context.public_constant(offsets[index])',
            'consumed_roles_.insert(contract.owner_id)',
            'duplicate-owner-job-role', 'owner-cohort-contract-role',
        ):
            self.assertIn(required, source)
        self.assertNotIn('DDNNT_ACTIVE_3N', source)
        self.assertNotIn('STOCK_MASCOT_ADDITIVE_SHARES_3P', source)
        self.assertNotIn('authenticate_additive_input_shares', source)
        self.assertNotIn('owner-active-triple-check', source)
        self.assertNotIn('v.push_back(context.random_auth())', source)
        self.assertGreaterEqual(source.count(
            'catch (...) { context_.poison(); throw; }'), 2)

        active = (SOURCE / 'owner_inputs_active.cpp').read_text()
        self.assertLess(active.index('context.check_field_pending()'),
                        active.index('ScalarCaptureSite::OwnerDdnntTripleS'))
        self.assertLess(active.index('ScalarCaptureSite::OwnerDdnntTripleW'),
                        active.index('owner_input_preprocessing_share_frame('))
        self.assertLess(active.index('owner_input_preprocessing_share_frame('),
                        active.index('preprocessing_frame.Send(socket)'))
        self.assertLess(active.index('owner_input_offset_frame('),
                        active.index('"owner-ddnnt-common-offset"'))
        self.assertLess(active.index('"owner-ddnnt-common-offset"'),
                        active.index('decode_owner_fr_frame(offset'))

    def test_owner_reconstructs_both_equations_before_one_common_offset(self):
        source = (SOURCE / 'owner_inputs_active.cpp').read_text()
        client = source[source.index('void send_private_inputs_active'):]
        self.assertIn('reconstruct_checked_ddnnt_masks', client)
        self.assertIn('make_owner_masked_difference_frame', client)
        self.assertIn('DDNNT_COMPONENT_COUNT * values.size()', client)
        self.assertIn('for (auto* socket : client.sockets)', client)
        self.assertIn('offset.Send(socket)', client)
        self.assertIn('VectorWipeGuard<Fr> masks_guard(masks)', client)
        self.assertIn('FrameWipeGuard offset_guard(offset)', client)

    def test_old_contract_ids_are_not_accepted(self):
        source = (SOURCE / 'owner_inputs_active.cpp').read_text()
        self.assertIn('KPI_OWNER_DDNNT_CONTRACT_V1', source)
        self.assertIn('KPI_OWNER_DDNNT_CONTRACT_V2', source)
        self.assertNotIn('version != "KPI_OWNER_CONTRACT_V1"', source)
        self.assertNotIn('version != "KPI_OWNER_CONTRACT_V2"', source)

    def test_owner_entrypoint_wipes_plaintext_values_on_every_exit(self):
        source = (SOURCE / 'owner_client_main.cpp').read_text()
        self.assertIn('OwnerValueWipeGuard', source)
        self.assertIn('wipe_owner_fr_values(values_)', source)

    def test_chunk_randomness_is_fresh_but_captured_once_per_batch(self):
        source = (SOURCE / 'auth_field.cpp').read_text()
        batch = source[source.index('MascotContext::random_auth_batch'):
                       source.index('MascotContext::multiply_batch')]
        self.assertIn('protocols_.preprocessing.get_random()', batch)
        self.assertIn('p1_capture_->randomness_values(site, result)', batch)
        self.assertEqual(batch.count('randomness_values(site, result)'), 1)


if __name__ == '__main__':
    unittest.main()
