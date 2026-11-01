import unittest

import bounded_constructor_privacy as privacy


class CandidateMapTests(unittest.TestCase):
    def setUp(self):
        self.inputs = tuple(range(3))
        self.outputs = tuple(range(6))

    def count(self, **facts):
        return len(list(privacy.map_candidates(self.inputs, self.outputs, **facts)))

    def test_public_view_has_540_full_maps(self):
        self.assertEqual(self.count(), 540)

    def test_colluder_self_map_leaves_12_maps_without_incoming_payment(self):
        self.assertEqual(self.count(colluder_input=0, colluder_outputs=(0, 1)), 12)

    def test_one_decrypted_incoming_sender_link_leaves_six_maps(self):
        self.assertEqual(self.count(colluder_input=0, colluder_outputs=(0, 1),
                                    incoming_creators=((2, 1),)), 6)

    def test_two_decrypted_incoming_sender_links_leave_four_maps(self):
        self.assertEqual(self.count(colluder_input=0, colluder_outputs=(0, 1),
                                    incoming_creators=((2, 1), (3, 2))), 4)

    def test_impossible_double_payment_from_one_honest_owner_has_no_map(self):
        self.assertEqual(self.count(colluder_input=0, colluder_outputs=(0, 1),
                                    incoming_creators=((2, 1), (3, 1))), 0)


if __name__ == "__main__":
    unittest.main()
