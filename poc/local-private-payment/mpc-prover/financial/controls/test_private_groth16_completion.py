from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PrivateGroth16CompletionControls(unittest.TestCase):
    """Finite source gate; a three-party proof run remains separate evidence."""

    def test_group_product_uses_fresh_authenticated_field_triples(self):
        header = (ROOT / "auth_groups.hpp").read_text()
        source = (ROOT / "auth_groups.cpp").read_text()
        self.assertIn("secret_scalar_g1_products", header)
        self.assertIn("GroupMacSetup& group_macs", header)
        self.assertIn("group_macs.require_bound(context)", source)
        for required in (
            "preprocessing.get_three(DATA_TRIPLE",
            "public_point_map(g1_generator, triple_a)",
            "public_point_map(g1_generator, triple_c)",
            "open_fresh_masked_scalar_pair",
            "open_masked_g1_pair",
            "scalar_difference",
            "group_difference",
            "add_public(product, group_difference * scalar_difference",
        ):
            self.assertIn(required, source)
        self.assertNotIn("open_public_checked(masked_scalars", source)
        self.assertIn("context.poison();", source)

    def test_only_final_groth16_points_are_unmasked_openings(self):
        paths = (
            ROOT / "auth_groth16.cpp",
            ROOT / "financial" / "packed_groth16.cpp",
            ROOT / "financial" / "financial_prover.cpp",
        )
        for path in paths:
            source = path.read_text()
            with self.subTest(path=path.name):
                self.assertIn("secret_scalar_g1_products", source)
                self.assertIn("open_final_groth16", source)
                self.assertNotIn("open_checked_g1_pair", source)
                self.assertNotIn("server_opened_point_map", source)
                self.assertNotIn("opened_b1", source)
                self.assertNotIn("masked-A-and-B1", source)
                self.assertNotIn("public_point_map(delta1, rs)", source)
                self.assertIn(".poison();", source)

    def test_final_open_is_joint_a_b2_c_after_c_is_complete(self):
        header = (ROOT / "auth_groups.hpp").read_text()
        source = (ROOT / "auth_groups.cpp").read_text()
        self.assertIn("struct FinalGroth16Opening", header)
        self.assertIn("G1Value a;", header)
        self.assertIn("G2Value b;", header)
        self.assertIn("G1Value c;", header)
        self.assertIn("open_final_groth16", header)
        self.assertIn("const std::vector<AuthG1> g1_shares{a, c};", source)
        self.assertIn("const std::vector<AuthG2> g2_shares{b};", source)
        self.assertLess(source.index("g1_checker.Check"),
                        source.index("return {g1_opened[0]"))
        self.assertLess(source.index("g2_checker.Check"),
                        source.index("return {g1_opened[0]"))


if __name__ == "__main__":
    unittest.main()
