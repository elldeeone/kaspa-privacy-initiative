"""Regression controls for truth-consistent, complete-history privacy scoring."""
import json
from pathlib import Path
import tempfile
import unittest

import score_live_correction as score


INITIAL = (("A", 10), ("B", 10))
TERMINAL = (("A", 6), ("B", 8), ("M", 2), ("M", 3), ("S", 1))
H1 = (("A", "M", 4), ("B", "M", 2), ("M", "S", 1))
H2 = (("A", "M", 3), ("A", "S", 1), ("B", "M", 2))


class TruthConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.sequences = score.candidates(INITIAL, TERMINAL, 3)

    def test_json_roundtrip_preserves_coupled_candidates(self):
        initial, terminal = json.loads(json.dumps([INITIAL, TERMINAL]))
        actual = score.candidates(initial, terminal, 3)
        self.assertEqual(score.describe(actual), score.describe(self.sequences))
        self.assertEqual({score.gross(H1), score.gross(H2)}, {score.gross(s) for s in actual})

    def test_unique_wrong_guess_is_not_reconstruction(self):
        view = score.condition(self.sequences, ("M", "S"))
        result = score.assess(view, H2, ("M", "S"))
        self.assertEqual(result["candidateCount"], 1)
        self.assertTrue(result["uniqueWrongPrediction"])
        self.assertFalse(result["successfulReconstruction"])
        self.assertFalse(result["externalFactConsistentWithExecution"])

    def test_both_worlds_have_truth_consistent_conditional_reconstruction(self):
        for truth, edge in ((H1, ("M", "S")), (H2, ("A", "S"))):
            result = score.assess(score.condition(self.sequences, edge), truth, edge)
            self.assertTrue(result["successfulReconstruction"])
            self.assertTrue(result["coupledExecutionTruthRetained"])

    def test_wrong_unique_prediction_rejected_even_without_fact_annotation(self):
        result = score.assess([H1], H2)
        self.assertFalse(result["successfulReconstruction"])
        self.assertEqual(result["status"], "model_excludes_execution_truth_invalid_result")

    def test_contradictory_relationship_evidence_cannot_be_a_privacy_pass(self):
        both = score.condition(score.condition(self.sequences, ("A", "S")), ("M", "S"))
        self.assertEqual(both, [])
        result = score.assess(both, H2)
        self.assertFalse(result["successfulReconstruction"])
        self.assertFalse(result["coupledExecutionTruthRetained"])

    def test_marginal_truth_retention_is_not_coupled_truth_retention(self):
        # Each real payment can occur somewhere in the candidate collection,
        # while no candidate contains the real complete history.
        false_candidates = [
            (H2[0], H1[1], H1[2]),
            (H1[0], H2[1], H1[2]),
        ]
        self.assertTrue(all(any(fact in history for history in false_candidates) for fact in H2))
        self.assertFalse(score.assess(false_candidates, H2)["coupledExecutionTruthRetained"])

    def test_redundant_extra_fact_does_not_erase_ambiguity(self):
        result = score.assess(score.condition(self.sequences, ("B", "M")), H2, ("B", "M"))
        self.assertEqual(result["candidateCount"], 2)
        self.assertFalse(result["successfulReconstruction"])
        self.assertTrue(result["coupledExecutionTruthRetained"])

    def test_identity_renaming_does_not_change_payment_ambiguity(self):
        rename = {"A": "z", "B": "x", "M": "q", "S": "w"}
        seq = score.candidates(
            [(rename[a], v) for a, v in INITIAL],
            [(rename[a], v) for a, v in TERMINAL], 3,
            [(rename[a], rename[b]) for a, b in score.EDGES],
        )
        expected = {tuple(sorted((rename[a], rename[b], v) for a, b, v in h)) for h in (H1, H2)}
        self.assertEqual({score.gross(s) for s in seq}, expected)

    def test_public_terminal_evidence_changes_candidates(self):
        changed = (("A", 5), ("B", 8), ("M", 4), ("M", 2), ("S", 1))
        seq = score.candidates(INITIAL, changed, 3)
        self.assertTrue(seq)
        self.assertNotEqual({score.gross(s) for s in seq}, {score.gross(s) for s in self.sequences})
        self.assertNotIn(score.gross(H2), {score.gross(s) for s in seq})

    def test_sompi_grid_rejects_float_bool_negative_zero_and_overflow(self):
        for invalid in (True, 10_000_000.0, -10_000_000, 0, 10_000_001, 2**64):
            with self.assertRaises(ValueError):
                score.units(invalid)
        self.assertEqual(score.units(10_000_000), 1)

    def test_recorded_execution_must_consume_existing_input_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            (run / "private").mkdir()
            path = run / "private/truth.json"
            path.write_text(json.dumps({"payments": [["A", "M", 100_000_000, 30_000_000], ["A", "S", 70_000_000, 10_000_000], ["B", "M", 100_000_000, 20_000_000]]}))
            path.chmod(0o600)
            self.assertEqual(tuple(score.private_execution(run, INITIAL, TERMINAL)), H2)
            invalid = json.loads(path.read_text())
            invalid["payments"][1][2] = 100_000_000  # A's original note was already spent.
            path.write_text(json.dumps(invalid))
            with self.assertRaises(ValueError):
                score.private_execution(run, INITIAL, TERMINAL)


if __name__ == "__main__":
    unittest.main()
