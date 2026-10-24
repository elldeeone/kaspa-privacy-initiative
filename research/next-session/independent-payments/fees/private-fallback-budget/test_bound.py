"""Source-analysis guards only; no native VM/proof/PK/backup/network call."""
import copy
import json
import unittest

import abstract_meter as core
import bound


class BoundControls(unittest.TestCase):
    def test_exact_selected_program_fits_with_complete_input_overhead(self):
        inputs = json.loads((bound.HERE / 'INPUTS.json').read_bytes())
        program = (bound.HERE / 'actual-W-redeem.bin').read_bytes()
        result = bound.calculate(program, inputs)
        self.assertEqual(result['complete_input_script_units_upper_bound'], 14_957_286)
        self.assertEqual(result['remaining_units'], 52_713)
        self.assertEqual(result['overhead_units_included_before_W_execution'], 52_364)
        self.assertFalse(result['script_engine_charged_prelude_or_postlude_excluded'])
        self.assertEqual(result['private_Groth16_exact_units'], 14_750_000)

    def test_program_identity_and_tail_mutation_fail_closed(self):
        inputs = json.loads((bound.HERE / 'INPUTS.json').read_bytes())
        program = bytearray((bound.HERE / 'actual-W-redeem.bin').read_bytes())
        for offset in (0, 114, len(program) - 1):
            altered = bytearray(program)
            altered[offset] ^= 1
            with self.assertRaisesRegex(ValueError, 'exact-selected-actual-W-program-and-tail'):
                bound.calculate(bytes(altered), inputs)
        altered_inputs = copy.deepcopy(inputs)
        altered_inputs['program']['bytes'] += 1
        with self.assertRaises(ValueError):
            bound.calculate(bytes(program), altered_inputs)

    def test_branch_maximum_and_unmetered_literal_overcharge(self):
        # Conditional is false, yet the larger true arm must remain in the bound.
        raw = b'\x00\x63\x4c\x64' + bytes(100) + b'\xa8\x67\x0a' + bytes(10) + b'\xa8\x68'
        m = core.Meter().run(core.ast(raw))
        self.assertEqual(m.units, 100 + 100 + 32)
        self.assertEqual(m.stack, [core.Item(32)])

    def test_unknown_instruction_shape_or_dynamic_width_refused(self):
        for raw, stack in [(b'\xff', []), (b'\x63\x51\x67\x68', [core.Item(1)]),
                           (b'\xcd', [core.Item(8), core.Item(8)]),
                           (b'\xb8', [core.Item(8), core.Item(8)])]:
            with self.assertRaises(ValueError):
                core.Meter(stack).run(core.ast(raw))

    def test_integer_serialization_and_fixed_width_literals(self):
        self.assertEqual(core.numeric(-(1 << 63)).length, 9)
        self.assertEqual(core.numeric().length, 9)
        self.assertEqual(core.Meter().run(core.ast(b'\xb2')).stack[-1].length, 9)
        self.assertIsNone(core.decode_number(bytes(112)))
        # Opcode-looking bytes inside a pushed112-byte state are data, not code.
        m = core.Meter().run(core.ast(b'\x4c\x70' + b'\xff' * 112 + b'\x75'))
        self.assertFalse(m.stack)
        self.assertEqual(m.units, 112)

    def test_SIZE_cannot_turn_inexact_upper_bound_into_constant(self):
        with self.assertRaisesRegex(ValueError, 'SIZE-requires-exact-length'):
            core.Meter([core.Item(128)]).run(core.ast(b'\x82'))
        m = core.Meter([core.Item(128, exact_length=True)]).run(core.ast(b'\x82'))
        self.assertEqual(m.stack[-1].number, 128)


if __name__ == '__main__':
    unittest.main()
