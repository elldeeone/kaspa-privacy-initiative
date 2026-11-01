#!/usr/bin/env python3
"""Selected-path controls for the raw trace-check capture reduction."""

from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
REGISTERED = FINANCIAL / 'registered_construction.cpp'
TRACE_SOURCE = MPC / 'trace' / 'trace_witness.cpp'
TRACE_HEADER = MPC / 'trace' / 'trace_witness.hpp'


def require_selected_reduction(source: str) -> None:
    """Reject any selected source that can omit, duplicate, or move the call."""
    call = ('trace_private_checks_hold(\n'
            '            context, result.private_checks, '
            'program.expected_private_checks)')
    if source.count('trace_private_checks_hold(') != 1:
        raise ValueError('trace-private-check-call-count')
    if call not in source:
        raise ValueError('trace-private-check-call-shape')
    if source.count(
            'result.private_checks.push_back(\n'
            '            context.public_constant(Fr(1)) - '
            'raw_trace_checks_hold);') != 1:
        raise ValueError('trace-private-check-residual-count')
    execute = source.index('auto result = execute_trace(')
    called = source.index(call)
    context_checks = source.index(
        'for (size_t byte = 0; byte < expected_context.size(); ++byte)')
    storage = source.index('std::make_shared<const Storage>')
    if not execute < called < context_checks < storage:
        raise ValueError('trace-private-check-order')


class RegisteredTracePrivateCheckCaptureControls(unittest.TestCase):
    def setUp(self):
        self.registered = REGISTERED.read_text(encoding='utf-8')

    def test_selected_path_binds_genuine_raw_checks_once_before_site16(self):
        require_selected_reduction(self.registered)
        assignment = (FINANCIAL / 'financial_assignment.cpp').read_text(
            encoding='utf-8')
        self.assertEqual(
            assignment.count(
                'ScalarCaptureSite::FinancialAssignmentResidual'), 1)
        self.assertNotIn('trace_private_checks_hold(', assignment)
        production_calls = []
        for path in MPC.rglob('*.cpp'):
            if 'evidence' in path.parts or 'controls' in path.parts:
                continue
            if path == TRACE_SOURCE:
                continue
            if 'trace_private_checks_hold(' in path.read_text(encoding='utf-8'):
                production_calls.append(path.relative_to(MPC).as_posix())
        self.assertEqual(production_calls,
                         ['financial/registered_construction.cpp'])

        child = (FINANCIAL / 'registered_role_child_program.cpp').read_text(
            encoding='utf-8')
        self.assertLess(
            child.index('FinancialConstruction::construct_registered('),
            child.index('FinancialValidatedAssignment::validate('))

    def test_omission_duplicate_wrong_order_and_wrong_count_are_detected(self):
        call = ('trace_private_checks_hold(\n'
                '            context, result.private_checks, '
                'program.expected_private_checks)')
        wrong_count_call = call.replace(
            'program.expected_private_checks)',
            'program.expected_private_checks + 1)')
        wrong_order = self.registered.replace(call, 'moved_call', 1)
        wrong_order = wrong_order.replace(
            'auto storage = std::make_shared<const Storage>',
            call + ';\n        auto storage = std::make_shared<const Storage>',
            1)
        cases = {
            'omission': self.registered.replace(call, 'raw_trace_check'),
            'duplicate': self.registered.replace(call, call + ';\n' + call),
            'wrong-count': self.registered.replace(
                call, wrong_count_call, 1),
            'wrong-order': wrong_order,
        }
        for name, source in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                require_selected_reduction(source)

    def test_bn254_raw_check_schedule_is_exact(self):
        header = TRACE_HEADER.read_text(encoding='utf-8')
        source = TRACE_SOURCE.read_text(encoding='utf-8')
        for token in (
                'TracePrivateCheckCaptureSchedule',
                'trace_private_check_capture_schedule'):
            self.assertIn(token, header)
            self.assertIn(token, source)
        self.assertIn('checks.size() != expected_count', source)

        modulus = int(
            '21888242871839275222246405745257275088548364400416034343698204186575808495617')
        exponent = modulus - 1
        self.assertEqual((exponent.bit_length(), exponent.bit_count()),
                         (254, 100))
        remaining = 33_896
        reduction_widths = []
        while remaining > 1:
            reduction_widths.append(remaining // 2)
            remaining = (remaining + 1) // 2
        self.assertEqual(reduction_widths, [
            16948, 8474, 4237, 2118, 1059, 530, 265, 132,
            66, 33, 17, 8, 4, 2, 1, 1])
        self.assertEqual(sum(reduction_widths), 33_895)


if __name__ == '__main__':
    unittest.main()
