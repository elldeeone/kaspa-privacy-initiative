import ast
import inspect
from pathlib import Path
import re
import textwrap
import unittest

import privacy_capture_model as capture


ROOT = Path(__file__).resolve().parents[3]
LEDGER = ROOT / 'research' / \
    'corrupt-p1-finite-source-assumption-ledger-2026-10-29.md'
COMBINED_LEDGER = ROOT / 'research' / \
    'combined-p1-c1-public-finite-assumption-ledger-2026-10-29.md'


def corrupt_server_unmodeled_fields():
    tree = ast.parse(textwrap.dedent(inspect.getsource(
        capture.corrupt_server)))
    selected = []
    for call in (node for node in ast.walk(tree)
                 if isinstance(node, ast.Call)):
        for keyword in call.keywords:
            if keyword.arg == 'unmodeled_fields':
                selected.append(ast.literal_eval(keyword.value))
    if len(selected) != 1:
        raise AssertionError('exact-corrupt-server-unmodeled-tuple')
    return tuple(selected[0])


class CorruptP1SourceAssumptionLedgerControls(unittest.TestCase):
    def test_markdown_disposition_table_covers_exact_base_unmodeled_set(self):
        expected = corrupt_server_unmodeled_fields()
        self.assertEqual(len(expected), 36)
        self.assertEqual(len(set(expected)), 36)

        text = LEDGER.read_text()
        section = text.split('## Per-field disposition\n', 1)[1].split(
            '\nAll `literal_public_identifiers`', 1)[0]
        rows = re.findall(r'^\| `([^`]+)` \|', section, re.MULTILINE)
        self.assertEqual(len(rows), 36)
        self.assertEqual(set(rows), {field for _, field in expected})

    def test_no_source_assumption_is_selected_before_c0(self):
        self.assertEqual(capture.SELECTED_SOURCE_ASSUMPTIONS, {})
        text = LEDGER.read_text()
        self.assertIn('SimplestOT_C -> libOTe malicious SoftSpoken -> MP-SPDZ',
                      text)
        self.assertIn('That proposition is an admitted assumption if selected.',
                      text)
        self.assertIn('No cited theorem covers it.', text)

    def test_unqualified_host_boundaries_remain_explicit(self):
        text = LEDGER.read_text()
        for boundary in (
                'P1_INTERNAL_OT_PRNG_RANDOM_TAPE',
                'ARBITRARY_MODIFIED_OR_MALICIOUS_HOST_OR_BINARY',
                'HOST_MEMORY_LOG_SWAP_CACHE_PAGE_SCHEDULE_CPU_GPU_STATE',
                'COVERT_AND_NETWORK_STACK_CHANNELS'):
            with self.subTest(boundary=boundary):
                self.assertIn('`' + boundary + '`', text)
        self.assertIn('modeled_or_harmless=false', text)
        self.assertIn('blocks_general_active_or_host_claims=true', text)

    def test_combined_ledger_is_finite_split_and_non_selecting(self):
        self.assertEqual(capture.SELECTED_SOURCE_ASSUMPTIONS, {})
        text = COMBINED_LEDGER.read_text()
        families = (
            'S1-CM-SHA256',
            'S2-CV-JOINT-HIDING',
            'S3-CV-BINDING',
            'S4-OUTPUT-GROTH16',
            'S5-CRYPTOBOX-CONFIDENTIALITY',
            'S6-CRYPTOBOX-RECIPIENT-PRIVACY',
            'S7-NF-HMAC-PRF',
            'S8-MASCOT-OT',
            'S9-DDNNT-5N',
            'S10-AUTHENTICATED-GROUPS',
            'S11-MIXED-SCALAR-GROUP',
            'S12-AGGREGATE-GROTH16',
            'S13-JOINT-AUXILIARY-COMPOSITION',
        )
        headings = re.findall(r'^### (S\d+-[^\n]+)$', text, re.MULTILINE)
        self.assertEqual(tuple(headings), families)
        self.assertIn('There is no qualifying build receipt', text)
        self.assertIn('ineligible for selection', text)
        self.assertIn('timing, length, order, direction, peer, fork, abort, retry',
                      text)
        self.assertIn('when they actually filter the candidate lattice',
                      ' '.join(text.split()))
        self.assertIn('**Status: NON-SELECTABLE RESEARCH HYPOTHESIS.**', text)
        self.assertIn('Selecting its\ndigest would be circular and is forbidden.',
                      text)
        for blocker in (
                'Exact runtime freshness and source closure',
                'CRS rebuild or reviewed ceremony',
                'Primary theorem or protocol redesign',
                'Circular target claim',
                'Direct or empirical leakage'):
            with self.subTest(blocker=blocker):
                self.assertIn('| ' + blocker + ' |', text)


if __name__ == '__main__':
    unittest.main()
