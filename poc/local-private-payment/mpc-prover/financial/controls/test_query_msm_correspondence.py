#!/usr/bin/env python3
"""Source/callsite controls for selected financial query/MSM reconstruction."""

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
FINANCIAL = HERE.parent
MODULUS = 101


def pair_add(first, second):
    return tuple((a + b) % MODULUS for a, b in zip(first, second))


def pair_scale(point, scalar):
    return tuple(point * lane % MODULUS for lane in scalar)


class ScalarEvents:
    def __init__(self, rows):
        self.rows = list(rows)
        self.at = 0

    def take(self, site, count):
        if self.at >= len(self.rows):
            raise ValueError('missing scalar event')
        selected, values = self.rows[self.at]
        if selected != site or len(values) != count:
            raise ValueError('scalar event site/count/order')
        self.at += 1
        return values

    def finish(self):
        if self.at != len(self.rows):
            raise ValueError('extra scalar event')


class QueryCursor:
    def __init__(self, identity, expected_identity, sections):
        if identity != expected_identity:
            raise ValueError('query identity')
        self.sections = list(sections)
        self.at = 0

    def take(self, name, count):
        if self.at >= len(self.sections):
            raise ValueError('missing query section')
        selected, points = self.sections[self.at]
        if selected != name or len(points) != count:
            raise ValueError('query cursor order/count')
        self.at += 1
        return points

    def finish(self):
        if self.at != len(self.sections):
            raise ValueError('extra query section')


def reconstruct_fixture(events, query_identity='query-pin', sections=None):
    """Small replay of the selected owner-to-trace-to-H-to-query graph."""
    owner = events.take(6, 2)
    assignment = [(1, 9), *owner]
    assignment += events.take(11, 1)
    products = events.take(19, 2)
    c_eval = [assignment[1], assignment[2]]
    h = [pair_add(products[index], pair_scale(-1, c_eval[index]))
         for index in range(2)]
    r = events.take(20, 1)[0]
    s = events.take(21, 1)[0]
    sections = sections or [
        ('A', [2, 3, 5, 7]), ('B1', [11, 13, 17, 19]),
        ('B2', [23, 29, 31, 37]), ('H', [41, 43]),
        ('L', [47, 53, 59]),
    ]
    cursor = QueryCursor(query_identity, 'query-pin', sections)

    def msm(points, scalars):
        total = (0, 0)
        for point, scalar in zip(points, scalars):
            total = pair_add(total, pair_scale(point, scalar))
        return total

    a = pair_add(msm(cursor.take('A', 4), assignment), pair_scale(61, r))
    b1 = msm(cursor.take('B1', 4), assignment)
    b2 = pair_add(msm(cursor.take('B2', 4), assignment), pair_scale(67, s))
    h_point = msm(cursor.take('H', 2), h)
    l = msm(cursor.take('L', 3), assignment[1:])
    cursor.finish()
    events.finish()
    return (a, b1, l, h_point), b2


def manifest_body(source):
    match = re.search(r'R"MANIFEST\((.*?)\)MANIFEST"', source, re.S)
    if not match:
        raise AssertionError('missing correspondence manifest')
    return match.group(1).encode()


class QueryMsmCorrespondenceControls(unittest.TestCase):
    def test_labeled_scalar_replay_reconstructs_exact_base_state_fail_closed(self):
        rows = [
            (6, [(3, 30), (4, 40)]),
            (11, [(12, 19)]),
            (19, [(22, 61), (35, 72)]),
            (20, [(8, 80)]),
            (21, [(9, 90)]),
        ]
        expected = reconstruct_fixture(ScalarEvents(rows))
        # Synthetic typed BASE record in canonical [A,B1,L,H], B2 order.
        captured = (((98, 69), (43, 15), (51, 5), (92, 21)),
                    (69, 61))
        self.assertEqual(expected, captured)
        mutations = {
            'missing': rows[:-1],
            'extra': rows + [(22, [(1, 1)])],
            'reordered': [rows[1], rows[0], *rows[2:]],
            'wrong-count': [(6, rows[0][1][:1]), *rows[1:]],
        }
        for name, changed in mutations.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError,
                                             'scalar event|missing'):
                    reconstruct_fixture(ScalarEvents(changed))
        with self.assertRaisesRegex(ValueError, 'query identity'):
            reconstruct_fixture(ScalarEvents(rows), 'wrong-query')
        wrong_order = [
            ('B1', [11, 13, 17, 19]), ('A', [2, 3, 5, 7]),
            ('B2', [23, 29, 31, 37]), ('H', [41, 43]),
            ('L', [47, 53, 59]),
        ]
        with self.assertRaisesRegex(ValueError, 'query cursor order/count'):
            reconstruct_fixture(ScalarEvents(rows), sections=wrong_order)

    def test_actual_worker_reduction_reconstructs_both_lanes(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-query-msm-correspondence-') as temporary:
            binary = Path(temporary) / 'control'
            compiled = subprocess.run([
                'g++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                '-pedantic', str(HERE / 'query_msm_correspondence_test.cpp'),
                '-pthread', '-o', str(binary),
            ], capture_output=True, text=True, check=False)
            self.assertEqual(compiled.returncode, 0,
                             compiled.stdout + compiled.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False, timeout=10)
            self.assertEqual((run.returncode, run.stdout, run.stderr),
                             (0, '', ''))

    def test_manifest_digest_and_selected_query_map_are_exact(self):
        header = (FINANCIAL / 'query_msm_correspondence.hpp').read_text()
        expected = hashlib.sha256(manifest_body(header)).hexdigest()
        declared = re.search(
            r'CORRESPONDENCE_MANIFEST_SHA256\s*=\s*\n\s*"([0-9a-f]{64})"',
            header).group(1)
        self.assertEqual(declared, expected)
        for row in (
                'A|public-query=A|scalar=assignment[0:variables]',
                'B1|public-query=B1|scalar=assignment[0:variables]',
                'B2|public-query=B2|scalar=assignment[0:variables]',
                'H|public-query=H[0:domain-1]|scalar=streamed-H[0:domain-1]',
                'L|public-query=L|scalar=assignment[instances:variables]',
                'temporary|worker-partial|captured=no|coverage='
                'executable-linear-reconstruction',
                'local-effect|public-stage-callback-label-and-time|'
                'captured=no|coverage=unmodeled'):
            self.assertIn(row, header)

    def test_every_scalar_producer_callsite_has_one_manifest_label(self):
        manifest = (MPC / 'p1_scalar_capture_manifest.hpp').read_text()
        enum = manifest[manifest.index('enum class ScalarCaptureSite'):
                        manifest.index('};', manifest.index(
                            'enum class ScalarCaptureSite'))]
        names = set(re.findall(r'^\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*\d+,',
                               enum, re.M))
        source = []
        for path in MPC.rglob('*'):
            if path.suffix not in ('.cpp', '.hpp'):
                continue
            relative = path.relative_to(MPC)
            if ('evidence' in relative.parts or 'controls' in relative.parts
                    or path.name == 'p1_scalar_capture_manifest.hpp'):
                continue
            source.append(path.read_text())
        calls = re.findall(r'ScalarCaptureSite::\s*([A-Za-z0-9_]+)',
                           '\n'.join(source))
        self.assertEqual(set(calls), names)
        self.assertEqual({name: calls.count(name) for name in names},
                         {name: 1 for name in names})
        field_header = (MPC / 'auth_field.hpp').read_text()
        self.assertRegex(field_header, re.compile(
            r'std::vector<AuthScalar> multiply_batch\(\s*'
            r'p1_capture::ScalarCaptureSite,\s*'
            r'std::span<const AuthScalar> left,', re.S))

    def test_query_store_and_actual_model_preimages_are_bound_before_use(self):
        gzip = (MPC / 'packed/gzip_queries.cpp').read_text()
        prover = (FINANCIAL / 'financial_prover.cpp').read_text()
        self.assertIn('KPI_GZIP_STOCK_PK_V1\\n', gzip)
        for pin in ('container_sha256', 'canonical_pk_sha256', 'vk_sha256',
                    'decoder_identity', 'container_bytes',
                    'canonical_pk_bytes', 'shape.instances',
                    'shape.witnesses', 'shape.domain'):
            self.assertIn(pin, gzip)
        self.assertIn('scan.finish();', gzip)
        bound = prover.index('capture->bind_financial_query_model(')
        schedule = prover.index('financial-local-query-schedule', bound)
        first_query = prover.index('auto a = query_g1(', schedule)
        self.assertLess(bound, schedule)
        self.assertLess(schedule, first_query)
        binding = prover[bound:bound + 180]
        self.assertIn('model.identity()', binding)
        self.assertIn('model.query_transport_identity()', binding)

    def test_cursor_query_order_temporary_reduction_and_peer_effects_are_fixed(self):
        prover = (FINANCIAL / 'financial_prover.cpp').read_text()
        positions = [prover.index(token) for token in (
            'auto a = query_g1(queries, packed::Query::A',
            'auto b1_base = query_g1(queries, packed::Query::B1',
            'auto b2 = query_g2(queries, assignment',
            'const auto h_point = query_g1(queries, packed::Query::H',
            'const auto l = query_g1(queries, packed::Query::L',
            'queries.finish();',
            'model.check_backing_unchanged();',
            'capture->proof_base_group_state(base_group_state, b2)',
        )]
        self.assertEqual(positions, sorted(positions))
        local = prover[prover.index('template<class Group>'):
                       prover.index('AuthG1 query_g1')]
        self.assertIn('query_msm::deterministic_worker_sum(', local)
        self.assertIn('return public_point_map(point, scalar);', local)
        for forbidden in ('Player', 'POpen', 'Send(', 'Receive(',
                          'Broadcast', 'random_auth', 'report_public_phase'):
            self.assertNotIn(forbidden, local)
        query_helpers = prover[prover.index('AuthG1 query_g1'):
                               prover.index('std::array<unsigned char, 128>')]
        for forbidden in ('Player', 'POpen', 'Send(', 'Receive(',
                          'Broadcast', 'random_auth', 'report_public_phase'):
            self.assertNotIn(forbidden, query_helpers)
        self.assertIn(
            'context.agree_public_bytes("financial-local-query-schedule"',
            prover)


if __name__ == '__main__':
    unittest.main()
