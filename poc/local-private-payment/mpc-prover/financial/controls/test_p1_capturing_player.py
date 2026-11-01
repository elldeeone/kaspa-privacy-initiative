#!/usr/bin/env python3
"""Behavior controls for the P1-only MP-SPDZ Player capture decorator."""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from financial.controls.test_p1_capture_stream import frames


HERE = Path(__file__).resolve().parent
MPC = HERE.parent.parent
ROOT = MPC.parents[2]
MP_SPDZ = ROOT / '.local' / 'mpc-prover-vendor' / 'MP-SPDZ'
PREFIX = ROOT / '.local' / 'mpc-prover-vendor' / 'prefix' / 'usr'
MCL = ROOT / '.local' / 'mpc-prover-vendor' / 'mcl'


class P1CapturingPlayerControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(
            prefix='kpb-p1-capturing-player-controls-')
        cls.binary = Path(cls.temporary.name) / 'controls'
        compiled = subprocess.run([
            'g++', '-std=c++20', '-march=native', '-Wall', '-Wextra',
            '-Werror', '-Wno-overloaded-virtual', '-pedantic',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            '-DKPI_P1_CAPTURE_TEST_SETUP',
            str(HERE / 'p1_capturing_player_test.cpp'),
            str(MPC / 'p1_capturing_player.cpp'),
            str(MPC / 'p1_capture_seams.cpp'),
            str(MPC / 'p1_capture_stream.cpp'),
            str(MPC / 'bn254_values.cpp'),
            '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
            '-L', str(MP_SPDZ), '-Wl,-rpath,' + str(MP_SPDZ),
            '-L', str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-Wl,-rpath,' + str(PREFIX / 'lib' / 'x86_64-linux-gnu'),
            '-L', str(MCL / 'lib'), '-lSPDZ', '-lmcl', '-lcrypto',
            '-lgmpxx', '-lgmp', '-pthread', '-o', str(cls.binary),
        ], capture_output=True, text=True, check=False)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_every_player_path_and_nested_fork_remains_captured(self):
        run = subprocess.run([str(self.binary)], capture_output=True,
                             check=False, timeout=20)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        decoded = frames(run.stdout)
        transport = [row for row in decoded
                     if row['type'] == 2 and row['semantic'] == 2]
        self.assertGreater(len(transport), 30)
        self.assertEqual({row['direction'] for row in transport}, {1, 2})
        self.assertEqual({row['peer'] for row in transport}, {0, 2})
        empty = [row for row in transport if row['payload'] == b'']
        self.assertEqual([(row['direction'], row['peer']) for row in empty],
                         [(1, 0), (2, 2)])
        forks = [row for row in decoded if row['type'] == 6]
        self.assertEqual(len(forks), 2)
        root = bytes(32)
        child_rows = [row for row in transport
                      if row['payload'] == b'child-private']
        grandchild_rows = [row for row in transport
                           if row['payload'] == b'grandchild-private']
        self.assertEqual(len(child_rows), 1)
        self.assertEqual(len(grandchild_rows), 1)
        self.assertNotEqual(child_rows[0]['fork'], root)
        self.assertNotEqual(grandchild_rows[0]['fork'], root)
        self.assertNotEqual(child_rows[0]['fork'], grandchild_rows[0]['fork'])
        sentinel_rows = [row for row in decoded
                         if b'PRIVATE_SENTINEL_TRANSPORT' in row['payload']]
        self.assertTrue(sentinel_rows)
        self.assertTrue(all(row['type'] == 2 and row['semantic'] == 2
                            for row in sentinel_rows))
        self.assertNotIn(b'PRIVATE_SENTINEL_TRANSPORT',
                         decoded[-2]['payload'])
        sizes = {semantic: [len(row['payload']) for row in decoded
                            if row['type'] == 2
                            and row['semantic'] == semantic]
                 for semantic in range(1, 18)}
        self.assertEqual(sizes[1], [32, 32, 32])
        self.assertEqual(sizes[11], [160, 160, 160])
        self.assertEqual(sizes[3], [32] * 18)
        self.assertEqual(sizes[4], [32] * 18)
        self.assertEqual(sizes[5], [32] * 4)
        self.assertEqual(sizes[6], [32] * 4)
        self.assertEqual(sizes[10], [32])
        self.assertEqual(sizes[7], [130])
        self.assertEqual(sizes[8], [129])
        self.assertEqual(sizes[9], [10685])
        self.assertEqual(sizes[12], [130])
        self.assertEqual(sizes[13], [64])
        self.assertEqual(sizes[14], [32])
        self.assertEqual(sizes[15], [521, 781, 261, 261])
        self.assertEqual(sizes[16], [259, 259])
        self.assertEqual(sizes[17], [16] * 22)
        self.assertEqual(decoded[-1]['type'], 5)

    def test_role_transport_and_party_bypasses_emit_no_bytes(self):
        for scenario in ('wrong-role', 'unencrypted', 'wrong-parties'):
            with self.subTest(scenario=scenario):
                run = subprocess.run([str(self.binary), scenario],
                                     capture_output=True, check=False,
                                     timeout=5)
                self.assertEqual((run.returncode, run.stdout, run.stderr),
                                 (0, b'', b''))

    def test_failed_fork_poisons_capture_and_blocks_escape(self):
        run = subprocess.run([str(self.binary), 'failed-fork'],
                             capture_output=True, check=False, timeout=5)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        decoded = frames(run.stdout)
        self.assertFalse(any(row['type'] == 5 for row in decoded))
        self.assertFalse(any(row['payload'] == b'must-not-escape'
                             for row in decoded))

    def test_concurrent_softspoken_style_send_receive_does_not_deadlock(self):
        run = subprocess.run([str(self.binary), 'concurrent-io'],
                             capture_output=True, check=False, timeout=5)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        transport = [row for row in frames(run.stdout)
                     if row['type'] == 2 and row['semantic'] == 2]
        self.assertEqual({(row['direction'], row['peer']) for row in transport},
                         {(1, 0), (2, 2)})

    def test_owner_frame_tee_is_post_validation_pre_unpack_and_role_locked(self):
        source = (MPC / 'owner_inputs_active.cpp').read_text()
        prepare = source[source.index('prepare_ddnnt_input_supply'):
                         source.index('receive_ddnnt_offset_and_derive')]
        checked = prepare.index('context.check_field_pending()')
        packed = prepare.index('s[index].get_share().pack', checked)
        for lane, site in (('s', 'OwnerDdnntTripleS'),
                           ('r', 'OwnerDdnntTripleR'),
                           ('w', 'OwnerDdnntTripleW')):
            captured = prepare.index(
                'context.capture_authenticated_values(\n'
                f'            p1_capture::ScalarCaptureSite::{site}, {lane})',
                checked)
            self.assertLess(checked, captured)
            self.assertLess(captured, packed)

        offset = source[source.index('receive_ddnnt_offset_and_derive'):
                        source.index('}  // namespace')]
        received = offset.index('offset.Receive(socket)')
        length = offset.index('require_owner_fr_frame_length(offset, masks.size())')
        tee = offset.index('capture->owner_input_offset_frame', length)
        agreement = offset.index('"owner-ddnnt-common-offset"', tee)
        unpack = offset.index('decode_owner_fr_frame(offset, masks.size())',
                              agreement)
        self.assertLess(received, length)
        self.assertLess(length, tee)
        self.assertLess(tee, agreement)
        self.assertLess(agreement, unpack)
        tee_call = offset[tee:tee + 220]
        self.assertIn('offset.get_data()', tee_call)
        self.assertIn('offset.get_length()', tee_call)

        for entry in ('ActiveOwnerInputServer::receive(',
                      'ActiveOwnerInputServer::receive_cohort('):
            body = source[source.index(entry):]
            prepared = body.index('prepare_ddnnt_input_supply(')
            outbound = body.index(
                'selected_capture->owner_input_preprocessing_share_frame',
                prepared)
            sent = body.index('preprocessing_frame.Send(socket)', outbound)
            self.assertLess(prepared, outbound)
            self.assertLess(outbound, sent)
            self.assertIn('context_.party_id() != 1', body[:prepared])
            call = body[outbound:outbound + 300]
            self.assertIn('preprocessing_frame.get_data()', call)
            self.assertIn('preprocessing_frame.get_length()', call)

    def test_typed_local_callsites_are_genuine_but_authority_stays_unselected(self):
        field = (MPC / 'auth_field.cpp').read_text()
        groups = (MPC / 'auth_groups.cpp').read_text()
        owner = (MPC / 'owner_inputs_active.cpp').read_text()
        history = (MPC / 'history/epoch_ticket.cpp').read_text()
        stream = (MPC / 'p1_capture_stream.cpp').read_text()
        self.assertIn('p1_capture_->randomness_values', field)
        self.assertIn('p1_capture_->authenticated_values', field)
        self.assertIn('p1_capture_->field_openings', field)
        self.assertIn('capture->masked_group_differences(opened)', groups)
        self.assertIn('capture->begin_final_group_opening_capture(', groups)
        self.assertIn('capture->final_group_openings(', groups)
        self.assertIn('capture->masked_field_differences(opened)', groups)
        self.assertIn(
            'context.capture_authenticated_values(\n'
            '        p1_capture::ScalarCaptureSite::OwnerDerivedInput, inputs)',
            owner)
        staged = history.index('context.capture_released_projection(projection_)')
        final_agreement = history.index(
            'context.agree_public_bytes("history-all-three-durable-final-candidate"')
        closed = history.index('context.complete_p1_capture()', final_agreement)
        self.assertLess(staged, final_agreement)
        self.assertLess(final_agreement, closed)
        self.assertIn('.configured = false', stream)
        self.assertIn('.registered_driver_integrated = false', stream)
        self.assertIn('.producer_integrated = false', stream)
        self.assertIn('.launch_authorized = false', stream)
        self.assertIn('.actual_receipt_enabled = false', stream)
        production = '\n'.join(
            path.read_text() for path in MPC.rglob('*.cpp')
            if 'controls' not in path.parts)
        self.assertEqual(production.count('attach_p1_capture('), 1)

    def test_group_state_callsites_and_final_opening_capability_are_exact(self):
        groups = (MPC / 'auth_groups.cpp').read_text()
        toy = (MPC / 'auth_groth16.cpp').read_text()
        financial = (MPC / 'financial/financial_prover.cpp').read_text()
        packed = (MPC / 'financial/packed_groth16.cpp').read_text()
        header = (MPC / 'p1_capture_seams_contract.hpp').read_text()
        production = '\n'.join(
            path.read_text() for path in MPC.rglob('*.cpp')
            if 'controls' not in path.parts and 'evidence' not in path.parts)
        self.assertEqual(production.count(
            'capture->begin_final_group_opening_capture('), 1)
        self.assertEqual(production.count('capture->final_group_openings('), 1)
        self.assertIn('friend class ::kpi::mpc::GroupMacSetup;', header)
        self.assertIn(
            'FinalGroupOpeningPermit(const FinalGroupOpeningPermit&) = delete;',
            header)
        self.assertIn('permit.context_ != &context',
                      (MPC / 'p1_capture_seams.cpp').read_text())
        self.assertIn('permit.generation_ != context.generation()',
                      (MPC / 'p1_capture_seams.cpp').read_text())
        self.assertIn('permit.failure_epoch_ != context.failure_epoch()',
                      (MPC / 'p1_capture_seams.cpp').read_text())
        permit = groups.index('capture->begin_final_group_opening_capture(')
        checked = groups.index('auto [g1_opened, g2_opened] = checked_open()',
                               permit)
        emitted = groups.index('capture->final_group_openings(', checked)
        self.assertLess(permit, checked)
        self.assertLess(checked, emitted)
        self.assertIn('proof_base_group_state(base_group_state, b2)', toy)
        self.assertIn('proof_base_group_state(base_group_state, b2)', financial)
        self.assertIn('proof_base_group_state(base_group_state, b2)', packed)
        self.assertIn('beaver_mixed_group_state(mixed_group_state)', groups)
        self.assertIn('beaver_product_group_state(products)', groups)
        self.assertRegex(groups, re.compile(
            r'const std::array<AuthG1, 6> mixed_group_state\{\{\s*'
            r'group_masks\[0\], product_masks\[0\], masked_groups\[0\],\s*'
            r'group_masks\[1\], product_masks\[1\], masked_groups\[1\]\}\};'))
        self.assertIn('const std::array<AuthG1, 4> base_group_state{', toy)
        self.assertIn('const std::array<AuthG1, 4> base_group_state{', financial)
        for source in (toy, financial, packed):
            base = source.index('const std::array<AuthG1, 4> base_group_state{')
            body = source[base:base + 180]
            self.assertRegex(body, r'a,\s*b1_base,\s*l,\s*h_(group|point)')
        opener_calls = {
            path.relative_to(MPC).as_posix(): path.read_text().count(
                'open_final_groth16(')
            for path in MPC.rglob('*.cpp')
            if 'controls' not in path.parts and 'evidence' not in path.parts
            and 'open_final_groth16(' in path.read_text()
        }
        self.assertEqual(opener_calls, {
            'auth_groups.cpp': 2,
            'auth_groth16.cpp': 1,
            'financial/financial_prover.cpp': 1,
            'financial/packed_groth16.cpp': 1,
        })
        self.assertEqual(financial.count(
            'FinalGroth16CaptureAuthority final_capture_authority(context)'), 1)
        self.assertEqual(financial.count(
            'std::move(final_capture_authority)'), 1)
        self.assertNotIn('FinalGroth16CaptureAuthority', toy)
        self.assertNotIn('FinalGroth16CaptureAuthority', packed)
        self.assertIn('captured-final-opening-authority-required', groups)
        self.assertIn('out.set_share(point * scalar.get_share())', groups)
        self.assertIn('out.set_mac(point * scalar.get_mac())', groups)
        self.assertIn('result += point_map<Group, AuthGroup>', groups)
        for source in (toy, packed):
            self.assertRegex(source, re.compile(
                r'(AuthG1|auto) c = products\[0\];\s*'
                r'c \+= products\[1\];\s*'
                r'c \+= (l|h_point);\s*c \+= (h_group|h_point|l);\s*'
                r'const auto opened = open_final_groth16', re.MULTILINE))
        self.assertRegex(financial, re.compile(
            r'auto c = products\[0\];\s*c \+= products\[1\];\s*'
            r'c \+= h_point;\s*c \+= l;\s*'
            r'FinalGroth16CaptureAuthority final_capture_authority\(context\);\s*'
            r'const auto opened = open_final_groth16\(\s*'
            r'context, checks, a, b2, c, std::move\(final_capture_authority\)\);',
            re.MULTILINE))

    def test_direct_final_group_capture_callsite_is_private(self):
        hostile = r'''\
#include "p1_capture_seams.hpp"
using namespace kpi::mpc;
void leak(p1_capture::P1TypedCaptureSeams& capture,
          std::span<const G1Value> values) {
    capture.final_group_openings(values);
}
'''
        source = Path(self.temporary.name) / 'hostile_final_capture.cpp'
        source.write_text(hostile)
        compiled = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(compiled.returncode, 0)
        self.assertRegex(compiled.stderr, r'(private|no member named)')

        fake_friend = r'''\
#include "p1_capture_seams.hpp"
namespace kpi::mpc {
class GroupMacSetup final {
public:
    static void leak(p1_capture::P1TypedCaptureSeams& capture,
                     std::span<const G1Value> values) {
        capture.final_group_openings(values);
    }
};
}
'''
        source.write_text(fake_friend)
        forged = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(forged.returncode, 0)
        self.assertIn('redefinition of', forged.stderr)

        forged_authority = r'''\
#include "p1_capture_seams.hpp"
using namespace kpi::mpc;
FinalGroth16CaptureAuthority forge(MascotContext& context) {
    return FinalGroth16CaptureAuthority(context);
}
'''
        source.write_text(forged_authority)
        forged = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(forged.returncode, 0)
        self.assertIn('private', forged.stderr)

        fake_financial_friend = r'''\
#include "p1_capture_seams.hpp"
namespace kpi::mpc::financial {
class FinancialValidatedAssignment final {
public:
    static FinalGroth16CaptureAuthority forge(MascotContext& context) {
        return FinalGroth16CaptureAuthority(context);
    }
};
}
'''
        source.write_text(fake_financial_friend)
        forged = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(forged.returncode, 0)
        self.assertIn('redefinition of', forged.stderr)

    def test_capture_authority_friend_cannot_be_redefined_to_forge(self):
        hostile = r'''\
#include "p1_capturing_player.hpp"
namespace kpi::mpc::financial::registered_driver {
class CapturePlanAuthorityBridge final {
public:
    static p1_capture::P1PlayerCaptureAuthority forge() {
        return p1_capture::P1PlayerCaptureAuthority(23, 1, {});
    }
};
}
'''
        source = Path(self.temporary.name) / 'hostile_friend.cpp'
        source.write_text(hostile)
        compiled = subprocess.run([
            'g++', '-std=c++20', '-fsyntax-only',
            '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
            '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
            '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
            str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
            '-I', str(PREFIX / 'include'),
            '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
            '-I', str(MCL / 'include'),
        ], capture_output=True, text=True, check=False)
        self.assertNotEqual(compiled.returncode, 0)
        self.assertIn('redefinition of', compiled.stderr)

    def test_typed_seam_friend_is_complete_before_private_grants(self):
        probes = {
            'stream': r'''\
#include "p1_capture_stream.hpp"
namespace kpi::mpc::p1_capture {
class P1TypedCaptureSeams final {
public:
    static void attacker_poison(P1CaptureStream& stream) {
        stream.poison();
    }
};
}
''',
            'player': r'''\
#include "p1_capturing_player.hpp"
namespace kpi::mpc::p1_capture {
class P1TypedCaptureSeams final {
public:
    static std::shared_ptr<P1CaptureStream> steal(
        P1CapturingPlayer& player) {
        return player.capture_;
    }
};
}
''',
            'stream-player-friend': r'''\
#include "p1_capture_stream.hpp"
namespace kpi::mpc::p1_capture {
class P1CapturingPlayer final {
public:
    static void attacker_poison(P1CaptureStream& stream) {
        stream.poison();
    }
};
}
''',
        }
        for name, hostile in probes.items():
            with self.subTest(name=name):
                source = Path(self.temporary.name) / f'hostile_{name}_seam.cpp'
                source.write_text(hostile)
                compiled = subprocess.run([
                    'g++', '-std=c++20', '-fsyntax-only',
                    '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
                    '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK',
                    '-DMCL_FP_BIT=384', '-DMCL_FR_BIT=256', '-DMCL_MSM=0',
                    str(source), '-I', str(MPC), '-I', str(MP_SPDZ),
                    '-I', str(PREFIX / 'include'),
                    '-I', str(PREFIX / 'include' / 'x86_64-linux-gnu'),
                    '-I', str(MCL / 'include'),
                ], capture_output=True, text=True, check=False)
                self.assertNotEqual(compiled.returncode, 0)
                self.assertIn('redefinition of', compiled.stderr)

    def test_production_context_wraps_roster_before_mascot_setup(self):
        header = (MPC / 'financial/registered_p1_context.hpp').read_text()
        source = (MPC / 'financial/registered_p1_context.cpp').read_text()
        field_header = (MPC / 'auth_field.hpp').read_text()
        player_header = (
            MPC / 'p1_capturing_player_contract.hpp').read_text()
        player_source = (MPC / 'p1_capturing_player.cpp').read_text()

        split = source.index('CapturePlanAuthorityBridge::split_for_driver(')
        wrapper = source.index('P1CapturingPlayer::begin(', split)
        seams = source.index('P1TypedCaptureSeams', wrapper)
        context = source.index('std::make_unique<MascotContext>', seams)
        self.assertLess(split, wrapper)
        self.assertLess(wrapper, seams)
        self.assertLess(seams, context)
        self.assertIn('split.take_session()', source)
        self.assertIn('split.take_p1_player_capture()', source)
        self.assertIn('selected.role == 1', source)
        self.assertIn('!split.has_p1_player_capture()', source)
        self.assertIn('CapturePlanAuthority take_session()', header)
        self.assertIn('P1TypedCaptureSeams& capture', field_header)
        captured_key = field_header.index('captured_setup_key(')
        self.assertGreater(captured_key, field_header.index(
            'begin_captured_setup('))
        field_source = (MPC / 'auth_field.cpp').read_text()
        key_capture = field_source.index('capture.mac_key_share(key)')
        captured_initializer = field_source.index(
            'alpha_i_(captured_setup_key(setup_, capture, stage))')
        protocols_initializer = field_source.index(
            'protocols_(begin_protocols(player, alpha_i_, stage))',
            captured_initializer)
        self.assertLess(key_capture, captured_initializer)
        self.assertLess(captured_initializer, protocols_initializer)
        self.assertIn('public financial::RosterPinnedPlayer', player_header)
        self.assertIn('authenticated_roster() const noexcept', player_header)
        self.assertIn('authenticated_registered_binding() const noexcept',
                      player_header)
        self.assertIn('roster_.authenticated_roster()', player_source)
        self.assertIn('roster_.authenticated_registered_binding()',
                      player_source)

        registered_build = (
            MPC / 'financial/build_registered_financial.py').read_text()
        for unit in ('financial/registered_p1_capture_bridge.cpp',
                     'financial/registered_p1_context.cpp'):
            self.assertIn("'" + unit + "'", registered_build)

    def test_every_build_that_compiles_p1_also_links_the_p1_units(self):
        for relative in ('build.py', 'trace/build_trace.py'):
            source = (MPC / relative).read_text()
            for unit in ('p1_capture_stream.cpp',
                         'p1_capturing_player.cpp', 'p1_capture_seams.cpp'):
                self.assertGreaterEqual(source.count("'" + unit + "'"), 2,
                                        relative + ':' + unit)
        for relative in ('financial/build_financial.py',
                         'financial/build_registered_financial.py'):
            source = (MPC / relative).read_text()
            for unit in ('p1_capture_stream.cpp',
                         'p1_capturing_player.cpp', 'p1_capture_seams.cpp'):
                self.assertIn("'" + unit + "'", source,
                              relative + ':' + unit)


if __name__ == '__main__':
    unittest.main()
