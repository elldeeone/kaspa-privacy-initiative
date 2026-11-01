#!/usr/bin/env python3
"""Pre-CryptoPlayer source-policy identity controls."""

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


class PrelaunchPolicyDomainAuthorityControls(unittest.TestCase):
    def compile(self, source, output, *, setup=False):
        command = [
            'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
            '-pedantic', '-I', str(HERE),
        ]
        if setup:
            command.append('-DKPB_PRELAUNCH_POLICY_DOMAIN_TEST_SETUP')
        command.extend([
            str(source),
            str(HERE / 'privacy_prelaunch_policy_domain_authority.cpp'),
            '-o', str(output),
        ])
        return subprocess.run(command, capture_output=True, text=True,
                              check=False)

    def test_exact_reviewed_source_pins_and_one_use_authority(self):
        implementation = (HERE /
            'privacy_prelaunch_policy_domain_authority.cpp').read_text(
                encoding='utf-8')
        pins = {
            'ACCEPTED_HEAD_CPP_SHA256':
                ROOT / 'mpc-prover/financial/accepted_head.cpp',
            'ACCEPTED_HEAD_HPP_SHA256':
                ROOT / 'mpc-prover/financial/accepted_head.hpp',
            'REGISTERED_SELECTION_CPP_SHA256':
                ROOT / 'mpc-prover/financial/registered_selection.cpp',
            'REGISTERED_SELECTION_HPP_SHA256':
                ROOT / 'mpc-prover/financial/registered_selection.hpp',
            'FIXED_PUBLIC_RUN_CPP_SHA256':
                ROOT / 'mpc-prover/financial/fixed_public_run.cpp',
            'FIXED_PUBLIC_RUN_HPP_SHA256':
                ROOT / 'mpc-prover/financial/fixed_public_run.hpp',
        }
        for name, path in pins.items():
            matched = re.search(
                rf'{name}\s*=\s*\n\s*"([0-9a-f]{{64}})";',
                implementation)
            self.assertIsNotNone(matched, name)
            self.assertEqual(
                matched.group(1), hashlib.sha256(path.read_bytes()).hexdigest(),
                name)
        with tempfile.TemporaryDirectory(
                prefix='kpb-prelaunch-policy-domain-') as raw:
            binary = Path(raw) / 'control'
            built = self.compile(
                HERE / 'privacy_prelaunch_policy_domain_authority_control.cpp',
                binary, setup=True)
            self.assertEqual(built.returncode, 0,
                             built.stdout + built.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_production_surface_has_no_digest_getter_or_runtime_input(self):
        with tempfile.TemporaryDirectory(
                prefix='kpb-prelaunch-policy-surface-') as raw:
            root = Path(raw)
            source = root / 'surface.cpp'
            source.write_text(r'''
#include "privacy_prelaunch_policy_domain_authority.hpp"
#include <concepts>
using namespace kpb::measurement::prelaunch_policy_domain;
template<class T> concept HasAccepted = requires(const T& value) {
    value.accepted_head_policy_identity();
};
template<class T> concept HasSelected = requires(const T& value) {
    value.selected_main_policy_identity();
};
template<class T> concept HasDigest = requires(const T& value) {
    value.digest();
};
static_assert(!std::default_initializable<
    RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(!std::copy_constructible<
    RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(std::move_constructible<
    RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(!HasAccepted<RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(!HasSelected<RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(!HasDigest<RegisteredPrelaunchPolicyDomainAuthority>);
static_assert(kRegisteredPrelaunchPolicyDomainStatus.exact_source_pin_constants);
static_assert(kRegisteredPrelaunchPolicyDomainStatus.accepted_head_policy_algorithm_identity);
static_assert(kRegisteredPrelaunchPolicyDomainStatus.selected_main_policy_algorithm_identity);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.caller_digest_or_path_input);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.runtime_accepted_head_authority);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.runtime_selected_main_authority);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.selected_prelaunch_compiler_consumer);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.producer_plus_two_capsule_split);
static_assert(!kRegisteredPrelaunchPolicyDomainStatus.configured);
int main() {
    auto value = RegisteredPrelaunchPolicyDomainSourceBridge::acquire();
    (void)value;
}
''', encoding='utf-8')
            binary = root / 'surface'
            built = self.compile(source, binary)
            self.assertEqual(built.returncode, 0,
                             built.stdout + built.stderr)
            run = subprocess.run([str(binary)], capture_output=True,
                                 text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_authority_header_does_not_depend_on_post_tls_runtime_types(self):
        header = (HERE /
            'privacy_prelaunch_policy_domain_authority.hpp').read_text(
                encoding='utf-8')
        for forbidden in (
                'MascotContext', 'AcceptedFinancialHead',
                'RegisteredFinancialSelection', 'RegisteredService',
                'PackedModel'):
            self.assertNotIn(forbidden, header)


if __name__ == '__main__':
    unittest.main()
