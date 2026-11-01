#!/usr/bin/env python3
"""Controls for the compiled registered-role model admission boundary."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


HERE = Path(__file__).resolve().parent
FINANCIAL = HERE.parent
MPC = FINANCIAL.parent
ROOT = MPC.parents[2]
VENDOR = ROOT / '.local/mpc-prover-softspoken-vendor'


def compiler_flags():
    compiler = shutil.which('x86_64-linux-gnu-g++-15') or shutil.which('g++')
    if compiler is None:
        raise unittest.SkipTest('C++ compiler unavailable')
    flags = [
        compiler, '-std=c++20', '-O1', '-g0', '-march=native', '-pthread',
        '-Wall', '-Wextra', '-Werror', '-Wno-overloaded-virtual',
        '-DNO_MIXED_CIRCUITS', '-DNO_AVX_OT', '-DUSE_GF2N_LONG',
        '-DMCL_USE_GMP=1', '-DMCL_DONT_USE_XBYAK', '-DMCL_FP_BIT=384',
        '-DMCL_FR_BIT=256', '-DMCL_MSM=0', '-fsyntax-only',
    ]
    for include in [
        MPC, VENDOR / 'MP-SPDZ', VENDOR / 'MP-SPDZ/deps',
        VENDOR / 'MP-SPDZ/local/include', VENDOR / 'mcl/include',
        VENDOR / 'prefix/usr/include',
        VENDOR / 'prefix/usr/include/x86_64-linux-gnu',
    ]:
        flags.extend(['-I', str(include)])
    return flags


class RegisteredRoleModelAdmissionControls(unittest.TestCase):
    def test_source_compiles_with_production_surface(self):
        result = subprocess.run(
            [*compiler_flags(),
             str(FINANCIAL / 'registered_role_model_admission.cpp')],
            capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_contract_consumes_typed_configuration_and_pending_bootstrap(self):
        header = (FINANCIAL / 'registered_role_model_admission.hpp').read_text()
        source = (FINANCIAL / 'registered_role_model_admission.cpp').read_text()
        self.assertIn('CompiledRoleModelConfigurationAuthority&&', header)
        self.assertIn('const RegisteredChildBootstrapPending&', header)
        self.assertIn('RegisteredParentBootstrapTransport::query_artifact', source)
        self.assertIn('packed::GzipQueryStore::admit', source)
        self.assertIn('packed::PackedModel::admit_compressed', source)
        self.assertIn('model.check_backing_unchanged()', source)
        self.assertNotIn('PackedModel&&', header)
        self.assertNotIn('std::span<const unsigned char>', header)

    def test_no_production_configuration_mint_or_runtime_input(self):
        header = (FINANCIAL / 'registered_role_model_admission.hpp').read_text()
        authority = header[header.index(
            'class CompiledRoleModelConfigurationAuthority final'):]
        authority = authority[:authority.index('\n};')]
        self.assertIn('KPI_REGISTERED_ROLE_MODEL_ADMISSION_TEST_SETUP', authority)
        self.assertIn('test_only_mint', authority)
        public = authority[authority.index('public:'):]
        before_test = public[:public.index(
            '#ifdef KPI_REGISTERED_ROLE_MODEL_ADMISSION_TEST_SETUP')]
        self.assertNotIn('PublicCompiledRoleModelConfiguration', before_test)
        for forbidden in ('argc', 'argv', 'getenv', 'JSON', 'json'):
            self.assertNotIn(forbidden, header)

    def test_hostile_tu_cannot_mint_configuration(self):
        attacks = {
            'macro-only-mint': '''
                auto forged =
                    CompiledRoleModelConfigurationAuthority::test_only_mint(
                        std::move(value));
                (void)forged;
            ''',
            'private-constructor': '''
                CompiledRoleModelConfigurationAuthority forged(
                    std::move(value));
                (void)forged;
            ''',
        }
        for name, attack in attacks.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                source = Path(root) / 'hostile.cpp'
                source.write_text(textwrap.dedent(f'''
                    #include "financial/registered_role_model_admission.hpp"
                    #include <utility>
                    using namespace kpi::mpc::financial::registered_driver;
                    int main() {{
                      PublicCompiledRoleModelConfiguration value{{}};
                      {attack}
                    }}
                '''), encoding='utf-8')
                result = subprocess.run(
                    [*compiler_flags(), str(source)], capture_output=True,
                    text=True, check=False)
            self.assertNotEqual(result.returncode, 0, name)

    def test_no_caller_model_vk_row_or_verifier_admission_factory(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'surface.cpp'
            source.write_text(textwrap.dedent('''
                #include "financial/registered_role_model_admission.hpp"
                #include <concepts>
                using namespace kpi::mpc::financial::registered_driver;
                template<class T> concept PublicConfigurationMint = requires(
                        PublicCompiledRoleModelConfiguration value) {
                    T::mint(value);
                };
                template<class T> concept PathAdmission = requires(
                        kpi::mpc::financial::registered_detail::
                            DriverConfiguration config,
                        const RegisteredChildBootstrapPending& pending) {
                    T::admit(config, pending);
                };
                static_assert(!std::default_initializable<
                    CompiledRoleModelConfigurationAuthority>);
                static_assert(!std::constructible_from<
                    CompiledRoleModelConfigurationAuthority,
                    PublicCompiledRoleModelConfiguration>);
                static_assert(!PublicConfigurationMint<
                    CompiledRoleModelConfigurationAuthority>);
                static_assert(!PathAdmission<RegisteredRoleModelAdmission>);
                int main() { return 0; }
            '''), encoding='utf-8')
            result = subprocess.run(
                [*compiler_flags(), str(source)], capture_output=True,
                text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_status_reports_the_concrete_child_callsite_but_not_configuration(self):
        source = (FINANCIAL / 'registered_role_model_admission.cpp').read_text()
        self.assertIn('.selected_child_callsite = true', source)
        self.assertIn('.production_compiled_configuration_minter = false', source)
        self.assertIn('.registered_driver_configured = false', source)
        self.assertIn('.launch_authorized = false', source)


if __name__ == '__main__':
    unittest.main()
