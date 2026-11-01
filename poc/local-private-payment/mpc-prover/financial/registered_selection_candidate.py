#!/usr/bin/env python3
"""Prepare the public-only trial-03 registered source snapshot candidate.

This module copies already selected PUBLIC bytes into a fresh, single-link,
read-only snapshot and verifies their exact source/build relationships. It
reopens only the selected empty trial journal/anchor READY records through the
selected initializer. It does not configure the driver, read private-key or
owner-input bodies, contact a network, construct MPC state, prove, broadcast,
or settle. Hermetic execution is exposed only as CONTROL_ONLY evidence while
CONFIGURED=0. Production admission hard-refuses until a selected outer build
and supervisor inject a nonforgeable, build-pinned capability.
"""
import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import io
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
import re
import ssl
import stat
import socket
import subprocess
import tempfile


REPOSITORY_ROOT = Path(
    '/home/luke/projects/kpi-intensive-2026-10-22/continuation')
TRIAL_ROOT = (REPOSITORY_ROOT / '.local/registered-financial-trial-03').resolve()
TRIAL_ID = '46c16c64-2ba3-4d69-89e0-c00bd3a1277b'
TRIAL_SELECTION_SHA256 = (
    '77252d3ca1a4faffa3ee8e03706a93604e0909034cc274309c7ea2300c198401')
REGISTRATION_SHA256 = (
    '101b682fcd64f51ec4214ee5858f06f1adefa49f225be89b32a3318d71c8f92d')
REGISTRATION_FILE_SHA256 = (
    'ed8c928d5c4be40b376df8e86036cf116e9b8861fe32499725dceaeecfd0d9be')
CA_DER_SHA256 = (
    'b7b01ec85773ac19389441befed50a349fb9c21d9f438711bc8905cd8dec927f')
CERTIFICATE_DER_SHA256 = (
    'c1f0a1c3500a850ff68d0e13b105de3621b11040e78a09ec79b838ff039bc556',
    '55d70d4f5611a57ccb197e17de498ab2871c7282944cbd7f2827de66abdfa9e8',
    '3bff49233fd98b71fc8121e57d059b590282b09fef7859768f5d280d8c475e8d',
)
ACQUISITION_SOURCE_CLOSURE_SHA256 = (
    'a63868c1cbb8fad1e184833a60f8c2c67e8766ca605f78949738a87834c2595b')
BASE_QUALIFIER_SOURCE_CLOSURE_SHA256 = (
    '22b7c027c7c51e892fc4d552cf3db0723e475acfe85f0b5b33452a1a21f8c9d4')
BASE_QUALIFIER_BUILD_SHA256 = (
    '637d4a76ab40d72c8a49a8ad7f0d0113d76aa800a7e513fdec32463871ab8fdd')
BASE_QUALIFIER_AUTHORITY_BUILD_SHA256 = (
    'a5a37ca8d7d52671156975898eb8d9b9fd6fb3a8f7287b85e64c73b373a948bb')
BASE_QUALIFIER_BINARY_SHA256 = (
    'f6fb3926efcf158fa5553a727a72b342f4af4da2daef061ea01427de832d1e16')
QUALIFIER_SOURCE_CLOSURE_SHA256 = (
    '8a8dd4c7a0de02b1003ed0119c070867dff72a2270b6fc35466ea3a417e51d1e')
QUALIFIER_BUILD_SHA256 = (
    'c73ab6807f4fa62383af3f52df4b7d330effe36da5e20dde567063753345a4c9')
QUALIFIER_AUTHORITY_BUILD_SHA256 = (
    '05143193847dd93a147c0f53abc771d29be8edfd9c316b2492263fc00c363ac0')
QUALIFIER_BINARY_SHA256 = (
    '110e46e8471b7885b34fe3259bf32135c026751c7cd54e74e34b303ec6db3eea')
STATE_INITIALIZATION_SHA256 = (
    '8024df3c3410786ba0fb0a41d65d7c535d7941a7e9cc64f90fe38d059d6c4196')
SOURCE_SELECTION_SHA256 = (
    'd378240b68cac22fc68ad61513139ee392a6c8d1b075086627fb1162a6e69936')
INITIALIZER_SHA256 = (
    'ba42dded84033a614cd1464866fe7ef020a41d0bd2b6cd1572b56ae54127387b')
READY_CHECKPOINT_SHA256 = (
    '5bf83f9dc55264a7908337dafdf32c3f19c6ee74638b405b5d6d83c378818a5e')
CONFIGURATION_SELECTION_SHA256 = (
    'f6ad556c12ffa97656b928df662ed61258d0a1f3e568bff294b0b6f1e77c964a')
COMPILER_SHA256 = (
    'e6718f7e0c7d057c3ff77b550c603da9bc4030e3ede3c053705acce1293dbe4d')
BUILD_CONTRACT_SHA256 = (
    'f4bb3f12590d292bb6fee6338d3df8de79dca12f22c3f11f0385e7b4b70dc262')
VENDOR_CLOSURE_SHA256 = (
    'c10d5d15a085714fec79de3d76bc5611814ca40f0b439bc1a28fbec1972fa34f')
TOOLCHAIN_SHA256 = (
    '1e37d21c6bdced6ea77909ace0b492f45e1f8a3fcf298d5204b5468d5d3c0461')
COMPILE_DEPENDENCY_CLOSURE_SHA256 = (
    'd79b432e224be55af6e7493f4b842e706534eabc1d9959bd830daf753631b017')
OBJECT_CLOSURE_SHA256 = (
    'fca5914251db269eb43ea17ac65e6183399835b40ce94006081be833330b04f4')
LINK_DEPENDENCY_CLOSURE_SHA256 = (
    '5b11b464db8f391cfefd9bf43d1f9f90403c48ee2393d6a369bfef5da1bba601')
OPENSSL_SHA256 = (
    '1d72cbc5bf62be3f3dbd7626c295b63c5fdc1dd8439f323ac47998d8a062b4c9')
PYTHON_SHA256 = (
    '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41')
BWRAP_SHA256 = (
    '523da3e7399044be5163aee6f57a77a6bef7454376e28f0a0627920bae1b76b6')
PYTHON_STDLIB_SOURCE_COUNT = 555
PYTHON_STDLIB_SOURCE_CLOSURE_SHA256 = (
    '7bd209dd30a5cdf950062b8d3581aba0dc1a88e99170cb495c1381a9d70b27b5')
PYTHON_STDLIB_ARCHIVE_SHA256 = (
    '9effba1a6065428d94026fb5ddf8e764e3efbaf6117a17710c518519cd7887ef')
PYTHON_STDLIB_ARCHIVE_BYTES = 2773759
HISTORICAL_CONTROL_BASE_CONFIG_SHA256 = (
    '6fa69b0fc3ac83b16b05e3f1f5e7cbf9a2797c82327c9adc65e8a84625a0099b')
LIVE_VENDOR_ROOT = (
    REPOSITORY_ROOT / '.local/mpc-prover-softspoken-vendor').resolve()
VERIFIER_REPOSITORY_PATH = (
    REPOSITORY_ROOT /
    'poc/local-private-payment/mpc-prover/financial/'
    'registered_selection_candidate.py').resolve()

# Runtime objects are copied as regular, single-link files under their exact
# DT_NEEDED names.  The selected loader is invoked directly with this finite
# directory and with both the host cache and the binary's absolute RUNPATH
# disabled.  These pins are independent of the source-owned build receipt.
RUNTIME_OBJECTS = {
    'ld-linux-x86-64.so.2': (
        '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2',
        'bda779ea9e9ad234f60315477d7cfd0bdde861cd8ddd9df8cdaf62f18c4cec14',
        254864),
    'libSPDZ.so': (
        str(LIVE_VENDOR_ROOT / 'MP-SPDZ/libSPDZ.so'),
        '06fb18d0e8521b9dca7114d0e1b810a68be8468acfadc1f0a7e895f9368c8036',
        1739176),
    'libboost_filesystem.so.1.90.0': (
        '/usr/lib/x86_64-linux-gnu/libboost_filesystem.so.1.90.0',
        '8092f4e043bd199619cd4d2a759edeab53bfee30bee1004dd07ce43b5107ecd6',
        158192),
    'libboost_iostreams.so.1.90.0': (
        '/usr/lib/x86_64-linux-gnu/libboost_iostreams.so.1.90.0',
        'b5e56950ef7d16cac95eb13c82a862c3545e1da7b65ca87896c3f4f5dd28343b',
        92416),
    'libbz2.so.1.0': (
        '/usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4',
        '7138aeb748f73c150b1d34d67de69139a441910cd7b269076ba3c8b986dea9a7',
        83120),
    'libc.so.6': (
        '/usr/lib/x86_64-linux-gnu/libc.so.6',
        '85e64f97e348786a8fb4d9f3d52fec289e2fb86bba20f0731dfe61990525e0f7',
        2190608),
    'libcap.so.2': (
        '/usr/lib/x86_64-linux-gnu/libcap.so.2.75',
        'c5b463a8136dabb152bad8b04e89bf67bd2049ef49777ed0b96bdbc6cb5b9565',
        51616),
    'libcrypto.so.3': (
        '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
        '5385f0436ac2e284ba8c5fb1488874057c29c04be72dea32add832694f381e28',
        6386528),
    'libexpat.so.1': (
        '/usr/lib/x86_64-linux-gnu/libexpat.so.1.11.2',
        '2e5f66e2784c2746775567ff9916f6e7503182a8f1f2deb8ca729dfc1463849f',
        186704),
    'libffi.so.8': (
        '/usr/lib/x86_64-linux-gnu/libffi.so.8.2.0',
        '1a0dc86f787f73e025a6e521056360afcbe70f2a82cd808132fefc2b4ee95daa',
        64184),
    'libgcc_s.so.1': (
        '/usr/lib/x86_64-linux-gnu/libgcc_s.so.1',
        '9d339ecb409578d6a5d587e6c537a8f9589b8a13fefba30d167433a4b5758bee',
        187120),
    'libgmp.so.10': (
        '/usr/lib/x86_64-linux-gnu/libgmp.so.10.5.0',
        'fda9699eef15deda5f1c626e9140377a7f5d88c41516a54278ac02429cb20fa5',
        543168),
    'libgmpxx.so.4': (
        str(LIVE_VENDOR_ROOT /
            'prefix/usr/lib/x86_64-linux-gnu/libgmpxx.so.4.7.0'),
        'c6261b838536ec28a47008433227aaaf2573f408b54bfa79bea8c9c98c4acaa6',
        31264),
    'liblzma.so.5': (
        '/usr/lib/x86_64-linux-gnu/liblzma.so.5.8.3',
        '515749273a91ca5e3b273b4025dc2c1f8827f90005baea0ab85ffb594e74f72f',
        215448),
    'libm.so.6': (
        '/usr/lib/x86_64-linux-gnu/libm.so.6',
        '1c488db6f4fe8cecb72456bc018de000b7a9b539c2994864b0416b5e8371b3d8',
        1198376),
    'libpcre2-8.so.0': (
        '/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0',
        '4a6b6b2078685b074869d75cb068664d7da6b3036df7bca0442b1bbbd4ac7e65',
        699056),
    'libselinux.so.1': (
        '/usr/lib/x86_64-linux-gnu/libselinux.so.1',
        '7538ee77765a27966563c0d22437a3080dcdb346ff76cc16d71a3ce3379a716a',
        199120),
    'libsodium.so.23': (
        '/usr/lib/x86_64-linux-gnu/libsodium.so.23.3.0',
        'f9fdc530581d9c0978097c3838d12e33b12d7496106699c796635e97a0407421',
        367408),
    'libssl.so.3': (
        '/usr/lib/x86_64-linux-gnu/libssl.so.3',
        '63b47f444efa588e291e9b650a5ba2ab02f856356f2d50f13a2e477db9119e09',
        1114280),
    'libstdc++.so.6': (
        '/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.35',
        '5bb0d21308f123b6ad46c6f35b42cedfcb8d6d439a53aa3dae04d880aaffdde3',
        2735712),
    'libz.so.1': (
        '/usr/lib/x86_64-linux-gnu/libz.so.1.3.1',
        '27fa6c6cb94fb5b099ead61758a300dbc392d1dbf307fff6c16a9b8e57fdc9de',
        121272),
    'libzstd.so.1': (
        '/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.7',
        '060eeb79531d435306665fd78329d8a9dd579f95876c5960bb67937825362a80',
        796824),
}

PYTHON_DYNLOAD = {
    '_ctypes.cpython-314-x86_64-linux-gnu.so': (
        '140e837f2bc9344f3a98dea90e8bdf6f208370e45f3eccbac759c59e59d4d045',
        158368),
    '_hashlib.cpython-314-x86_64-linux-gnu.so': (
        'f57bc22cc1b6f3b48c43778634af1a7e79c5ae0632350fa5144d050c7848112c',
        64448),
    '_ssl.cpython-314-x86_64-linux-gnu.so': (
        '53789b72a5011867c45036d115ef10f452282751b8735691d1eaf22bf8fe5587',
        236736),
}
HEX32 = re.compile('[0-9a-f]{64}')
AT_FDCWD = -100
RENAME_NOREPLACE = 1
SELECTED_RUNTIME_CHILD = False
SELECTED_PARENT_NETNS = None
SELECTED_EXTERNAL_AUTHORITY = None
SANDBOX_SNAPSHOT_ROOT = Path('/selection')
SEALED_RUNTIME_ROOT = Path('/sealed')
# Final authority is injected only by the selected outer build/supervisor after
# its complete source closure stabilizes. Source-only controls cannot mint it.
OUTER_SUPERVISOR_AUTHORITY_SHA256 = '00' * 32
OUTER_SUPERVISOR_AUTHORITY_CONFIGURED = False

SEALED_TOOLS = {
    'runtime/bin/python3.14': '/sealed/bin/python3.14',
    'runtime/bin/openssl': '/sealed/bin/openssl',
    'trial/registered-trial-init': '/sealed/tools/registered-trial-init',
    'qualifier/mpc-registered-financial-gate':
        '/sealed/tools/mpc-registered-financial-gate',
    'qualifier/authority-mpc-registered-financial-gate':
        '/sealed/tools/authority-mpc-registered-financial-gate',
    'qualifier/base/mpc-registered-financial-gate':
        '/sealed/tools/base-mpc-registered-financial-gate',
}


# target-relative path -> (repository-relative selected source, sha256, mode)
EXPECTED_FILES = {
    'trial/BOOTSTRAP.json': (
        '.local/registered-financial-trial-03/public/BOOTSTRAP.json',
        'fea6578e2f1039d3f5e74fff931c613d1e4b7dcf21fa81db36e41738dbb14107', 0o400),
    'trial/SELECTION-CANDIDATE.json': (
        '.local/registered-financial-trial-03/public/SELECTION-CANDIDATE.json',
        TRIAL_SELECTION_SHA256, 0o400),
    'trial/SOURCE-SELECTION.json': (
        '.local/registered-financial-trial-03/public/SOURCE-SELECTION.json',
        'd378240b68cac22fc68ad61513139ee392a6c8d1b075086627fb1162a6e69936', 0o400),
    'trial/STATE-INITIALIZATION.txt': (
        '.local/registered-financial-trial-03/public/STATE-INITIALIZATION.txt',
        '8024df3c3410786ba0fb0a41d65d7c535d7941a7e9cc64f90fe38d059d6c4196', 0o400),
    'trial/BUILD.json': (
        '.local/registered-financial-trial-03/public/build/BUILD.json',
        'b4699295eb6261a7f48e0e0f1c80578468360f254ff3dc608fd8986d297fb362', 0o400),
    'trial/registered-trial-init': (
        '.local/registered-financial-trial-03/public/build/registered-trial-init',
        'ba42dded84033a614cd1464866fe7ef020a41d0bd2b6cd1572b56ae54127387b', 0o500),
    'trial/registration/REGISTRATION.json': (
        '.local/registered-financial-trial-03/public/registration/REGISTRATION.json',
        REGISTRATION_FILE_SHA256, 0o400),
    'trial/certificates/ca.pem': (
        '.local/registered-financial-trial-03/public/certificates/ca.pem',
        '8bf33598b5e81da0b2121d0deada762a85f52adc2e09853817cee99cff1d826c', 0o400),
    'trial/certificates/P0.pem': (
        '.local/registered-financial-trial-03/public/certificates/P0.pem',
        '13cf5e265194e5d7fce59bc2cf5554fc82d783840681b9ff10d728dc6750411b', 0o400),
    'trial/certificates/P1.pem': (
        '.local/registered-financial-trial-03/public/certificates/P1.pem',
        '9799a54028059716a070adcbe60b81b6ec46e2cf7c823303ae4dd64ddfaceddb', 0o400),
    'trial/certificates/P2.pem': (
        '.local/registered-financial-trial-03/public/certificates/P2.pem',
        '234828b2cd594b6f5dd4d29c769c838b16ebebe7aaf7e204ae4cbba975564ec1', 0o400),
    'accepted-head/accepted_head.cpp': (
        'poc/local-private-payment/mpc-prover/financial/accepted_head.cpp',
        '6da0b804f210640b58d455e65fbd36a6e06a605e25d08e1544e01e6e3495f2cf', 0o400),
    'accepted-head/accepted_head.hpp': (
        'poc/local-private-payment/mpc-prover/financial/accepted_head.hpp',
        'd3e1b0c46e816d7e55b3c3c180dd1e3883601217658274de98982e5a91bb8956', 0o400),
    'accepted-head/fixed_public_run.cpp': (
        'poc/local-private-payment/mpc-prover/financial/fixed_public_run.cpp',
        '9172b4ab67818a55f1080e2559a053251df5f19908955cf970ebd5f6989f7a37', 0o400),
    'accepted-head/fixed_public_run.hpp': (
        'poc/local-private-payment/mpc-prover/financial/fixed_public_run.hpp',
        '1495669a83401b37116e3b8ef5ec6ccd23c3beffb0296529fac73a083a74668a', 0o400),
    'accepted-head/QUALIFICATION.json': (
        '.local/private-batch-registered-head-candidate-01/source/producer/QUALIFICATION.json',
        '9b9fbf75636cf67402fdf082f0dc3c58690219b9aed6bc2934c22480ae6679ff', 0o400),
    'accepted-head/producer.py': (
        '.local/private-batch-registered-head-candidate-01/source/producer/producer.py',
        'aef0c1d462b35334aa3d45c45028dcda99fd298af11fdadf9a4bdeef253701f8', 0o400),
    'accepted-head/head_protocol.py': (
        '.local/private-batch-registered-head-candidate-01/source/producer/head_protocol.py',
        '260ae2d07f858643f9bbfe06fdf3279517810ca74004ab8352ef28ddda7d2d72', 0o400),
    'accepted-head/acquire_head.mjs': (
        '.local/private-batch-registered-head-candidate-01/source/producer/acquire_head.mjs',
        '203fabefe07935875e680036ebacf528d6a474f2481a109e8cac6decafc4ba8e', 0o400),
    'accepted-head/test_protocol.py': (
        '.local/private-batch-registered-head-candidate-01/source/producer/test_protocol.py',
        '43753e2a88e8622d2907e306b1828a8ad29eb479ae4d2794a51726fcf12d4666', 0o400),
    'accepted-head/test_acquire_head.mjs': (
        '.local/private-batch-registered-head-candidate-01/source/producer/test_acquire_head.mjs',
        '830e19d0c9a725c4787971529c5fba68a756ed6b0e8f9da5903e6a710824d1e9', 0o400),
    'accepted-head/README.md': (
        '.local/private-batch-registered-head-candidate-01/source/producer/README.md',
        '80abb584ea1f3e4526d7d7cffaaa6d5a79f9eff6d2f1e9908d066c37737c23d1', 0o400),
    'accepted-head/JS-CONTROLS.json': (
        '.local/private-batch-registered-head-candidate-01/source/producer/JS-CONTROLS.json',
        'b094863903269d8a8bdad595aa46b2e7722bbbbe36b2587fd72f044ec7a88483', 0o400),
    'qualifier/BUILD-RESULT.json': (
        '.local/registered-financial-gate-build-12/BUILD-RESULT.json',
        QUALIFIER_BUILD_SHA256, 0o400),
    'qualifier/mpc-registered-financial-gate': (
        '.local/registered-financial-gate-build-12/mpc-registered-financial-gate',
        QUALIFIER_BINARY_SHA256, 0o500),
    'qualifier/AUTHORITY-BUILD-RESULT.json': (
        '.local/registered-financial-gate-build-10/BUILD-RESULT.json',
        QUALIFIER_AUTHORITY_BUILD_SHA256, 0o400),
    'qualifier/authority-mpc-registered-financial-gate': (
        '.local/registered-financial-gate-build-10/mpc-registered-financial-gate',
        QUALIFIER_BINARY_SHA256, 0o500),
    'qualifier/base/BUILD-RESULT.json': (
        '.local/registered-financial-gate-build-04/BUILD-RESULT.json',
        BASE_QUALIFIER_BUILD_SHA256, 0o400),
    'qualifier/base/AUTHORITY-BUILD-RESULT.json': (
        '.local/registered-financial-gate-build-03/BUILD-RESULT.json',
        BASE_QUALIFIER_AUTHORITY_BUILD_SHA256, 0o400),
    'qualifier/base/mpc-registered-financial-gate': (
        '.local/registered-financial-gate-build-04/mpc-registered-financial-gate',
        BASE_QUALIFIER_BINARY_SHA256, 0o500),
    'exporter/export_registered_program.py': (
        'poc/local-private-payment/mpc-prover/financial/export_registered_program.py',
        'edc99f410e61aa1d1e391e71ad27c11e7a0d01b0b82dfc19fd76c72bcfb04979', 0o400),
    'exporter/SOURCE.json': (
        '.local/private-batch-trace-preparation-20261028-01/SOURCE.json',
        '943c1c82e9990b5b9207714c1867a78a75381e8a891fc0a83c7c2c7b502292df', 0o400),
    'exporter/export_financial_trace': (
        '.local/private-batch-relation-target/release/examples/export_financial_trace',
        '7e90412697bd71b2e0e85c7a40d3c95933ab838809bf47b13013ef7d46ad9247', 0o500),
    'native/ADMISSION.json': (
        '.local/private-batch-public-native-final-parameters-01/ADMISSION.json',
        '1275ac003c6160cfced795518eb43ea9591af8ed6ec704ee9f86f1c85ba877cc', 0o400),
    'native/PARAMETERS.json': (
        '.local/private-batch-public-native-final-parameters-01/PARAMETERS.json',
        '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751', 0o400),
    'native/IMMUTABLE-TAIL.bin': (
        '.local/private-batch-public-native-final-parameters-01/IMMUTABLE-TAIL.bin',
        '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d', 0o400),
    'native/native-codec': (
        '.local/private-batch-public-native-final-parameters-01/public/native-codec',
        'cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7', 0o500),
    'contract/registered_roster_transport.hpp': (
        'poc/local-private-payment/mpc-prover/financial/registered_roster_transport.hpp',
        '9b3fbfdcebf93542baf9f07fb8ce4bc6c0710f6dee694222135c350e11710f12', 0o400),
    'contract/registered_trial03_candidate.hpp': (
        'poc/local-private-payment/mpc-prover/financial/registered_trial03_candidate.hpp',
        'a73466dcfd6916d8c8880bcb9b18afd0b0c20b67dadd7cd4e3bc9b26468a2a09', 0o400),
    'driver/REGISTERED-ACTUAL-HEAD-SELECTION.json': (
        'poc/local-private-payment/mpc-prover/financial/REGISTERED-ACTUAL-HEAD-SELECTION.json',
        '2e69ae9a9951072312b9414483e368c784d0e99614973039e1de09234b0da977', 0o400),
}


def need(condition, category):
    if not condition:
        raise ValueError('registered-selection-candidate-' + category)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def encoded(value):
    return canonical(value) + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def word(value):
    need(type(value) is str and HEX32.fullmatch(value), 'canonical-hex32')
    return value


def metadata_signature(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
            value.st_nlink, value.st_uid, value.st_mtime_ns,
            value.st_ctime_ns)


def stable_read(path, expected, *, immutable=False, mode=None):
    path = Path(path)
    need(path.is_absolute() and path == Path(os.path.normpath(path)),
         'absolute-normal-path')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and not path.is_symlink(),
         'regular-nonsymlink-input')
    if immutable:
        need(before.st_uid == os.getuid() and before.st_nlink == 1 and
             stat.S_IMODE(before.st_mode) == mode and
             not (before.st_mode & 0o222), 'immutable-single-link-input')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = os.fstat(descriptor)
        need((before.st_dev, before.st_ino, before.st_size,
              before.st_mtime_ns, before.st_ctime_ns) ==
             (opened.st_dev, opened.st_ino, opened.st_size,
              opened.st_mtime_ns, opened.st_ctime_ns), 'input-open-race')
        raw = b''
        while len(raw) < opened.st_size:
            block = os.read(descriptor, opened.st_size - len(raw))
            need(block, 'input-short-read')
            raw += block
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    named_after = path.lstat()
    for name in ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_nlink',
                 'st_uid', 'st_mtime_ns', 'st_ctime_ns'):
        need(getattr(opened, name) == getattr(after, name) ==
             getattr(named_after, name), 'input-changed-during-read')
    need(sha(raw) == expected, 'input-hash')
    return raw


def write_new(path, raw, mode):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def publish_new(source, target):
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, 'renameat2', None)
    need(renameat2 is not None, 'renameat2-required')
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(AT_FDCWD, os.fsencode(source), AT_FDCWD,
                       os.fsencode(target), RENAME_NOREPLACE)
    if result:
        error = ctypes.get_errno()
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            raise ValueError('registered-selection-candidate-existing-target')
        raise OSError(error, os.strerror(error), str(target))


def _selected_verifier_bytes():
    path = Path(__file__).resolve()
    first = path.read_bytes()
    return stable_read(path, sha(first))


def _python_stdlib_archive():
    import zipfile
    root = Path('/usr/lib/python3.14')
    omitted = {
        '__pycache__', 'test', 'tests', 'idlelib', 'tkinter', 'turtledemo',
        'config-3.14-x86_64-linux-gnu', 'ensurepip',
    }
    selected = [
        path for path in root.rglob('*.py')
        if not any(part in omitted for part in path.relative_to(root).parts)
        and path.resolve().is_relative_to(root.resolve())
    ]
    source = {}
    source_raw = {}
    for path in sorted(selected):
        relative = path.relative_to(root).as_posix()
        selected_path = path.resolve()
        need(selected_path.is_relative_to(root.resolve()),
             'python-stdlib-symlink-target')
        first = selected_path.read_bytes()
        raw = stable_read(selected_path, sha(first))
        info = selected_path.stat()
        need(info.st_uid == 0 and not (info.st_mode & 0o022),
             'selected-python-stdlib-source')
        source[relative] = sha(raw)
        source_raw[relative] = raw
    need(len(source) == PYTHON_STDLIB_SOURCE_COUNT and
         sha(canonical(source)) == PYTHON_STDLIB_SOURCE_CLOSURE_SHA256,
         'python-stdlib-source-closure')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for relative, raw in source_raw.items():
            entry = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100400 << 16
            entry.create_system = 3
            archive.writestr(entry, raw, compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    raw = output.getvalue()
    need(len(raw) == PYTHON_STDLIB_ARCHIVE_BYTES and
         sha(raw) == PYTHON_STDLIB_ARCHIVE_SHA256,
         'python-stdlib-archive')
    return raw


def _runtime_expected_records(verifier_raw):
    records = [
        {'path': 'runtime/verifier/registered_selection_candidate.py',
         'sha256': sha(verifier_raw), 'mode': oct(0o400),
         'bytes': len(verifier_raw)},
        {'path': 'runtime/bin/python3.14', 'sha256': PYTHON_SHA256,
         'mode': oct(0o500), 'bytes': 7477160},
        {'path': 'runtime/bin/bwrap', 'sha256': BWRAP_SHA256,
         'mode': oct(0o500), 'bytes': 80424},
        {'path': 'runtime/bin/openssl', 'sha256': OPENSSL_SHA256,
         'mode': oct(0o500), 'bytes': 1132128},
        {'path': 'runtime/loader',
         'sha256': RUNTIME_OBJECTS['ld-linux-x86-64.so.2'][1],
         'mode': oct(0o500),
         'bytes': RUNTIME_OBJECTS['ld-linux-x86-64.so.2'][2]},
        {'path': 'runtime/python/lib/python314.zip',
         'sha256': PYTHON_STDLIB_ARCHIVE_SHA256,
         'mode': oct(0o400), 'bytes': PYTHON_STDLIB_ARCHIVE_BYTES},
    ]
    for name, (_, expected, size) in sorted(RUNTIME_OBJECTS.items()):
        records.append({
            'path': 'runtime/lib/' + name, 'sha256': expected,
            'mode': oct(0o400), 'bytes': size,
        })
    for name, (expected, size) in sorted(PYTHON_DYNLOAD.items()):
        records.append({
            'path': 'runtime/python/lib/python3.14/lib-dynload/' + name,
            'sha256': expected, 'mode': oct(0o400), 'bytes': size,
        })
    return sorted(records, key=lambda record: record['path'])


def _materialize_runtime(stage):
    verifier_raw = _selected_verifier_bytes()
    records = _runtime_expected_records(verifier_raw)
    sources = {
        'runtime/verifier/registered_selection_candidate.py':
            (None, verifier_raw),
        'runtime/bin/python3.14': ('/usr/bin/python3.14', None),
        'runtime/bin/bwrap': ('/usr/bin/bwrap', None),
        'runtime/bin/openssl': ('/usr/bin/openssl', None),
        'runtime/loader': (RUNTIME_OBJECTS['ld-linux-x86-64.so.2'][0], None),
        'runtime/python/lib/python314.zip': (None, _python_stdlib_archive()),
    }
    for name, (source, _, _) in RUNTIME_OBJECTS.items():
        sources['runtime/lib/' + name] = (source, None)
    dynload = Path('/usr/lib/python3.14/lib-dynload')
    for name in PYTHON_DYNLOAD:
        sources['runtime/python/lib/python3.14/lib-dynload/' + name] = (
            str(dynload / name), None)
    by_path = {record['path']: record for record in records}
    need(set(sources) == set(by_path), 'exact-runtime-materialization-map')
    for target, (source, supplied) in sorted(sources.items()):
        record = by_path[target]
        raw = supplied
        if raw is None:
            raw = stable_read(Path(source), record['sha256'])
        need(sha(raw) == record['sha256'] and
             len(raw) == record['bytes'], 'runtime-materialization-pin')
        write_new(stage / target, raw, int(record['mode'], 8))
    return records


def _runtime_records(root, verifier_expected=None):
    verifier_path = Path(root) / \
        'runtime/verifier/registered_selection_candidate.py'
    if verifier_expected is None:
        verifier_raw = _selected_verifier_bytes()
    else:
        verifier_raw = stable_read(
            verifier_path, verifier_expected, immutable=True, mode=0o400)
    records = _runtime_expected_records(verifier_raw)
    for record in records:
        stable_read(Path(root) / record['path'], record['sha256'],
                    immutable=True, mode=int(record['mode'], 8))
    return records


@contextmanager
def _mirrored_trial_state():
    """Yield a writable mirror because EpochJournal opens READY files O_RDWR.

    The namespace never receives a writable mount of the authoritative trial.
    We verify that every source object is byte/metadata stable before and after
    the selected verifier runs.
    """
    with tempfile.TemporaryDirectory(prefix='kpb-trial-state-mirror-') as name:
        mirror = Path(name) / 'trial'
        (mirror / 'state').mkdir(parents=True, mode=0o700)
        mirror.chmod(0o700)
        (mirror / 'state').chmod(0o700)
        signatures = {}
        hashes = {}
        for party in range(3):
            source_base = TRIAL_ROOT / 'state' / f'party-{party}'
            target_base = mirror / 'state' / f'party-{party}'
            for suffix in ('', 'journal', 'anchor'):
                source = source_base / suffix if suffix else source_base
                target = target_base / suffix if suffix else target_base
                info = source.lstat()
                need(source.is_dir() and not source.is_symlink() and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     'trial-mirror-source-directory')
                target.mkdir(mode=0o700)
                signatures[str(source)] = metadata_signature(info)
            for relative in ('journal/journal.bin', 'anchor/latest.bin'):
                source = source_base / relative
                info = source.lstat()
                need(stat.S_ISREG(info.st_mode) and not source.is_symlink() and
                     info.st_uid == os.getuid() and info.st_nlink == 1 and
                     stat.S_IMODE(info.st_mode) == 0o600,
                     'trial-mirror-source-file')
                first = source.read_bytes()
                expected = sha(first)
                raw = stable_read(source, expected)
                write_new(mirror / 'state' / f'party-{party}' / relative,
                          raw, 0o600)
                signatures[str(source)] = metadata_signature(info)
                hashes[str(source)] = expected
        yield mirror
        for selected, signature in signatures.items():
            path = Path(selected)
            need(metadata_signature(path.lstat()) == signature,
                 'trial-state-changed-during-mirror-use')
            if selected in hashes:
                need(sha(path.read_bytes()) == hashes[selected],
                     'trial-state-bytes-changed-during-mirror-use')


def _external_control_pin(path, snapshot_root, expected_sha256):
    path = Path(path).absolute()
    snapshot_root = Path(snapshot_root).absolute()
    need(not path.is_relative_to(snapshot_root),
         'external-control-pin-inside-snapshot')
    for current in [path, *path.parents]:
        need(not current.is_symlink(), 'external-control-pin-symlink-parent')
        if current == current.root:
            break
    word(expected_sha256)
    raw = stable_read(
        path, expected_sha256, immutable=True, mode=0o400)
    value = json.loads(raw)
    need(raw == encoded(value) and set(value) == {
        'schema', 'status', 'configuration_candidate_sha256',
        'selected_verifier_sha256', 'selected_runtime_closure_sha256',
        'registered_driver_configured', 'launch_authorized',
    } and
         value['schema'] ==
            'kpb-registered-isolation-control-pin/v1' and
         value['status'] == 'CONTROL_ONLY_UNCONFIGURED' and
         value['registered_driver_configured'] is False and
         value['launch_authorized'] is False,
         'external-control-pin-record')
    for name in ('configuration_candidate_sha256',
                 'selected_verifier_sha256',
                 'selected_runtime_closure_sha256'):
        word(value[name])
    return value, raw, metadata_signature(path.lstat())


def _sealed_memfd(name, raw):
    descriptor = os.memfd_create(
        name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            need(written > 0, 'sealed-memfd-write')
            offset += written
        seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                 fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, seals)
        need(fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) == seals,
             'sealed-memfd-seals')
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _capsule_target(logical):
    if logical == 'runtime/verifier/registered_selection_candidate.py':
        return Path('/sealed/verifier.py')
    if logical == 'runtime/loader':
        return Path('/sealed/loader')
    if logical.startswith('runtime/lib/'):
        return Path('/sealed/lib') / Path(logical).name
    if logical == 'runtime/bin/python3.14':
        return Path('/sealed/bin/python3.14')
    if logical == 'runtime/bin/openssl':
        return Path('/sealed/bin/openssl')
    if logical.startswith('runtime/python/'):
        return Path('/sealed') / logical.removeprefix('runtime/')
    return None


@contextmanager
def _sealed_execution_capsule(root, authority, capability_raw):
    root = Path(root).absolute()
    verifier_path = root / \
        'runtime/verifier/registered_selection_candidate.py'
    verifier_raw = stable_read(
        verifier_path, authority['selected_verifier_sha256'],
        immutable=True, mode=0o400)
    mounts = []
    descriptors = []
    identities = []

    def add(path, expected, mode, destination):
        raw = stable_read(path, expected, immutable=True, mode=mode)
        signature = metadata_signature(Path(path).lstat())
        descriptor = _sealed_memfd(Path(destination).name, raw)
        descriptors.append(descriptor)
        mounts.append((descriptor, str(destination), mode))
        identities.append((Path(path), expected, mode, signature))

    try:
        for record in _runtime_expected_records(verifier_raw):
            destination = _capsule_target(record['path'])
            if destination is None:
                need(record['path'] == 'runtime/bin/bwrap',
                     'sealed-runtime-file-map')
                continue
            add(root / record['path'], record['sha256'],
                int(record['mode'], 8), destination)
        for logical, expected in (
                ('trial/registered-trial-init', INITIALIZER_SHA256),
                ('qualifier/mpc-registered-financial-gate',
                 QUALIFIER_BINARY_SHA256),
                ('qualifier/authority-mpc-registered-financial-gate',
                 QUALIFIER_BINARY_SHA256),
                ('qualifier/base/mpc-registered-financial-gate',
                 BASE_QUALIFIER_BINARY_SHA256)):
            add(root / logical, expected, 0o500, SEALED_TOOLS[logical])
        capability = _sealed_memfd('authority-capability', capability_raw)
        descriptors.append(capability)
        mounts.append((capability, '/sealed/capability.json', 0o400))
        yield {
            'mounts': mounts,
            'pass_fds': tuple(descriptors),
            'identities': identities,
            'verifier_raw': verifier_raw,
        }
    finally:
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_post_execution_identities(identities):
    for path, expected, mode, signature in identities:
        stable_read(path, expected, immutable=True, mode=mode)
        need(metadata_signature(path.lstat()) == signature,
             'post-execution-identity-changed')


@contextmanager
def _host_isolation_probes():
    with tempfile.TemporaryDirectory(prefix='kpb-host-isolation-') as name:
        root = Path(name)
        sentinel = root / 'private-sentinel'
        write_new(sentinel, b'not-private-input-control\n', 0o600)
        socket_path = root / 'host.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(socket_path))
            server.listen(1)
            yield sentinel, socket_path
        finally:
            server.close()


def _loader_command(root, executable, arguments=(), *, list_only=False,
                    runtime_root=None):
    root = Path(root).absolute()
    runtime = (root / 'runtime' if runtime_root is None else
               Path(runtime_root))
    command = [
        str(runtime / 'loader'), '--inhibit-cache', '--inhibit-rpath', '',
        '--library-path', str(runtime / 'lib'),
    ]
    if list_only:
        command.append('--list')
    command.extend([str(executable), *map(str, arguments)])
    return command


def _resolved_runtime_objects(root, executable, *, runtime_root=None):
    runtime = ((Path(root).absolute() / 'runtime').resolve()
               if runtime_root is None else Path(runtime_root))
    result = subprocess.run(
        _loader_command(root, executable, list_only=True,
                        runtime_root=runtime),
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True, env={})
    need(result.returncode == 0 and result.stderr == b'',
         'runtime-object-resolution')
    objects = {}
    for raw_line in result.stdout.decode('utf-8', 'strict').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('linux-vdso.so.1'):
            continue
        if '=>' in line:
            name, selected = line.split('=>', 1)
            name = name.strip()
            selected = selected.strip().split()[0]
        elif line.startswith('/'):
            selected = line.split()[0]
            name = Path(selected).name
        else:
            need(False, 'runtime-object-resolution-line')
        path = Path(selected)
        need(path.is_absolute() and path.is_relative_to(runtime) and
             (path.parent == runtime / 'lib' or path == runtime / 'loader'),
             'snapshot-only-runtime-object')
        expected = (RUNTIME_OBJECTS['ld-linux-x86-64.so.2'][1]
                    if path == runtime / 'loader' else
                    RUNTIME_OBJECTS.get(path.name, (None, None, None))[1])
        need(expected is not None and sha(path.read_bytes()) == expected,
             'resolved-runtime-object-pin')
        objects[name] = str(path)
    need(objects, 'nonempty-runtime-object-resolution')
    return objects


def _directory_options(path):
    selected = []
    current = Path('/')
    for part in Path(path).parts[1:]:
        current /= part
        selected.extend(['--dir', str(current)])
    return selected


def _bwrap_command(root, inner_command, *, trial_mirror=None,
                   file_mounts=(), environment=None):
    root = Path(root).absolute()
    # This host permits unprivileged namespaces only for the administrator-
    # installed /usr/bin/bwrap path.  Pin that root-owned launcher byte-for-
    # byte to the snapshot copy; all code executed *inside* the namespace uses
    # the selected loader and runtime below.
    launcher = Path('/usr/bin/bwrap')
    raw = stable_read(launcher, BWRAP_SHA256)
    info = launcher.stat()
    need(info.st_uid == 0 and info.st_nlink == 1 and
         not (info.st_mode & 0o022) and
         raw == (root / 'runtime/bin/bwrap').read_bytes(),
         'pinned-network-namespace-launcher')
    command = [
        str(launcher), '--unshare-net', '--unshare-pid', '--unshare-ipc',
        '--unshare-uts', '--die-with-parent', '--new-session', '--clearenv',
        '--hostname', 'kpb-selected', '--tmpfs', '/',
        '--dir', str(SANDBOX_SNAPSHOT_ROOT), '--ro-bind', str(root),
        str(SANDBOX_SNAPSHOT_ROOT), '--dir', '/proc', '--proc', '/proc',
        '--dev', '/dev', '--dir', '/tmp', '--tmpfs', '/tmp',
    ]
    if trial_mirror is not None:
        command += _directory_options(TRIAL_ROOT)
        command += ['--bind', str(trial_mirror), str(TRIAL_ROOT)]
    destinations = set()
    for descriptor, destination, mode in file_mounts:
        destination = Path(destination)
        need(destination.is_absolute() and destination not in destinations,
             'sealed-mount-destination')
        destinations.add(destination)
        command += _directory_options(destination.parent)
        command += ['--perms', oct(mode)[2:], '--file', str(descriptor),
                    str(destination)]
    for name, value in sorted((environment or {}).items()):
        command += ['--setenv', name, value]
    command += ['--chdir', str(SANDBOX_SNAPSHOT_ROOT), *inner_command]
    return command


def _inside_snapshot_path(root, value):
    path = Path(value)
    if not path.is_absolute():
        return str(value)
    try:
        relative = path.relative_to(Path(root).absolute())
    except ValueError:
        return str(value)
    return str(SANDBOX_SNAPSHOT_ROOT / relative)


def _sealed_tool_path(root, executable):
    relative = str(Path(executable).relative_to(Path(root)))
    need(relative in SEALED_TOOLS, 'selected-sealed-tool')
    return Path(SEALED_TOOLS[relative])


def _run_hermetic(root, executable, arguments=(), *, trial_state=False):
    if SELECTED_RUNTIME_CHILD:
        selected = _sealed_tool_path(root, executable)
        _resolved_runtime_objects(
            root, selected, runtime_root=SEALED_RUNTIME_ROOT)
        command = _loader_command(
            root, selected, arguments, runtime_root=SEALED_RUNTIME_ROOT)
        return subprocess.run(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, cwd=root, env={})
    _resolved_runtime_objects(root, executable)
    selected = Path(_inside_snapshot_path(root, executable))
    selected_arguments = [_inside_snapshot_path(root, value)
                          for value in arguments]
    inner = _loader_command(
        SANDBOX_SNAPSHOT_ROOT, selected, selected_arguments)
    if trial_state:
        with _mirrored_trial_state() as mirror:
            command = _bwrap_command(root, inner, trial_mirror=mirror)
            return subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd=root, env={})
    command = _bwrap_command(root, inner)
    return subprocess.run(
        command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, close_fds=True, cwd=root, env={})


def static_file_records(root):
    root = Path(root)
    return [
        {'path': target, 'sha256': selected[1], 'mode': oct(selected[2]),
         'bytes': (root / target).stat().st_size}
        for target, selected in sorted(EXPECTED_FILES.items())
    ]


def qualifier_source_records(root, build, *, repository_source=False):
    source_map = build['source_sha256']
    need(type(source_map) is dict and len(source_map) == 268 and
         sha(canonical(source_map)) == QUALIFIER_SOURCE_CLOSURE_SHA256,
         'exact-qualifier-source-map')
    records = []
    for logical, expected in sorted(source_map.items()):
        relative = Path(logical)
        need(not relative.is_absolute() and '..' not in relative.parts and
             type(expected) is str and HEX32.fullmatch(expected) and
             'run_financial.py' not in logical,
             'safe-qualifier-source-path')
        if repository_source:
            selected = REPOSITORY_ROOT / \
                'poc/local-private-payment/mpc-prover' / relative
        else:
            selected = Path(root) / 'qualifier/source' / relative
        raw = stable_read(selected.absolute(), expected,
                          immutable=not repository_source,
                          mode=0o400 if not repository_source else None)
        records.append({
            'path': str(Path('qualifier/source') / relative),
            'sha256': expected, 'mode': oct(0o400), 'bytes': len(raw),
        })
    return records


def qualifier_dependency_records(root, build, *, repository_source=False):
    compile_dependencies = build['compile_dependencies']
    link_dependencies = build['link_dependencies']
    need(type(compile_dependencies) is dict and
         len(compile_dependencies) == 2859 and
         sha(canonical(compile_dependencies)) ==
            COMPILE_DEPENDENCY_CLOSURE_SHA256 and
         type(link_dependencies) is dict and
         len(link_dependencies) == 76 and
         sha(canonical(link_dependencies)) ==
            LINK_DEPENDENCY_CLOSURE_SHA256,
         'exact-build-dependency-maps')
    dependencies = {}
    for selected in (compile_dependencies, link_dependencies):
        for logical, expected in selected.items():
            need(type(logical) is str and type(expected) is str and
                 HEX32.fullmatch(expected) and
                 dependencies.get(logical, expected) == expected,
                 'consistent-build-dependency')
            dependencies[logical] = expected
    toolchain = build['toolchain']
    tool_files = [toolchain['compiler'], toolchain['build_interpreter'],
                  toolchain['runtime_inspector'],
                  *toolchain['subtools'].values()]
    for record in tool_files:
        need(set(record) == {'path', 'sha256', 'bytes'},
             'toolchain-file-record')
        dependencies.setdefault(record['path'], record['sha256'])
        need(dependencies[record['path']] == record['sha256'],
             'toolchain-dependency-agreement')
    records = {}
    for logical, expected in sorted(dependencies.items()):
        if logical.startswith('${SOURCE}/'):
            source_name = logical.removeprefix('${SOURCE}/')
            need(build['source_sha256'].get(source_name) == expected,
                 'dependency-selected-source-agreement')
            continue
        if logical.startswith('${VENDOR}/'):
            relative = Path(logical.removeprefix('${VENDOR}/'))
            need('..' not in relative.parts, 'safe-vendor-dependency-path')
            target = Path('qualifier/dependencies/vendor') / relative
            selected = REPOSITORY_ROOT / '.local/mpc-prover-softspoken-vendor' / relative
        elif logical.startswith('${OUTPUT}/'):
            relative = Path(logical.removeprefix('${OUTPUT}/'))
            need('..' not in relative.parts, 'safe-output-dependency-path')
            target = Path('qualifier/dependencies/output') / relative
            selected = REPOSITORY_ROOT / \
                '.local/registered-financial-gate-build-12' / relative
        else:
            absolute = Path(logical)
            need(absolute.is_absolute() and '..' not in absolute.parts,
                 'safe-system-dependency-path')
            target = Path('qualifier/dependencies/rootfs').joinpath(
                *absolute.parts[1:])
            selected = absolute
        if not repository_source:
            selected = Path(root) / target
        raw = stable_read(selected.absolute(), expected,
                          immutable=not repository_source,
                          mode=0o400 if not repository_source else None)
        target_name = str(target)
        need(target_name not in records or
             records[target_name]['sha256'] == expected,
             'dependency-target-collision')
        records[target_name] = {
            'path': target_name, 'sha256': expected,
            'mode': oct(0o400), 'bytes': len(raw),
        }
    return [records[name] for name in sorted(records)]


def trial_authority_record():
    return {
        'schema': 'kpb-registered-trial03-authority/v1',
        'trial_root': str(TRIAL_ROOT),
        'trial_id': TRIAL_ID,
        'selection_sha256': TRIAL_SELECTION_SHA256,
        'registration_sha256': REGISTRATION_SHA256,
        'registration_file_sha256': REGISTRATION_FILE_SHA256,
        'source_selection_sha256': SOURCE_SELECTION_SHA256,
        'initializer_sha256': INITIALIZER_SHA256,
        'state_initialization_sha256': STATE_INITIALIZATION_SHA256,
        'ready_checkpoint_sha256': READY_CHECKPOINT_SHA256,
        'certificate_authority_der_sha256': CA_DER_SHA256,
        'server_certificate_der_sha256': list(CERTIFICATE_DER_SHA256),
        'journal_anchor_reopened_by_selected_initializer': True,
        'self_authored_trial_envelope_is_authority': False,
    }


def build_authority_record():
    return {
        'schema': 'kpi-registered-unconfigured-build-authority/v1',
        'build_receipt_sha256': QUALIFIER_BUILD_SHA256,
        'authority_build_receipt_sha256':
            QUALIFIER_AUTHORITY_BUILD_SHA256,
        'binary_sha256': QUALIFIER_BINARY_SHA256,
        'source_closure_sha256': QUALIFIER_SOURCE_CLOSURE_SHA256,
        'build_contract_sha256': BUILD_CONTRACT_SHA256,
        'vendor_closure_sha256': VENDOR_CLOSURE_SHA256,
        'toolchain_sha256': TOOLCHAIN_SHA256,
        'compile_dependency_closure_sha256':
            COMPILE_DEPENDENCY_CLOSURE_SHA256,
        'object_closure_sha256': OBJECT_CLOSURE_SHA256,
        'link_dependency_closure_sha256':
            LINK_DEPENDENCY_CLOSURE_SHA256,
        'compiler_sha256': COMPILER_SHA256,
        'configuration_selection_sha256':
            CONFIGURATION_SELECTION_SHA256,
        'configured': False,
        'independent_reproduction_passed': True,
        'default_refusal_reexecuted': True,
        'self_authored_build_envelope_is_authority': False,
    }


def authority_sha256(value):
    return sha(canonical(value))


def runtime_authority(file_records):
    selected = {
        row['path']: row['sha256'] for row in file_records
        if row['path'].startswith('runtime/')
    }
    need(selected and
         'runtime/verifier/registered_selection_candidate.py' in selected and
         'runtime/bin/python3.14' in selected and
         'runtime/bin/bwrap' in selected and
         'runtime/loader' in selected and
         'runtime/lib/libSPDZ.so' in selected,
         'complete-hermetic-runtime-records')
    return {
        'schema': 'kpb-registered-selected-runtime/v1',
        'closure_sha256': sha(canonical(selected)),
        'files': len(selected),
        'verifier_sha256':
            selected['runtime/verifier/registered_selection_candidate.py'],
        'interpreter_sha256': selected['runtime/bin/python3.14'],
        'loader_sha256': selected['runtime/loader'],
        'network_namespace_required': True,
        'environment_cleared': True,
        'host_cache_and_runpath_disabled': True,
        'resolved_objects_must_be_snapshot_files': True,
        'live_vendor_path_masked': True,
    }


def manifest(file_records):
    return {
        'schema': 'kpb-registered-trial03-configuration-candidate/v1',
        'status': 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED',
        'scope': 'PUBLIC_SOURCE_ONLY_NO_NETWORK_OWNER_MPC_PROOF_OR_BROADCAST',
        'authority': {
            'trial_id': TRIAL_ID,
            'selection_sha256': TRIAL_SELECTION_SHA256,
            'registration_sha256': REGISTRATION_SHA256,
            'registration_file_sha256': REGISTRATION_FILE_SHA256,
            'certificate_authority_der_sha256': CA_DER_SHA256,
            'server_certificate_der_sha256': list(CERTIFICATE_DER_SHA256),
            'self_authorizing_manifest': False,
            'trial_authority_sha256':
                authority_sha256(trial_authority_record()),
        },
        'transport_contract': {
            'requires_concrete_roster_pinned_player': True,
            'requires_mutual_TLS_chain_to_selected_CA': True,
            'runtime_roster_or_authority_override': False,
        },
        'accepted_head': {
            'source_closure_sha256': ACQUISITION_SOURCE_CLOSURE_SHA256,
            'unconfigured_full_closure_binary_sha256':
                QUALIFIER_BINARY_SHA256,
            'imported_report_authority': False,
        },
        'qualifier': {
            'source_closure_sha256': QUALIFIER_SOURCE_CLOSURE_SHA256,
            'build_receipt_sha256': QUALIFIER_BUILD_SHA256,
            'authority_build_receipt_sha256':
                QUALIFIER_AUTHORITY_BUILD_SHA256,
            'binary_sha256': QUALIFIER_BINARY_SHA256,
            'build_contract_sha256': BUILD_CONTRACT_SHA256,
            'build_authority_sha256':
                authority_sha256(build_authority_record()),
            'configured': False,
            'independently_reproduced': True,
            'default_refusal_directly_reexecuted': True,
            'source05_is_registered_authority': False,
        },
        'roster_base_qualifier': {
            'source_closure_sha256':
                BASE_QUALIFIER_SOURCE_CLOSURE_SHA256,
            'build_receipt_sha256': BASE_QUALIFIER_BUILD_SHA256,
            'authority_build_receipt_sha256':
                BASE_QUALIFIER_AUTHORITY_BUILD_SHA256,
            'binary_sha256': BASE_QUALIFIER_BINARY_SHA256,
            'bound_by_registered_trial03_candidate_header': True,
        },
        'exporter': {
            'adapter_sha256':
                'edc99f410e61aa1d1e391e71ad27c11e7a0d01b0b82dfc19fd76c72bcfb04979',
            'native_exporter_sha256':
                '7e90412697bd71b2e0e85c7a40d3c95933ab838809bf47b13013ef7d46ad9247',
            'specification_still_required': True,
        },
        'native': {
            'parameters_sha256':
                '3f9f2f294c8203c8fc99ba66e1a78e769a1eecc4ecc5cf8f8b631eea28138751',
            'immutable_tail_sha256':
                '4081fc4efb08131bba7b64c38cfe002a3456c8a8a93394622ee9085e3706435d',
            'component_profile_sha256':
                '2598cd4baa438e6fb5c95bc4d1f6b8f1f7db607879f428c43f82a5247aca7f36',
            'outer_image_hex32':
                'd62eaf8b01ed970048bd8f2565e55ae9f2af3dcad8b7f12d94a40819805dd119',
            'program_sha256':
                'af7064025876e1045a88f42119ef95a79b1a6a44334a43fcad0d2528d840450c',
            'codec_sha256':
                'cc498d61898d15e077f483f8786d2b5993e0bd2a89e30a01d8489e03a31103c7',
            'outer_selection_qualified': False,
        },
        'head_policy': {
            'selection': 'FRESH_REGISTERED_ACCEPTED_HEAD_PER_ROUND',
            'rounds': ['ROUND1', 'ROUND2'],
            'same_head_replay_allowed': False,
            'source05_retag_allowed': False,
            'attempt_binding': 'DYNAMIC_FROM_REGISTERED_SELECTION',
        },
        'freshness_authority': {
            'durable_registered_journal_anchor_registry_admitted': False,
            'caller_prior_identities_are_authority': False,
            'caller_completion_json_is_authority': False,
            'completion_requires_direct_cpp_accepted_head_and_financial_R0_receipts':
                True,
            'launch_authorized': False,
        },
        'hermetic_runtime': runtime_authority(file_records),
        'configuration_complete': False,
        'registered_driver_configured': False,
        'files': file_records,
        'remaining_blockers': [
            'fresh complete acquisition SPEC and selected node SDK closure',
            'fresh complete exporter SPEC and immutable signature matrix',
            'concrete roster-pinned Player source and build',
            'root-owned immutable model PK VK verifier and work roots',
            'selected outer image remains unqualified',
            'separately reviewed KPI_REGISTERED_FINANCIAL_CONFIGURED=1 selection',
            'Round1 and Round2 actual accepted-head selection controls',
            'durable journal-owned attempt/head identity replay registry',
            'direct completion join to C++ AcceptedFinancialHead and financial/R0 receipts',
            'registered proof EGRESS FINAL settlement and privacy qualification',
        ],
    }


def prepare_snapshot(output):
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink(), 'fresh-output')
    parent = output.parent
    need(parent.is_dir() and not parent.is_symlink() and
         not (parent.stat().st_mode & stat.S_IWOTH), 'safe-output-parent')
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '.staging-',
                                 dir=parent))
    stage.chmod(0o700)
    records = []
    for target, (source, expected, mode) in sorted(EXPECTED_FILES.items()):
        source_path = (REPOSITORY_ROOT / source).absolute()
        raw = stable_read(source_path, expected)
        write_new(stage / target, raw, mode)
        records.append({'path': target, 'sha256': expected,
                        'mode': oct(mode), 'bytes': len(raw)})
    build = json.loads((stage / 'qualifier/BUILD-RESULT.json').read_bytes())
    source_records = qualifier_source_records(
        REPOSITORY_ROOT, build, repository_source=True)
    for record in source_records:
        logical = Path(record['path']).relative_to('qualifier/source')
        source_path = REPOSITORY_ROOT / \
            'poc/local-private-payment/mpc-prover' / logical
        raw = stable_read(source_path.absolute(), record['sha256'])
        write_new(stage / record['path'], raw, 0o400)
        records.append(record)
    dependency_records = qualifier_dependency_records(
        REPOSITORY_ROOT, build, repository_source=True)
    for record in dependency_records:
        relative = Path(record['path'])
        if relative.is_relative_to('qualifier/dependencies/vendor'):
            selected = REPOSITORY_ROOT / '.local/mpc-prover-softspoken-vendor' / \
                relative.relative_to('qualifier/dependencies/vendor')
        elif relative.is_relative_to('qualifier/dependencies/output'):
            selected = REPOSITORY_ROOT / \
                '.local/registered-financial-gate-build-12' / \
                relative.relative_to('qualifier/dependencies/output')
        else:
            need(relative.is_relative_to('qualifier/dependencies/rootfs'),
                 'selected-dependency-target')
            selected = Path('/').joinpath(
                *relative.relative_to('qualifier/dependencies/rootfs').parts)
        raw = stable_read(selected.absolute(), record['sha256'])
        write_new(stage / record['path'], raw, 0o400)
        records.append(record)
    records.extend(_materialize_runtime(stage))
    records.sort(key=lambda record: record['path'])
    selected = manifest(records)
    selected_raw = encoded(selected)
    write_new(stage / 'CONFIGURATION-CANDIDATE.json', selected_raw, 0o400)
    receipt = {
        'schema': 'kpb-registered-trial03-source-snapshot/v1',
        'status': 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED',
        'trial_id': TRIAL_ID,
        'selection_sha256': TRIAL_SELECTION_SHA256,
        'registration_sha256': REGISTRATION_SHA256,
        'configuration_candidate_sha256': sha(selected_raw),
        'trial_authority_sha256':
            authority_sha256(trial_authority_record()),
        'unconfigured_build_authority_sha256':
            authority_sha256(build_authority_record()),
        'files': len(records),
        'selected_verifier_sha256':
            selected['hermetic_runtime']['verifier_sha256'],
        'selected_runtime_closure_sha256':
            selected['hermetic_runtime']['closure_sha256'],
        'selected_verifier_executed': False,
        'registered_driver_configured': False,
        'network_owner_mpc_proof_or_broadcast': False,
    }
    write_new(stage / 'SNAPSHOT.json', encoded(receipt), 0o400)
    for directory in sorted(
            (item for item in stage.rglob('*') if item.is_dir()),
            key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o500)
    stage.chmod(0o500)
    publish_new(stage, output)
    admitted = admit_snapshot(output)
    need(admitted.trial_id == TRIAL_ID, 'post-publication-source-admission')
    return receipt


def prepare_isolation_control_snapshot(base, output):
    """Refresh only the hermetic runtime over a pinned historical fixture.

    This exists so isolation controls remain deterministic while the real
    registry/supervisor/driver source closure is being rebuilt.  It ignores the
    old receipt, cannot mint authority, and must never be selected or launched.
    """
    base = Path(base).absolute()
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink(),
         'fresh-control-output')
    manifest_raw = stable_read(
        base / 'CONFIGURATION-CANDIDATE.json',
        HISTORICAL_CONTROL_BASE_CONFIG_SHA256,
        immutable=True, mode=0o400)
    prior = json.loads(manifest_raw)
    need(prior['status'] == 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED' and
         prior['configuration_complete'] is False and
         prior['registered_driver_configured'] is False and
         prior['freshness_authority']['launch_authorized'] is False,
         'retracted-control-base-boundary')
    stage = Path(tempfile.mkdtemp(
        prefix='.' + output.name + '.control-staging-', dir=output.parent))
    stage.chmod(0o700)
    records = []
    for record in prior['files']:
        if record['path'].startswith('runtime/'):
            continue
        raw = stable_read(
            base / record['path'], record['sha256'], immutable=True,
            mode=int(record['mode'], 8))
        write_new(stage / record['path'], raw, int(record['mode'], 8))
        records.append(record)
    records.extend(_materialize_runtime(stage))
    records.sort(key=lambda record: record['path'])
    selected = manifest(records)
    selected_raw = encoded(selected)
    write_new(stage / 'CONFIGURATION-CANDIDATE.json', selected_raw, 0o400)
    receipt = {
        'schema': 'kpb-registered-trial03-source-snapshot/v1',
        'status': 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED',
        'trial_id': TRIAL_ID,
        'selection_sha256': TRIAL_SELECTION_SHA256,
        'registration_sha256': REGISTRATION_SHA256,
        'configuration_candidate_sha256': sha(selected_raw),
        'trial_authority_sha256':
            authority_sha256(trial_authority_record()),
        'unconfigured_build_authority_sha256':
            authority_sha256(build_authority_record()),
        'files': len(records),
        'selected_verifier_sha256':
            selected['hermetic_runtime']['verifier_sha256'],
        'selected_runtime_closure_sha256':
            selected['hermetic_runtime']['closure_sha256'],
        'selected_verifier_executed': False,
        'registered_driver_configured': False,
        'network_owner_mpc_proof_or_broadcast': False,
    }
    write_new(stage / 'SNAPSHOT.json', encoded(receipt), 0o400)
    for directory in sorted(
            (item for item in stage.rglob('*') if item.is_dir()),
            key=lambda item: len(item.parts), reverse=True):
        directory.chmod(0o500)
    stage.chmod(0o500)
    publish_new(stage, output)
    admitted = admit_snapshot(output)
    need(admitted.trial_id == TRIAL_ID,
         'post-publication-control-admission')
    result = dict(receipt)
    result['control_only'] = True
    result['authority_admitted'] = False
    result['historical_base_receipt_reused'] = False
    return result


def _verify_chain(root):
    openssl = root / 'runtime/bin/openssl'
    ca = root / 'trial/certificates/ca.pem'
    try:
        ca_der = ssl.PEM_cert_to_DER_cert(ca.read_text('ascii'))
        if type(ca_der) is str:
            ca_der = ca_der.encode('latin1')
    except (ValueError, UnicodeError):
        raise ValueError(
            'registered-selection-candidate-certificate-authority-DER') from None
    need(sha(ca_der) == CA_DER_SHA256, 'certificate-authority-DER-pin')
    for party in range(3):
        leaf = root / f'trial/certificates/P{party}.pem'
        try:
            leaf_der = ssl.PEM_cert_to_DER_cert(leaf.read_text('ascii'))
            if type(leaf_der) is str:
                leaf_der = leaf_der.encode('latin1')
        except (ValueError, UnicodeError):
            raise ValueError(
                'registered-selection-candidate-certificate-DER') from None
        need(sha(leaf_der) == CERTIFICATE_DER_SHA256[party],
             'certificate-DER-pin')
        result = _run_hermetic(root, openssl, [
            'verify', '-no-CApath', '-no-CAfile', '-trusted', str(ca),
            '-verify_hostname', f'P{party}', str(leaf)])
        need(result.returncode == 0 and result.stderr == b'',
             'certificate-chain-and-role')


def _verify_ready_state(root, trial):
    need(trial['trial_root'] == str(TRIAL_ROOT), 'selected-trial-root')
    trial_info = TRIAL_ROOT.lstat()
    need(TRIAL_ROOT.is_dir() and not TRIAL_ROOT.is_symlink() and
         trial_info.st_uid == os.getuid() and
         not (trial_info.st_mode & 0o022), 'selected-trial-root-metadata')
    selected_state = trial['state']
    need(type(selected_state) is list and len(selected_state) == 3,
         'selected-three-state-records')
    for party, record in enumerate(selected_state):
        base = TRIAL_ROOT / 'state' / f'party-{party}'
        journal = base / 'journal'
        anchor = base / 'anchor'
        need(record['party'] == party and record['sequence'] == 0 and
             record['phase'] == 'READY' and
             record['checkpoint_hex32'] == READY_CHECKPOINT_SHA256 and
             record['journal_directory'] == str(journal) and
             record['anchor_directory'] == str(anchor),
             'selected-ready-state-record')
        for directory in (base, journal, anchor):
            info = directory.lstat()
            need(directory.is_dir() and not directory.is_symlink() and
                 info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o700,
                 'selected-state-directory-metadata')
        for leaf in (journal / 'journal.bin', anchor / 'latest.bin'):
            info = leaf.lstat()
            need(stat.S_ISREG(info.st_mode) and not leaf.is_symlink() and
                 info.st_uid == os.getuid() and info.st_nlink == 1 and
                 stat.S_IMODE(info.st_mode) == 0o600,
                 'selected-state-leaf-metadata')
    initializer = root / 'trial/registered-trial-init'
    result = _run_hermetic(root, initializer, [
        'verify', str(TRIAL_ROOT), REGISTRATION_SHA256,
        *CERTIFICATE_DER_SHA256], trial_state=True)
    expected = (root / 'trial/STATE-INITIALIZATION.txt').read_bytes()
    need(result.returncode == 0 and result.stderr == b'' and
         result.stdout == expected and sha(result.stdout) ==
            STATE_INITIALIZATION_SHA256 and
         result.stdout.count(
            (' ' + READY_CHECKPOINT_SHA256 + ' READY\n').encode()) == 3,
         'selected-initializer-reopened-ready-state')


def _verify_default_refusal(binary, root):
    result = _run_hermetic(root, binary)
    need(result.returncode == 78 and result.stdout == b'' and
         result.stderr ==
            b'KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n',
         'direct-default-refusal')


def _verify_build(root, selected):
    build_raw = (root / 'qualifier/BUILD-RESULT.json').read_bytes()
    authority_raw = (
        root / 'qualifier/AUTHORITY-BUILD-RESULT.json').read_bytes()
    build = json.loads(build_raw)
    authority = json.loads(authority_raw)
    exact_fields = {
        'schema', 'configured', 'compiler', 'toolchain',
        'configuration_selection', 'build_contract', 'source_sha256',
        'compile_dependencies', 'object_sha256', 'link_dependencies',
        'zlib_binary', 'zlib_headers_sha256', 'vendor_artifacts', 'compile',
        'link', 'controls', 'reproduction', 'success',
        'proof_or_private_input_executed'}
    need(set(build) == exact_fields and set(authority) == exact_fields and
         sha(build_raw) == QUALIFIER_BUILD_SHA256 and
         sha(authority_raw) == QUALIFIER_AUTHORITY_BUILD_SHA256,
         'exact-build-receipts')
    compiler = {
        'path': '/usr/bin/x86_64-linux-gnu-g++-15',
        'sha256': COMPILER_SHA256,
        'bytes': 1305304,
    }
    compiler_path = root / 'qualifier/dependencies/rootfs' / \
        compiler['path'].removeprefix('/')
    compiler_raw = stable_read(
        compiler_path, COMPILER_SHA256, immutable=True, mode=0o400)
    compiler_info = compiler_path.stat()
    need(len(compiler_raw) == compiler['bytes'] and
         compiler_info.st_uid == os.getuid() and compiler_info.st_nlink == 1,
         'selected-build-compiler')
    configuration = {
        'path': 'financial/registered_service_selection.hpp',
        'sha256': CONFIGURATION_SELECTION_SHA256,
        'configured': False,
        'driver_header': None,
        'default_action':
            'REFUSE_BEFORE_FILE_NETWORK_OWNER_OR_MPC_ACCESS',
    }
    for receipt in (authority, build):
        need(receipt['schema'] ==
                'kpi-registered-financial-gate-build/v3' and
             receipt['success'] is True and receipt['configured'] is False and
             receipt['proof_or_private_input_executed'] is False and
             receipt['compiler'] == compiler and
             receipt['configuration_selection'] == configuration and
             sha(canonical(receipt['toolchain'])) == TOOLCHAIN_SHA256 and
             sha(canonical(receipt['source_sha256'])) ==
                QUALIFIER_SOURCE_CLOSURE_SHA256 and
             len(receipt['source_sha256']) == 268 and
             sha(canonical(receipt['compile_dependencies'])) ==
                COMPILE_DEPENDENCY_CLOSURE_SHA256 and
             len(receipt['compile_dependencies']) == 2859 and
             sha(canonical(receipt['object_sha256'])) ==
                OBJECT_CLOSURE_SHA256 and
             len(receipt['object_sha256']) == 29 and
             sha(canonical(receipt['link_dependencies'])) ==
                LINK_DEPENDENCY_CLOSURE_SHA256 and
             len(receipt['link_dependencies']) == 76 and
             sha(canonical(receipt['build_contract'])) ==
                BUILD_CONTRACT_SHA256 and
             sha(canonical(receipt['vendor_artifacts'])) ==
                VENDOR_CLOSURE_SHA256,
             'source-owned-build-contract')
        contract = receipt['build_contract']
        need(contract['schema'] ==
                'kpi-registered-financial-build-contract/v2' and
             contract['compiler'] == compiler and
             contract['toolchain_sha256'] == TOOLCHAIN_SHA256 and
             contract['configuration_selection'] == configuration and
             contract['dependency_mode'] ==
                'GCC_MD_FULL_SYSTEM_HEADERS' and
             contract['source_closure_sha256'] ==
                QUALIFIER_SOURCE_CLOSURE_SHA256 and
             contract['compile_dependency_closure_sha256'] ==
                COMPILE_DEPENDENCY_CLOSURE_SHA256 and
             contract['object_closure_sha256'] ==
                OBJECT_CLOSURE_SHA256 and
             contract['link_dependency_closure_sha256'] ==
                LINK_DEPENDENCY_CLOSURE_SHA256 and
             contract['vendor_closure_sha256'] ==
                VENDOR_CLOSURE_SHA256 and
             contract['default_control'] == {
                'exit_code': 78,
                'stdout_sha256': sha(b''),
                'stderr_sha256': sha(
                    b'KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n'),
                'file_network_owner_or_mpc_input_supplied': False,
             }, 'build-contract-semantics')
        units = contract['compile_units']
        commands = receipt['compile']
        need(type(units) is list and len(units) == len(commands) == 29 and
             [row['source'] for row in commands] == units and
             len(set(units)) == 29 and
             'financial/registered_gate_main.cpp' in units and
             'financial/registered_service.cpp' in units and
             'financial/registered_selection.cpp' in units and
             'financial/registered_construction.cpp' in units and
             'financial/accepted_head.cpp' in units and
             'financial/fixed_public_run.cpp' in units and
             all('run_financial.py' not in unit for unit in units),
             'exact-compile-units')
        for row in commands:
            need(set(row) == {'source', 'argv', 'exit_code', 'object',
                              'object_sha256', 'dependency_file'} and
                 row['exit_code'] == 0 and type(row['argv']) is list and
                 row['argv'][0] == compiler['path'] and
                 row['argv'].count('-c') == row['argv'].count('-o') == 1 and
                 row['argv'].count('-MD') == row['argv'].count('-MF') == 1 and
                 row['argv'][-4] == '-c' and row['argv'][-2] == '-o' and
                 row['argv'][-3].endswith('/mpc-prover/' + row['source']) and
                 row['argv'][-1] == row['object'] and
                 row['object_sha256'] ==
                    receipt['object_sha256'][row['source']] and
                 row['argv'][row['argv'].index('-MF') + 1] ==
                    row['dependency_file'] and
                 '-Werror' in row['argv'] and '-march=native' in row['argv'],
                 'compile-command-contract')
        need(type(receipt['link']) is list and len(receipt['link']) == 1,
             'single-link')
        link = receipt['link'][0]
        need(link['binary'] == 'mpc-registered-financial-gate' and
             link['exit_code'] == 0 and
             link['sha256'] == QUALIFIER_BINARY_SHA256 and
             link['argv'][0] == compiler['path'] and
             link['map'].endswith('/mpc-registered-financial-gate.link.map') and
             ('-Wl,-Map,' + link['map']) in link['argv'] and
             link['argv'][-2:] == ['-z', 'noexecstack'] and
             all(row['object'] in link['argv'] for row in commands),
             'link-command-contract')
        need(receipt['controls'] == [{
            'name': 'default-unconfigured-refusal',
            'argv': [link['argv'][3]],
            'exit_code': 78,
            'stdout_sha256': sha(b''),
            'stderr_sha256': sha(
                b'KPI_REGISTERED_FINANCIAL_UNCONFIGURED_REFUSED\n'),
            'pass': True,
            'file_network_owner_or_mpc_input_supplied': False,
        }], 'recorded-default-refusal')
    need(authority['reproduction'] is None,
         'authority-is-first-independent-build')
    need(build['reproduction'] == {
        'schema': 'kpi-registered-financial-build-reproduction/v2',
        'authority_build_receipt_sha256':
            QUALIFIER_AUTHORITY_BUILD_SHA256,
        'authority_binary_sha256': QUALIFIER_BINARY_SHA256,
        'reproduced_binary_sha256': QUALIFIER_BINARY_SHA256,
        'independent_output_directory': True,
        'exact_build_contract_match': True,
        'exact_toolchain_and_dependency_closure_match': True,
        'exact_object_closure_match': True,
        'default_refusal_reexecuted': True,
        'pass': True,
    }, 'independent-build-reproduction')
    need(build['build_contract'] == authority['build_contract'] and
         build['toolchain'] == authority['toolchain'] and
         build['source_sha256'] == authority['source_sha256'] and
         build['compile_dependencies'] == authority['compile_dependencies'] and
         build['object_sha256'] == authority['object_sha256'] and
         build['link_dependencies'] == authority['link_dependencies'] and
         build['vendor_artifacts'] == authority['vendor_artifacts'],
         'independent-build-same-inputs')
    base_raw = (root / 'qualifier/base/BUILD-RESULT.json').read_bytes()
    base_authority_raw = (
        root / 'qualifier/base/AUTHORITY-BUILD-RESULT.json').read_bytes()
    base = json.loads(base_raw)
    base_authority = json.loads(base_authority_raw)
    need(sha(base_raw) == BASE_QUALIFIER_BUILD_SHA256 and
         sha(base_authority_raw) ==
            BASE_QUALIFIER_AUTHORITY_BUILD_SHA256 and
         base['schema'] == base_authority['schema'] ==
            'kpi-registered-financial-gate-build/v2' and
         base['success'] is True and base_authority['success'] is True and
         base['configured'] is False and
         base_authority['configured'] is False and
         sha(canonical(base['source_sha256'])) ==
            BASE_QUALIFIER_SOURCE_CLOSURE_SHA256 and
         base['link'][0]['sha256'] ==
            base_authority['link'][0]['sha256'] ==
            BASE_QUALIFIER_BINARY_SHA256 and
         base['reproduction']['pass'] is True and
         base['reproduction']['authority_build_receipt_sha256'] ==
            BASE_QUALIFIER_AUTHORITY_BUILD_SHA256,
         'roster-base-qualifier-build-pair')
    selected_qualifier = selected['qualifier']
    need(selected_qualifier == {
        'source_closure_sha256': QUALIFIER_SOURCE_CLOSURE_SHA256,
        'build_receipt_sha256': QUALIFIER_BUILD_SHA256,
        'authority_build_receipt_sha256':
            QUALIFIER_AUTHORITY_BUILD_SHA256,
        'binary_sha256': QUALIFIER_BINARY_SHA256,
        'build_contract_sha256': BUILD_CONTRACT_SHA256,
        'build_authority_sha256':
            authority_sha256(build_authority_record()),
        'configured': False,
        'independently_reproduced': True,
        'default_refusal_directly_reexecuted': True,
        'source05_is_registered_authority': False,
    }, 'selected-build-authority')
    need(selected['roster_base_qualifier'] == {
        'source_closure_sha256':
            BASE_QUALIFIER_SOURCE_CLOSURE_SHA256,
        'build_receipt_sha256': BASE_QUALIFIER_BUILD_SHA256,
        'authority_build_receipt_sha256':
            BASE_QUALIFIER_AUTHORITY_BUILD_SHA256,
        'binary_sha256': BASE_QUALIFIER_BINARY_SHA256,
        'bound_by_registered_trial03_candidate_header': True,
    }, 'selected-roster-base-qualifier')
    _verify_default_refusal(
        root / 'qualifier/mpc-registered-financial-gate', root)
    _verify_default_refusal(
        root / 'qualifier/authority-mpc-registered-financial-gate', root)
    _verify_default_refusal(
        root / 'qualifier/base/mpc-registered-financial-gate', root)


def _verify_semantics(root, selected):
    authority = selected['authority']
    need(authority == {
        'trial_id': TRIAL_ID,
        'selection_sha256': TRIAL_SELECTION_SHA256,
        'registration_sha256': REGISTRATION_SHA256,
        'registration_file_sha256': REGISTRATION_FILE_SHA256,
        'certificate_authority_der_sha256': CA_DER_SHA256,
        'server_certificate_der_sha256': list(CERTIFICATE_DER_SHA256),
        'self_authorizing_manifest': False,
        'trial_authority_sha256':
            authority_sha256(trial_authority_record()),
    }, 'fixed-external-authority')
    trial = json.loads((root / 'trial/SELECTION-CANDIDATE.json').read_bytes())
    registration = json.loads(
        (root / 'trial/registration/REGISTRATION.json').read_bytes())
    need(trial['trial_root'] == str(TRIAL_ROOT) and
         trial['trial_id'] == TRIAL_ID and
         trial['registration_sha256'] == REGISTRATION_SHA256 and
         trial['registration_file_sha256'] == REGISTRATION_FILE_SHA256 and
         trial['source_selection_sha256'] == SOURCE_SELECTION_SHA256 and
         trial['initializer']['sha256'] == INITIALIZER_SHA256 and
         [row['certificate_der_sha256'] for row in trial['certificates']] ==
         list(CERTIFICATE_DER_SHA256) and
         trial['registered_driver_configured'] is False and
         trial['network_node_contacted'] is False and
         trial['owner_input_or_mpc_executed'] is False,
         'trial-selection-semantics')
    need(registration['registration_sha256'] == REGISTRATION_SHA256 and
         registration['registration']['trial_id'] == TRIAL_ID and
         registration['registration']['registered_driver_configured'] is False,
         'registration-semantics')
    qualification = json.loads(
        (root / 'accepted-head/QUALIFICATION.json').read_bytes())
    source_map = {row['path']: row['sha256']
                  for row in qualification['source_files']}
    need(sha(canonical(source_map)) == ACQUISITION_SOURCE_CLOSURE_SHA256 and
         qualification[
          'actual_network_genuine_financial_proof_NativeFull_or_registered_head_execution_performed'
         ] is False, 'accepted-head-source-qualification-boundary')
    _verify_ready_state(root, trial)
    _verify_build(root, selected)
    native = json.loads((root / 'native/ADMISSION.json').read_bytes())
    need(native['parameters_sha256'] ==
            selected['native']['parameters_sha256'] and
         native['immutable_tail_sha256'] ==
            selected['native']['immutable_tail_sha256'] and
         native['component_profile_sha256'] ==
            selected['native']['component_profile_sha256'] and
         native['outer_image_hex32'] ==
            selected['native']['outer_image_hex32'] and
         native['program_sha256'] == selected['native']['program_sha256'] and
         native['native_codec_sha256'] ==
            selected['native']['codec_sha256'] and
         native['outer_selection_selected'] is False and
         native['aggregate_proof_or_R0_receipt_or_native_acceptance'] is False,
         'native-pin-and-boundary')
    need(selected['transport_contract'] == {
        'requires_concrete_roster_pinned_player': True,
        'requires_mutual_TLS_chain_to_selected_CA': True,
        'runtime_roster_or_authority_override': False,
    } and selected['head_policy'] == {
        'selection': 'FRESH_REGISTERED_ACCEPTED_HEAD_PER_ROUND',
        'rounds': ['ROUND1', 'ROUND2'],
        'same_head_replay_allowed': False,
        'source05_retag_allowed': False,
        'attempt_binding': 'DYNAMIC_FROM_REGISTERED_SELECTION',
    } and selected['freshness_authority'] == {
        'durable_registered_journal_anchor_registry_admitted': False,
        'caller_prior_identities_are_authority': False,
        'caller_completion_json_is_authority': False,
        'completion_requires_direct_cpp_accepted_head_and_financial_R0_receipts':
            True,
        'launch_authorized': False,
    } and selected['configuration_complete'] is False and
         selected['registered_driver_configured'] is False,
         'unconfigured-dynamic-head-policy')
    need(selected['hermetic_runtime'] == runtime_authority(selected['files']),
         'selected-hermetic-runtime-authority')
    _verify_chain(root)


@dataclass
class Admission:
    trial_id: str
    registration: str
    selection: str
    state_initialization: str
    trial_authority: str
    build_authority: str
    driver_configured: bool = False
    configured_build_admitted: bool = False
    durable_freshness_admitted: bool = False
    launch_authorized: bool = False
    _heads: dict = field(default_factory=dict, repr=False)

    def bind_fresh_head(self, round_name, head_identity):
        """Check a non-authorizing two-round source-selection candidate.

        Durable launch freshness must come from the registered journal and a
        direct C++ AcceptedFinancialHead. This in-memory check never mints
        launch or completion authority.
        """
        need(round_name in ('ROUND1', 'ROUND2'), 'round-name')
        word(head_identity)
        need(head_identity != '00' * 32 and round_name not in self._heads and
             head_identity not in self._heads.values(), 'fresh-head-replay')
        if round_name == 'ROUND2':
            need('ROUND1' in self._heads, 'round-order')
        self._heads[round_name] = head_identity
        return head_identity


def admit_snapshot(root):
    root = Path(root).absolute()
    info = root.lstat()
    need(root.is_dir() and not root.is_symlink() and info.st_uid == os.getuid()
         and stat.S_IMODE(info.st_mode) == 0o500, 'immutable-snapshot-root')
    initial_items = list(root.rglob('*'))
    need(not any(item.is_symlink() for item in initial_items),
         'snapshot-contains-no-symlinks')
    directories = [root, *(item for item in initial_items if item.is_dir())]
    directory_signatures = {}
    for directory in directories:
        selected_info = directory.lstat()
        need(selected_info.st_uid == os.getuid() and
             stat.S_IMODE(selected_info.st_mode) == 0o500,
             'immutable-snapshot-directory')
        directory_signatures[str(directory.relative_to(root))] = \
            metadata_signature(selected_info)
    expected_records = static_file_records(root)
    for record in expected_records:
        stable_read(root / record['path'], record['sha256'], immutable=True,
                    mode=int(record['mode'], 8))
    build = json.loads((root / 'qualifier/BUILD-RESULT.json').read_bytes())
    expected_records.extend(qualifier_source_records(root, build))
    expected_records.extend(qualifier_dependency_records(root, build))
    external = SELECTED_EXTERNAL_AUTHORITY
    expected_records.extend(_runtime_records(
        root, None if external is None else
        external['selected_verifier_sha256']))
    expected_records.sort(key=lambda record: record['path'])
    manifest_path = root / 'CONFIGURATION-CANDIDATE.json'
    manifest_raw = stable_read(
        manifest_path,
        (sha(manifest_path.read_bytes()) if external is None else
         external['configuration_candidate_sha256']),
        immutable=True, mode=0o400)
    selected = json.loads(manifest_raw)
    need(selected == manifest(expected_records), 'exact-source-owned-manifest')
    if external is not None:
        need(selected['hermetic_runtime']['closure_sha256'] ==
             external['selected_runtime_closure_sha256'] and
             selected['hermetic_runtime']['verifier_sha256'] ==
             external['selected_verifier_sha256'],
             'external-runtime-authority')
    receipt_raw = stable_read(root / 'SNAPSHOT.json',
                              sha((root / 'SNAPSHOT.json').read_bytes()),
                              immutable=True, mode=0o400)
    receipt = json.loads(receipt_raw)
    need(receipt == {
        'schema': 'kpb-registered-trial03-source-snapshot/v1',
        'status': 'SOURCE_SNAPSHOT_CANDIDATE_UNCONFIGURED',
        'trial_id': TRIAL_ID,
        'selection_sha256': TRIAL_SELECTION_SHA256,
        'registration_sha256': REGISTRATION_SHA256,
        'configuration_candidate_sha256': sha(manifest_raw),
        'trial_authority_sha256':
            authority_sha256(trial_authority_record()),
        'unconfigured_build_authority_sha256':
            authority_sha256(build_authority_record()),
        'files': len(expected_records),
        'selected_verifier_sha256':
            selected['hermetic_runtime']['verifier_sha256'],
        'selected_runtime_closure_sha256':
            selected['hermetic_runtime']['closure_sha256'],
        'selected_verifier_executed': False,
        'registered_driver_configured': False,
        'network_owner_mpc_proof_or_broadcast': False,
    }, 'snapshot-receipt')
    allowed = {record['path'] for record in expected_records}
    allowed.update({'CONFIGURATION-CANDIDATE.json', 'SNAPSHOT.json'})
    actual = {str(item.relative_to(root)) for item in root.rglob('*')
              if item.is_file() or item.is_symlink()}
    need(actual == allowed, 'finite-snapshot-files')
    _verify_semantics(root, selected)
    final_directories = [root, *(item for item in root.rglob('*')
                                  if item.is_dir())]
    need({str(directory.relative_to(root)):
          metadata_signature(directory.lstat())
          for directory in final_directories} == directory_signatures,
         'snapshot-directories-changed-during-admission')
    return Admission(
        TRIAL_ID, REGISTRATION_SHA256, TRIAL_SELECTION_SHA256,
        STATE_INITIALIZATION_SHA256,
        authority_sha256(trial_authority_record()),
        authority_sha256(build_authority_record()))


def _current_runtime_is_snapshot_only(runtime=SEALED_RUNTIME_ROOT):
    runtime = Path(runtime)
    selected = set()
    for line in Path('/proc/self/maps').read_text('ascii').splitlines():
        fields = line.split()
        if len(fields) < 6 or not fields[-1].startswith('/'):
            continue
        path = Path(fields[-1].removesuffix(' (deleted)'))
        name = path.name
        if ('.so' in name or 'ld-linux' in name or
                name.startswith('python3.14')):
            need(path.is_relative_to(runtime),
                 'selected-verifier-live-runtime-object')
            selected.add(str(path))
    need(selected, 'selected-verifier-runtime-maps')
    return sorted(selected)


def _namespace_id(name):
    return os.readlink('/proc/self/ns/' + name)


def _selected_child_entry(root, capability_path):
    global SELECTED_RUNTIME_CHILD, SELECTED_EXTERNAL_AUTHORITY
    root = Path(root)
    need(root == SANDBOX_SNAPSHOT_ROOT,
         'selected-child-snapshot-root')
    capability_raw = Path(capability_path).read_bytes()
    capability = json.loads(capability_raw)
    need(encoded(capability) == capability_raw and set(capability) == {
        'schema', 'nonce_hex', 'authority', 'parent_namespaces',
        'host_pid1_sha256', 'private_sentinel_path', 'unix_socket_path',
    } and capability['schema'] ==
        'kpb-selected-verifier-capability/v1' and
         re.fullmatch('[0-9a-f]{64}', capability['nonce_hex']),
         'selected-child-capability')
    authority = capability['authority']
    need(type(authority) is dict, 'selected-child-authority')
    parent_namespaces = capability['parent_namespaces']
    names = ('net', 'pid', 'ipc', 'uts', 'mnt')
    need(set(parent_namespaces) == set(names),
         'selected-child-parent-namespaces')
    current_namespaces = {name: _namespace_id(name) for name in names}
    isolated = {name: current_namespaces[name] != parent_namespaces[name]
                for name in names}
    need(all(isolated.values()), 'selected-child-namespace-isolation')
    status_lines = Path('/proc/self/status').read_text('ascii').splitlines()
    nspid = next((line.split()[1:] for line in status_lines
                  if line.startswith('NSpid:')), [])
    visible_pids = {
        int(path.name) for path in Path('/proc').iterdir()
        if path.name.isdigit()
    }
    fresh_pid_namespace_kernel_evidence = (
        len(nspid) == 1 and int(nspid[0]) <= 4 and
        visible_pids and max(visible_pids) <= 4)
    network_interfaces = {
        line.split(':', 1)[0].strip()
        for line in Path('/proc/net/dev').read_text('ascii').splitlines()
        if ':' in line
    }
    loopback_only_network = network_interfaces == {'lo'}
    fixed_uts_hostname = socket.gethostname() == 'kpb-selected'
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text('ascii').splitlines():
        fields = line.split()
        separator = fields.index('-')
        mounts[fields[4]] = {
            'options': fields[5].split(','),
            'filesystem': fields[separator + 1],
        }
    minimal_mount_root = (
        mounts.get('/', {}).get('filesystem') == 'tmpfs' and
        'ro' in mounts.get('/selection', {}).get('options', []))
    need(fresh_pid_namespace_kernel_evidence and loopback_only_network and
         fixed_uts_hostname and minimal_mount_root,
         'selected-child-kernel-isolation-evidence')
    proc1_sha256 = sha(Path('/proc/1/cmdline').read_bytes())
    host_proc_hidden = proc1_sha256 != capability['host_pid1_sha256']
    private_sentinel_hidden = not Path(
        capability['private_sentinel_path']).exists()
    unix_socket_unreachable = False
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        try:
            client.connect(capability['unix_socket_path'])
        except OSError:
            unix_socket_unreachable = True
    finally:
        client.close()
    live_vendor_hidden = not LIVE_VENDOR_ROOT.exists()
    selected_home = str(SEALED_RUNTIME_ROOT / 'python')
    need(os.environ.get('PYTHONHOME') == selected_home,
         'selected-python-home')
    hostile_keys = sorted(set(os.environ).intersection({
        'LD_AUDIT', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'PYTHONPATH',
        'PYTHONSTARTUP',
    }))
    need(host_proc_hidden and private_sentinel_hidden and
         unix_socket_unreachable and live_vendor_hidden and
         not hostile_keys, 'selected-child-host-isolation')
    SELECTED_RUNTIME_CHILD = True
    SELECTED_EXTERNAL_AUTHORITY = authority
    admission = admit_snapshot(root)
    runtime_objects = _current_runtime_is_snapshot_only()
    selected_verifier = Path('/sealed/verifier.py').read_bytes()
    need(sha(selected_verifier) == authority['selected_verifier_sha256'],
         'selected-child-verifier-pin')
    result = {
        'status': 'INTERNAL_CONTROL_EVIDENCE',
        'authority_admitted': False,
        'trial_id': admission.trial_id,
        'registration_sha256': admission.registration,
        'selection_sha256': admission.selection,
        'trial_authority_sha256': admission.trial_authority,
        'unconfigured_build_authority_sha256': admission.build_authority,
        'selected_verifier_sha256': sha(selected_verifier),
        'selected_verifier_executed': True,
        'sealed_runtime_executed': True,
        'network_namespace_isolated': isolated['net'],
        'pid_namespace_isolated': isolated['pid'],
        'ipc_namespace_isolated': isolated['ipc'],
        'uts_namespace_isolated': isolated['uts'],
        'mount_namespace_isolated': isolated['mnt'],
        'namespace_ids': current_namespaces,
        'fresh_pid_namespace_kernel_evidence':
            fresh_pid_namespace_kernel_evidence,
        'loopback_only_network': loopback_only_network,
        'fixed_uts_hostname': fixed_uts_hostname,
        'minimal_mount_root': minimal_mount_root,
        'host_proc_hidden': host_proc_hidden,
        'proc1_cmdline_sha256': proc1_sha256,
        'private_sentinel_hidden': private_sentinel_hidden,
        'host_unix_socket_unreachable': unix_socket_unreachable,
        'live_vendor_runtime_hidden': live_vendor_hidden,
        'snapshot_only_runtime_objects': bool(runtime_objects),
        'resolved_runtime_objects': runtime_objects,
        'inherited_environment_keys': hostile_keys,
        'capability_sha256': sha(capability_raw),
        'external_authority_sha256': sha(encoded(authority)),
        'durable_freshness_admitted': False,
        'launch_authorized': False,
        'registered_driver_configured': False,
    }
    print(json.dumps(result, sort_keys=True))


def exercise_selected_verifier_control(
        root, authority_path, authority_sha256, *, after_seal_hook=None):
    """Exercise isolation only; this never returns admission authority."""
    root = Path(root).absolute()
    authority_path = Path(authority_path).absolute()
    authority, authority_raw, authority_signature = _external_control_pin(
        authority_path, root, authority_sha256)
    manifest_path = root / 'CONFIGURATION-CANDIDATE.json'
    stable_read(manifest_path,
                authority['configuration_candidate_sha256'],
                immutable=True, mode=0o400)
    manifest_signature = metadata_signature(manifest_path.lstat())
    manifest = json.loads(manifest_path.read_bytes())
    need(manifest['hermetic_runtime']['verifier_sha256'] ==
         authority['selected_verifier_sha256'] and
         manifest['hermetic_runtime']['closure_sha256'] ==
         authority['selected_runtime_closure_sha256'],
         'external-authority-manifest-agreement')
    parent_namespaces = {
        name: _namespace_id(name) for name in ('net', 'pid', 'ipc', 'uts', 'mnt')
    }
    with _host_isolation_probes() as (sentinel, unix_socket), \
            _mirrored_trial_state() as mirror:
        capability = {
            'schema': 'kpb-selected-verifier-capability/v1',
            'nonce_hex': os.getrandom(32).hex(),
            'authority': authority,
            'parent_namespaces': parent_namespaces,
            'host_pid1_sha256': sha(Path('/proc/1/cmdline').read_bytes()),
            'private_sentinel_path': str(sentinel),
            'unix_socket_path': str(unix_socket),
        }
        capability_raw = encoded(capability)
        with _sealed_execution_capsule(
                root, authority, capability_raw) as capsule:
            if after_seal_hook is not None:
                after_seal_hook()
            bootstrap = (
                "import runpy; s=runpy.run_path('/sealed/verifier.py', "
                "run_name='kpb_selected_verifier'); "
                "s['_selected_child_entry']('/selection', "
                "'/sealed/capability.json')")
            inner = _loader_command(
                SANDBOX_SNAPSHOT_ROOT, '/sealed/bin/python3.14',
                ['-S', '-P', '-c', bootstrap],
                runtime_root=SEALED_RUNTIME_ROOT)
            command = _bwrap_command(
                root, inner, trial_mirror=mirror,
                file_mounts=capsule['mounts'],
                environment={'PYTHONHOME': '/sealed/python'})
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, close_fds=True, cwd=root, env={},
                pass_fds=capsule['pass_fds'])
            _verify_post_execution_identities(capsule['identities'])
    reread, reread_raw, reread_signature = _external_control_pin(
        authority_path, root, authority_sha256)
    need(reread == authority and reread_raw == authority_raw and
         reread_signature == authority_signature,
         'post-execution-authority-changed')
    stable_read(manifest_path,
                authority['configuration_candidate_sha256'],
                immutable=True, mode=0o400)
    need(metadata_signature(manifest_path.lstat()) == manifest_signature,
         'post-execution-manifest-changed')
    need(result.returncode == 0 and result.stderr == b'',
         'selected-verifier-execution')
    try:
        selected = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(
            'registered-selection-candidate-selected-verifier-output') from None
    need(selected['status'] == 'INTERNAL_CONTROL_EVIDENCE' and
         selected['selected_verifier_executed'] is True and
         selected['sealed_runtime_executed'] is True and
         all(selected[name] is True for name in (
             'network_namespace_isolated', 'pid_namespace_isolated',
             'ipc_namespace_isolated', 'uts_namespace_isolated',
             'mount_namespace_isolated', 'host_proc_hidden',
             'private_sentinel_hidden', 'host_unix_socket_unreachable',
             'live_vendor_runtime_hidden',
             'snapshot_only_runtime_objects',
             'fresh_pid_namespace_kernel_evidence',
             'loopback_only_network',
             'fixed_uts_hostname', 'minimal_mount_root')) and
         selected['inherited_environment_keys'] == [] and
         selected['capability_sha256'] == sha(capability_raw) and
         selected['external_authority_sha256'] == authority_sha256 and
         sha(authority_raw) == authority_sha256 and
         all(selected['namespace_ids'][name] != parent_namespaces[name]
             for name in parent_namespaces) and
         selected['proc1_cmdline_sha256'] !=
            capability['host_pid1_sha256'] and
         selected['selected_verifier_sha256'] ==
            authority['selected_verifier_sha256'] and
         selected['registered_driver_configured'] is False and
         selected['launch_authorized'] is False,
         'selected-verifier-result')
    selected['status'] = 'CONTROL_ONLY_UNCONFIGURED'
    selected['authority_admitted'] = False
    return selected


def run_selected_verifier(root, supervisor_capability_fd):
    """Production authority entrypoint; unavailable while CONFIGURED=0.

    The future selected outer supervisor must own and pass an opaque capability
    whose digest is compiled into the selected build.  A path, caller hash, or
    JSON record can never substitute for that capability.
    """
    del root, supervisor_capability_fd
    need(OUTER_SUPERVISOR_AUTHORITY_CONFIGURED and
         OUTER_SUPERVISOR_AUTHORITY_SHA256 != '00' * 32,
         'outer-supervisor-authority-not-configured')
    need(False, 'outer-supervisor-capability-adapter-not-selected')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = prepare_snapshot(args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError):
        raise SystemExit('registered selection candidate refused') from None
