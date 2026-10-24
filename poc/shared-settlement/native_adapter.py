"""Authenticated public W emitter/body codec; never executes a native VM.

ReceiptW and UNSAFE_HASH_ORACLE_ONLY are distinct immutable code selections.
The diagnostic constructor is only for unfunded codec tests and cannot be a
financial deployment/profile selection. Actual receipt verification is separate.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

from wire import h, hexbytes, need, p2sh

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'poc/shared-settlement-verifier'))
from public_g16 import CheckerUnavailable, sealed_fd

DEFAULT_BINARY = Path('/home/luke/projects/kpi-intensive-2026-10-22/shared-settlement-native-target/release/kpi-shared-settlement-native')
DEFAULT_SHA256 = '76cfc5cc381e503e5517864044fd9a66826864f2790154157e351bff08fd4ee1'


class NativeCodec:
    def __init__(self, image, child_profile_sha256, binary=DEFAULT_BINARY, expected_sha256=DEFAULT_SHA256,
                 *, unsafe_unfunded_hash_oracle=False):
        need(type(image) is bytes and len(image) == 32, 'externally_selected_outer_image')
        hexbytes(child_profile_sha256, 32)
        hexbytes(expected_sha256, 32)
        need(type(unsafe_unfunded_hash_oracle) is bool, 'explicit_unsafe_diagnostic_selection')
        self.image, self.child_profile_sha256 = image, child_profile_sha256
        self.binary, self.expected_sha256 = Path(binary), expected_sha256
        self.unsafe_diagnostic = unsafe_unfunded_hash_oracle
        self.kind = 'UNSAFE_HASH_ORACLE_ONLY' if self.unsafe_diagnostic else 'ACTUAL_R0_W'

    def call(self, request):
        fd = os.open(self.binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= 64 * 1024 * 1024:
                raise CheckerUnavailable('new_native_codec_type_or_size')
            with os.fdopen(fd, 'rb', closefd=False) as source:
                code = source.read(64 * 1024 * 1024 + 1)
            if len(code) != metadata.st_size or h(code).hex() != self.expected_sha256:
                raise CheckerUnavailable('new_native_codec_whole_ELF_identity')
        finally:
            os.close(fd)
        executable = sealed_fd('public-new-W-codec', code, True)
        try:
            result = subprocess.run([f'/proc/self/fd/{executable}'],
                input=json.dumps(request, sort_keys=True, separators=(',', ':'), allow_nan=False).encode(),
                pass_fds=(executable,), capture_output=True, check=False, timeout=3600,
                env={'PATH': '/usr/bin:/bin', 'RISC0_DEV_MODE': '0'})
        finally:
            os.close(executable)
        if result.returncode or result.stderr or len(result.stdout) > 1024 * 1024:
            # An infrastructure/protocol failure is not an accepted rejection
            # control. Test callers may separately record a typed CLI refusal.
            raise CheckerUnavailable('new_native_codec_operation_refused')
        value = json.loads(result.stdout)
        if value['template_kind'] != self.kind or value['outer_image_hex32'] != self.image.hex():
            raise CheckerUnavailable('new_native_codec_kind_or_external_image')
        return value

    def emit(self, state):
        need(type(state) is bytes and len(state) == 112, 'public_W_state112')
        result = self.call({'operation': 'emit-oracle' if self.unsafe_diagnostic else 'emit',
                            'state_hex112': state.hex(), 'outer_image_hex32': self.image.hex()})
        raw = hexbytes(result['redeem_hex'])
        if (result['child_profile_source_sha256'] != self.child_profile_sha256
            or result['redeem_bytes'] != len(raw) or result['redeem_sha256'] != h(raw).hex()
            or result['state_hex112'] != state.hex() or result['script_public_key'] != p2sh(raw)
            or result['actual_funding_native_VM_receipt_or_private_inputs'] is not False):
            raise CheckerUnavailable('new_native_codec_emission_identity')
        return raw

    def body(self, case):
        result = self.call({'operation': 'body', 'case': case})
        if (result['native_VM_executed'] is not False or result['receipt_or_child_G16_verified'] is not False
            or result['financial_projection_bytes'] != 8301 or len(hexbytes(result['journal_hex424'])) != 424
            or result['journal_sha256'] != h(hexbytes(result['journal_hex424'])).hex()
            or result['financial_projection_sha256'] != h(hexbytes(result['financial_projection_hex'])).hex()):
            raise CheckerUnavailable('new_native_codec_body_identity')
        return result
