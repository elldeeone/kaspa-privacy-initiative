"""Pinned public-body normalization and explicit optional native validation.

Normalization recomputes official V1 BLAKE3 txID/storage mass without a VM call.
Validation executes the real VM/Full checker on supplied public UTXOs; neither
operation establishes accepted-chain backing or currentness.
"""
from pathlib import Path
import copy
import json
import os
import stat
import subprocess
import tempfile
import time

from public_g16 import CheckerUnavailable, digest, sealed_fd

BINARY = Path('/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator')
BINARY_SHA256 = '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'


def execute(case, mode):
    if mode not in ('control-normalize-freeze', 'validate-transaction'):
        raise ValueError('fixed_public_operation_required')
    raw = json.dumps(case, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError('public_case_size')
    source_fd = os.open(BINARY, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        st = os.fstat(source_fd)
        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
            raise CheckerUnavailable('native_file_type_or_size')
        with os.fdopen(source_fd, 'rb', closefd=False) as source:
            code = source.read(64 * 1024 * 1024 + 1)
        if len(code) != st.st_size or digest(code) != BINARY_SHA256:
            raise CheckerUnavailable('native_identity')
    finally:
        os.close(source_fd)
    fds = []
    try:
        fds.append(sealed_fd('public-native-checker', code, True))
        fds.append(sealed_fd('public-validation-case', raw))
        with tempfile.TemporaryDirectory(prefix='PUBLIC-DO-NOT-FUND-native-') as temporary:
            out = Path(temporary) / 'result'
            began = time.monotonic()
            result = subprocess.run([f'/proc/self/fd/{fds[0]}', mode,
                f'/proc/self/fd/{fds[1]}', str(out)], pass_fds=tuple(fds),
                stdin=subprocess.DEVNULL, capture_output=True,
                env={'PATH': '/usr/bin:/bin'}, timeout=3600, check=False)
            if result.returncode or result.stderr or result.stdout:
                raise CheckerUnavailable('public_native_operation_failed')
            files = ('transaction.json', 'metrics.json') if mode == 'control-normalize-freeze' else (
                'native-validation.json', 'metrics.json')
            values = {name: json.loads((out/name).read_bytes()) for name in files}
            return {'operation': mode, 'seconds': time.monotonic()-began,
                'native_elf_sha256': BINARY_SHA256, 'case_sha256': digest(raw),
                'native_VM_executed': mode == 'validate-transaction',
                'accepted_chain_or_currentness_claimed': False, **values}
    finally:
        for fd in reversed(fds):
            os.close(fd)


def normalize(case):
    result = execute(case, 'control-normalize-freeze')
    actual = result['transaction.json']
    expected = copy.deepcopy(case['transaction'])
    expected['id'], expected['mass'] = actual['id'], actual['mass']
    if actual != expected:
        raise CheckerUnavailable('normalizer_changed_non_derived_body_field')
    result['transaction'] = result.pop('transaction.json')
    result['metrics'] = result.pop('metrics.json')
    return result


def validate(case):
    result = execute(case, 'validate-transaction')
    result['report'] = result.pop('native-validation.json')
    result['metrics'] = result.pop('metrics.json')
    return result
