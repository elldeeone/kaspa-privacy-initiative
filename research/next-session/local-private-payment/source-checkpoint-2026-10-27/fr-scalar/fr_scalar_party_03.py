#!/usr/bin/env python3
"""One synthetic-input MASCOT worker; raw engine state/logs remain private."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(ok):
    if not ok:
        raise ValueError('FR_PARTY_INCOMPLETE')


def checked_public_output(stdout_raw, stderr_raw, run_id):
    # Both raw streams stay inside this one worker. No raw diagnostic is
    # returned to the controller, including on failed decoding/checks.
    need(type(stdout_raw) is bytes and type(stderr_raw) is bytes)
    need(b'insecure' not in stdout_raw.lower() and b'insecure' not in stderr_raw.lower())
    lines = stdout_raw.decode('utf-8').splitlines()
    tagged = [line for line in lines if line.startswith('KPI_FR_')]
    expected = ['KPI_FR_SCALAR_GATE ' + run_id] + [
        'KPI_FR_RESIDUAL %d 0' % index for index in range(28)]
    need(tagged == expected)
    return [int(line.rsplit(' ', 1)[1]) for line in tagged[1:]]


def main():
    need(len(sys.argv) == 6)
    party, run_id, input_sha, device, inode = sys.argv[1:]
    need(party in ('0', '1', '2') and re.fullmatch('[0-9a-f]{32}', run_id))
    need(re.fullmatch('[0-9a-f]{64}', input_sha))
    fd = os.open('/public-input.txt', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
         stat.S_IMODE(info.st_mode) == 0o400 and
         (info.st_dev, info.st_ino) == (int(device), int(inode)))
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read()
    need(hashlib.sha256(raw).hexdigest() == input_sha and raw.endswith(b'\n'))
    fields = raw.decode('ascii').splitlines()
    need(len(fields) == 7)
    for text in fields:
        need(text.isascii() and text.isdecimal() and
             (text == '0' or not text.startswith('0')) and 0 <= int(text) < FR)
    argv = ['/engine', '-N', '3', '-I', '-p', party, '-h', '127.0.0.1',
            '-pn', '17349', '--prime', str(FR), '--batch-size', '1024',
            'kpi_fr_scalar_gate-' + run_id]
    stdout_path = Path('/work/Player-Data/engine.stdout')
    stderr_path = Path('/work/Player-Data/engine.stderr')
    started = time.monotonic()
    with stdout_path.open('xb') as out, stderr_path.open('xb') as err:
        process = subprocess.run(argv, input=raw, stdout=out, stderr=err,
                                 cwd='/work', env=CLEAN)
    need(process.returncode == 0)
    # Only the selected worker reads its new engine logs. No TLS/MAC-key body
    # is read by this code; the engine opens its own transport state as needed.
    residuals = checked_public_output(stdout_path.read_bytes(), stderr_path.read_bytes(), run_id)
    return {'schema': 'kpxa-public-fr-scalar-party/v1', 'status': 'PASS',
            'party': int(party), 'run_id': run_id, 'field_decimal': str(FR),
            'engine_argv': argv, 'engine_exit': process.returncode,
            'residuals': residuals, 'insecure_warning_seen': False,
            'elapsed_milliseconds': int((time.monotonic() - started) * 1000)}


if __name__ == '__main__':
    try:
        result = main()
    except Exception:
        os.write(2, b'FR_PARTY_INCOMPLETE\n')
        raise SystemExit(1)
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
