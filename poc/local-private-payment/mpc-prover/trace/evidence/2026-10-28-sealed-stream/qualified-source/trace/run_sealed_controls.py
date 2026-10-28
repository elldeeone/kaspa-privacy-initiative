#!/usr/bin/env python3
"""Public container controls; this never links or starts an MPC context."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--public-trace', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(exist_ok=False)
    binary = args.binary.resolve()
    digest = lambda body: hashlib.sha256(body).hexdigest()
    records = []

    def case(name, payload, encoded=None, expected=None, mode='positive', canonical_pin=None,
             container_pin=None, count=None, special=None):
        encoded = payload if encoded is None else encoded
        path = args.output / (name + '.bin')
        if special == 'fifo': os.mkfifo(path)
        elif special == 'directory': path.mkdir()
        elif special == 'symlink': path.symlink_to(args.public_trace.resolve())
        else: path.write_bytes(encoded)
        command = [str(binary), str(path), canonical_pin or digest(payload),
                   str(len(payload) if count is None else count), container_pin or digest(encoded), mode]
        # This is a public negative test, not an operational deadline for a
        # private trial. FIFO admission must refuse rather than block in open.
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        passed = result.returncode == 0 and result.stdout.startswith('PUBLIC_SEALED_TRACE_PASS ')
        if expected:
            passed = result.returncode == 1 and result.stdout == 'PUBLIC_SEALED_TRACE_REFUSED ' + expected + '\n'
        record = {'name': name, 'expected': expected or 'accept', 'exit_code': result.returncode,
                  'stdout': result.stdout, 'stderr': result.stderr, 'passed': passed}
        records.append(record)
        if not passed:
            (args.output / 'FAILED.json').write_text(json.dumps(record, indent=2) + '\n')
            raise RuntimeError(json.dumps(record))

    for size in (0, 1, 2, 137, 65535, 65536, 65537, 131071, 131072, 131073):
        payload = bytes((i * 37 + 11) % 256 for i in range(size))
        case('plain-' + str(size), payload)
        case('gzip-' + str(size), payload, gzip.compress(payload, mtime=0))
    payload = args.public_trace.read_bytes()
    encoded = gzip.compress(payload, mtime=0)
    case('actual-sha3-plain', payload)
    case('actual-sha3-gzip', payload, encoded)
    case('replace-original-plain', payload, mode='replace-source')
    case('replace-original-gzip', payload, encoded, mode='replace-source')
    case('wrong-canonical-pin', payload, encoded, canonical_pin='0' * 64,
         expected='public-sealed-canonical-pin')
    case('wrong-container-pin', payload, encoded, container_pin='0' * 64,
         expected='public-sealed-container-pin')
    case('wrong-byte-count', payload, encoded, count=len(payload) + 1,
         expected='public-sealed-byte-count')
    case('trailing-junk', payload, encoded + b'junk', expected='trace-gzip-trailing-container-data')
    case('concatenated-empty', payload, encoded + gzip.compress(b'', mtime=0),
         expected='trace-gzip-trailing-container-data')
    case('concatenated-body', payload, encoded + encoded, expected='trace-gzip-trailing-container-data')
    for removed in (1, 8, len(encoded) - 10, len(encoded) - 2):
        case('truncated-' + str(removed), payload, encoded[:-removed], expected='trace-gzip-truncated')
    for name, position, value in [('corrupt-crc', -8, encoded[-8] ^ 1),
                                  ('corrupt-size', -1, encoded[-1] ^ 1),
                                  ('wrong-method', 2, 9), ('reserved-flags', 3, 0xe0)]:
        changed = bytearray(encoded); changed[position] = value
        case(name, payload, bytes(changed), expected='trace-gzip-invalid-or-corrupt')
    case('fifo', b'', expected='trace-artifact-file-type', special='fifo')
    case('directory', b'', expected='trace-artifact-file-type', special='directory')
    case('symlink', b'', expected='trace-artifact-file-open', special='symlink')
    summary = {'schema': 'public-sealed-trace-controls/v1', 'cases_passed': len(records),
        'actual_public_trace_bytes': len(payload), 'actual_public_trace_gzip_bytes': len(encoded),
        'MPC_or_private_input_executed': False, 'records': records}
    (args.output / 'PUBLIC-RESULT.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k != 'records'}, indent=2))


if __name__ == '__main__': main()
