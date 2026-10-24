#!/usr/bin/env python3
"""Fixed own-input engine wrapper. Raw private diagnostics never leave party."""
import os
from pathlib import Path
import subprocess
import sys

from codec import INPUT_BYTES, INPUT_DIGITS, INPUT_FIELDS, Q, canonical_json, engine_output, hex32, need, scalar


def main():
    need(len(sys.argv) == 5 and sys.argv[1] in ('0', '1', '2'), 'fixed-party-arguments')
    party, session_sha = int(sys.argv[1]), hex32(sys.argv[2])
    path = Path(f'/input/Input-P{party}-0')
    # Only this isolated party opens its own confidential stream. The host
    # controller does not open, copy, hash, pipe or inspect any owner input.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    source = os.fdopen(fd, 'rb')
    opened = os.fstat(fd)
    need((opened.st_dev, opened.st_ino) == (int(sys.argv[3]), int(sys.argv[4])) and
         opened.st_nlink == 1 and opened.st_mode & 0o777 == 0o400,
         'selected-own-input-inode-before-first-byte')
    with source:
        raw = source.read()
    values = raw.decode('ascii').splitlines()
    need(len(raw) == INPUT_BYTES and len(values) == INPUT_FIELDS and
         all(len(v) == INPUT_DIGITS and v.isdecimal() for v in values),
         'fixed-width-own-private-input-shape')
    numbers = [int(v) for v in values]
    from codec import unpack_row
    unpack_row(numbers[:17]); unpack_row(numbers[17:34]); scalar(numbers[34])
    need(raw == ''.join(f'{v:0{INPUT_DIGITS}d}\n' for v in numbers).encode(),
         'exact-fixed-private-stream-encoding')
    # Normalize only inside this owner namespace, in memory and an owner-only
    # pipe. No variable-length normalized host file or metadata is produced.
    normalized = ''.join(str(v) + '\n' for v in numbers).encode()
    private = Path('/work/Player-Data')
    stdout, stderr = private / 'engine.stdout', private / 'engine.stderr'
    with stdout.open('xb') as out, stderr.open('xb') as err:
        result = subprocess.run(['/engine', '-N', '3', '-I', '-p', str(party),
                                 '-h', '127.0.0.1', '-pn', '17349', '--prime', str(Q),
                                 'kpx7_mix-' + session_sha], input=normalized, stdout=out, stderr=err,
                                cwd='/work', env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'})
    need(result.returncode == 0, 'engine-incomplete')
    need(b'insecure' not in stderr.read_bytes().lower(), 'stock-insecure-warning')
    public = engine_output(stdout.read_bytes(), session_sha)
    # This receipt goes directly to the owner's private runtime directory,
    # independently of anything the public coordinator later proposes.
    with (private / 'OWN-MPC-PROJECTION.json').open('xb') as output:
        output.write(canonical_json(public))
    # The only stdout is the final checked public projection. Nothing from
    # raw prompts, input failures or internal engine diagnostics is relayed.
    sys.stdout.buffer.write(canonical_json(public)); sys.stdout.buffer.flush()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # The detailed local exception may include a malicious input. Keep it
        # private; expose only an unsuccessful exit and a fixed public reason.
        os.write(2, b'KPX7_PARTY_INCOMPLETE\n')
        sys.exit(1)
