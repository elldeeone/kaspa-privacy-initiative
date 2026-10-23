#!/usr/bin/env python3
"""Submit one exact public fixture to the sole already-resident fresh key."""
import hashlib
import json
import os
from pathlib import Path
import sys


def write_new(path, raw):
    with path.open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def main():
    evidence, label, fixture = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()
    plan = json.loads((evidence / 'PLAN.json').read_bytes())
    ready = json.loads((evidence / 'READY.json').read_bytes())
    if label not in plan['proof_case_names']:
        raise ValueError('unselected case')
    raw = fixture.read_bytes()
    value = json.loads(raw)
    if value['classification'] != 'PUBLIC_SYNTHETIC_DO_NOT_FUND':
        raise ValueError('only public synthetic fixtures authorized')
    if len(bytes.fromhex(value['auth_hex528'])) != 528:
        raise ValueError('Auth528 required')
    stage = Path(plan['stage_directory'])
    command_dir = evidence / 'commands' / label
    command_dir.mkdir(parents=True, exist_ok=False)
    inputs = stage / 'inputs'
    inputs.mkdir(exist_ok=True)
    pinned = inputs / (label + '.json')
    write_new(pinned, raw)
    write_new(command_dir / 'fixture.json', raw)
    command = {'fixture': '/out/inputs/' + label + '.json', 'output': '/out/proofs/' + label}
    record = {'classification': value['classification'], 'fixture_original_path': str(fixture),
              'fixture_bytes': len(raw), 'fixture_sha256': hashlib.sha256(raw).hexdigest(),
              'resident_vk_sha256': ready['vk_sha256'], 'command': command,
              'native_or_chain_acceptance_claimed': False}
    write_new(command_dir / 'SUBMISSION.json', (json.dumps(record, indent=2, sort_keys=True) + '\n').encode())
    # Write less than PIPE_BUF atomically after both copies and the metadata are synced.
    with open(ready['command_fifo'], 'w') as pipe:
        pipe.write(json.dumps(command) + '\n')
        pipe.flush()
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    main()
