#!/usr/bin/env python3
"""Bounded PUBLIC transport inspection; no PK/setup/proof claim is emitted."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import sys
import time


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(65536):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--reader', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    if not args.inside_scope:
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect',
            '--unit', 'kpi-packed-rows-' + secrets.token_hex(16),
            '-p', 'MemoryMax=2G', '-p', 'CPUQuota=100%', sys.executable,
            str(Path(__file__).resolve()), *sys.argv[1:], '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    entries = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
               if line.startswith('0::')]
    if len(entries) != 1 or 'kpi-packed-rows-' not in entries[0]:
        raise RuntimeError('selected public row resource scope absent')
    scope = Path('/sys/fs/cgroup') / entries[0].lstrip('/')
    memory, cpu = (scope / 'memory.max').read_text().strip(), (scope / 'cpu.max').read_text().strip()
    quota, period = cpu.split()
    if memory != str(2 * 1024**3) or quota == 'max' or int(quota) > int(period):
        raise RuntimeError('selected public row resource scope changed')
    manifest_sha = sha(args.manifest)
    source = json.loads(args.manifest.read_text())
    if source['schema'] != 'kpi-r1cs-axis-gzip/v1' or source['private_assignment_included'] is not False:
        raise RuntimeError('selected transport is not public unassigned rows')
    build = json.loads((args.reader.parent / 'BUILD-RESULT.json').read_text())
    reader_sha = sha(args.reader)
    if not build['success'] or build['link']['binary_sha256'] != reader_sha:
        raise RuntimeError('selected public reader identity mismatch')
    args.output.mkdir(parents=True, exist_ok=False)
    command = [str(args.reader.resolve()), '--rows-only', str(source['num_instances']),
        str(source['num_witnesses']), str(source['num_constraints']), source['canonical_r1cs_fingerprint']]
    terms = 0
    for axis, pin in enumerate(source['axes']):
        if pin['axis'] != axis or pin['file'] not in [f'{"ABC"[axis]}.r1cs.bin.gz', f'{"ABC"[axis]}.rows.gz']:
            raise RuntimeError('public axis filename or order mismatch')
        raw = pin['uncompressed_bytes']
        term_bytes = raw - 80 - 8 * source['num_constraints']
        if term_bytes < 0 or term_bytes % 40:
            raise RuntimeError('public axis byte/count geometry')
        terms += term_bytes // 40
        command += [str((args.manifest.parent / pin['file']).resolve()), pin['compressed_sha256'],
                    pin['uncompressed_sha256'], str(pin['compressed_bytes']), str(raw)]
    start = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    (args.output / 'PUBLIC-READER.stdout').write_text(result.stdout)
    (args.output / 'PUBLIC-READER.stderr').write_text(result.stderr)
    accepted = json.loads(result.stdout)
    passed = result.returncode == 0 and accepted.get('matrix_transport_valid') is True and \
        accepted.get('pk_or_model_claim') is False and accepted['matrix_fingerprint'] == source['canonical_r1cs_fingerprint'] and \
        accepted['admitted_rows'] == 3 * source['num_constraints'] and accepted['admitted_terms'] == terms and \
        sha(args.manifest) == manifest_sha and sha(args.reader) == reader_sha
    receipt = {'schema': 'kpi-public-rows-inspection-control/v1', 'passed': passed,
        'manifest_sha256': manifest_sha, 'reader_sha256': reader_sha,
        'resources': {'memory_max_bytes': int(memory), 'cpu_max': cpu},
        'wall_seconds': time.monotonic() - start, 'exit': result.returncode,
        'public_result': accepted, 'private_input_MPC_or_setup_executed': False}
    (args.output / 'RESULT.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
