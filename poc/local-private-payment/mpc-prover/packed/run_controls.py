#!/usr/bin/env python3
"""PUBLIC small-fixture storage controls; never starts MPC or setup.

Malformed transports get fresh matching hashes to exercise the decoder itself,
not merely the outer selected-artifact hash check. Large financial artifacts
are deliberately outside this mutation harness.
"""
import argparse
import copy
import gzip
import hashlib
import json
from pathlib import Path
import resource
import secrets
import shutil
import struct
import subprocess
import sys
import time

from pack_existing import FR, FQ, digest_file, metadata_bytes


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    for name in ['reader', 'packed', 'pk', 'vk', 'original-model', 'output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-receipt', type=Path)
    parser.add_argument('--inside-scope', action='store_true')
    args = parser.parse_args()
    if not args.inside_scope:
        unit = 'kpi-packed-model-controls-' + secrets.token_hex(16)
        command = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', unit,
                   '-p', 'MemoryMax=2G', '-p', 'CPUQuota=100%', sys.executable,
                   str(Path(__file__).resolve()), *sys.argv[1:], '--inside-scope']
        raise SystemExit(subprocess.run(command).returncode)
    entries = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
               if line.startswith('0::')]
    if len(entries) != 1 or 'kpi-packed-model-controls-' not in entries[0]:
        raise RuntimeError('selected public-control resource scope absent')
    scope = Path('/sys/fs/cgroup') / entries[0].lstrip('/')
    memory, cpu = (scope / 'memory.max').read_text().strip(), (scope / 'cpu.max').read_text().strip()
    quota, period = cpu.split()
    if memory != str(2 * 1024**3) or quota == 'max' or int(quota) > int(period):
        raise RuntimeError('selected public-control resource scope changed')
    args.output.mkdir(parents=True, exist_ok=False)
    build = json.loads((args.reader.parent / 'BUILD-RESULT.json').read_text())
    reader_sha = digest_file(args.reader)[0]
    if not build['success'] or build['link']['binary_sha256'] != reader_sha:
        raise RuntimeError('selected packed-reader build/executable mismatch')
    original = json.loads((args.packed / 'MANIFEST.json').read_text())
    if original['instances'] != 3 or original['rows'] != 28849 or original['witnesses'] != 28539:
        raise RuntimeError('mutation harness requires the selected small PUBLIC SHA fixture')
    pk_original, vk_original = args.pk.read_bytes(), args.vk.read_bytes()
    raw_a = gzip.decompress((args.packed / 'A.rows.gz').read_bytes())
    if struct.unpack('<Q', raw_a[80:88])[0] == 0:
        raise RuntimeError('first public fixture row must have a term for boundary controls')
    records = []

    def run(name, directory, pk, vk, meta_sha, expected, compare=False):
        command = [str(args.reader.resolve()), str(directory.resolve()), str(pk.resolve()),
                   str(vk.resolve()), meta_sha]
        if compare:
            command.append(str(args.original_model.resolve()))
        start = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True)
        (args.output / (name + '.stdout')).write_text(result.stdout)
        (args.output / (name + '.stderr')).write_text(result.stderr)
        expected_exit = 0 if expected else 1
        passed = result.returncode == expected_exit
        row = {'case': name, 'expected_accepted': expected, 'exit': result.returncode,
               'passed': passed, 'seconds': time.monotonic() - start}
        if expected:
            try:
                row['public_reader_result'] = json.loads(result.stdout)
                if row['public_reader_result'].get('admitted') is not True or \
                   row['public_reader_result'].get('full_original_equivalence') is not compare:
                    row['passed'] = False
            except json.JSONDecodeError:
                row['passed'] = False
        records.append(row)
        if not row['passed']:
            raise RuntimeError('public packed control failed: ' + name)

    baseline_rss = 0
    if args.baseline_receipt:
        baseline = json.loads(args.baseline_receipt.read_text())
        accepted = baseline['public_result']
        if baseline['exit'] != 0 or accepted.get('admitted') is not True or \
           accepted.get('full_original_equivalence') is not True or \
           accepted['packed_model_sha256'] != original['packed_model_sha256']:
            raise RuntimeError('previous exact-equivalence receipt mismatch')
        baseline_rss = accepted['max_rss_KiB']
        records.append({'case': 'full-exact-row-and-query-equivalence', 'passed': True,
                        'reused_passing_receipt_sha256': digest_file(args.baseline_receipt)[0],
                        'selected_reader_sha256': reader_sha, 'public_reader_result': accepted})
    else:
        run('full-exact-row-and-query-equivalence', args.packed, args.pk, args.vk,
            original['packed_model_sha256'], True, compare=True)
    run('wrong-selected-root', args.packed, args.pk, args.vk, '0' * 64, False)

    def case(name, edit_record=None, edit_raw=None, edit_compressed=None,
             edit_pk=None, edit_vk=None, edit_meta=None, expected=False):
        directory = args.output / name
        directory.mkdir()
        record = copy.deepcopy(original)
        for axis in 'ABC':
            shutil.copyfile(args.packed / (axis + '.rows.gz'), directory / (axis + '.rows.gz'))
        pk, vk = args.pk, args.vk
        if edit_raw is not None or edit_compressed is not None:
            raw = edit_raw(raw_a) if edit_raw else raw_a
            compressed = gzip.compress(raw, compresslevel=1, mtime=0)
            if edit_compressed:
                compressed = edit_compressed(compressed)
            (directory / 'A.rows.gz').write_bytes(compressed)
            record['axes'][0].update(raw_sha256=sha(raw), raw_bytes=len(raw),
                compressed_sha256=sha(compressed), compressed_bytes=len(compressed))
        if edit_pk is not None:
            data = edit_pk(pk_original)
            pk = directory / 'pk.bin'; pk.write_bytes(data)
            record.update(pk_sha256=sha(data), pk_bytes=len(data))
        if edit_vk is not None:
            data = edit_vk(vk_original)
            vk = directory / 'vk.bin'; vk.write_bytes(data)
            record.update(vk_sha256=sha(data), vk_bytes=len(data))
        if edit_record:
            edit_record(record)
        encoded = metadata_bytes(record)
        if edit_meta:
            encoded = edit_meta(encoded)
        (directory / 'model.meta').write_bytes(encoded)
        run(name, directory, pk, vk, sha(encoded), expected)

    def replace(data, offset, encoded):
        output = bytearray(data); output[offset:offset + len(encoded)] = encoded
        return bytes(output)

    case('axis-label-mismatch', edit_raw=lambda b: replace(b, 16, struct.pack('<Q', 1)))
    case('axis-field-mismatch', edit_raw=lambda b: replace(b, 24, (FR - 1).to_bytes(32, 'little')))
    case('axis-slot-count-mismatch', edit_raw=lambda b: replace(b, 56, struct.pack('<Q', 4)))
    case('row-arity-overflow', edit_raw=lambda b: replace(b, 80, b'\xff' * 8))
    case('coefficient-Fr-alias', edit_raw=lambda b: replace(b, 88, FR.to_bytes(32, 'little')))
    case('column-outside-model', edit_raw=lambda b: replace(b, 120,
        struct.pack('<Q', original['instances'] + original['witnesses'])))
    case('extra-decoded-row-byte', edit_raw=lambda b: b + b'\0')
    case('truncated-decoded-rows', edit_raw=lambda b: b[:-1])
    case('concatenated-gzip-member', edit_compressed=lambda b: b + gzip.compress(b'', mtime=0))
    case('gzip-trailing-garbage', edit_compressed=lambda b: b + b'TRAILING')
    case('gzip-invalid-CRC', edit_compressed=lambda b: replace(b, len(b) - 8,
        bytes([b[-8] ^ 1]) + b[-7:-4]))
    case('wrong-matrix-fingerprint', edit_record=lambda r: r.update(matrix_fingerprint='0' * 64))
    case('unknown-metadata-policy', edit_meta=lambda b: replace(b, 16, struct.pack('<Q', 99)))
    case('metadata-trailing-byte', edit_meta=lambda b: b + b'\0')
    case('public-prefix-Fr-alias', edit_meta=lambda b: replace(b, 672 + 32, FR.to_bytes(32, 'little')))
    case('public-prefix-ONE-mismatch', edit_meta=lambda b: replace(b, 672, (2).to_bytes(32, 'little')))
    vk_bytes = len(vk_original)
    case('PK-query-count-mismatch', edit_pk=lambda b: replace(b, vk_bytes + 64,
        struct.pack('<Q', original['instances'] + original['witnesses'] - 1)))
    case('PK-trailing-byte', edit_pk=lambda b: b + b'\0')
    case('VK-prefix-mismatch', edit_vk=lambda b: bytes([b[0] ^ 1]) + b[1:])
    identity = b'\0' * 31 + b'\x40'
    bad_flags = b'\0' * 31 + b'\xc0'
    for name, point in [('base-identity-policy', identity), ('sign-plus-infinity', bad_flags),
                        ('base-Fq-alias', FQ.to_bytes(32, 'little'))]:
        case(name, edit_pk=lambda b, p=point: replace(b, 0, p),
             edit_vk=lambda b, p=point: replace(b, 0, p))
    nonsquare_x = next(x for x in range(100) if pow((x**3 + 3) % FQ, (FQ - 1) // 2, FQ) == FQ - 1)
    point = nonsquare_x.to_bytes(32, 'little')
    case('base-nonsquare-curve', edit_pk=lambda b: replace(b, 0, point),
         edit_vk=lambda b: replace(b, 0, point))

    def mode2(record):
        record.update(prefix_mode=2, public_prefix=[], origin_model_sha256='0' * 64,
                      derived_outputs=2,
                      prefix_recipe_sha256=sha(b'PUBLIC_STRUCTURAL_RECIPE_NOT_FINANCIAL_EXECUTION'),
                      prefix_layout_sha256=sha(b'PUBLIC_STRUCTURAL_LAYOUT_NOT_FINANCIAL_EXECUTION'))

    case('derived-policy-values-absent-structural-only', edit_record=mode2, expected=True)
    case('derived-policy-recipe-missing', edit_record=mode2,
         edit_meta=lambda b: replace(b, 680, b'\0' * 32))
    result = {'schema': 'kpi-packed-public-model-controls/v1', 'controls': records,
              'passed': all(row['passed'] for row in records), 'control_count': len(records),
              'reader_sha256': reader_sha,
              'resources': {'memory_max_bytes': int(memory), 'cpu_max': cpu},
              'packed_model_sha256': original['packed_model_sha256'],
              'maximum_child_rss_KiB': max(baseline_rss, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss),
              'private_input_or_MPC_or_setup_executed': False,
              'financial_or_privacy_qualification': False}
    (args.output / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
