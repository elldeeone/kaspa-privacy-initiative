#!/usr/bin/env python3
"""Known-public byte/manifest controls; never a final packet or owner worker."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import time


def run(source_pin, output):
    read = runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')['read']
    source = Path(__file__).absolute().with_name('split_public_data_archive.py')
    raw = read(str(source), source_pin)
    module = {'__name__': '_known_public_archive_split', '__file__': str(source)}
    exec(compile(raw, str(source), 'exec'), module)
    controls = []

    def check(name, function):
        function()
        controls.append({'name': name, 'passed': True})

    def reject(name, function):
        try:
            function()
        except (ValueError, OSError, TypeError, KeyError, AssertionError):
            controls.append({'name': name, 'passed': True})
            return
        raise AssertionError('known-public rejection missing: ' + name)

    for size in (1, 6, 7, 8, 14, 15, 28, 29):
        data = (b'KNOWN PUBLIC ARCHIVE TRANSPORT BYTES\x00\xff' * 2)[:size]
        manifest = module['manifest_for_bytes'](data, 7)
        pieces = [data[i:i + 7] for i in range(0, len(data), 7)]
        check('exact-concatenation-boundary-%d' % size,
              lambda p=pieces, d=data, m=manifest: (
                  None if b''.join(p) == d and m['archive']['sha256'] == hashlib.sha256(d).hexdigest()
                  and all(hashlib.sha256(x).hexdigest() == row['sha256']
                          for x, row in zip(p, m['parts']))
                  else (_ for _ in ()).throw(AssertionError('byte transport changed'))))
    base = module['manifest_for_bytes'](b'KNOWN PUBLIC MULTIPART FIXTURE DATA', 7)
    for name, mutate in [
        ('wrong-domain', lambda v: v.update(domain_hex32='00' * 32)),
        ('extra-field', lambda v: v.update(local_source='/unselected')),
        ('missing-part', lambda v: v['parts'].pop()),
        ('duplicate-part', lambda v: v['parts'].append(copy.deepcopy(v['parts'][-1]))),
        ('wrong-order', lambda v: v['parts'].reverse()),
        ('unsafe-part-name', lambda v: v['parts'][0].update(name='../data.tar.part-00000')),
        ('wrong-part-size', lambda v: v['parts'][0].update(bytes=6)),
        ('empty-part', lambda v: v['parts'][-1].update(bytes=0)),
        ('bool-count', lambda v: v['parts'][0].update(bytes=True)),
        ('float-count', lambda v: v['archive'].update(bytes=1.0)),
        ('bad-part-pin', lambda v: v['parts'][0].update(sha256='x' * 64)),
        ('wrong-archive-name', lambda v: v['archive'].update(name='other.tar')),
    ]:
        value = copy.deepcopy(base)
        mutate(value)
        reject(name, lambda v=value: module['validate_manifest'](v))
    for value in (0, -1, True, 1.0, 1 << 31):
        reject('invalid-part-width-' + repr(value), lambda v=value: module['part_size'](v))
    reject('empty-public-archive', lambda: module['manifest_for_bytes'](b'', 7))
    reject('mutable-public-byte-array', lambda: module['manifest_for_bytes'](bytearray(b'PUBLIC'), 7))
    reject('generic-output-parent', lambda: module['fresh_output']('/dev/shm/unselected-public-output'))
    reject('private-source-refused-before-read', lambda: module['split_archive'](
        '/var/tmp/kpi-owner-private-lifecycle-01/private/data.tar', '00' * 32, 1,
        '/var/tmp/kpi-local-private-payment-01/publication-release/not-created-by-negative-control'))

    # Tiny real public-file integration. Its source and every retained part are
    # read through unchanged helper09. No final archive is selected.
    parent = module['OUTPUT_PARENTS'][0]
    identity = str(time.time_ns())
    fixture = parent / ('split-known-public-input-' + identity)
    fixture.mkdir(mode=0o700)
    data = b'KNOWN PUBLIC CANONICAL-TRANSPORT FIXTURE\x00\xff' * 17
    archive = fixture / 'data.tar'
    module['write_new'](archive, data)
    destination = parent / ('split-known-public-output-' + identity)
    result = module['split_archive'](archive, hashlib.sha256(data).hexdigest(), len(data), destination, 257)
    body = read(result['manifest']['path'], result['manifest']['sha256'])
    manifest = json.loads(body)
    module['validate_manifest'](manifest)
    combined = bytearray()
    for row in manifest['parts']:
        piece = read(str(destination / row['name']), row['sha256'])
        assert len(piece) == row['bytes']
        combined.extend(piece)
    check('guarded-public-file-roundtrip', lambda: None if bytes(combined) == data
          else (_ for _ in ()).throw(AssertionError('roundtrip bytes changed')))
    reject('existing-output-refused', lambda: module['split_archive'](
        archive, hashlib.sha256(data).hexdigest(), len(data), destination, 257))
    reject('wrong-whole-pin-refused', lambda: module['split_archive'](
        archive, '00' * 32, len(data), parent / ('split-wrong-pin-' + identity), 257))
    reject('wrong-whole-size-refused', lambda: module['split_archive'](
        archive, hashlib.sha256(data).hexdigest(), len(data) + 1,
        parent / ('split-wrong-size-' + identity), 257))
    report = {'schema': 'kpxa-known-public-archive-split-controls/v1',
              'classification': 'KNOWN_PUBLIC_SYNTHETIC_BYTES_NOT_ACCEPTED_HISTORY',
              'source_sha256': source_pin, 'controls': controls, 'all_passed': True,
              'actual_archive_or_private_original_or_network_selected': False,
              'fixture_output': str(destination), 'part_manifest_sha256': result['manifest']['sha256']}
    payload = module['encoded'](report)
    target = Path(output)
    module['write_new'](target, payload)
    assert read(str(target), hashlib.sha256(payload).hexdigest()) == payload
    print(json.dumps({'path': str(target), 'bytes': len(payload),
                      'sha256': hashlib.sha256(payload).hexdigest(),
                      'controls': len(controls), 'all_passed': True}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-sha256', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    run(args.source_sha256, args.output)
