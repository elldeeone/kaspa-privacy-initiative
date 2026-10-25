#!/usr/bin/env python3
"""Map a finite downloaded recovery inventory to the existing campaign interface.

Template mode makes no acquisition claim. Materialize mode consumes an externally
pinned actual-download receipt; it never creates receipts or downloads anything.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import runpy
from urllib.parse import urlsplit

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
INVENTORY_SHA = '707cff8442c1617fc526d9d83659dcdba32d966d4dc89d0f1f27aee825822376'
SOFTWARE_SHA = 'd85ad87f7b3094c5ee8747ba8f3c5e774895bd63f958fd1ca5fd845b1095d89a'
SOFTWARE_BYTES = 29_849_600
EXIT_SHA = 'fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1'
EXIT_BYTES = 591_206_448


def need(value):
    if not value:
        raise ValueError('cold-campaign-selector-refused')


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value)
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_float=lambda _: need(False), parse_constant=lambda _: need(False))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absolute(value):
    path = Path(value)
    need(type(value) is str and path.is_absolute() and '..' not in path.parts
         and str(path) == value and '\0' not in value and '\\' not in value)
    return path


def inventory_rows(raw):
    need(sha(raw) == INVENTORY_SHA)
    value = parse(raw)
    need(value['schema'] == 'kpxa-recovery-software-inventory/v1'
         and value['domain_hex32'] == DOMAIN and value['PKs_included'] is False
         and value['payload_file_count'] == 22 and len(value['files']) == 22)
    rows = {}
    for row in value['files']:
        need(set(row) == {'path', 'sha256', 'bytes', 'mode'})
        name = PurePosixPath(row['path'])
        need(type(row['path']) is str and not name.is_absolute() and name.parts
             and str(name) == row['path'] and '..' not in name.parts
             and '\\' not in row['path'] and '\0' not in row['path']
             and row['path'] not in rows and row['mode'] in ('0400', '0500'))
        rows[row['path']] = row
    rows['INVENTORY.json'] = {'path': 'INVENTORY.json', 'sha256': INVENTORY_SHA,
                              'bytes': len(raw), 'mode': '0400'}
    return rows


def selector(root, receipt_path, receipt_sha, rows, exit_path):
    root, receipt_path, exit_path = map(absolute, (root, receipt_path, exit_path))
    need(type(receipt_sha) is str and len(receipt_sha) == 64
         and all(c in '0123456789abcdef' for c in receipt_sha))
    files = [{'target': '/public/' + name, 'path': str(root / name),
              'sha256': row['sha256'], 'executable': row['mode'] == '0500'}
             for name, row in sorted(rows.items())]
    files.append({'target': '/public/parameters/exit/parameters.pk',
                  'path': str(exit_path), 'sha256': EXIT_SHA, 'executable': False})
    by_target = {row['target']: row for row in files}
    targets = {'validator': '/public/verification/native/validate_selected_case.py',
               'engine': '/public/bin/native-engine', 'codec': '/public/bin/native-codec',
               'component': '/public/verification/component-profile.json',
               'selection': '/public/verification/outer-selection.json'}
    native = set(targets.values()) | {'/public/verification/native_case.py',
                                     '/public/verification/wire.py'}
    need(len(files) == len(by_target) == 24 and len(native) == 7 and native <= set(by_target))
    return {'download_receipt': {'path': str(receipt_path), 'sha256': receipt_sha},
        'files': files, 'worker_target': '/public/wallet/worker.py',
        'wallet_assets_target': '/public/WALLET-ASSETS.json',
        'wallet_assets_sha256': rows['WALLET-ASSETS.json']['sha256'],
        'native_fee_policy_target': '/public/NATIVE-FEE-POLICY.json',
        'native_fee_policy_sha256': rows['NATIVE-FEE-POLICY.json']['sha256'],
        'native_files': [by_target[name] for name in sorted(native)], 'native_targets': targets,
        'native_selectors': {name: {key: by_target[target][key] for key in ('path', 'sha256')}
                             for name, target in targets.items() if name != 'validator'}}


def from_receipt(read, receipt_path, receipt_sha):
    receipt_path = str(absolute(receipt_path))
    raw = read(receipt_path, receipt_sha)
    value = parse(raw)
    need(set(value) == {'schema', 'classification', 'transport', 'inventory', 'artifacts', 'files'}
         and value['schema'] == 'kpxa-downloaded-recovery-receipt/v1'
         and value['classification'] == 'ACTUAL_TOR_TLS_DOWNLOAD_AND_INVENTORY_VERIFIED'
         and value['transport'] == 'TOR_SOCKS5H_TLS')
    need(set(value['inventory']) == {'path', 'sha256'} and value['inventory']['sha256'] == INVENTORY_SHA)
    root = absolute(value['inventory']['path']).parent
    raw_inventory = read(value['inventory']['path'], INVENTORY_SHA)
    rows = inventory_rows(raw_inventory)
    need(type(value['artifacts']) is list and len(value['artifacts']) == 2)
    artifacts = {}
    for row in value['artifacts']:
        need(set(row) == {'path', 'sha256', 'bytes', 'origin_url'})
        origin = urlsplit(row['origin_url'])
        need(origin.scheme == 'https' and origin.hostname and origin.username is None
             and origin.password is None and not origin.fragment)
        path = absolute(row['path'])
        need(row['sha256'] not in artifacts and type(row['bytes']) is int)
        artifacts[row['sha256']] = row
    need(set(artifacts) == {SOFTWARE_SHA, EXIT_SHA}
         and artifacts[SOFTWARE_SHA]['bytes'] == SOFTWARE_BYTES
         and artifacts[EXIT_SHA]['bytes'] == EXIT_BYTES)
    expected = {(str(root / name), row['sha256']): row['bytes'] for name, row in rows.items()}
    exit_path = artifacts[EXIT_SHA]['path']
    expected[(exit_path, EXIT_SHA)] = EXIT_BYTES
    actual = {}
    need(type(value['files']) is list)
    for row in value['files']:
        need(set(row) == {'path', 'sha256', 'bytes'} and type(row['bytes']) is int)
        key = (str(absolute(row['path'])), row['sha256'])
        need(key not in actual)
        actual[key] = row['bytes']
    need(actual == expected)
    # Authenticate every mounted leaf, then both retained acquisitions. The
    # receipt's honest Tor acquisition provenance remains root's trust boundary.
    verified = set()
    for (path, pin), size in expected.items():
        need(len(read(path, pin)) == size)
        verified.add((path, pin, size))
    for row in artifacts.values():
        if (row['path'], row['sha256'], row['bytes']) not in verified:
            need(len(read(row['path'], row['sha256'])) == row['bytes'])
    return selector(str(root), receipt_path, receipt_sha, rows, exit_path)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('template', 'materialize'))
    p.add_argument('--receipt', required=True)
    p.add_argument('--receipt-sha256', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--download-root')
    p.add_argument('--exit-pk')
    p.add_argument('--inventory', default='/var/tmp/kpi-local-private-payment-01/recovery-release/software-02/INVENTORY.json')
    a = p.parse_args()
    try:
        read = runpy.run_path(GUARD)['read']
        if a.mode == 'materialize':
            value = from_receipt(read, a.receipt, a.receipt_sha256)
        else:
            rows = inventory_rows(read(a.inventory, INVENTORY_SHA))
            value = {'schema': 'kpxa-cold-campaign-selector-template/v1',
                'classification': 'TEMPLATE_ONLY_NOT_DOWNLOADED_OR_CAMPAIGN_RELEASED',
                'cold': selector(a.download_root, a.receipt, a.receipt_sha256, rows, a.exit_pk)}
        output = absolute(a.output)
        raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as target:
            target.write(raw)
        print(json.dumps({'output_sha256': sha(raw), 'template_only': a.mode == 'template',
                          'downloads_uploads_or_original_reads': False}, sort_keys=True))
    except Exception:
        p.exit(2, 'Cold selector refused; no acquisition or private operation performed.\n')


if __name__ == '__main__':
    main()
