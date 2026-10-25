#!/usr/bin/env python3
"""Build one finite public-only recovery software archive; never publish it.

All source and asset bytes enter through guard09. The three public proving keys
are described from the pinned selection, but are not opened or put in this tar.
No wallet, accepted history, private parent or directory tree is collected.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import runpy
import tarfile

GUARD = '/var/tmp/kpi-root-guard-helper-09.py'
DOMAIN = 'b8623a6244a81ed42c43f95aac77eccd927fa584db02a1a829faa3c857fed38c'
ASSETS = Path('/var/tmp/kpi-local-private-payment-01/assets')
STAGE = ASSETS / 'wallet-public-fixture-stage-03'
SELECTED_SHA = '713554f69e328d9462f62fd4a30207f7ff1f6f5ef2db40449f7daf172e79f4e8'
WALLET_SHA = 'edcc3179315a9b256b62f7ce22639ff1323c14444a43e426d292db8a294faf22'
FEE_SHA = '30a009f709857e929c3a71c594cde328c99346b721c46e63ba28b2150438c307'

# Explicit public source mapping. No glob, recursion, Git status selection or
# opportunistic dependency discovery is used by this release producer.
SOURCE = (
    ('wallet/worker.py', '4707057d33ca1a5154017c9bdff5f75c14fccf6398f8c5cdf9812461a6239785'),
    ('wallet/payment.py', '5ff0774fd1bb67ebc5ed5ec246ce2434082bfc4ce82dad9e58047b34232d2bda'),
    ('wallet/support.py', '32bea2787af89c97a94f22202758ac145a6b1f2ec29385b971f2557a9af58843'),
    ('recovery/history.py', '3e637e52ff598ef875b9b50c129e5b8da2057726458af631c788b13cacbab542'),
    ('integration/trees.py', '4936a7b571187469755b9aafae275c61ac589eb70ecd6a8efbced862d8c3bd3b'),
    ('integration/native_fees.py', '2d57a332b0c398b35add092650e6dea7f018540fa25461c2d41e6daf93f4ac55'),
    ('verification/wire.py', '6727e00a143596dbd31abf06c7fd5a2ceafa07082d6e3e6de47fa389a826def8'),
    ('verification/native_case.py', '8e8173f99c2122f6cdeecf9dcd162d98c3413bec9052acc73f9cd93a7925fbe2'),
    ('verification/native/validate_selected_case.py', '2723c4ff5e597cc7b258ce381d2e55d814ce41f58654866db27fe62b380a8a6d'),
)
PKS = {
    'spend': (601785008, '45ae6cd5110b09466c19de8c1f0cf89ec93f6c0d853f232773801e19bd0d62bd'),
    'output': (85578096, '887573cf53559e969007857cd50284db9948204390389fc6e85dd75644b1241d'),
    'exit': (591206448, 'fc531fcdb192dba2123bb13a02f78aa019cd5299e6905ad7ab4a5c6afdf481b1'),
}


def need(condition, code):
    if not condition:
        raise ValueError(code)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def parse(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate-public-JSON-field')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite-public-JSON'))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw, mode=0o400):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def prepare(repo, output):
    repo, output = Path(repo).absolute(), Path(output).absolute()
    need('..' not in repo.parts and '..' not in output.parts, 'canonical-selected-directory')
    need(output.parent == Path('/var/tmp/kpi-local-private-payment-01/recovery-release')
         and re.fullmatch(r'software-[0-9]{2}', output.name), 'finite-public-release-output')
    need(not any(p.is_symlink() for p in (repo, *repo.parents, output, *output.parents)), 'no-symlink-ancestry')
    need(not output.exists(), 'fresh-release-output-required')
    read = runpy.run_path(GUARD)['read']
    payload, sources = {}, []

    def add(name, path, pin, mode=0o400):
        name = str(PurePosixPath(name))
        need(name and not name.startswith('/') and '..' not in PurePosixPath(name).parts
             and name not in payload, 'finite-unique-archive-name')
        raw = read(str(path), pin)
        payload[name] = (raw, mode)
        sources.append({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                        'archive_path': name, 'mode': format(mode, '04o')})
        return raw

    selected_raw = read(str(ASSETS / 'relation/SELECTED.json'), SELECTED_SHA)
    selected = parse(selected_raw)
    need(selected['schema'] == 'kpxa-local-private-relation-selection/v1'
         and selected['domain_hex32'] == DOMAIN, 'new-relation-selection')
    wallet_raw = read(str(STAGE / 'WALLET-ASSETS.json'), WALLET_SHA)
    fees_raw = read(str(STAGE / 'NATIVE-FEE-POLICY.json'), FEE_SHA)
    wallet, fees = parse(wallet_raw), parse(fees_raw)
    need(wallet['schema'] == 'kpxa-local-wallet-assets/v1'
         and wallet['domain_hex32'] == DOMAIN
         and fees['schema'] == 'kpxa-native-fee-policy/v1', 'selected-wallet-fee-identities')

    base = repo / 'poc/local-private-payment'
    for name, pin in SOURCE:
        add(name, base / name, pin)
    add('recipient.py', Path(wallet['recipient']['path']), wallet['recipient']['sha256'])
    for name, row in [('relation', wallet['relation']), ('crypto', wallet['crypto']),
                      ('native-codec', fees['codec'])]:
        add('bin/' + name, Path(row['path']), row['sha256'], 0o500)
    add('bin/native-engine', ASSETS / 'verification/native-engine',
        '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061', 0o500)

    release_keys = []
    for role in ('spend', 'output', 'exit'):
        entry, wanted = selected['roles'][role], PKS[role]
        need((entry['pk_bytes'], entry['pk_sha256']) == wanted, 'exact-selected-public-PK-metadata')
        need(wallet[role]['pk'] == entry['pk_path']
             and wallet[role]['pk_sha256'] == entry['pk_sha256']
             and wallet[role]['manifest'] == entry['manifest_path']
             and wallet[role]['manifest_sha256'] == entry['manifest_sha256'], 'same-wallet-role-selection')
        manifest = parse(add('parameters/' + role + '/manifest.json',
                             Path(entry['manifest_path']), entry['manifest_sha256']))
        need(manifest['domain_hex32'] == DOMAIN and manifest['role'] == role
             and manifest['pk_bytes'] == wanted[0] and manifest['pk_sha256'] == wanted[1],
             'selected-role-manifest')
        release_keys.append({'role': role, 'asset_name': 'parameters-' + role + '.pk',
            'bytes': wanted[0], 'sha256': wanted[1],
            'namespace_path': '/public/parameters/' + role + '/parameters.pk',
            'required_for_cold_scan_and_exit': role == 'exit',
            'included_in_software_tar': False, 'PK_bytes_read_or_rehashed_by_this_producer': False})

    add('verification/component-profile.json', ASSETS / 'verification/component-profile.json',
        '9fd9651dfd96faa864705e67b9bbcf7b76503963c99d14605243859699b24018')
    add('verification/outer-selection.json', ASSETS / 'verification/outer-selection.json',
        '916c5e076dcf230644d0abf9557d17a70156963a76b1064e1f0d5468421d61e3')
    add('templates/payment-shape.bin', Path(fees['template_projection']['path']),
        fees['template_projection']['sha256'])

    # Rewrite only externally selected path fields. All immutable manifest bytes,
    # binary identities, VKs, tail, image, fees and protocol parameters stay exact.
    relocated_wallet = parse(wallet_raw)
    for key, name in [('relation', 'bin/relation'), ('crypto', 'bin/crypto'),
                      ('recipient', 'recipient.py'), ('wire', 'verification/wire.py'),
                      ('trees', 'integration/trees.py')]:
        relocated_wallet[key]['path'] = '/public/' + name
    for role in PKS:
        relocated_wallet[role]['manifest'] = '/public/parameters/' + role + '/manifest.json'
        relocated_wallet[role]['pk'] = '/public/parameters/' + role + '/parameters.pk'
    relocated_fees = parse(fees_raw)
    for key, name in [('native_case', 'verification/native_case.py'), ('codec', 'bin/native-codec'),
                      ('template_projection', 'templates/payment-shape.bin')]:
        relocated_fees[key]['path'] = '/public/' + name
    payload['WALLET-ASSETS.json'] = (encoded(relocated_wallet), 0o400)
    payload['NATIVE-FEE-POLICY.json'] = (encoded(relocated_fees), 0o400)
    need(len(payload) == 22, 'exact-22-software-payload-files')

    rows = [{'path': name, 'bytes': len(raw), 'sha256': sha(raw), 'mode': format(mode, '04o')}
            for name, (raw, mode) in sorted(payload.items())]
    inventory = encoded({'schema': 'kpxa-recovery-software-inventory/v1', 'domain_hex32': DOMAIN,
        'payload_file_count': len(rows), 'payload_bytes': sum(row['bytes'] for row in rows),
        'files': rows, 'inventory_self_hash_in_external_release_selection': True,
        'PKs_included': False, 'accepted_history_or_wallet_included': False,
        'OS_runtime_dependencies': ['Linux x86_64', 'Python3 and standard library',
            '/lib64/ld-linux-x86-64.so.2', 'libc.so.6', 'libgcc_s.so.1', 'libm.so.6', 'libstdc++.so.6'],
        'scope': 'LOCAL_SOFTWARE_PREPARATION_NOT_DOWNLOAD_RECOVERY_OR_PUBLICATION'})
    payload['INVENTORY.json'] = (inventory, 0o400)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, (raw, mode) in sorted(payload.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(raw), mode
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ''
            archive.addfile(member, io.BytesIO(raw))
    tar = stream.getvalue()
    selection = encoded({'schema': 'kpxa-recovery-software-release-preparation/v1',
        'domain_hex32': DOMAIN, 'status': 'LOCAL_PREPARED_NOT_PUBLISHED_OR_RECOVERY_TESTED',
        'archive': {'path': 'software.tar', 'bytes': len(tar), 'sha256': sha(tar), 'members': len(payload)},
        'inventory': {'path': 'INVENTORY.json', 'bytes': len(inventory), 'sha256': sha(inventory)},
        'original_public_inputs': {'relation_selection_sha256': SELECTED_SHA,
            'wallet_assets_sha256': WALLET_SHA, 'native_fee_policy_sha256': FEE_SHA},
        'relocated_selectors': {name: {'bytes': len(payload[name][0]), 'sha256': sha(payload[name][0])}
             for name in ('WALLET-ASSETS.json', 'NATIVE-FEE-POLICY.json')},
        'finite_public_sources': sources, 'separate_public_release_assets': release_keys,
        'private_reads_or_hashes': False, 'PK_bytes_read_or_rehashed': False,
        'actual_history_download_restore_replay_or_exit_executed': False,
        'Git_staging_commit_upload_or_publication': False})
    output.mkdir(parents=True, mode=0o700)
    save(output / 'software.tar', tar)
    save(output / 'INVENTORY.json', inventory)
    save(output / 'RELEASE-SELECTION.json', selection)
    return {'output': str(output), 'archive_sha256': sha(tar), 'archive_bytes': len(tar),
        'payload_files': len(rows), 'archive_members': len(payload),
        'inventory_sha256': sha(inventory), 'release_selection_sha256': sha(selection)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, default=Path(__file__).absolute().parents[3])
    p.add_argument('--output', type=Path,
        default=Path('/var/tmp/kpi-local-private-payment-01/recovery-release/software-02'))
    a = p.parse_args()
    print(json.dumps(prepare(a.repo, a.output), sort_keys=True))


if __name__ == '__main__':
    main()
