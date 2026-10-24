#!/usr/bin/env python3
"""Copy one fixed combined PUBLIC runtime; execute none of its members."""
import argparse
import os
from pathlib import Path
import stat

from public import ROOT, checked, digest, encoded, fields, need, parse, sha, write_new

BASE_SHA = '0a2d5964f998f6e26e1bee4872e857470493a0deb3c74f54d26e11ff4d24b6c7'
LIVE_SHA = 'c14ae7f00beb0f78f21b2c28f50daa79a9cc54407dc51053ad737145cb91e402'
CHAIN_SHA = '83053db87ba088fa8734aa6acf59896fddb7c538c8dbb310feaa6cbbfa3de7f9'
PROFILE_SHA = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
CONTRACT_SHA = 'a4835dacbcb77ab38a31a686c7f9aee1d283ae9e75125aa27d453601ecbc6ae4'
REPLAY_SHA = '2f8985eb7138ddd24a745f601b4f9c062f07e132728d1c4088c65d97a45edb56'
HELPER = 'poc/current-wrapper-runtime/vendor/software_bundle.py'
HELPER_SHA = 'b3e933ca76cfad21e70b50568824b6f9fff3034c58c4cbf5d8d36d7932e1a705'
OWN = ('public.py', 'journal.py', 'owner_journal.py', 'ledger.py', 'live_contracts.py',
       'preflight.py', 'journal_cli.py', 'submit.mjs', 'offline_sdk.mjs', 'runner.py')
SDK = {'kaspa.js': '6d92cb305d0cc2eb26de9e305b7f7a8c17daa130ad478f0b340b50490557dbcf',
       'kaspa_bg.wasm': 'c9657568610ae1d305bc2e1cf85208ceba0d1a7893c4057b38caa8add2ffb0f5',
       'package.json': '8b61fefaba842c41b805291d95b2f9e81778ec590813a6c34eddcd316659b8d0'}
KINDS = {'source', 'cargo-vendor', 'build-config', 'public-metadata',
         'selected-executable', 'runtime-source', 'public-canary'}


class Exclusions:
    """Metadata only for two original four-owner namespaces; never open them."""
    def __init__(self, trial_roots):
        roots = tuple(checked(root) for root in trial_roots)
        need(len(roots) == len(set(roots)) == 2, 'two-distinct-exclusion-trials')
        directories, identities = [], set()
        for root in roots:
            for role in ('A', 'B', 'C', 'D'):
                folder = checked(root / 'owners' / role)
                need(folder.is_dir(), 'original-owner-directory-metadata')
                backup = checked(folder / 'backup.json')
                info = backup.lstat()
                need(stat.S_ISREG(info.st_mode), 'original-backup-file-metadata')
                identities.add((info.st_dev, info.st_ino)); directories.append(folder)
        need(len(identities) == 8, 'eight-distinct-original-backup-identities')
        self.directories, self.identities = tuple(directories), frozenset(identities)

    def guard(self, paths):
        result = []
        for name in paths:
            path = checked(name)
            need(all(not path.is_relative_to(folder) for folder in self.directories),
                 'public-input-inside-original-owner-directory')
            before = path.lstat()
            need(stat.S_ISREG(before.st_mode)
                 and (before.st_dev, before.st_ino) not in self.identities,
                 'public-input-original-backup-alias')
            result.append((path, before))
        return tuple(result)

    def read(self, path, expected):
        sha(expected)
        ((path, before),) = self.guard((path,))
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            need(stat.S_ISREG(opened.st_mode)
                 and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino)
                 and (opened.st_dev, opened.st_ino) not in self.identities,
                 'public-input-swapped-before-first-byte')
            with os.fdopen(os.dup(fd), 'rb') as source:
                raw = source.read()
            after = os.fstat(fd)
            names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(tuple(getattr(before, name) for name in names) ==
                 tuple(getattr(after, name) for name in names)
                 and len(raw) == before.st_size and digest(raw) == expected,
                 'stable-exact-public-member')
            return raw
        finally:
            os.close(fd)


def relative(name):
    need(type(name) is str and name and '\\' not in name and '\0' not in name,
         'public-relative-path')
    path = Path(name)
    need(not path.is_absolute() and '..' not in path.parts and str(path) == name,
         'canonical-public-relative-path')
    return name


def rows(value, *, typed=False):
    need(type(value) is dict and type(value.get('files')) is list and value['files'],
         'finite-public-source-selection')
    result = {}
    for row in value['files']:
        if typed:
            fields(row, ('kind', 'path', 'bytes', 'sha256'), 'typed-public-base-entry')
            need(row['kind'] in KINDS, 'public-base-entry-kind')
        else:
            fields(row, ('path', 'bytes', 'sha256'), 'public-source-freeze-entry')
        name = relative(row['path'])
        need(name not in result and type(row['bytes']) is int and row['bytes'] >= 0,
             'unique-public-entry-and-length')
        sha(row['sha256']); result[name] = row
    return result


def stage(a):
    excluded = Exclusions(a.exclude_trial_directory)
    base, output = checked(a.base), checked(a.output)
    need(not output.exists() and not output.is_relative_to(ROOT)
         and not output.is_relative_to(base) and not base.is_relative_to(output)
         and all(not output.is_relative_to(folder) for folder in excluded.directories),
         'fresh-output-separate-from-existing-base-code-and-private-owners')
    documents = (base / 'SOFTWARE-BUNDLE.json', a.live_source_freeze, a.chain_source_freeze)
    excluded.guard(documents)
    base_raw = excluded.read(documents[0], BASE_SHA)
    live_raw = excluded.read(documents[1], LIVE_SHA)
    chain_raw = excluded.read(documents[2], CHAIN_SHA)
    base_doc, live_doc, chain_doc = (parse(raw) for raw in (base_raw, live_raw, chain_raw))
    fields(base_doc, ('schema', 'classification', 'files'), 'typed-public-base-inventory')
    need(base_doc['schema'] == 'kpx4-public-software-bundle/v1'
         and base_doc['classification'] == 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY'
         and live_doc['schema'] == 'kpx6-four-wallet-live-source-freeze/v1'
         and chain_doc['schema'] == 'kpx5-gn2-chain-source-freeze/v1', 'selected-public-document-schemas')
    selected, live, chain = rows(base_doc, typed=True), rows(live_doc), rows(chain_doc)
    need(len(selected) == 42
         and selected['runtime-source/poc/four-wallet-lifecycle/contracts.py']['sha256'] == CONTRACT_SHA
         and selected['runtime-source/poc/four-wallet-chain/chain_replay.py']['sha256'] == REPLAY_SHA
         and live_doc['selected_chain_replay_sha256'] == REPLAY_SHA,
         'coherent-owner-source03-chain02-live02')
    for name, row in selected.items():
        if name.startswith('runtime-source/poc/four-wallet-chain/'):
            need(row['sha256'] == chain[name[len('runtime-source/'):]]['sha256'],
                 'complete-existing-chain02-byte-join')
    need(selected['selection/financial-profile.json']['sha256'] == PROFILE_SHA,
         'selected-financial-profile41c')
    for name, expected in SDK.items():
        need(selected['runtime-sdk/' + name]['sha256'] == expected, 'exact-current-SDK3-pins')
    additions = []
    for name in OWN:
        source = 'poc/four-wallet-live/' + name
        additions.append((source, live[source]))
    for name in ('anchor.mjs', 'fetch.mjs'):
        source = 'poc/four-wallet-chain/' + name
        additions.append((source, chain[source]))
    additions.append((HELPER, {'sha256': HELPER_SHA,
        'bytes': (ROOT / HELPER).lstat().st_size}))
    members = [(name, base / name, row) for name, row in selected.items()]
    for source, row in additions:
        name = 'runtime-source/' + source
        need(name not in selected, 'no-source-overwrite-in-combined-installation')
        members.append((name, ROOT / source, {'kind': 'runtime-source', 'path': name,
                       'bytes': row['bytes'], 'sha256': row['sha256']}))
    # All eight original files/directories were excluded before document reads;
    # every selected member's metadata is excluded before the first member read.
    excluded.guard(path for _, path, _ in members)
    need(all(path.stat().st_mode & 0o222 == 0 for _, path, _ in members[:42]),
         'existing-selected-base-members-readonly')
    profile = parse(excluded.read(base / 'selection/financial-profile.json', PROFILE_SHA))
    for role in ('prover', 'native-validator', 'node', 'crypto'):
        row, executable = selected['runtime/' + role], profile['executables'][role]
        need(row['kind'] == 'selected-executable' and row['sha256'] == executable['sha256']
             and row['bytes'] == executable['bytes'], 'exact-profile-selected-executable-join')
    output.mkdir(parents=True, mode=0o700)
    final = []
    for name, original, row in members:
        raw = excluded.read(original, row['sha256'])
        need(len(raw) == row['bytes'], 'exact-public-member-length')
        target = output / name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_new(target, raw); target.chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
        final.append(dict(row))
    inventory = {'schema': 'kpx4-public-software-bundle/v1',
        'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
        'files': sorted(final, key=lambda row: row['path'])}
    raw_inventory = encoded(inventory) + b'\n'
    write_new(output / 'SOFTWARE-BUNDLE.json', raw_inventory)
    (output / 'SOFTWARE-BUNDLE.json').chmod(0o400)
    result = {'schema': 'kpx6-four-wallet-combined-public-runtime-staging/v1',
        'public_software_files': len(final), 'public_software_bytes': sum(row['bytes'] for row in final),
        'inventory_sha256': digest(raw_inventory), 'base_inventory_sha256': BASE_SHA,
        'live_source_freeze_sha256': LIVE_SHA, 'chain_source_freeze_sha256': CHAIN_SHA,
        'financial_profile_sha256': PROFILE_SHA, 'lifecycle_contract_sha256': CONTRACT_SHA,
        'chain_replay_sha256': REPLAY_SHA, 'SDK3_pins': SDK,
        'excluded_original_backup_file_count': 8, 'excluded_original_owner_directory_count': 8,
        'existing_runtime_or_publication_modified': False,
        'original_backup_PK_key_or_witness_read': False,
        'staged_source_ELF_SDK_native_prover_or_network_executed': False,
        'accepted_backing_payout_or_complete_trial_readiness': False}
    write_new(output / 'STAGING-RESULTS.json', result)
    (output / 'STAGING-RESULTS.json').chmod(0o400)
    return result


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'output', 'live-source-freeze', 'chain-source-freeze'):
        p.add_argument('--' + name, required=True, type=Path)
    p.add_argument('--exclude-trial-directory', required=True, action='append', type=Path)
    return p


if __name__ == '__main__':
    p = parser()
    try:
        result = stage(p.parse_args())
        print(encoded(result).decode())
    except (ValueError, OSError, KeyError, TypeError):
        p.exit(2, 'combined public runtime staging incomplete; no staged member executed\n')
