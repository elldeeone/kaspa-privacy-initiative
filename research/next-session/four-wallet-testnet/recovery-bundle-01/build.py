#!/usr/bin/env python3
"""Package selected public bytes only; never run a wallet, prover or network."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import types

PROFILE = '41c60779f005ebdae27e9f154950478fb7ae8bf613dec7bf9753056600cb6b5a'
BASE = 'a4442e933608f8cca58943846a25fb9c06c03c5128ce1044504329cbffbfc100'
GUARD = 'da559335c0e071d15b7daee5cd4d256776295c934d5db569c1e13c3d2bf83195'
PK = '793cf0bf9456cc4187719b8e23dcf35402410c5c9006ac4c06de303d2a5a3ee0'
PARAMETERS = '923900f528483e20e1de4134ae4ef786f76cf3ce947e37058bb1e34d7c8a7e8c'
VK = '2b385052a622057c1863c3f71930fd040e82e1885cbaac914abf3348e7734406'
SOFTWARE_HELPER = 'b3e933ca76cfad21e70b50568824b6f9fff3034c58c4cbf5d8d36d7932e1a705'
UNPACK_HELPER = '19c41c96b41c968a0ed0dfefe3a38fe855a323ce366b1f1aba46ef155a6d2a22'
EXTRA = {
    'poc/four-wallet-lifecycle/run_owner.py':
        'e023737591a305ac79a06eb8c6fb315df9ff7326a87321f9caffeca04a48cd7e',
    'poc/four-wallet-lifecycle/installation.py':
        '5158c1e39038454a6db1d7426acea39672283e9cc19cffdc9832499526b302b9',
    'poc/current-wrapper-runtime/vendor/unpack_bundle.py': UNPACK_HELPER,
}
CLEAN = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC'}


def need(value, label):
    if not value:
        raise ValueError(label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def attrs(info):
    return tuple(getattr(info, name) for name in
                 ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def checked(value):
    path = Path(value).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'canonical-nonsymlink-path')
    return path


def load_guard(project, roots):
    """Only stat originals; exclude them before the first public source read."""
    roots = tuple(checked(root) for root in roots)
    need(len(roots) == len(set(roots)) == 2, 'two-original-trial-metadata-selectors')
    identities, directories = set(), []
    for root in roots:
        for role in 'ABCD':
            folder = checked(root / 'owners' / role)
            info = checked(folder / 'backup.json').stat()
            need(folder.is_dir() and stat.S_ISREG(info.st_mode), 'original-metadata-only')
            identities.add((info.st_dev, info.st_ino)); directories.append(folder)
    need(len(identities) == 8, 'eight-original-file-identities')
    path = checked(project / 'poc/four-wallet-profile/outer_run.py')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and (before.st_dev, before.st_ino) not in identities
         and all(not path.is_relative_to(folder) for folder in directories), 'guard-source-not-private')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as file:
        need(attrs(os.fstat(file.fileno())) == attrs(before), 'guard-source-opened-inode')
        raw = file.read(); after = os.fstat(file.fileno())
    need(attrs(after) == attrs(before) and len(raw) == before.st_size and sha(raw) == GUARD,
         'selected-stable-guard-source')
    module = types.ModuleType('_kpx6_recovery_public_guard'); module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    module.GUARD = module.PublicGuard(roots)
    return module


def stream(guard, path, expected, expected_bytes, destination=None):
    """Authenticate complete stable public bytes without loading the PK in RAM."""
    path, before = guard.GUARD.metadata(path)
    need(before.st_size == expected_bytes, 'selected-public-size-before-first-byte')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    target, count, digest = None, 0, hashlib.sha256()
    try:
        with os.fdopen(descriptor, 'rb') as file:
            opened = os.fstat(file.fileno())
            need(attrs(opened) == attrs(before)
                 and (opened.st_dev, opened.st_ino) not in guard.GUARD.inodes,
                 'selected-public-opened-inode-before-read')
            if destination is not None:
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target = destination.open('xb')
            while chunk := file.read(8 * 1024 * 1024):
                digest.update(chunk); count += len(chunk)
                if target is not None:
                    target.write(chunk)
            after = os.fstat(file.fileno())
    finally:
        if target is not None:
            target.close()
    need(attrs(after) == attrs(before) and count == expected_bytes and digest.hexdigest() == expected,
         'stable-whole-public-object-identity')
    if destination is not None:
        destination.chmod(0o400)
    return {'bytes': count, 'sha256': digest.hexdigest()}


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as file:
        file.write(raw)
    path.chmod(0o400)


def module_from_bytes(name, path, raw):
    need(name not in sys.modules, 'fresh-selected-helper-module')
    result = types.ModuleType(name); result.__file__ = str(path); sys.modules[name] = result
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def build(args):
    project, software = checked(args.project_root), checked(args.software_root)
    guard = load_guard(project, args.exclude_private_root)
    inputs = [software / 'SOFTWARE-BUNDLE.json', project / 'poc/four-wallet-profile/financial-profile.json',
              args.parameter_manifest, args.pk, *(project / name for name in EXTRA),
              project / 'poc/current-wrapper-runtime/vendor/software_bundle.py']
    for path in inputs:
        guard.GUARD.metadata(path)
    profile_raw = guard.read(inputs[1], PROFILE); profile = guard.parse(profile_raw)
    manifest_raw = guard.read(args.parameter_manifest, PARAMETERS); manifest = guard.parse(manifest_raw)
    compact = profile['compact']; vk = bytes.fromhex(compact['vk_hex328'])
    need(len(vk) == 328 and sha(vk) == VK == manifest['vk_sha256']
         and manifest['pk_sha256'] == compact['pk_sha256'] == PK
         and manifest['pk_bytes'] == compact['pk_bytes'] == 1_307_894_256
         and manifest['domain_hex32'] == profile['child_domain_hex32']
         and manifest['compiled_build_identity_sha256'] == compact['compiled_build_identity_sha256'],
         'exact-selected-profile-parameter-VK-join')
    base_raw = guard.read(inputs[0], BASE); inventory = guard.parse(base_raw)
    need(inventory['schema'] == 'kpx4-public-software-bundle/v1' and len(inventory['files']) == 68,
         'selected-immutable-68-member-base')
    rows, sources, names = [], {}, set()
    for row in inventory['files']:
        name = row['path']; relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == name
             and name not in names, 'canonical-unique-public-member')
        names.add(name); rows.append(dict(row)); sources[name] = software / name
    for name, expected in EXTRA.items():
        target = 'runtime-source/' + name; source = project / name
        need(target not in names, 'no-public-source-overwrite')
        _, info = guard.GUARD.metadata(source)
        rows.append({'kind': 'runtime-source', 'path': target, 'bytes': info.st_size, 'sha256': expected})
        sources[target] = source; names.add(target)
    for path in sources.values():
        guard.GUARD.metadata(path)
    output = guard.fresh(args.output); objects = output / 'objects'; objects.mkdir(mode=0o700)
    tree = output / 'software-tree'; tree.mkdir(mode=0o700)
    for row in rows:
        destination = tree / row['path']
        stream(guard, sources[row['path']], row['sha256'], row['bytes'], destination)
        destination.chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
    software_doc = {'schema': 'kpx4-public-software-bundle/v1',
        'classification': 'PUBLIC_BYTES_NOT_SELF_AUTHENTICATING_CODE_AUTHORITY',
        'files': sorted(rows, key=lambda row: row['path'])}
    software_raw = encoded(software_doc); save(tree / 'SOFTWARE-BUNDLE.json', software_raw)
    save(tree / 'EXTERNAL-SELECTION.json', encoded({'schema': 'kpx6-four-wallet-recovery-software-selection/v1',
        'financial_profile_sha256': PROFILE, 'software_inventory_sha256': sha(software_raw),
        'base_inventory_sha256': BASE, 'outer_prover_or_compression_assets_required_to_exit': False,
        'wallet_backups_witnesses_owner_maps_or_history_included': False,
        'currentness_backing_or_spend_authority': False,
        'external_expected_object_and_financial_digests_required': True}))
    save(tree / 'DEPENDENCY-ACQUISITION.json', encoded({'schema': 'kpx6-four-wallet-recovery-platform/v1',
        'platform': 'Linux x86_64 compatible with selected prebuilt binaries',
        'trusted_host': 'OS/system libraries, Python standard library, bwrap, zstd and TLS trust remain supplied externally.',
        'source_or_payload_executed': False, 'independent_operator_or_retention_verified': False,
        'outer_proving_compression_GPU_Rust_build_registry_or_NPM_required_to_exit': False}))
    helper_path = project / 'poc/current-wrapper-runtime/vendor/software_bundle.py'
    helper_raw = guard.read(helper_path, SOFTWARE_HELPER)
    helper = module_from_bytes('software_bundle', helper_path, helper_raw)
    helper.verify(tree, software_raw, sha(software_raw))
    all_rows = rows + [{'kind': 'public-metadata', 'path': name,
        **stream(guard, tree / name, sha(guard.read(tree / name)), (tree / name).stat().st_size)}
        for name in ('SOFTWARE-BUNDLE.json', 'EXTERNAL-SELECTION.json', 'DEPENDENCY-ACQUISITION.json')]
    members = {'schema': 'kpx4-software-archive-members/v1',
        'typed_software_inventory_sha256': sha(software_raw),
        'contains_backup_PK_private_witness_history_or_controller_plan': False,
        'members': sorted(all_rows, key=lambda row: row['path'])}
    member_raw = encoded(members); save(objects / 'SOFTWARE-ARCHIVE-MEMBERS.json', member_raw)
    tar_path = output / 'software.tar'
    with tarfile.open(tar_path, 'w:', format=tarfile.USTAR_FORMAT) as archive:
        for row in members['members']:
            raw = guard.read(tree / row['path'], row['sha256']); need(len(raw) == row['bytes'], 'archive-member-length')
            info = tarfile.TarInfo(row['path']); info.size = len(raw)
            info.mode = 0o500 if row['kind'] == 'selected-executable' else 0o400
            info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(raw))
    archive_path = objects / 'four-wallet-recovery-software.tar.zst'
    with archive_path.open('xb') as target:
        subprocess.run(['/usr/bin/zstd', '-q', '-T4', '-3', '-c', str(tar_path)], stdout=target,
                       env=CLEAN, check=True)
    archive_path.chmod(0o400)
    archive_bytes = archive_path.stat().st_size; archive_sha = sha(guard.read(archive_path))
    save(objects / 'compact2-parameters.json', manifest_raw)
    save(objects / 'compact2.vk', vk); save(objects / 'financial-profile.json', profile_raw)
    save(objects / 'SOFTWARE-BUNDLE.json', software_raw)
    stream(guard, args.pk, PK, compact['pk_bytes'], objects / 'compact2.pk')
    stream(guard, objects / 'compact2.pk', PK, compact['pk_bytes'])
    unpack_path = project / 'poc/current-wrapper-runtime/vendor/unpack_bundle.py'
    unpack = module_from_bytes('_kpx6_selected_unpack', unpack_path, guard.read(unpack_path, UNPACK_HELPER))
    restored = unpack.unpack(archive_path, objects / 'SOFTWARE-ARCHIVE-MEMBERS.json', archive_sha,
        archive_bytes, sha(member_raw), sha(software_raw), output / 'opaque-restored-software')
    kinds = {'compact2.pk': 'public-proving-parameters', 'compact2.vk': 'public-verification-key',
        'compact2-parameters.json': 'public-parameter-manifest', 'financial-profile.json': 'financial-reference',
        'four-wallet-recovery-software.tar.zst': 'public-software-archive',
        'SOFTWARE-ARCHIVE-MEMBERS.json': 'public-software-members', 'SOFTWARE-BUNDLE.json': 'public-software-inventory'}
    asset_rows = []
    for name, kind in kinds.items():
        path = objects / name
        expected = PK if name == 'compact2.pk' else sha(guard.read(path))
        asset_rows.append({'id': name, 'kind': kind, **stream(guard, path, expected, path.stat().st_size)})
    index = {'schema': 'kpx6-four-wallet-public-recovery-objects/v1',
        'classification': 'PREPARED_PUBLIC_OBJECTS_NOT_PROVIDER_OR_FUNDED_RECOVERY_QUALIFICATION',
        'financial_profile_sha256': PROFILE, 'software_inventory_sha256': sha(software_raw),
        'assets': sorted(asset_rows, key=lambda row: row['id']),
        'accepted_history': {'available': False, 'required_later': 'Actual LIVE descriptor and retained Full accepted prefix; no LOCAL substitution.'},
        'provider_or_retention': {'configured': False, 'independent_administration_verified': False,
            'issuer_loss_real_provider_retrieval_executed': False},
        'external_authority': 'Expected index/object digests and financial profile must be selected independently of downloaded bytes.'}
    index_raw = encoded(index); save(objects / 'RECOVERY-OBJECTS.json', index_raw)
    result = {'schema': 'kpx6-four-wallet-public-recovery-object-build/v1',
        'financial_profile_sha256': PROFILE, 'object_index_sha256': sha(index_raw),
        'software_inventory_sha256': sha(software_raw), 'software_typed_files': len(rows),
        'software_archive_members': len(all_rows), 'software_archive_bytes': archive_bytes,
        'software_archive_sha256': archive_sha, 'parameter_PK_bytes': compact['pk_bytes'],
        'parameter_PK_sha256': PK, 'asset_bytes': sum(row['bytes'] for row in asset_rows),
        'existing_fixed_unpack_opaque_restore': restored,
        'all8_originals_metadata_excluded_before_public_reads': True,
        'original_backup_contents_hashes_keys_witnesses_owner_maps_read_or_included': False,
        'wallet_prover_SDK_native_VM_network_or_payload_execution': False,
        'actual_accepted_history_provider_retention_or_funded_recovery_verified': False}
    save(output / 'RESULTS.json', encoded(result)); print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('project-root', 'software-root', 'parameter-manifest', 'pk', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--exclude-private-root', type=Path, action='append', required=True)
    build(parser.parse_args())


if __name__ == '__main__':
    main()
