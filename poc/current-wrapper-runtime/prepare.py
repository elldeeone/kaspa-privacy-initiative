#!/usr/bin/env python3
"""Pack an explicitly selected current-W public software allowlist; execute none."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE/'vendor'))
import software_bundle as bundle

PROFILE = {
    'child_domain_hex32': 'd55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb',
    'wrapper_domain_hex32': 'becdc8b30d3724ec79c773f0af662e3e25695b9d9a203d636fc3f6aef5c3b067',
    'outer_image_hex32': '633b3244225320ddc029a7b3b18d76b5f579bed808bbaecff25a50341b76f7f4',
    'child_profile_sha256': '492a0981ad04891ea68243f2c8221976f436501acf940e42211bb8773744fbdd',
    'role_manifest_sha256': 'd6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011',
    'child_vk_sha256': '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987',
    'child_PK_sha256': '6c518076ed6194d1f0e1925be6902182951ddf8f17347fe4aa8ec200a2a8fb11',
    'child_PK_bytes': 1307894256,
    'W_immutable_tail_sha256': '5c9e15357f07f092e25f272ea40bb92f1c0335574e37e0e4e687297db4e56559',
}
EXECUTABLES = {
    'runtime/prover': '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621',
    'runtime/w-codec': '76cfc5cc381e503e5517864044fd9a66826864f2790154157e351bff08fd4ee1',
    'runtime/native-validator': '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061',
    'runtime/node': 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c',
    'runtime/crypto': '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff',
}

def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as target:
        target.write(raw)

def document(path, value):
    save(path, bundle.encoded(value)+b'\n')

def prepare(plan_path, expected_plan_sha256, output):
    raw = bundle.read_public(plan_path)
    bundle.need(bundle.digest(raw) == expected_plan_sha256, 'external-public-source-plan-pin')
    plan = bundle.parse(raw)
    bundle.need(type(plan) is dict and set(plan) == {'schema','profile','wallet_source_freeze_sha256','files'}
                and plan['schema'] == 'kpx5-current-W-runtime-source-plan/v1'
                and plan['profile'] == PROFILE and type(plan['files']) is list,
                'current-W-source-plan-schema')
    selected = {}
    for row in plan['files']:
        bundle.need(type(row) is dict and set(row) == {'kind','path','source','bytes','sha256'},
                    'source-plan-entry-fields')
        name = bundle.relative(row['path'])
        bundle.need(name not in selected and row['kind'] in bundle.KINDS,
                    'duplicate-or-invalid-source-entry')
        bundle.need(type(row['bytes']) is int and row['bytes'] >= 0,
                    'source-plan-length')
        selected[name] = row
    bundle.need({p: selected.get(p, {}).get('sha256') for p in EXECUTABLES} == EXECUTABLES,
                'all-five-current-selected-runtime-identities')
    bundle.need(all(selected[p]['kind'] == 'selected-executable' for p in EXECUTABLES)
                and sum(r['kind'] == 'selected-executable' for r in selected.values()) == 5,
                'no-other-selected-executable')
    bundle.need(selected.get('selection/WALLET-SOURCE-FREEZE.json', {}).get('sha256')
                == plan['wallet_source_freeze_sha256'], 'wallet-freeze-selection')
    freeze_row = selected['selection/WALLET-SOURCE-FREEZE.json']
    freeze_raw = bundle.read_public(freeze_row['source'], expected_bytes=freeze_row['bytes'])
    bundle.need(bundle.digest(freeze_raw) == plan['wallet_source_freeze_sha256'],
                'final-wallet-freeze-whole-byte-pin')
    freeze = bundle.parse(freeze_raw)
    bundle.need(freeze['schema'] == 'kpx5-owner-source-freeze/v1'
                and freeze['private_budget'] == 1500 and freeze['aggregate_budget'] == 1600,
                'current-wallet-source-freeze-profile')
    expected_wallet = {}
    for row in freeze['files']:
        bundle.need(row['path'].startswith('poc/shared-settlement-wallet/'),
                    'only-current-wallet-freeze-paths')
        # The control source contains a deliberate public test seed recipe.
        # It stays in repository evidence and is never needed in the runtime.
        if row['path'] != 'poc/shared-settlement-wallet/test_wallet.py':
            expected_wallet['runtime-source/'+row['path']] = (row['bytes'], row['sha256'])
    actual_wallet = {name:(row['bytes'], row['sha256']) for name,row in selected.items()
                     if name.startswith('runtime-source/poc/shared-settlement-wallet/')}
    bundle.need(len(expected_wallet) == 8 and actual_wallet == expected_wallet,
                'every-runtime-wallet-source-joins-final-freeze')
    output = bundle.checked_path(output)
    bundle.need(not output.exists(), 'fresh-package-output-required')
    output.mkdir(parents=True, mode=0o700)
    tree = output/'tree'; tree.mkdir()
    for name, row in sorted(selected.items()):
        contents = bundle.read_public(row['source'], expected_bytes=row['bytes'])
        bundle.need(bundle.digest(contents) == row['sha256'], 'selected-public-source-digest')
        save(tree/name, contents)
        (tree/name).chmod(0o500 if row['kind'] == 'selected-executable' else 0o400)
    inventory = bundle.inventory(tree, [(r['kind'], name) for name, r in selected.items()])
    document(tree/'SOFTWARE-BUNDLE.json', inventory)
    inv_raw = (tree/'SOFTWARE-BUNDLE.json').read_bytes(); inv_sha = bundle.digest(inv_raw)
    bundle.verify(tree, inv_raw, inv_sha)
    selection = {'schema':'kpx5-current-W-runtime-selection/v1', 'profile':PROFILE,
        'typed_software_inventory_sha256':inv_sha,
        'wallet_source_freeze_sha256':plan['wallet_source_freeze_sha256'],
        'public_source_plan_sha256':expected_plan_sha256,
        'scope':'CURRENT_UNFUNDED_W_PREBUILT_AND_SOURCE_AVAILABILITY_ONLY',
        'old_B05_or_D35_financial_selection_inherited':False,
        'outer_proving_or_compression_assets_required_to_exit':False,
        'backup_witness_seed_private_owner_plan_or_accepted_history_included':False,
        'chain_currentness_backing_or_spend_authorized':False}
    document(tree/'EXTERNAL-SELECTION.json', selection)
    document(tree/'DEPENDENCY-ACQUISITION.json', {
        'schema':'kpx5-current-W-prebuilt-dependency-contract/v1',
        'Rust_or_WASM_build_executed':False, 'registry_or_NPM_packages_acquired':False,
        'Python_third_party_packages_required':[],
        'trusted_host_premise':'Compatible Linux OS, Python standard library, system libraries, bwrap and zstd remain supplied by the trusted host.',
        'generic_byte_reuse_does_not_inherit_prior_financial_authority':True,
        'current_4ef_source_cold_rebuild_is_separate_evidence':True})
    sidecars = ['SOFTWARE-BUNDLE.json','EXTERNAL-SELECTION.json','DEPENDENCY-ACQUISITION.json']
    rows = inventory['files'] + [{'kind':'public-metadata','path':name,
        'bytes':(tree/name).stat().st_size,'sha256':bundle.digest((tree/name).read_bytes())}
        for name in sidecars]
    members = {'schema':'kpx4-software-archive-members/v1',
        'typed_software_inventory_sha256':inv_sha,
        'contains_backup_PK_private_witness_history_or_controller_plan':False,
        'members':sorted(rows, key=lambda r:r['path'])}
    document(output/'ARCHIVE-MEMBERS.json', members)
    tar_path = output/'software.tar'
    with tarfile.open(tar_path, 'w:', format=tarfile.USTAR_FORMAT) as archive:
        for row in members['members']:
            contents = bundle.read_public(tree/row['path'], expected_bytes=row['bytes'])
            bundle.need(bundle.digest(contents) == row['sha256'], 'public-source-mutated-before-archive')
            info = tarfile.TarInfo(row['path']); info.size = len(contents)
            info.mode = 0o500 if row['kind'] == 'selected-executable' else 0o400
            info.uid = info.gid = info.mtime = 0; info.uname = info.gname = ''
            archive.addfile(info, io.BytesIO(contents))
    archive_path = output/'current-W-software.tar.zst'
    with archive_path.open('xb') as target:
        subprocess.run(['/usr/bin/zstd','-q','-T2','-9','-c',str(tar_path)],stdout=target,check=True)
    archive_raw = bundle.read_public(archive_path)
    metadata = {'schema':'kpx5-current-W-runtime-archive/v1',
        'archive_bytes':len(archive_raw),'archive_sha256':bundle.digest(archive_raw),
        'member_inventory_sha256':bundle.digest((output/'ARCHIVE-MEMBERS.json').read_bytes()),
        'typed_software_inventory_sha256':inv_sha,'typed_files':len(inventory['files']),
        'archive_members':len(rows),'selected_profile':PROFILE,
        'payload_execution_or_import':False,'currentness_or_backing_qualified':False}
    document(output/'ARCHIVE.json', metadata)
    print(json.dumps(metadata,sort_keys=True))
    return metadata

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    prepare(args.plan,args.plan_sha256,args.output)
