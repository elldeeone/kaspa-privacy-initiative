"""Prepare current-capacity public bytes; never reuse old capsule authority.

This is a byte-only publication adapter. It does not decode proving parameters,
replay financial state, read backups, prove, broadcast or execute downloaded code.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

MANIFEST = 'd6f0e2bbafab39a72106ef0a0ebd6483362a858926117721a8be5aa37a459011'
DOMAIN = 'd55d006a9bb253963db4f4e44495e60333df9fcc83c1c3ae220806d0f326a0bb'
PK = '6c518076ed6194d1f0e1925be6902182951ddf8f17347fe4aa8ec200a2a8fb11'
PK_BYTES = 1_307_894_256
PROVER = '4ef4fc4f6290bc1c5472e732e118476b6ad20b692438c0957e27cf3f6bc00621'
VK = '074c06a5f21f46c7c87a948c8ca6a0896198cc9fc255b8d5e08cc01ceb73a987'
FREEZE = 'c341fbfbce61ce9d3bf1f198a8ef8be800416d3d99f9910dc0bd0ff0b10160b3'
TOOLS = {'public_fetch.py': '37f1a3aa6a7b0c9e4f5363ffb15f2deebde087295c49b60d1cd9b2b9f6eb32ae',
    'trusted_util.py': '78633b9e62a57796d609b600139cea77f4e1866ec362aa5bdd2588516baad9a6',
    'vendor/capsule.py': 'ba6fba072eb00e54297e47473c61ce7ef2230356183c9dfd60d0a8741cc492d2',
    'vendor/chunk_public.py': 'c713a4871079acd040f5c434ceed47c4d6f71885c8e5256199a86488a5f724aa'}
NOTICE = b'''CURRENT CAPACITY PROFILE PUBLIC DEVELOPMENT MATERIAL - DO NOT FUND
Profile Dd55, compact role, manifest d6f0, public PK6c518, selected prover4ef.
This is NOT the older D35/c8d/1662 recovery demonstration or its software bundle.
No backup, seed, witness, owner map, private controller plan or old main history.
No W descriptor/history/outer proof is asserted by this parameter generation.
Root must separately authenticate current financial/program/software selection.
Hashes/TLS recover selected bytes, not chain currentness, spend authorization,
setup soundness, provider independence, long-term retention or trial readiness.
The included selected prover is never automatically executed by this adapter.
'''


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def need(test, reason):
    if not test:
        raise ValueError(reason)


def public_bytes(path, expected=None):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
         'public-source-path')
    need(stat.S_ISREG(path.lstat().st_mode), 'public-source-not-regular')
    raw = path.read_bytes()
    need(expected is None or digest(raw) == expected, 'selected-public-source-digest')
    return raw


def save(path, raw):
    with path.open('xb') as target:
        target.write(raw)
        target.flush()
        os.fsync(target.fileno())
    path.chmod(0o444)


def copy_large(source, target, expected_bytes, expected_sha):
    # Input is only the explicit root-released public PK; no private file is a
    # supported input or mounted in the issued preparation namespace.
    source = Path(source)
    need(not any(p.is_symlink() for p in (source, *source.parents)), 'public-large-path')
    before = source.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_size == expected_bytes,
         'public-large-length')
    total, hasher = 0, hashlib.sha256()
    part = target.with_name(target.name + '.part')
    with source.open('rb') as inp, part.open('xb') as out:
        while raw := inp.read(min(1_048_576, expected_bytes - total + 1)):
            total += len(raw)
            need(total <= expected_bytes, 'public-large-overflow')
            hasher.update(raw)
            out.write(raw)
        after = os.fstat(inp.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(tuple(getattr(before, f) for f in fields) ==
             tuple(getattr(after, f) for f in fields), 'public-large-changed')
        need(total == expected_bytes and hasher.hexdigest() == expected_sha,
             'public-large-whole-digest')
        out.flush()
        os.fsync(out.fileno())
    part.chmod(0o444)
    os.link(part, target, follow_symlinks=False)
    part.unlink()


def prepare(root, manifest_path, source_freeze, selected_prover, pk, transport, output):
    manifest_raw = public_bytes(manifest_path, MANIFEST)
    manifest = json.loads(manifest_raw)
    need(encoded(manifest) == manifest_raw, 'canonical-role-manifest')
    need(manifest['domain_hex32'] == DOMAIN and manifest['role'] == 'compact2'
        and manifest['program_label'] == 'AUTH528_PRIVATE_CAPACITY_EXIT/v1'
        and manifest['pk_bytes'] == PK_BYTES and manifest['pk_sha256'] == PK
        and manifest['vk_sha256'] == VK, 'root-selected-current-profile')
    freeze_raw = public_bytes(source_freeze, FREEZE)
    freeze = json.loads(freeze_raw)
    prover_raw = public_bytes(selected_prover, PROVER)
    owned_sources = []
    for row in freeze['files']:
        path = Path(row['path'])
        need(not path.is_absolute() and '..' not in path.parts
             and str(path).startswith('poc/private-exit-stress/prover/'), 'frozen-source-path')
        raw = public_bytes(Path(root) / path, row['sha256'])
        need(len(raw) == row['bytes'], 'frozen-source-length')
        owned_sources.append((row, raw))
    tool_bytes = {name: public_bytes(Path(transport) / name, pin) for name, pin in TOOLS.items()}
    output = Path(output).absolute()
    need(not output.exists() and not any(p.is_symlink() for p in output.parents), 'fresh-output')
    output.mkdir(mode=0o700)
    assets, objects = output / 'assets', output / 'objects' / 'sha256'
    assets.mkdir(mode=0o700)
    objects.mkdir(parents=True, mode=0o700)
    helper = output / 'byte-transport'
    (helper / 'vendor').mkdir(parents=True, mode=0o700)
    for name, raw in tool_bytes.items():
        save(helper / name, raw)
    command = [sys.executable, '-B', str(helper / 'vendor/chunk_public.py'), 'pack',
        '--source', str(pk), '--expected-bytes', str(PK_BYTES), '--expected-sha256', PK,
        '--output-dir', str(output / 'chunks')]
    child = subprocess.run(command, capture_output=True, text=True,
        env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    need(child.returncode == 0, 'root-selected-chunk-pack-failed')
    chunks_raw = public_bytes(output / 'chunks/manifest.json')
    chunks = json.loads(chunks_raw)
    copy_large(pk, objects / PK, PK_BYTES, PK)
    rows = []

    def asset(kind, name, raw):
        sha = digest(raw)
        if not (assets / name).exists():
            save(assets / name, raw)
        if not (objects / sha).exists():
            save(objects / sha, raw)
        rows.append({'kind': kind, 'basename': name, 'bytes': len(raw), 'sha256': sha})
        return name

    asset('current_role_manifest', 'current-compact-public-parameters.json', manifest_raw)
    asset('current_chunk_index', 'current-compact-chunks.json', chunks_raw)
    asset('selected_current_prover', 'current-compact-prover', prover_raw)
    asset('current_source_freeze', 'current-prover-source-freeze.json', freeze_raw)
    source_rows = []
    for row, raw in owned_sources:
        name = 'source-' + row['sha256'] + Path(row['path']).suffix
        asset('current_prover_source', name, raw)
        source_rows.append({**row, 'asset_basename': name})
    for name, raw in tool_bytes.items():
        asset('byte_transport_source', 'transport-' + digest(raw) + '.py', raw)
    for chunk in chunks['chunks']:
        target = assets / chunk['basename']
        copy_large(output / 'chunks' / chunk['basename'], target, chunk['bytes'], chunk['sha256'])
        if not (objects / chunk['sha256']).exists():
            os.link(target, objects / chunk['sha256'], follow_symlinks=False)
        rows.append({'kind': 'current_public_PK_chunk', 'basename': chunk['basename'],
                     'bytes': chunk['bytes'], 'sha256': chunk['sha256']})
    asset('notice', 'NOTICE.txt', NOTICE)
    inventory = {'schema': 'kpi-current-cap-public-software-source-inventory/v1',
        'program_label': manifest['program_label'], 'domain_hex32': DOMAIN,
        'role_manifest_sha256': MANIFEST, 'selected_prover_sha256': PROVER,
        'source_freeze_sha256': FREEZE, 'files': source_rows,
        'whole_cold_wallet_dependency_bundle_complete': False,
        'W_outer_software_selection_complete': False, 'downloaded_code_automatically_run': False}
    asset('current_software_source_inventory', 'current-software-source-inventory.json', encoded(inventory))
    publication = {'schema': 'kpi-current-profile-public-byte-distribution/v1',
        'classification': 'UNFUNDED_CURRENT_CAP_PROFILE_DO_NOT_FUND',
        'program_label': manifest['program_label'], 'domain_hex32': DOMAIN, 'role': 'compact2',
        'role_manifest_sha256': MANIFEST, 'vk_sha256': VK,
        'whole_PK': {'bytes': PK_BYTES, 'sha256': PK}, 'selected_prover_sha256': PROVER,
        'assets': sorted(rows, key=lambda row: row['basename']),
        'old_D35_capsule_or_software_authority_reused': False,
        'W_descriptor_history_or_genuine_outer_body_included': False,
        'financial_replay_or_selection_authority': False,
        'current_state_verified': False, 'spend_authorized': False}
    save(output / 'PUBLICATION.json', encoded(publication))
    save(objects / digest(encoded(publication)), encoded(publication))
    return {'schema': 'kpi-current-profile-public-byte-preparation-result/v1',
        'publication_sha256': digest(encoded(publication)), 'asset_count': len(rows) + 1,
        'asset_bytes_including_publication': sum(row['bytes'] for row in rows) + len(encoded(publication)),
        'domain_hex32': DOMAIN, 'role_manifest_sha256': MANIFEST, 'whole_PK_sha256': PK,
        'selected_prover_sha256': PROVER, 'unpublished': True,
        'financial_material_complete': False, 'current_state_verified': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('repo-root', 'manifest', 'source-freeze', 'selected-prover', 'public-PK',
                'transport-directory', 'output'):
        parser.add_argument('--' + arg, required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.repo_root, args.manifest, args.source_freeze,
            args.selected_prover, args.public_PK, args.transport_directory, args.output), sort_keys=True))
    except (ValueError, OSError, KeyError):
        print(json.dumps({'status': 'CURRENT_PROFILE_PUBLIC_BYTES_INCOMPLETE',
                          'financial_material_complete': False, 'current_state_verified': False}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
