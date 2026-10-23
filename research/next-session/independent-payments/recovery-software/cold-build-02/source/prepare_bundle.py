#!/usr/bin/env python3
"""Fixed public-source packer; never includes a backup, PK or private history."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from software_bundle import encoded, inventory, need, read_public

ROOT = Path(__file__).resolve().parents[2]
SOURCE_FREEZE = ROOT / 'research/next-session/compact-batch/prover/build-05/SOURCE-FREEZE.json'
SOURCE_FREEZE_SHA = 'e97a2342e93e46b5ce2c3ecd5cfc0cfcf014a78985bcbf686563ec11eab0602b'
PROVER = Path('/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-prover-target/selected-owner-build05/kpi-compact-batch-prover')
PROVER_SHA = '1662fcd9a5b90b8658e07aed2250a4c9c11d2390e80d7addae717090d63fb94d'
BUILD_ID = '8c6a5ab16aab7212cccaf6125f39363d94c854b824bd89ff1eb633f0bad7590a'
RUNTIME = (
    ('emitter', '/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-native-target/selected-release-01/emitter', '2ed7562656cfa8344c4b3d3176278b789e0392861732a5526c9c34db9f6f469c'),
    ('native-validator', '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/native-validator', '077585b8a8c739abb70007507a757fafe6584734338d11db84a69e6e6dd8a061'),
    ('crypto', '/home/luke/.local/share/kpi-private-cashout-trial-runtime/adr0054-01/crypto', '6f65ec202a2d634d0cf8c5ba3034fd591790374da0ea9ea1a144470eec3143ff'),
    ('node', '/home/luke/.local/share/kpi-private-network-runtime/adr0054-01/node', 'd1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c'))
LIFECYCLE = {
    'primitives.py': '184463d416a8e3c5605ce929bf2cead378c00e82d3827d30c83f8a6e19de5986',
    'receiver.py': '9733a7c97baaef3b91c70766007173c41d770e6f260fb7f0bf3116ad95c0665b',
    'actions.py': 'a1b725e026dc7403bbe4a3d6c1f713bf48d4e67ecdbed67facda7d6098658484',
    'history.py': 'b24f5712d16b75e5d1c33e6021e7f3e06e3bf180926af00f5ee01a09e1060202',
    'native_runtime.py': 'dac6d42987a9419864c967773677a033c143028053f33f5f6ad506739ef005af',
    'owner.py': '8d6a0bfedc9072039ad6a8d126af78ef2222274d8aa14b493c15968c6c2b1a49',
    'run_owner.py': 'c620788d4f694ea25f4876c49a4f853d39224eef83e91501ad819796c2cc5185'}


def prepare(output, allow_locked_registry_downloads=False):
    need(output.is_absolute() and not output.exists() and not output.is_relative_to(ROOT),
         'fresh-public-package-outside-repository')
    output.mkdir(parents=True, mode=0o700)
    typed = []

    def copy(source, name, kind, expected=None):
        raw = read_public(source)
        need(expected is None or hashlib.sha256(raw).hexdigest() == expected, 'selected-source-or-release-pin')
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o500 if kind == 'selected-executable' else 0o400)
        typed.append((kind, name))

    freeze_raw = read_public(SOURCE_FREEZE)
    need(hashlib.sha256(freeze_raw).hexdigest() == SOURCE_FREEZE_SHA, 'selected-source-freeze')
    freeze = json.loads(freeze_raw)
    for row in freeze['files']:
        name = row['path'].removeprefix('poc/compact-batch-prover/')
        need(name != row['path'], 'source-package-prefix')
        copy(ROOT / row['path'], 'prover/' + name, 'source', row['sha256'])
    copy(SOURCE_FREEZE, 'selection/SOURCE-FREEZE.json', 'public-metadata', SOURCE_FREEZE_SHA)
    copy(PROVER, 'runtime/prover', 'selected-executable', PROVER_SHA)
    for name, source, expected in RUNTIME:
        copy(source, 'runtime/' + name, 'selected-executable', expected)
    for name, expected in LIFECYCLE.items():
        copy(ROOT / 'poc/compact-batch-lifecycle' / name,
             'runtime-source/poc/compact-batch-lifecycle/' + name, 'runtime-source', expected)
    for name, expected in (
        ('poc/future-recipient/v2/recipient.py', '93a3d01b99e6c8f0ac6f3d682d41f65d2cc2d40489d1fbd4226f1fb351edd1d2'),
        ('poc/private-cashout-trial/sdk.mjs', '7e09cb2316dd08072fa4d29e221020215f137e68f761937d7cc0751ee1678e63')):
        copy(ROOT / name, 'runtime-source/' + name, 'runtime-source', expected)
    sdk = Path('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa')
    for name in ('kaspa.js', 'kaspa_bg.wasm', 'package.json'):
        copy(sdk / name, 'runtime-sdk/' + name, 'runtime-source')
    # Cargo vendor verifies registry/Cargo.lock checksums. No build scripts run.
    # Dependencies come from LOCAL source cache, not a network-retention claim.
    command = ['/home/luke/.cargo/bin/cargo', 'vendor', '--locked']
    if not allow_locked_registry_downloads:
        command.append('--offline')
    command += ['--versioned-dirs', str(output / 'vendor')]
    import tomllib
    lock = tomllib.loads((output / 'prover/Cargo.lock').read_text())
    cache = Path('/home/luke/.cargo/registry/cache')
    before = []
    for row in lock['package']:
        if 'source' not in row:
            continue
        need(row['source'] == 'registry+https://github.com/rust-lang/crates.io-index',
             'only-locked-crates-io-source')
        candidates = list(cache.glob('*/' + row['name'] + '-' + row['version'] + '.crate'))
        valid = [path for path in candidates
                 if hashlib.sha256(read_public(path)).hexdigest() == row['checksum']]
        before.append({'name': row['name'], 'version': row['version'],
                       'locked_registry_sha256': row['checksum'],
                       'verified_archive_in_local_cache_before': bool(valid)})
    result = subprocess.run(command, cwd=output / 'prover', capture_output=True, text=True)
    (output / 'VENDOR-STDERR.log').write_text(result.stderr)
    need(result.returncode == 0, 'offline-vendor-failed')
    (output / 'VENDOR-CONFIG.txt').write_text(result.stdout)
    (output / 'DEPENDENCY-ACQUISITION.json').write_bytes(encoded({
        'schema': 'kpx4-locked-dependency-acquisition/v1',
        'network_allowed_for_missing_locked_registry_archives': allow_locked_registry_downloads,
        'packages': before}))
    for path in sorted((output / 'vendor').rglob('*')):
        need(not path.is_symlink(), 'vendored-symlink')
        if path.is_file():
            path.chmod(0o400)
            typed.append(('cargo-vendor', path.relative_to(output).as_posix()))
    config = output / 'prover/.cargo/config.toml'
    config.parent.mkdir()
    config.write_text('[source.crates-io]\nreplace-with = "vendored-sources"\n'
                      '[source.vendored-sources]\ndirectory = "/bundle/vendor"\n'
                      '[net]\noffline = true\n')
    typed.append(('build-config', 'prover/.cargo/config.toml'))
    data = inventory(output, typed)
    raw = encoded(data)
    (output / 'SOFTWARE-BUNDLE.json').write_bytes(raw)
    selection = {'schema': 'kpx4-cold-software-external-selection/v1',
                 'source_base_commit': '5aaf99532d8714e510d421102df719f60f54d073',
                 'bundle_inventory_sha256': hashlib.sha256(raw).hexdigest(),
                 'selected_prover_sha256': PROVER_SHA, 'compiled_build_identity_sha256': BUILD_ID,
                 'source_freeze_sha256': SOURCE_FREEZE_SHA,
                 'registry_acquisition_allowed_only_for_exact_locked_checksums': allow_locked_registry_downloads,
                 'locked_registry_packages': len(before),
                 'missing_archives_before_vendor': sum(not row['verified_archive_in_local_cache_before'] for row in before),
                 'files': len(data['files']), 'bytes': sum(row['bytes'] for row in data['files'])}
    (output / 'EXTERNAL-SELECTION.json').write_bytes(encoded(selection))
    return selection


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fresh_public_output', type=Path)
    parser.add_argument('--allow-locked-registry-downloads', action='store_true')
    args = parser.parse_args()
    print(json.dumps(prepare(args.fresh_public_output, args.allow_locked_registry_downloads), sort_keys=True))
