#!/usr/bin/env python3
"""Stage verified public sources, export diagnostic key, check committed capsule.

No original source/cache edit, proof generation, RPC or native key import.
Requires Cargo/Rust 1.95.0, Python 3.12+, patch and exact fetched dependencies.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def reproduce():
    # Fetch/metadata verifies the existing lock; it does not change its content.
    interop = REPO / 'poc/orchard-interop/Cargo.toml'
    meta = json.loads(subprocess.check_output([
        'cargo', '+1.95.0', 'metadata', '--locked', '--format-version', '1',
        '--manifest-path', str(interop),
    ]))
    packages = {p['name']: p for p in meta['packages']}
    orchard = Path(packages['orchard']['manifest_path']).parent
    halo2 = Path(packages['halo2_proofs']['manifest_path']).parent
    rev = subprocess.check_output(['git', '-C', str(orchard), 'rev-parse', 'HEAD']).decode().strip()
    if rev != '616a669df8c9a59c33d47064d3ce04b25d026b2e':
        raise ValueError('wrong Orchard source')
    run(['git', '-C', str(orchard), 'diff', '--exit-code'], stdout=subprocess.DEVNULL)
    local = REPO / '.local'
    local.mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='native-key-export-', dir=local))
    sources = work / 'sources'
    sources.mkdir()
    shutil.copytree(orchard, sources / 'orchard', ignore=shutil.ignore_patterns('.git', 'target'))
    archive = halo2.parents[2] / 'cache' / halo2.parent.name / 'halo2_proofs-0.4.1.crate'
    if hashlib.sha256(archive.read_bytes()).hexdigest() != 'd886268046f1ceedd464c95382a64c7e86520b029b18e02ee92bf94f5120817d':
        raise ValueError('Halo2 archive differs from locked official checksum')
    with tarfile.open(archive) as tar:
        tar.extractall(sources, filter='data')
    (sources / 'halo2_proofs-0.4.1').rename(sources / 'halo2_proofs')
    for row in json.loads((HERE / 'source-inputs.json').read_text()):
        data = (sources / row['component'] / row['path']).read_bytes()
        if hashlib.sha256(data).hexdigest() != row['source_sha256']:
            raise ValueError('source drift: ' + row['component'] + '/' + row['path'])
    with (HERE / 'diagnostic-export.patch').open('rb') as patch:
        run(['patch', '--batch', '-p1', '-d', str(sources)], stdin=patch)
    helper = work / 'helper'
    (helper / 'src').mkdir(parents=True)
    # JSON string escaping is also valid inside a TOML quoted string.
    escaped_repo = json.dumps(str(REPO))[1:-1]
    text = (HERE / 'Cargo.toml.in').read_text().replace('@REPOSITORY@', escaped_repo)
    (helper / 'Cargo.toml').write_text(text)
    shutil.copyfile(HERE / 'Cargo.lock', helper / 'Cargo.lock')
    shutil.copyfile(HERE / 'main.rs', helper / 'src/main.rs')
    target = work / 'target'
    run(['cargo', '+1.95.0', 'build', '--release', '--locked', '--manifest-path',
         str(helper / 'Cargo.toml'), '--target-dir', str(target)])
    artifacts = work / 'artifacts'
    run([str(target / 'release/kpi-native-key-export'), str(artifacts),
         str(REPO / 'poc/orchard-interop/vectors')])
    for name in ['fixed-post-nu6-2.vk-capsule.bin', 'upstream-pinned-key-description.txt']:
        if (artifacts / name).read_bytes() != (HERE.parent / 'artifacts' / name).read_bytes():
            raise ValueError('export is not byte-identical: ' + name)
    shutil.copyfile(HERE.parent / 'artifacts/portable-key-manifest.json', artifacts / 'portable-key-manifest.json')
    run(['python3', str(HERE / 'check_capsule.py'), str(artifacts)])
    print('Fresh copied-source export reproduced the complete capsule and provenance. Existing 3 bundles reverified. Artifacts: ' + str(artifacts))


if __name__ == '__main__':
    reproduce()
