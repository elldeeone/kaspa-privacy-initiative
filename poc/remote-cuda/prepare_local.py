#!/usr/bin/env python3
"""Prepare a separate task-owned sm86 build from the pinned public package.

Optional --build runs a CPU-only container; no rental, GPU job or wallet data.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import urllib.request

from common import sha
from package import checked_archive

BASE = 'nvidia/cuda:12.8.1-base-ubuntu24.04@sha256:e711c99333fdfe8ae1e677b4972be6c5021f0128a1d31f775c7e58d88921b6a9'
RECURSION = '744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849'


def prepare(output, recursion_archive=None):
    if not __debug__:
        raise RuntimeError('archive validation requires Python without -O')
    source = Path(__file__).resolve().parent
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name in ('build', 'output', 'package'):
        (output / name).mkdir()
    manifest = json.loads((source / 'evidence/manifest.json').read_text())
    expected = manifest['files']['public-package.tar.gz']
    archive = source / 'evidence/public-package.tar.gz'
    if archive.stat().st_size != expected['bytes']:
        raise RuntimeError('public package size mismatch')
    contents = checked_archive(archive, expected['sha256'])
    for name, raw in contents.items():
        target = output / 'package' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(0o755 if name == 'bin/kpi-takeover-host' else 0o644)
    destination = output / 'build/recursion_zkr.zip'
    if recursion_archive:
        shutil.copyfile(recursion_archive, destination)
    else:
        url = 'https://risc0-artifacts.s3.us-west-2.amazonaws.com/zkr/' + RECURSION + '.zip'
        with urllib.request.urlopen(url, timeout=120) as response:
            raw = response.read(128 * 1024 ** 2 + 1)
        if len(raw) > 128 * 1024 ** 2:
            raise RuntimeError('recursion archive unexpectedly large')
        destination.write_bytes(raw)
    if sha(destination.read_bytes()) != RECURSION:
        raise RuntimeError('recursion archive identity mismatch')
    original = (source / 'build_cuda.sh').read_text()
    script = original.replace('-arch=sm_89', '-arch=sm_86')
    (output / 'build/build_cuda.sh').write_text(script)
    name = 'kpi-local-cuda-' + hashlib.sha256(str(output).encode()).hexdigest()[:12]
    command = ['docker', 'run', '--name', name, '--cpus', '4', '--memory', '16g', '--memory-swap', '20g',
               '-e', 'CARGO_HOME=/opt/cargo', '-e', 'RUSTUP_HOME=/opt/rustup',
               '-e', 'PATH=/opt/cargo/bin:/usr/local/cuda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               '--mount', 'type=bind,source=' + str(output / 'build') + ',target=/opt/build,readonly',
               '--mount', 'type=bind,source=' + str(output / 'output') + ',target=/opt/kpi',
               '--entrypoint', 'bash', BASE, '/opt/build/build_cuda.sh']
    (output / 'preparation.json').write_text(json.dumps({'scope': 'LOCAL_SM86_PREPARATION_NOT_PROOF',
        'sourceBuildScriptSha256': sha(original.encode()), 'modifiedBuildScriptSha256': sha(script.encode()),
        'recursionArchiveSha256': RECURSION, 'publicPackageSha256': expected['sha256'],
        'buildCommand': command}, indent=2) + '\n')
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--recursion-archive', type=Path)
    parser.add_argument('--build', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    command = prepare(output, args.recursion_archive)
    if args.build:
        with (output / 'build.log').open('xb') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(result.returncode)
    print(json.dumps({'output': str(output), 'buildExecuted': args.build, 'gpuProofExecuted': False}))


if __name__ == '__main__':
    main()
