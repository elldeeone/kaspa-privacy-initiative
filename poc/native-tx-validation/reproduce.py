#!/usr/bin/env python3
"""Generate into a fresh ignored directory; compare every fixture in fresh processes."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    local = ROOT / '.local'
    local.mkdir(exist_ok=True)
    target = Path(tempfile.mkdtemp(prefix='native-authorization-', dir=local))
    env = dict(os.environ)
    env.setdefault('CARGO_TARGET_DIR', str(local / 'orchard-interop/target'))
    command = ['cargo', '+1.95.0', 'run', '--release', '--locked', '--manifest-path', str(HERE / 'Cargo.toml'), '--']
    subprocess.run(command + ['generate', str(target)], env=env, check=True)
    expected = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE / 'vectors').iterdir() if p.is_file()}
    actual = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in target.iterdir() if p.is_file()}
    if actual != expected:
        raise ValueError('generated public fixtures differ; retain both sets for diagnosis: ' + str(target))
    subprocess.run(['python3', str(HERE / 'check_vectors.py'), str(target)], check=True)
    subprocess.run(command + ['check-fixtures', str(target)], env=env, check=True)
    print(f'{len(expected)} public fixture files reproduced exactly and verified in fresh processes: {target}')


if __name__ == '__main__':
    main()
