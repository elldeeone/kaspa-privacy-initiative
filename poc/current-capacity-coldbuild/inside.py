#!/usr/bin/env python3
"""Fixed precompile namespace checks; no downloaded recipe is executed."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

TOOLCHAIN = '/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu'
REGISTRY = '/home/luke/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f'
absent = [
    '/home/luke/projects/kpi-intensive-2026-10-22/continuation',
    '/home/luke/projects/kpi-intensive-2026-10-22/capacity-exit-selected-prover-01',
    '/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-prover-target',
    '/home/luke/.cargo/registry/cache', '/home/luke/.cargo/registry/index',
    '/home/luke/.cargo/bin', '/home/luke/.cargo/config.toml',
]
assert all(not Path(name).exists() for name in absent)
assert not any(Path('/build/cargo-home').iterdir())
assert not Path('/build/target').exists()
assert sorted(p.name for p in Path('/home/luke/.cargo').iterdir()) == ['registry']
assert sorted(p.name for p in Path('/home/luke/.cargo/registry').iterdir()) == ['src']
assert sorted(p.name for p in Path('/home/luke/.cargo/registry/src').iterdir()) == ['index.crates.io-1949cf8c6b5b557f']
assert len(list(Path(REGISTRY).iterdir())) == 148
assert Path(TOOLCHAIN + '/lib/rustlib/src/rust/library').is_dir()
interfaces = [name for _, name in socket.if_nameindex()]
assert interfaces == ['lo']
receipt = {'schema': 'kpi-current-capacity-coldbuild-namespace/v1',
    'original_HOST_checkout_cache_targets_absent': True,
    'absence_probes': len(absent), 'empty_CARGO_HOME': True, 'target_absent_before_build': True,
    'logical_home_cargo_contains_only_public_dependency_registry': True,
    'public_dependency_packages': 148, 'installed_rust_source_visible': True,
    'network_interfaces': interfaces, 'actual_network_namespace': os.readlink('/proc/self/ns/net'),
    'logical_original_registry_path_absent': False,
    'compiler_OS_toolchain_preinstalled_and_trusted': True}
Path('/build/NAMESPACE.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
sys.exit(subprocess.call([TOOLCHAIN + '/bin/cargo', 'build', '--release', '--locked', '--offline',
                          '--bin', 'kpi-private-capacity-prover', '-j4']))
