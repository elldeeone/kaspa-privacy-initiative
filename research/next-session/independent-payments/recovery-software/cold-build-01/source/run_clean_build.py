#!/usr/bin/env python3
"""Fixed offline compiler invocation over only authenticated restored entries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from prepare_bundle import PROVER_SHA, ROOT
from software_bundle import encoded, need, read_public, restore

TOOLCHAIN = Path('/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu')


def build(bundle, expected_inventory, output):
    need(output.is_absolute() and not output.exists() and not output.is_relative_to(ROOT),
         'fresh-cold-build-output')
    output.mkdir(parents=True, mode=0o700)
    raw = read_public(bundle / 'SOFTWARE-BUNDLE.json')
    restored = output / 'restored'
    receipt = restore(bundle, raw, expected_inventory, restored)
    (output / 'RESTORE.json').write_bytes(encoded(receipt))
    work = output / 'work'
    work.mkdir()
    shutil.copytree(restored / 'prover', work / 'source')
    for path in (work / 'source').rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    (work / 'cargo-home').mkdir()
    # Target is deliberately absent; no registry, build target or Cargo cache is mounted.
    need(not (work / 'target').exists() and not any((work / 'cargo-home').iterdir()),
         'empty-cargo-home-and-target-required')
    selected = read_public(restored / 'runtime/prover')
    need(hashlib.sha256(selected).hexdigest() == PROVER_SHA, 'external-selected-prover-pin')
    trusted_tools = {}
    for name in ('cargo', 'rustc', 'rust-lld'):
        path = TOOLCHAIN / 'bin' / name
        if path.is_file():
            trusted_tools[name] = {'bytes': path.stat().st_size,
                                   'sha256': hashlib.sha256(read_public(path)).hexdigest()}
    environment = {'PATH': '/toolchain/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
        'HOME': '/build/empty-home', 'CARGO_HOME': '/build/cargo-home',
        'CARGO_TARGET_DIR': '/build/target', 'RUSTC': '/toolchain/bin/rustc',
        'CARGO_ENCODED_RUSTFLAGS': '', 'CARGO_NET_OFFLINE': 'true', 'RAYON_NUM_THREADS': '4'}
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
        '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
        '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64',
        '--ro-bind', '/etc/alternatives', '/etc/alternatives', '--proc', '/proc', '--dev', '/dev',
        '--tmpfs', '/tmp', '--ro-bind', str(TOOLCHAIN), '/toolchain',
        '--ro-bind', str(restored), '/bundle', '--bind', str(work), '/build',
        '--chdir', '/build/source']
    for key, value in environment.items():
        command += ['--setenv', key, value]
    # Static script checks missing ORIGINAL paths before the compiler runs. No downloaded command is used.
    absence = [str(ROOT), '/home/luke/.cargo',
               '/home/luke/projects/kpi-intensive-2026-10-22/compact-batch-prover-target']
    script = ('import json,pathlib,subprocess,sys; '
              'paths=' + repr(absence) + '; '
              'assert all(not pathlib.Path(p).exists() for p in paths); '
              'pathlib.Path("/build/ABSENCE.json").write_text(json.dumps({"original_paths_absent":True,"count":len(paths),'
              '"empty_cargo_home":not any(pathlib.Path("/build/cargo-home").iterdir()),'
              '"target_absent":not pathlib.Path("/build/target").exists()})); '
              'sys.exit(subprocess.call(["/toolchain/bin/cargo","build","--release","--locked","--offline",'
              '"--bin","kpi-compact-batch-prover","-j4"]))')
    command += ['/usr/bin/python3', '-B', '-c', script]
    (output / 'BUILD-COMMAND.json').write_bytes(encoded({'command': command,
        'compiler_toolchain_preinstalled_not_network_bootstrapped': True,
        'trusted_tool_hashes': trusted_tools, 'system_OS_loader_libc_linker_trusted': True,
        'authenticated_payload_only_no_unlisted_source_mount': True}))
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True)
    (output / 'STDOUT.log').write_text(result.stdout)
    (output / 'STDERR.log').write_text(result.stderr)
    binary = work / 'target/release/kpi-compact-batch-prover'
    actual = hashlib.sha256(read_public(binary)).hexdigest() if result.returncode == 0 else None
    report = {'schema': 'kpx4-cold-build-outcome/v1', 'returncode': result.returncode,
        'wall_seconds': time.monotonic() - started, 'inventory_sha256': expected_inventory,
        'rebuilt_prover_sha256': actual, 'externally_selected_prover_sha256': PROVER_SHA,
        'byte_identical_to_selected_release': actual == PROVER_SHA,
        'mismatch_does_not_select_or_authorize_new_executable': True,
        'network_disabled': True, 'original_source_cache_target_absent': True,
        'private_seed_witness_or_PK_read': False, 'currentness_verified': False, 'spend_authorized': False}
    (output / 'RESULTS.json').write_bytes(encoded(report))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('externally_selected_inventory_sha256')
    parser.add_argument('fresh_output', type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.bundle, args.externally_selected_inventory_sha256, args.fresh_output), sort_keys=True))
