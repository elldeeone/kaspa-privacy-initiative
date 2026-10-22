#!/usr/bin/env python3
"""Rebuild selected host, freeze it, then execute the already declared cases."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import subprocess

ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/proof')
TARGET=ROOT.parent/'proof-target'
OUT=TARGET/'two-v6-state-selected-host'
OUT.mkdir()
prior=json.loads((TARGET/'two-v6-state-build/build-freeze.json').read_text())

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

selection='poc/two-v6-state/host/pins/guest-selection.json'
for name,expected in prior['files'].items():
    if name!=selection:
        assert sha(ROOT/name)==expected,('source changed',name)
env=dict(os.environ)
env.update(CARGO_HOME=str(TARGET/'cargo-home'),CARGO_TARGET_DIR=str(TARGET),
    RUSTC='/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc')
cargo='/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo'
subprocess.run([cargo,'build','--offline','--locked','--release','--jobs','2',
    '--manifest-path',str(ROOT/'poc/two-v6-state/host/Cargo.toml')],env=env,check=True)
host=TARGET/'release/kpi-two-v6-state-proof-host'
host_sha=sha(host)
selected=json.loads((ROOT/selection).read_text())
for name in ('current-anchor','historical-anchor'):
    result=subprocess.run([str(host),'check-target',name,str(TARGET/'two-v6-state-programs'),
        str(ROOT/'poc/two-v6-state/public-fixtures'/name/'input.bin')],env=env,capture_output=True,text=True,check=True)
    (OUT/(name+'-target.json')).write_text(result.stdout)
preflight=subprocess.run([str(host),'validate-key'],env=env,capture_output=True,text=True,check=True)
(OUT/'checked-key-preflight.json').write_text(preflight.stdout)
freeze={'schema':'kpi-two-v6-state-selected-host-freeze-v1','frozen_before_execution':datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'image':selected['image'],'program_sha256':selected['program_sha256'],
    'host_path':str(host),'host_sha256':host_sha,'host_bytes':host.stat().st_size,
    'root_selection_sha256':selected['root_selection_sha256'],
    'guest_build_freeze_sha256':sha(TARGET/'two-v6-state-build/build-freeze.json'),
    'files':{name:sha(ROOT/name) for name in prior['files']},
    'executor_path':str(TARGET/'tools/r0vm'),'executor_sha256':sha(TARGET/'tools/r0vm'),
    'execution_controller_sha256':sha(TARGET/'tools/execute_state_cases.py'),
    'native_predecessor_authenticated':False,'native_settlement':False}
(OUT/'selected-host-freeze.json').write_text(json.dumps(freeze,indent=2)+'\n')
print(json.dumps({'selected_host_sha256':host_sha,'freeze':str(OUT/'selected-host-freeze.json')}),flush=True)
env.update(RISC0_PROVER='ipc',RISC0_SERVER_PATH=str(TARGET/'tools/r0vm'),
    RISC0_WORK_DIR=str(TARGET/'two-v6-state-cpu-work'),RISC0_HOME=str(TARGET/'two-v6-state-risc0-home'),
    XDG_CACHE_HOME=str(TARGET/'two-v6-state-cpu-cache'),GITHUB_TOKEN='',RAYON_NUM_THREADS='2',OMP_NUM_THREADS='2')
for name in ('two-v6-state-cpu-work','two-v6-state-risc0-home','two-v6-state-cpu-cache'):
    (TARGET/name).mkdir()
subprocess.run(['/usr/bin/python3',str(TARGET/'tools/execute_state_cases.py'),host_sha],env=env,check=True)
