#!/usr/bin/env python3
"""Reproduce an overwritten preselection host, preserving that fact explicitly."""
from pathlib import Path
import datetime
import hashlib
import json
import os
import shutil
import subprocess

ROOT=Path('/home/luke/projects/kpi-intensive-2026-10-22/proof')
TARGET=ROOT.parent/'proof-target'
OUT=TARGET/'two-v6-state-build-archive'
PIN=ROOT/'poc/two-v6-state/host/pins/guest-selection.json'
HOST=TARGET/'release/kpi-two-v6-state-proof-host'
SELECTED=TARGET/'two-v6-state-selected-host/kpi-two-v6-state-proof-host'
OLD='f9108922ff25452f881621fab088f7677c90dd23e432ab7a7533c5eefc5a0b82'
NEW='efba3e34eaca4b42e01c27ee92389bf0a46fa3708f7e15e77a43037384d90d01'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()

assert sha(SELECTED)==NEW
selected=(OUT/'selected-guest-selection.json').read_bytes()
old=(OUT/'preselection-guest-selection.json').read_bytes()
assert PIN.read_bytes()==selected
env=dict(os.environ)
env.update(CARGO_HOME=str(TARGET/'cargo-home'),CARGO_TARGET_DIR=str(TARGET),
    RUSTC='/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc')
command=['/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo',
    'build','--offline','--locked','--release','--jobs','2','--manifest-path',str(ROOT/'poc/two-v6-state/host/Cargo.toml')]
report={'schema':'kpi-two-v6-state-preselection-reproduction-v1',
    'reason':'Archive instruction arrived after selected-host rebuild replaced original output; original binary was not preserved before replacement.',
    'original_preselection_sha256':OLD,'selected_sha256':NEW,
    'reconstructed_after_original_overwrite':True,
    'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
try:
    PIN.write_bytes(old)
    subprocess.run(command,env=env,check=True)
    report['reconstructed_sha256']=sha(HOST)
    assert report['reconstructed_sha256']==OLD,'preselection reproduction did not match original bytes'
    shutil.copy2(HOST,OUT/'kpi-two-v6-state-proof-host-preselection')
    report['byte_identical_to_original_record']=True
finally:
    PIN.write_bytes(selected)
    subprocess.run(command,env=env,check=True)
    report['restored_selected_sha256']=sha(HOST)
    report['selected_pin_restored']=PIN.read_bytes()==selected
    assert sha(HOST)==NEW and report['selected_pin_restored']
    report['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    (OUT/'reproduction.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
