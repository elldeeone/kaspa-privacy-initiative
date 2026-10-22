#!/usr/bin/env python3
"""Source-frozen, offline build only. No guest execution or proving."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/home/luke/projects/kpi-intensive-2026-10-22/proof')
TARGET = ROOT.parent / 'proof-target'
PACKAGE = ROOT / 'poc/two-v6-state'
OUT = TARGET / 'two-v6-state-build'
CARGO = Path('/home/luke/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo')
RUSTC = CARGO.parent / 'rustc'
GUEST = TARGET / 'tools/risc0-rust/bin'
FLAGS = '-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def write(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2) + '\n')

def sources():
    files = {}
    for path in PACKAGE.rglob('*'):
        if path.is_file() and 'evidence' not in path.relative_to(PACKAGE).parts:
            files[str(path.relative_to(ROOT))] = digest(path)
    old = json.loads((ROOT / 'poc/two-v6-binding/evidence/build-freeze.json').read_text())
    for name, expected in old['files'].items():
        actual = digest(ROOT / name)
        assert actual == expected, ('prior frozen pair source changed', name)
        files[name] = actual
    return files

def run(label, args, env):
    started = time.monotonic()
    print('BUILD STAGE', label, now(), flush=True)
    result = subprocess.run([str(arg) for arg in args], env=env)
    stages.append({'stage': label, 'seconds': time.monotonic()-started, 'exit_code': result.returncode})
    write('stages.json', stages)
    if result.returncode:
        raise SystemExit(result.returncode)

stages = []
before = sources()
write('sources-before.json', before)
env = dict(os.environ)
env.update(CARGO_HOME=str(TARGET / 'cargo-home'), CARGO_TARGET_DIR=str(TARGET),
           RUSTC=str(RUSTC), CARGO_BUILD_JOBS='8')
for name in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RISC0_DEV_MODE', 'RISC0_FEATURE_bigint2'):
    env.pop(name, None)
manifest = PACKAGE / 'host/Cargo.toml'
run('host-build', [CARGO,'build','--offline','--locked','--release','--jobs','8','--manifest-path',manifest], env)
run('host-tests', [CARGO,'test','--offline','--locked','--release','--jobs','8','--manifest-path',manifest], env)
run('core-tests-pinned-host-graph', [CARGO,'test','--offline','--locked','--release','--jobs','8','--manifest-path',manifest,'-p','kpi-two-v6-state'], env)
host = TARGET / 'release/kpi-two-v6-state-proof-host'
preflight = subprocess.run([str(host),'validate-key'],env=env,capture_output=True,text=True,check=True)
preflight = json.loads(preflight.stdout)
assert preflight['checked_immutable_key']
assert preflight['vk_sha256'] == '2a9acd1639fb7b454384c65fb317a139695f5a2cbb3ebd941dd13b5f6045a2f4'
preflight['checked_at_before_guest_build'] = now()
preflight['host_sha256'] = digest(host)
write('checked-key-preflight.json', preflight)
for name in ('current-anchor','historical-anchor'):
    run('host-oracle-'+name,[host,'host-check',name,PACKAGE/'public-fixtures'/name/'input.bin',OUT/('host-'+name)],env)
guest_env = dict(env)
guest_env.update(RUSTC=str(GUEST/'rustc'),RISC0_FEATURE_bigint2='1',RUSTFLAGS=FLAGS)
run('guest-build',[GUEST/'cargo','build','--offline','--locked','--release','--jobs','8',
    '--target','riscv32im-risc0-zkvm-elf','--manifest-path',PACKAGE/'guest/Cargo.toml'],guest_env)
raw = TARGET / 'riscv32im-risc0-zkvm-elf/release/kpi-two-v6-state-guest'
programs = TARGET / 'two-v6-state-programs'
wrapped = subprocess.run([str(host),'wrap',str(raw),str(programs)],env=env,capture_output=True,text=True,check=True)
wrap = json.loads(wrapped.stdout)
write('derived-program.json',wrap)
blocked = subprocess.run([str(host),'check-target','current-anchor',str(programs),str(PACKAGE/'public-fixtures/current-anchor/input.bin')],env=env,capture_output=True,text=True)
assert blocked.returncode != 0 and 'has not been selected' in blocked.stderr
write('unselected-execution-block.json', {'exit_code':blocked.returncode,'error':blocked.stderr,'execution_attempted':False})
after = sources()
assert before == after, 'source changed during build'
write('sources-after.json',after)
outputs = [programs/'guest.raw.elf',programs/'guest.program.bin',host,OUT/'checked-key-preflight.json']
tools = [CARGO,RUSTC,GUEST/'cargo',GUEST/'rustc',TARGET/'tools/r0vm',TARGET/'tools/r0vm-cuda',TARGET/'tools/risc0-rust.tgz',TARGET/'tools/cargo-risczero.tgz']
freeze = {'schema':'kpi-two-v6-state-build-freeze-v1','frozen_at':now(),
    'scope':'NONFUNDABLE_SYNTHETIC_STATE_ASSERTION_BUILD_ONLY',
    'status':'built-not-executed-no-selected-image','derived_image':wrap['derived_image'],
    'files':after,'outputs':{str(p):{'sha256':digest(p),'bytes':p.stat().st_size} for p in outputs},
    'tools':{str(p):{'sha256':digest(p),'bytes':p.stat().st_size} for p in tools},
    'static_key_prevalidation':preflight,'guest_env':{'RISC0_FEATURE_bigint2':'1','RUSTFLAGS':FLAGS},
    'resource_limits':{'cpu_quota_percent':800,'memory_max_bytes':10*1024**3,'swap_max_bytes':0,'build_wall_limit_seconds':1800},
    'guest_execution':False,'proof_generation':False,'native_predecessor_authenticated':False,'native_settlement':False}
write('build-freeze.json',freeze)
print(json.dumps({'built':True,'derived_image':wrap['derived_image'],'programs':str(programs),'freeze':str(OUT/'build-freeze.json')}),flush=True)
