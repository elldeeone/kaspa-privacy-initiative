#!/usr/bin/env python3
"""Source-fixed offline guest build/wrap only; no R0 execution or proof."""
from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path(__file__).resolve().parents[2]
PACKAGE=Path(__file__).resolve().parent
TARGET=Path('/home/luke/projects/kpi-intensive-2026-10-22/shared-settlement-proof-target')
TOOLS=Path('/home/luke/projects/kpi-intensive-2026-10-22/proof-target/tools')
OUT=TARGET/'guest-build-02'
FLAGS='-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg getrandom_backend="custom"'
def sha(p):
    with Path(p).open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()
def sources():
    rows={}
    for directory in [PACKAGE/'common',PACKAGE/'guest',ROOT/'poc/accelerated-bn254/common',ROOT/'poc/groth16-comparison/common']:
        for p in directory.rglob('*'):
            if p.is_file() and 'target' not in p.parts:rows[str(p.relative_to(ROOT))]=sha(p)
    rows[str((PACKAGE/'child-profile.json').relative_to(ROOT))]=sha(PACKAGE/'child-profile.json')
    return rows
def main():
    OUT.mkdir(parents=True,exist_ok=False)
    auth=json.loads((ROOT/'research/next-session/independent-payments/fees/SDK-AUTHENTICATION-01.json').read_bytes())
    for row in auth['whole_bytes_reauthenticated']:
        assert sha(row['path'])==row['sha256'] and Path(row['path']).stat().st_size==row['bytes']
    before=sources();(OUT/'sources-before.json').write_text(json.dumps(before,sort_keys=True,indent=2)+'\n')
    host=TARGET/'release/kpi-shared-settlement-host'
    key=subprocess.run([str(host),'key-check'],capture_output=True,text=True,check=True)
    (OUT/'key-check.json').write_text(key.stdout)
    env={'PATH':str(TOOLS/'risc0-rust/bin')+':/usr/bin:/bin','CARGO_HOME':'/home/luke/projects/kpi-intensive-2026-10-22/proof-target/cargo-home',
        'CARGO_TARGET_DIR':str(TARGET),'CARGO_BUILD_JOBS':'4','RUSTC':str(TOOLS/'risc0-rust/bin/rustc'),
        'RISC0_FEATURE_bigint2':'1','RUSTFLAGS':FLAGS,'LANG':'C.UTF-8'}
    command=[str(TOOLS/'risc0-rust/bin/cargo'),'build','--offline','--locked','--release','--jobs','4',
        '--target','riscv32im-risc0-zkvm-elf','--manifest-path',str(PACKAGE/'guest/Cargo.toml')]
    began=time.monotonic();result=subprocess.run(command,env=env)
    report={'schema':'kpx5-public-settlement-guest-build/v1','command':command,'seconds':time.monotonic()-began,
        'exit_code':result.returncode,'host_elf_sha256':sha(host),'RUSTFLAGS':FLAGS,'RISC0_FEATURE_bigint2':'1',
        'guest_execution_or_proof_generation':False,'wrapper_native_acceptance_or_chain_claim':False}
    (OUT/'BUILD.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    assert result.returncode==0,'guest build failed'
    after=sources();assert before==after,'source changed during build'
    raw=TARGET/'riscv32im-risc0-zkvm-elf/release/kpi-shared-settlement-guest'
    wrapped=subprocess.run([str(host),'wrap',str(raw),str(TARGET/'guest-program-01')],capture_output=True,text=True,check=True)
    (OUT/'WRAPPED.json').write_text(wrapped.stdout)
    (OUT/'sources-after.json').write_text(json.dumps(after,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'guest_built_not_executed':True,'wrapped':json.loads(wrapped.stdout)},sort_keys=True))
if __name__=='__main__':main()
